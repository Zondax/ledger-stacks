#![allow(non_camel_case_types, non_snake_case, clippy::missing_safety_doc)]
use crate::parser::{parser_common::ParserError, transaction::Transaction, Message};
use crate::{bolos::c_zemu_log_stack, check_canary};
use nom::error::ErrorKind;

use core::mem::ManuallyDrop;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Tag {
    Transaction,
    Message,
}

// safety: this is memory allocated in C and last the application lifetime
// and is initialized once which means that once the object is initialized with an especific
// union variant such variant wont be changed.
#[repr(C)]
pub union Obj<'a> {
    tx: ManuallyDrop<Transaction<'a>>,
    msg: ManuallyDrop<Message<'a>>,
}

#[repr(C)]
pub struct ParsedObj<'a> {
    tag: Tag,
    obj: Obj<'a>,
}

impl<'a> ParsedObj<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ParserError> {
        if data.is_empty() {
            return Err(ParserError::parser_no_data);
        }
        // we expect a transaction
        let mut tag = Tag::Transaction;

        if Message::is_message(data) {
            tag = Tag::Message;
        }
        let obj = Obj::from_bytes(data)?;
        Ok(Self { tag, obj })
    }

    pub fn read(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        if data.is_empty() {
            return Err(ParserError::parser_no_data);
        }

        // we expect a transaction
        self.tag = Tag::Transaction;

        unsafe {
            if !Message::is_message(data) {
                self.obj.read_tx(data)
            } else {
                self.tag = Tag::Message;
                self.obj.read_msg(data)
            }
        }
    }

    pub fn num_items(&mut self) -> Result<u8, ParserError> {
        unsafe {
            match self.tag {
                Tag::Transaction => self.obj.transaction().num_items(),
                Tag::Message => self.obj.message().num_items(),
            }
        }
    }

    pub fn get_item(
        &mut self,
        display_idx: u8,
        key: &mut [u8],
        value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        unsafe {
            match self.tag {
                Tag::Transaction => {
                    self.obj
                        .transaction()
                        .get_item(display_idx, key, value, page_idx)
                }
                Tag::Message => self
                    .obj
                    .message()
                    .get_item(display_idx, key, value, page_idx),
            }
        }
    }

    pub fn is_transaction(&self) -> bool {
        matches!(self.tag, Tag::Transaction)
    }
    // For now we support only ByteString messages
    // but this later new data types could be to added
    pub fn is_message(&self) -> bool {
        matches!(self.tag, Tag::Message)
    }

    #[inline(always)]
    pub fn transaction(&mut self) -> Option<&mut Transaction<'a>> {
        unsafe {
            if self.tag == Tag::Transaction {
                Some(self.obj.transaction())
            } else {
                None
            }
        }
    }

    pub fn message(&mut self) -> Option<&mut Message<'a>> {
        unsafe {
            if self.tag == Tag::Message {
                Some(self.obj.message())
            } else {
                None
            }
        }
    }

    #[cfg(any(test, fuzzing))]
    pub fn validate(tx: &mut Self) -> Result<(), ParserError> {
        extern crate std;
        use std::*;
        let mut key = [0u8; 64];
        let mut value = [0u8; 64];
        let mut page_idx = 0;
        let mut display_idx = 0;

        let num_items = tx.num_items()?;
        while display_idx < num_items {
            let pages = tx.get_item(display_idx, &mut key, &mut value, page_idx)?;
            let k = string::String::from_utf8_lossy(key.as_ref());
            let v = string::String::from_utf8_lossy(value.as_ref());
            println!("key: {}", k);
            println!("value: {}", v);
            key.iter_mut().for_each(|v| *v = 0);
            value.iter_mut().for_each(|v| *v = 0);
            page_idx += 1;
            if page_idx >= pages {
                page_idx = 0;
                display_idx += 1;
            }
        }
        Ok(())
    }
}

impl<'a> Obj<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ParserError> {
        if Message::is_message(data) {
            let msg = ManuallyDrop::new(Message::from_bytes(data)?);
            Ok(Self { msg })
        } else {
            let tx = ManuallyDrop::new(Transaction::from_bytes(data)?);
            Ok(Self { tx })
        }
    }
    pub unsafe fn read_tx(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        (&mut *self.tx).read(data)
    }

    pub unsafe fn read_msg(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        (&mut *self.msg).read(data)
    }

    #[inline(always)]
    pub unsafe fn transaction(&mut self) -> &mut Transaction<'a> {
        &mut *self.tx
    }

    pub unsafe fn message(&mut self) -> &mut Message<'a> {
        &mut *self.msg
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use serde::{Deserialize, Serialize};
    use serde_json::{Result, Value};
    use std::vec::Vec;

    use super::*;

    use crate::parser::*;
    use std::fs;
    use std::path::PathBuf;
    use std::string::String;
    use std::string::ToString;

    #[derive(Serialize, Deserialize)]
    struct StxTransaction {
        raw: String,
        recipient: String,
        sender: String,
        nonce: u64,
        amount: u64,
        fee: u32,
        post_condition_principal: Option<String>,
    }

    #[derive(Serialize, Deserialize)]
    struct SmartContractTx {
        raw: String,
        sender: String,
        sponsor_addrs: Option<String>,
        fee: u64,
        nonce: u64,
        contract_name: String,
    }

    #[derive(Serialize, Deserialize)]
    struct ContractCallTx {
        raw: String,
        sender: String,
        sponsor_addrs: Option<String>,
        fee: u64,
        nonce: u64,
        contract_name: String,
        function_name: String,
        num_args: u32,
        post_condition_principal: Option<String>,
        post_condition_asset_name: Option<String>,
    }

    #[test]
    fn read_message() {
        let msg = "Hello World";
        let data = format!("\x19Stacks Signed Message:\n{}{}", msg.len(), msg);
        let mut parsed_obj = ParsedObj::from_bytes(data.as_bytes()).expect("Invalid input data");
        ParsedObj::validate(&mut parsed_obj).unwrap();
    }

    #[test]
    fn test_token_stx_transfer() {
        let input_path = {
            let mut r = PathBuf::new();
            r.push(env!("CARGO_MANIFEST_DIR"));
            r.push("tests");
            r.push("stx_token_transfer");
            r.set_extension("json");
            r
        };
        let str = std::fs::read_to_string(input_path).expect("Error opening json file");
        let json: StxTransaction = serde_json::from_str(&str).unwrap();

        let bytes = hex::decode(&json.raw).unwrap();
        let mut transaction = ParsedObj::from_bytes(&bytes).unwrap();
        transaction.read(&bytes).unwrap();
        ParsedObj::validate(&mut transaction).unwrap();
        let transaction = transaction.transaction().unwrap();

        assert!(transaction.transaction_auth.is_standard_auth());

        let spending_condition = transaction.transaction_auth.origin();

        assert_eq!(json.nonce, spending_condition.nonce().unwrap());
        assert_eq!(json.fee, spending_condition.fee().unwrap() as u32);

        let origin = spending_condition
            .signer_address(transaction.version)
            .unwrap();
        let origin = core::str::from_utf8(&origin[0..origin.len()]).unwrap();
        assert_eq!(&json.sender, origin);

        let recipient = transaction.payload_recipient_address().unwrap();
        let addr_len = recipient.len();
        let address = core::str::from_utf8(&recipient[0..addr_len]).unwrap();
        assert_eq!(&json.recipient, address);
        //assert!(ParsedObj::validate(&mut transaction).is_ok());
    }

    #[test]
    fn test_multisig_token_transfer() {
        let input_path = {
            let mut r = PathBuf::new();
            r.push(env!("CARGO_MANIFEST_DIR"));
            r.push("tests");
            r.push("stx_multisig_token_transfer");
            r.set_extension("json");
            r
        };
        let str = std::fs::read_to_string(input_path).expect("Error opening json file");
        let json: StxTransaction = serde_json::from_str(&str).unwrap();

        let bytes = hex::decode(&json.raw).unwrap();
        let mut transaction = ParsedObj::from_bytes(&bytes).unwrap();
        transaction.read(&bytes).unwrap();
        ParsedObj::validate(&mut transaction).unwrap();
        let transaction = transaction.transaction().unwrap();

        assert!(transaction.transaction_auth.is_standard_auth());

        let spending_condition = transaction.transaction_auth.origin();

        assert_eq!(json.nonce, spending_condition.nonce().unwrap());
        assert_eq!(json.fee, spending_condition.fee().unwrap() as u32);

        let origin = spending_condition
            .signer_address(transaction.version)
            .unwrap();
        let origin = core::str::from_utf8(&origin[0..origin.len()]).unwrap();
        assert_eq!(&json.sender, origin);

        let recipient = transaction.payload_recipient_address().unwrap();
        let addr_len = recipient.len();
        let address = core::str::from_utf8(&recipient[0..addr_len]).unwrap();
        assert_eq!(&json.recipient, address);
        //assert!(ParsedObj::validate(&mut transaction).is_ok());
    }

    #[test]
    fn test_token_stx_transfer_testnet() {
        let input_path = {
            let mut r = PathBuf::new();
            r.push(env!("CARGO_MANIFEST_DIR"));
            r.push("tests");
            r.push("stx_token_transfer_testnet");
            r.set_extension("json");
            r
        };
        let str = std::fs::read_to_string(input_path).expect("Error opening json file");
        let json: StxTransaction = serde_json::from_str(&str).unwrap();

        let bytes = hex::decode(&json.raw).unwrap();
        let mut transaction = ParsedObj::from_bytes(&bytes).unwrap();
        transaction.read(&bytes).unwrap();
        ParsedObj::validate(&mut transaction).unwrap();
        let transaction = transaction.transaction().unwrap();

        assert!(transaction.transaction_auth.is_standard_auth());

        let spending_condition = transaction.transaction_auth.origin();

        assert_eq!(json.nonce, spending_condition.nonce().unwrap());
        assert_eq!(json.fee, spending_condition.fee().unwrap() as u32);

        let origin = spending_condition
            .signer_address(TransactionVersion::Mainnet)
            .unwrap();
        let origin = core::str::from_utf8(&origin[0..origin.len()]).unwrap();
        assert_eq!(&json.sender, origin);

        let recipient = transaction.payload_recipient_address().unwrap();
        let addr_len = recipient.len();
        let address = core::str::from_utf8(&recipient[0..addr_len]).unwrap();
        assert_eq!(&json.recipient, address);
        //assert!(ParsedObj::validate(&mut transaction).is_ok());
    }

    #[test]
    fn test_token_stx_transfer_with_postcondition() {
        let input_path = {
            let mut r = PathBuf::new();
            r.push(env!("CARGO_MANIFEST_DIR"));
            r.push("tests");
            r.push("stx_token_transfer_postcondition");
            r.set_extension("json");
            r
        };
        let str = std::fs::read_to_string(input_path).expect("Error opening json file");
        let json: StxTransaction = serde_json::from_str(&str).unwrap();

        let bytes = hex::decode(&json.raw).unwrap();
        let mut transaction = ParsedObj::from_bytes(&bytes).unwrap();
        transaction.read(&bytes).unwrap();
        ParsedObj::validate(&mut transaction).unwrap();
        let transaction = transaction.transaction().unwrap();

        assert!(transaction.transaction_auth.is_standard_auth());

        let spending_condition = transaction.transaction_auth.origin();

        assert_eq!(json.nonce, spending_condition.nonce().unwrap());
        assert_eq!(json.fee, spending_condition.fee().unwrap() as u32);

        let origin = spending_condition
            .signer_address(TransactionVersion::Mainnet)
            .unwrap();
        let origin = core::str::from_utf8(&origin[0..origin.len()]).unwrap();
        assert_eq!(&json.sender, origin);

        let recipient = transaction.payload_recipient_address().unwrap();
        let addr_len = recipient.len();
        let address = core::str::from_utf8(&recipient[0..addr_len]).unwrap();
        assert_eq!(&json.recipient, address);

        // Check postconditions
        assert_eq!(1, transaction.post_conditions.conditions.len());
        let conditions = transaction.post_conditions.get_postconditions();
        let post_condition = TransactionPostCondition::from_bytes(conditions[0])
            .unwrap()
            .1;
        assert!(post_condition.is_stx());
        let condition_code = post_condition.fungible_condition_code().unwrap();
        assert_eq!(condition_code, FungibleConditionCode::SentGe);
        let stx_condition_amount = post_condition.amount_stx().unwrap();
        assert_eq!(12345, stx_condition_amount);
        assert!(!post_condition.is_origin_principal());
        //assert!(ParsedObj::validate(&mut transaction).is_ok());
    }

    #[test]
    fn test_standard_smart_contract_tx() {
        let input_path = {
            let mut r = PathBuf::new();
            r.push(env!("CARGO_MANIFEST_DIR"));
            r.push("tests");
            r.push("standard_smart_contract");
            r.set_extension("json");
            r
        };
        let str = std::fs::read_to_string(input_path).expect("Error opening json file");
        let json: SmartContractTx = serde_json::from_str(&str).unwrap();
        let bytes = hex::decode(&json.raw).unwrap();
        let mut transaction = ParsedObj::from_bytes(&bytes).unwrap();
        transaction.read(&bytes).unwrap();
        ParsedObj::validate(&mut transaction).unwrap();
        let transaction = transaction.transaction().unwrap();

        assert!(transaction.transaction_auth.is_standard_auth());
        assert!(transaction.payload.is_smart_contract_payload());
        let contract_name =
            core::str::from_utf8(transaction.payload.contract_name().unwrap()).unwrap();
        assert_eq!(json.contract_name, contract_name);

        let spending_condition = transaction.transaction_auth.origin();

        assert_eq!(json.nonce, spending_condition.nonce().unwrap());
        assert_eq!(json.fee as u32, spending_condition.fee().unwrap() as u32);

        let origin = spending_condition
            .signer_address(transaction.version)
            .unwrap();
        let origin = core::str::from_utf8(&origin[0..origin.len()]).unwrap();
        assert_eq!(json.sender, origin);
        //assert!(ParsedObj::validate(&mut transaction).is_ok());
    }

    #[test]
    fn test_sponsored_smart_contract_tx() {
        let input_path = {
            let mut r = PathBuf::new();
            r.push(env!("CARGO_MANIFEST_DIR"));
            r.push("tests");
            r.push("sponsored_smart_contract");
            r.set_extension("json");
            r
        };
        let str = std::fs::read_to_string(input_path).expect("Error opening json file");
        let json: SmartContractTx = serde_json::from_str(&str).unwrap();
        let bytes = hex::decode(&json.raw).unwrap();
        let mut transaction = ParsedObj::from_bytes(&bytes).unwrap();
        transaction.read(&bytes).unwrap();
        ParsedObj::validate(&mut transaction).unwrap();
        let transaction = transaction.transaction().unwrap();

        assert!(!transaction.transaction_auth.is_standard_auth());
        assert!(transaction.payload.is_smart_contract_payload());
        let contract_name =
            core::str::from_utf8(transaction.payload.contract_name().unwrap()).unwrap();
        assert_eq!(json.contract_name, contract_name);

        let spending_condition = transaction.transaction_auth.origin();
        let spending_condition_s = transaction.transaction_auth.sponsor().unwrap();

        assert_eq!(json.nonce, spending_condition.nonce().unwrap());
        assert_eq!(json.fee as u32, spending_condition.fee().unwrap() as u32);

        let origin = spending_condition
            .signer_address(transaction.version)
            .unwrap();
        let origin = core::str::from_utf8(&origin[0..origin.len()]).unwrap();
        assert_eq!(json.sender, origin);

        let sponsor_addrs = spending_condition_s
            .signer_address(transaction.version)
            .unwrap();
        let sponsor_addrs = core::str::from_utf8(&sponsor_addrs[0..sponsor_addrs.len()]).unwrap();
        assert_eq!(json.sponsor_addrs.unwrap(), sponsor_addrs);
        //assert!(ParsedObj::validate(&mut transaction).is_ok());
    }

    #[test]
    fn test_standard_contract_call_tx() {
        let input_path = {
            let mut r = PathBuf::new();
            r.push(env!("CARGO_MANIFEST_DIR"));
            r.push("tests");
            r.push("contract_call_testnet");
            r.set_extension("json");
            r
        };
        let str = std::fs::read_to_string(input_path).expect("Error opening json file");
        let json: ContractCallTx = serde_json::from_str(&str).unwrap();
        let bytes = hex::decode(&json.raw).unwrap();
        let mut transaction = ParsedObj::from_bytes(&bytes).unwrap();
        transaction.read(&bytes).unwrap();
        ParsedObj::validate(&mut transaction).unwrap();
        let transaction = transaction.transaction().unwrap();

        assert!(transaction.transaction_auth.is_standard_auth());
        assert!(transaction.payload.is_contract_call_payload());
        let contract_name =
            core::str::from_utf8(transaction.payload.contract_name().unwrap()).unwrap();
        assert_eq!(json.contract_name, contract_name);

        let function_name =
            core::str::from_utf8(transaction.payload.function_name().unwrap()).unwrap();
        assert_eq!(json.function_name, function_name);

        let num_args = transaction.payload.num_args().unwrap();
        assert_eq!(json.num_args, num_args);

        let origin = transaction.transaction_auth.origin();

        assert_eq!(json.nonce, origin.nonce().unwrap());
        assert_eq!(json.fee as u32, origin.fee().unwrap() as u32);

        let origin_addr = origin.signer_address(transaction.version).unwrap();
        let origin_addr = core::str::from_utf8(&origin_addr[..origin_addr.len()]).unwrap();
        assert_eq!(json.sender, origin_addr);

        //assert!(ParsedObj::validate(&mut transaction).is_ok());
    }

    #[test]
    fn test_standard_contract_call_tx_with_fungible_post_condition() {
        let input_path = {
            let mut r = PathBuf::new();
            r.push(env!("CARGO_MANIFEST_DIR"));
            r.push("tests");
            r.push("contract_call_with_fungible_postcondition");
            r.set_extension("json");
            r
        };
        let str = std::fs::read_to_string(input_path).expect("Error opening json file");
        let json: ContractCallTx = serde_json::from_str(&str).unwrap();
        let bytes = hex::decode(&json.raw).unwrap();
        let mut transaction = ParsedObj::from_bytes(&bytes).unwrap();
        transaction.read(&bytes).unwrap();
        ParsedObj::validate(&mut transaction).unwrap();
        let transaction = transaction.transaction().unwrap();

        assert!(transaction.transaction_auth.is_standard_auth());
        assert!(transaction.payload.is_contract_call_payload());
        let contract_name =
            core::str::from_utf8(transaction.payload.contract_name().unwrap()).unwrap();
        assert_eq!(json.contract_name, contract_name);

        let function_name =
            core::str::from_utf8(transaction.payload.function_name().unwrap()).unwrap();
        assert_eq!(json.function_name, function_name);

        let num_args = transaction.payload.num_args().unwrap();
        assert_eq!(json.num_args, num_args);

        let origin = transaction.transaction_auth.origin();

        assert_eq!(json.nonce, origin.nonce().unwrap());
        assert_eq!(json.fee as u32, origin.fee().unwrap() as u32);

        let origin_addr = origin.signer_address(transaction.version).unwrap();
        let origin_addr = core::str::from_utf8(&origin_addr[..origin_addr.len()]).unwrap();
        assert_eq!(json.sender, origin_addr);

        let post_conditions = transaction.post_conditions.get_postconditions();
        assert_eq!(post_conditions.len(), 1);
        let condition = TransactionPostCondition::from_bytes(post_conditions[0])
            .unwrap()
            .1;
        assert!(condition.is_fungible());
        let addr = condition.get_principal_address().unwrap();
        let principal_addr = core::str::from_utf8(&addr[..addr.len()]).unwrap();
        assert_eq!(json.post_condition_principal, Some(principal_addr.into()));

        //assert!(ParsedObj::validate(&mut transaction).is_ok());
    }

    #[test]
    fn test_sponsored_contract_call_tx() {
        let input_path = {
            let mut r = PathBuf::new();
            r.push(env!("CARGO_MANIFEST_DIR"));
            r.push("tests");
            r.push("sponsored_contract_call_testnet.json");
            r.set_extension("json");
            r
        };
        let str = std::fs::read_to_string(input_path).expect("Error opening json file");
        let json: ContractCallTx = serde_json::from_str(&str).unwrap();
        let bytes = hex::decode(&json.raw).unwrap();
        let mut transaction = ParsedObj::from_bytes(&bytes).unwrap();
        transaction.read(&bytes).unwrap();
        ParsedObj::validate(&mut transaction).unwrap();
        let transaction = transaction.transaction().unwrap();

        assert!(!transaction.transaction_auth.is_standard_auth());
        assert!(transaction.payload.is_contract_call_payload());
        let contract_name =
            core::str::from_utf8(transaction.payload.contract_name().unwrap()).unwrap();
        assert_eq!(json.contract_name, contract_name);

        let function_name =
            core::str::from_utf8(transaction.payload.function_name().unwrap()).unwrap();
        assert_eq!(json.function_name, function_name);

        // Test number of cuntion args
        let num_args = transaction.payload.num_args().unwrap();
        assert_eq!(json.num_args, num_args);

        let origin = transaction.transaction_auth.origin();
        let sponsor = transaction.transaction_auth.sponsor().unwrap();

        // test Fee, Nonce of origin
        assert_eq!(json.nonce, origin.nonce().unwrap());
        assert_eq!(json.fee as u32, origin.fee().unwrap() as u32);

        // Test origin and sponsor addresses
        let origin_addr = origin.signer_address(transaction.version).unwrap();
        let origin_addr = core::str::from_utf8(&origin_addr[..origin_addr.len()]).unwrap();
        assert_eq!(json.sender, origin_addr);

        let sponsor_addrs = sponsor.signer_address(transaction.version).unwrap();
        let sponsor_addrs = core::str::from_utf8(&sponsor_addrs[..sponsor_addrs.len()]).unwrap();
        assert_eq!(json.sponsor_addrs.unwrap(), sponsor_addrs);
        //assert!(ParsedObj::validate(&mut transaction).is_ok());
    }

    #[test]
    fn test_standard_contract_call_tx_with_7_postconditions() {
        let input_path = {
            let mut r = PathBuf::new();
            r.push(env!("CARGO_MANIFEST_DIR"));
            r.push("tests");
            r.push("contract_call_with_7_postconditions");
            r.set_extension("json");
            r
        };
        let str = std::fs::read_to_string(input_path).expect("Error opening json file");
        let json: ContractCallTx = serde_json::from_str(&str).unwrap();
        let bytes = hex::decode(&json.raw).unwrap();
        let mut transaction = ParsedObj::from_bytes(&bytes).unwrap();
        transaction.read(&bytes).unwrap();
        ParsedObj::validate(&mut transaction).unwrap();
        let transaction = transaction.transaction().unwrap();

        assert!(transaction.transaction_auth.is_standard_auth());
        assert!(transaction.payload.is_contract_call_payload());
        let contract_name =
            core::str::from_utf8(transaction.payload.contract_name().unwrap()).unwrap();
        assert_eq!(json.contract_name, contract_name);

        let function_name =
            core::str::from_utf8(transaction.payload.function_name().unwrap()).unwrap();
        assert_eq!(json.function_name, function_name);

        let num_args = transaction.payload.num_args().unwrap();
        assert_eq!(json.num_args, num_args);

        let origin = transaction.transaction_auth.origin();

        assert_eq!(json.nonce, origin.nonce().unwrap());
        assert_eq!(json.fee as u32, origin.fee().unwrap() as u32);

        let origin_addr = origin.signer_address(transaction.version).unwrap();
        let origin_addr = core::str::from_utf8(&origin_addr[..origin_addr.len()]).unwrap();
        assert_eq!(json.sender, origin_addr);

        let post_conditions = transaction.post_conditions.get_postconditions();
        assert_eq!(post_conditions.len(), 7);
        let condition = TransactionPostCondition::from_bytes(post_conditions[0])
            .unwrap()
            .1;
        assert!(condition.is_fungible());
        let addr = condition.get_principal_address().unwrap();
        let principal_addr = core::str::from_utf8(&addr[..addr.len()]).unwrap();
        assert_eq!(json.post_condition_principal, Some(principal_addr.into()));

        //assert!(ParsedObj::validate(&mut transaction).is_ok());
    }
}
