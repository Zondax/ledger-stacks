#![allow(non_camel_case_types, non_snake_case, clippy::missing_safety_doc)]

use super::Jwt;
use super::{error::ParserError, transaction::Transaction, Message};

use core::mem::ManuallyDrop;

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Tag {
    Transaction,
    Message,
    Jwt,
    Invalid,
}

// safety: this is memory allocated in C and last the application lifetime
// and is initialized once which means that once the object is initialized with an especific
// union variant such variant wont be changed.
#[repr(C)]
pub union Obj<'a> {
    tx: ManuallyDrop<Transaction<'a>>,
    msg: ManuallyDrop<Message<'a>>,
    jwt: ManuallyDrop<Jwt<'a>>,
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
        let tag;

        if Message::is_message(data) {
            tag = Tag::Message;
        } else if Jwt::is_jwt(data) {
            tag = Tag::Jwt;
        } else {
            tag = Tag::Transaction;
        }

        let obj = Obj::from_bytes(data, tag)?;
        Ok(Self { tag, obj })
    }

    pub fn read(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        if data.is_empty() {
            return Err(ParserError::parser_no_data);
        }

        // we expect a transaction
        self.tag = Tag::Invalid;

        unsafe {
            if Message::is_message(data) {
                self.tag = Tag::Message;
                self.obj.read_msg(data)
            } else if Jwt::is_jwt(data) {
                self.tag = Tag::Jwt;
                self.obj.read_jwt(data)
            } else {
                self.tag = Tag::Transaction;
                self.obj.read_tx(data)
            }
        }
    }

    pub fn num_items(&mut self) -> Result<u8, ParserError> {
        unsafe {
            match self.tag {
                Tag::Transaction => self.obj.transaction().num_items(),
                Tag::Message => Ok(self.obj.message().num_items()),
                Tag::Jwt => Ok(self.obj.jwt().num_items()),
                _ => Err(ParserError::parser_unexpected_error),
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
                Tag::Jwt => self.obj.jwt().get_item(display_idx, key, value, page_idx),
                _ => Err(ParserError::parser_unexpected_error),
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

    pub fn is_jwt(&self) -> bool {
        matches!(self.tag, Tag::Jwt)
    }

    pub fn get_type(&mut self) -> Tag {
        self.tag
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

    pub fn jwt(&mut self) -> Option<&mut Jwt<'a>> {
        unsafe {
            if self.tag == Tag::Jwt {
                Some(self.obj.jwt())
            } else {
                None
            }
        }
    }

    #[cfg(any(test, fuzzing))]
    pub fn validate(tx: &mut Self) -> Result<(), ParserError> {
        use std::*;
        let mut key = [0u8; 100];
        let mut value = [0u8; 100];
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
    pub fn from_bytes(data: &'a [u8], tag: Tag) -> Result<Self, ParserError> {
        match tag {
            Tag::Transaction => Ok(Self {
                tx: ManuallyDrop::new(Transaction::from_bytes(data)?),
            }),
            Tag::Message => Ok(Self {
                msg: ManuallyDrop::new(Message::from_bytes(data)?),
            }),
            Tag::Jwt => Ok(Self {
                jwt: ManuallyDrop::new(Jwt::from_bytes(data)?),
            }),
            _ => Err(ParserError::parser_unexpected_type),
        }
    }
    pub unsafe fn read_tx(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        (&mut *self.tx).read(data)
    }

    pub unsafe fn read_msg(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        (&mut *self.msg).read(data)
    }

    pub unsafe fn read_jwt(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        (&mut *self.jwt).read(data)
    }

    #[inline(always)]
    pub unsafe fn transaction(&mut self) -> &mut Transaction<'a> {
        &mut *self.tx
    }

    pub unsafe fn message(&mut self) -> &mut Message<'a> {
        &mut *self.msg
    }

    pub unsafe fn jwt(&mut self) -> &mut Jwt<'a> {
        &mut *self.jwt
    }
}

#[cfg(test)]
mod test {
    use serde::{Deserialize, Serialize};
    use std::prelude::v1::*;

    use super::*;

    use crate::parser::*;
    use std::path::PathBuf;

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
        let data = format!("\x18Stacks Signed Message:\n{}{}", msg.len(), msg);
        let mut parsed_obj = ParsedObj::from_bytes(data.as_bytes()).expect("Invalid input data");
        ParsedObj::validate(&mut parsed_obj).unwrap();
    }

    #[test]
    fn read_jwt() {
        let data = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ==.eyJpc3N1ZWRfYXQiOjE0NDA3MTM0MTQuODUsImNoYWxsZW5nZSI6IjdjZDllZDVlLWJiMGUtNDllYS1hMzIzLWYyOGJkZTNhMDU0OSIsImlzc3VlciI6InhwdWI2NjFNeU13QXFSYmNGUVZyUXI0UTRrUGphUDRKaldhZjM5ZkJWS2pQZEs2b0dCYXlFNDZHQW1Lem81VURQUWRMU005RHVmWmlQOGVhdXk1NlhOdUhpY0J5U3ZacDdKNXdzeVFWcGkyYXh6WiIsImJsb2NrY2hhaW5pZCI6InJ5YW4ifQ==";
        let mut parsed_obj =
            ParsedObj::from_bytes(data.as_bytes()).expect("Invalid jwt input data");
        ParsedObj::validate(&mut parsed_obj).unwrap();
        parsed_obj.read(data.as_bytes()).unwrap();
        assert!(parsed_obj.tag == Tag::Jwt);
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
    }

    #[test]
    fn parse_contract_call_tx() {
        let bytes_str = "0000000001040061e115b4463fb27425e80fa8e3e2616b4e5a17e40000000000000011000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003020000000200021661e115b4463fb27425e80fa8e3e2616b4e5a17e40500000000000f4240010316e685b016b3b6cd9ebf35f38e5ae29392e2acd51d0a616c65782d7661756c7416e685b016b3b6cd9ebf35f38e5ae29392e2acd51d176167653030302d676f7665726e616e63652d746f6b656e04616c657803000000001a6e83360216e685b016b3b6cd9ebf35f38e5ae29392e2acd51d11737761702d68656c7065722d76312d30330b737761702d68656c706572000000040616e685b016b3b6cd9ebf35f38e5ae29392e2acd51d0a746f6b656e2d777374780616e685b016b3b6cd9ebf35f38e5ae29392e2acd51d176167653030302d676f7665726e616e63652d746f6b656e0100000000000000000000000005f5e1000a010000000000000000000000001a6e8336";
        let bytes = hex::decode(&bytes_str).unwrap();

        let mut transaction = ParsedObj::from_bytes(&bytes).unwrap();
        transaction.read(&bytes).unwrap();
        ParsedObj::validate(&mut transaction).unwrap();
        let transaction = transaction.transaction().unwrap();
        assert_eq!(transaction.origin_fee(), 0);
    }
}
