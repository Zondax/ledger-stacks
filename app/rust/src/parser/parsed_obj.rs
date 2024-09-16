#![allow(non_camel_case_types, non_snake_case, clippy::missing_safety_doc)]

use super::{error::ParserError, transaction::Transaction, Message};
use super::{Jwt, StructuredMsg};

use core::mem::ManuallyDrop;

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum Tag {
    Transaction,
    Message,
    Jwt,
    StructuredMsg,
    Invalid,
}

// safety: this is memory allocated in C and last the application lifetime
// and is initialized once which means that once the object is initialized with an especific
// union variant such variant wont be changed.
#[repr(C)]
pub union Obj<'a> {
    tx: ManuallyDrop<Transaction<'a>>,
    msg: ManuallyDrop<Message<'a>>,
    structured_msg: ManuallyDrop<StructuredMsg<'a>>,
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
            return Err(ParserError::NoData);
        }
        // we expect a transaction
        let tag;

        if Message::is_message(data) {
            tag = Tag::Message;
        } else if Jwt::is_jwt(data) {
            tag = Tag::Jwt;
        } else if StructuredMsg::is_msg(data) {
            tag = Tag::StructuredMsg;
        } else {
            tag = Tag::Transaction;
        }

        let obj = Obj::from_bytes(data, tag)?;
        Ok(Self { tag, obj })
    }

    pub fn read(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        if data.is_empty() {
            return Err(ParserError::NoData);
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
            } else if StructuredMsg::is_msg(data) {
                self.tag = Tag::StructuredMsg;
                self.obj.read_structured_msg(data)
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
                Tag::StructuredMsg => Ok(self.obj.structured_msg().num_items()),
                Tag::Jwt => Ok(self.obj.jwt().num_items()),
                _ => Err(ParserError::UnexpectedError),
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
                Tag::StructuredMsg => {
                    self.obj
                        .structured_msg()
                        .get_item(display_idx, key, value, page_idx)
                }
                Tag::Jwt => self.obj.jwt().get_item(display_idx, key, value, page_idx),
                _ => Err(ParserError::UnexpectedError),
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

    pub fn structured_msg(&mut self) -> Option<&mut StructuredMsg<'a>> {
        unsafe {
            if self.tag == Tag::StructuredMsg {
                Some(self.obj.structured_msg())
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
            Tag::StructuredMsg => Ok(Self {
                structured_msg: ManuallyDrop::new(StructuredMsg::from_bytes(data)?),
            }),
            Tag::Jwt => Ok(Self {
                jwt: ManuallyDrop::new(Jwt::from_bytes(data)?),
            }),
            _ => Err(ParserError::UnexpectedType),
        }
    }
    pub unsafe fn read_tx(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        (*self.tx).read(data)
    }

    pub unsafe fn read_msg(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        (*self.msg).read(data)
    }

    pub unsafe fn read_structured_msg(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        (*self.structured_msg).read(data)
    }

    pub unsafe fn read_jwt(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        (*self.jwt).read(data)
    }

    #[inline(always)]
    pub unsafe fn transaction(&mut self) -> &mut Transaction<'a> {
        &mut self.tx
    }

    pub unsafe fn message(&mut self) -> &mut Message<'a> {
        &mut self.msg
    }

    pub unsafe fn structured_msg(&mut self) -> &mut StructuredMsg<'a> {
        &mut self.structured_msg
    }

    pub unsafe fn jwt(&mut self) -> &mut Jwt<'a> {
        &mut self.jwt
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
        let blob = "17537461636b73205369676e6564204d6573736167653a0a0b48656c6c6f20576f726c64";
        let blob = hex::decode(blob).unwrap();
        let mut parsed_obj = ParsedObj::from_bytes(&blob).expect("Invalid input data");
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
        let contract_name = transaction.payload.contract_name().unwrap();
        let contract_name = core::str::from_utf8(contract_name.name()).unwrap();
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
        let contract_name = transaction.payload.contract_name().unwrap();
        let contract_name = core::str::from_utf8(contract_name.name()).unwrap();
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
        let contract_name = transaction.payload.contract_name().unwrap();
        let contract_name = core::str::from_utf8(contract_name.name()).unwrap();
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
        let contract_name = transaction.payload.contract_name().unwrap();
        let contract_name = core::str::from_utf8(contract_name.name()).unwrap();
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
        let contract_name = transaction.payload.contract_name().unwrap();
        let contract_name = core::str::from_utf8(contract_name.name()).unwrap();
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
        let contract_name = transaction.payload.contract_name().unwrap();
        let contract_name = core::str::from_utf8(contract_name.name()).unwrap();
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
        let bytes = hex::decode(bytes_str).unwrap();

        let mut transaction = ParsedObj::from_bytes(&bytes).unwrap();
        transaction.read(&bytes).unwrap();
        ParsedObj::validate(&mut transaction).unwrap();

        let transaction = transaction.transaction().unwrap();
        assert_eq!(transaction.origin_fee(), 0);
    }

    #[test]
    fn parse_structured_msg() {
        let input = "5349503031380c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c00000008016100ffffffffffffffffffffffffffffffff01620200000008616263646566676808636861696e2d69640100000000000000000000000000000001016d0b0000000400ffffffffffffffffffffffffffffffff00ffffffffffffffffffffffffffffffff00ffffffffffffffffffffffffffffffff00ffffffffffffffffffffffffffffffff046e616d650c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e30057475706c650c0000000308636861696e2d69640100000000000000000000000000025983046e616d650c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300776657273696f6e0d00000005312e302e30067475706c65320c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300776657273696f6e0b000000020c0000000308636861696e2d69640100000000000000000000000000025983046e616d650c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300776657273696f6e0b000000050c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300776657273696f6e0b000000050c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e30";
        let bytes = hex::decode(input).unwrap();
        let mut msg = ParsedObj::from_bytes(&bytes).unwrap();
        msg.read(&bytes).unwrap();
        ParsedObj::validate(&mut msg).unwrap();
    }

    #[test]
    fn parse_versioned_contract() {
        let input = "8080000000040060dbb32efe0c56e1d418c020f4cb71c556b6a60d0000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000301000000000602107468656e2d677265656e2d6d61636177000004cf3b3b2068656c6c6f2d776f726c6420636f6e74726163740a0a28646566696e652d636f6e7374616e742073656e6465722027535a324a365a593438475631455a35563256355242394d5036365357383650594b4b51394836445052290a28646566696e652d636f6e7374616e7420726563697069656e742027534d324a365a593438475631455a35563256355242394d5036365357383650594b4b51565838583047290a0a28646566696e652d66756e6769626c652d746f6b656e206e6f76656c2d746f6b656e2d3139290a2866742d6d696e743f206e6f76656c2d746f6b656e2d3139207531322073656e646572290a2866742d7472616e736665723f206e6f76656c2d746f6b656e2d31392075322073656e64657220726563697069656e74290a0a28646566696e652d6e6f6e2d66756e6769626c652d746f6b656e2068656c6c6f2d6e66742075696e74290a0a286e66742d6d696e743f2068656c6c6f2d6e66742075312073656e646572290a286e66742d6d696e743f2068656c6c6f2d6e66742075322073656e646572290a286e66742d7472616e736665723f2068656c6c6f2d6e66742075312073656e64657220726563697069656e74290a0a28646566696e652d7075626c69632028746573742d656d69742d6576656e74290a202028626567696e0a20202020287072696e7420224576656e74212048656c6c6f20776f726c64220a20202020286f6b207531290a2020290a290a0a28626567696e2028746573742d656d69742d6576656e7429290a0a28646566696e652d7075626c69632028746573742d6576656e742d7479706573290a202028626567696e0a2020202028756e777261702d70616e6963202866742d6d696e743f206e6f76656c2d746f6b656e2d313920753320726563697069656e7429290a2020202028756e777261702d70616e696320286e66742d6d696e743f2068656c6c6f2d6e667420753220726563697069656e7429290a2020202028756e777261702d70616e696320287374782d7472616e736665723f207536302074782d73656e6465722027535a324a365a593438475631455a35563256355242394d5036365357383650594b4b5139483644505229290a2020202028756e777261702d70616e696320287374782d6275726e3f207532302074782d73656e64657229290a20202020286f6b207531290a2020290a290a0a28646566696e652d6d61702073746f7265207b206b65793a20286275666620333229207d207b2076616c75653a20286275666620333229207d290a0a28646566696e652d7075626c696320286765742d76616c756520286b65792028627566662033322929290a202028626567696e0a20202020286d6174636820286d61702d6765743f2073746f7265207b206b65793a206b6579207d290a202020202020656e74727920286f6b20286765742076616c756520656e74727929290a202020202020286572722030290a20202020290a2020290a290a0a28646566696e652d7075626c696320287365742d76616c756520286b65792028627566662033322929202876616c75652028627566662033322929290a202028626567696e0a20202020286d61702d7365742073746f7265207b206b65793a206b6579207d207b2076616c75653a2076616c7565207d290a20202020286f6b207531290a2020290a290a";
        let bytes = hex::decode(input).unwrap();
        let mut msg = ParsedObj::from_bytes(&bytes).unwrap();
        msg.read(&bytes).unwrap();
        ParsedObj::validate(&mut msg).unwrap();
    }
}
