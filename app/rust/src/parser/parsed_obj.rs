use crate::bolos::c_zemu_log_stack;

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

// Must stay <= PARSER_BUFFER_SIZE in app/src/parser.c: a compile-time guard so this
// struct can never silently outgrow the C-side parser buffer. Post-conditions are held
// as one slice over the whole serialized block rather than one slice each, so the size
// no longer scales with NUM_SUPPORTED_POST_CONDITIONS. The bound holds on the host too
// (a 64-bit build is larger, every pointer being twice as wide), so unlike before it
// needs no `#[cfg]`. parser_allocate() also checks this at runtime.
//
// Mirror of PARSER_BUFFER_SIZE in app/src/parser.c.
const MAX_PARSED_OBJ_SIZE: usize = 1024;
const _: () = assert!(core::mem::size_of::<ParsedObj>() <= MAX_PARSED_OBJ_SIZE);

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
        c_zemu_log_stack("ParsedObj::read\x00");
        if data.is_empty() {
            return Err(ParserError::NoData);
        }

        // we expect a transaction
        self.tag = Tag::Invalid;

        unsafe {
            if Message::is_message(data) {
                c_zemu_log_stack("Tag::Msg\x00");
                self.tag = Tag::Message;
                self.obj.read_msg(data)
            } else if Jwt::is_jwt(data) {
                c_zemu_log_stack("Tag::Jwt\x00");
                self.tag = Tag::Jwt;
                self.obj.read_jwt(data)
            } else if StructuredMsg::is_msg(data) {
                c_zemu_log_stack("Tag::StructuredMsg\x00");
                self.tag = Tag::StructuredMsg;
                self.obj.read_structured_msg(data)
            } else {
                c_zemu_log_stack("Tag::Transaction\x00");
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
        c_zemu_log_stack("ParsedObj::get_item\x00");
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

    #[cfg(any(test, feature = "fuzzing"))]
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
impl core::fmt::Debug for ParsedObj<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug_struct = f.debug_struct("ParsedObj");
        debug_struct.field("tag", &self.tag);

        // Safety: We're matching on the tag to ensure we access the correct
        // union variant. The union is guaranteed to be initialized with the
        // correct variant and that variant won't change during the lifetime
        // of the object.
        match self.tag {
            Tag::Transaction => unsafe {
                debug_struct.field("obj", &self.obj.tx);
            },
            Tag::Message => unsafe {
                debug_struct.field("obj", &self.obj.msg);
            },
            Tag::Jwt => unsafe {
                debug_struct.field("obj", &self.obj.jwt);
            },
            Tag::StructuredMsg => unsafe {
                debug_struct.field("obj", &self.obj.structured_msg);
            },
            Tag::Invalid => {
                debug_struct.field("obj", &"<invalid>");
            }
        }

        debug_struct.finish()
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
        assert_eq!(1, transaction.post_conditions.num_conditions());
        let post_condition = transaction.post_conditions.first_post_condition().unwrap();
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

    /// Collects every review item the device would show for `bytes`, as `(key, value)` pairs.
    fn review_items(bytes: &[u8]) -> Vec<(String, String)> {
        let mut obj = ParsedObj::from_bytes(bytes).unwrap();
        obj.read(bytes).unwrap();
        ParsedObj::validate(&mut obj).unwrap();

        let num_items = obj.num_items().unwrap();
        let mut items = Vec::new();
        for idx in 0..num_items {
            let mut key = [0u8; 64];
            let mut value = [0u8; 64];
            obj.get_item(idx, &mut key, &mut value, 0)
                .expect("every index below num_items must render");
            let take = |b: &[u8]| {
                core::str::from_utf8(b)
                    .unwrap()
                    .trim_end_matches('\0')
                    .to_string()
            };
            items.push((take(&key), take(&value)));
        }
        items
    }

    /// Every transaction review states what happens to assets no post-condition covers.
    ///
    /// The mode byte was parsed and validated but never rendered, so an `Allow`-mode transaction
    /// showed the same protective-looking list of post-conditions as a `Deny`-mode one.
    #[test]
    fn test_post_condition_mode_is_displayed() {
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

        // Locate the mode byte in the raw blob so each variant can be exercised.
        let mode_offset = {
            let mut obj = ParsedObj::from_bytes(&bytes).unwrap();
            obj.read(&bytes).unwrap();
            let tx = obj.transaction().unwrap();
            tx.transaction_modes.as_ptr() as usize - bytes.as_ptr() as usize + 1
        };

        for (byte, expected) in [(0x01u8, "Allow"), (0x02, "Deny"), (0x03, "Originator")] {
            let mut patched = bytes.clone();
            patched[mode_offset] = byte;

            let items = review_items(&patched);
            let mode = items
                .iter()
                .find(|(k, _)| k == "Post-cond mode")
                .map(|(_, v)| v.as_str())
                .unwrap_or_else(|| panic!("no mode item for {:#04x}", byte));
            assert_eq!(mode, expected);
        }
    }

    /// A genuine SIP-10 transfer is reviewed through the compact card, with the base items and
    /// post-conditions suppressed.
    ///
    /// This is the branch the hiding predicate exists for. The negative case below proves the
    /// predicate does not fire when it should not; without this one, nothing proves it still
    /// fires when it should, and tightening it further could silently disable the compact card.
    #[test]
    fn test_registry_transfer_hides_base_items_and_post_conditions() {
        let input_path = {
            let mut r = PathBuf::new();
            r.push(env!("CARGO_MANIFEST_DIR"));
            r.push("tests");
            r.push("sip10_transfer_hidden_details");
            r.set_extension("json");
            r
        };
        let str = std::fs::read_to_string(input_path).expect("Error opening json file");
        let json: ContractCallTx = serde_json::from_str(&str).unwrap();
        let bytes = hex::decode(&json.raw).unwrap();

        assert_eq!(json.function_name, "transfer");

        let items = review_items(&bytes);
        let keys: Vec<&str> = items.iter().map(|(k, _)| k.as_str()).collect();

        // The compact card: header items, then exactly the four transfer arguments.
        assert_eq!(
            keys,
            std::vec![
                "Origin",
                "Nonce",
                "Fee (uSTX)",
                "Post-cond mode",
                "Amount",
                "From",
                "To",
                "Memo"
            ],
            "{:?}",
            items
        );

        // The suppressed items really are absent, not merely reordered.
        for hidden in ["Contract address", "Contract name", "Function name", "Asset name"] {
            assert!(!keys.contains(&hidden), "{} still shown: {:?}", hidden, keys);
        }
    }

    /// A contract call to a *registry* contract that is not a SIP-10 `transfer` must be reviewed
    /// in full.
    ///
    /// The item-hiding predicate matched on contract address and name alone, while the compact
    /// SIP-10 renderer additionally requires the function to be `transfer`. When the two
    /// disagreed, `num_items` shrank by the three base items but `get_item` still rendered them,
    /// so the review ran out of slots before the end of the payload. Which items were lost
    /// depended on the argument count; this fixture takes one argument, where everything after
    /// the contract address went unshown while the signature still covered it.
    #[test]
    fn test_registry_contract_non_transfer_call_shows_every_item() {
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

        // The fixture calls "hello-world", which the host-side registry stub recognises, with a
        // post-condition whose code is the one that stub advertises -- everything the hiding
        // predicate used to look at. Only the function name keeps it off the compact card.
        assert_ne!(json.function_name, "transfer");

        let items = review_items(&bytes);
        let keys: Vec<&str> = items.iter().map(|(k, _)| k.as_str()).collect();

        assert!(keys.contains(&"Contract address"), "{:?}", keys);
        assert!(keys.contains(&"Contract name"), "{:?}", keys);
        assert!(keys.contains(&"Function name"), "{:?}", keys);
        assert!(keys.iter().any(|k| k.starts_with("arg")), "{:?}", keys);
        assert!(keys.contains(&"Asset name"), "{:?}", keys);

        let function_name = items
            .iter()
            .find(|(k, _)| k == "Function name")
            .map(|(_, v)| v.as_str())
            .unwrap();
        assert_eq!(function_name, json.function_name);
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

        assert_eq!(transaction.post_conditions.num_conditions(), 1);
        let condition = transaction.post_conditions.first_post_condition().unwrap();
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

        assert_eq!(transaction.post_conditions.num_conditions(), 7);
        let condition = transaction.post_conditions.first_post_condition().unwrap();
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

    #[test]
    fn test_swap_tx() {
        let input = "000000000104009ef3889fd070159edcd8ef88a0ec87cea1592c83000000000000000000000000000f42400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000302000000060002169ef3889fd070159edcd8ef88a0ec87cea1592c830100000000000027100003167c5f674a8fd08efa61dd9b11121e046dd2c892730a756e6976322d636f72650300000000000000000103167c5f674a8fd08efa61dd9b11121e046dd2c892730a756e6976322d636f7265168c5e2f8d25627d6edebeb6d10fa3300f5acc8441086c6f6e67636f696e086c6f6e67636f696e0300000000000000000103167c5f674a8fd08efa61dd9b11121e046dd2c892730a756e6976322d636f7265168c5e2f8d25627d6edebeb6d10fa3300f5acc8441086c6f6e67636f696e086c6f6e67636f696e0300000000000000000102169ef3889fd070159edcd8ef88a0ec87cea1592c83168c5e2f8d25627d6edebeb6d10fa3300f5acc8441086c6f6e67636f696e086c6f6e67636f696e030000000000000000010316402da2c079e5d31d58b9cfc7286d1b1eb2f7834e0f616d6d2d7661756c742d76322d303116402da2c079e5d31d58b9cfc7286d1b1eb2f7834e0a746f6b656e2d616c657804616c65780300000000011c908a02162ec1a2dc2904ebc8b408598116c75e42c51afa2617726f757465722d76656c61722d616c65782d762d312d320d737761702d68656c7065722d6100000007010000000000000000000000000000271001000000000000000000000000011c908a040c00000002016106167c5f674a8fd08efa61dd9b11121e046dd2c892730477737478016206168c5e2f8d25627d6edebeb6d10fa3300f5acc8441086c6f6e67636f696e06167c5f674a8fd08efa61dd9b11121e046dd2c8927312756e6976322d73686172652d6665652d746f0c0000000201610616402da2c079e5d31d58b9cfc7286d1b1eb2f7834e0b746f6b656e2d776c6f6e6701620616402da2c079e5d31d58b9cfc7286d1b1eb2f7834e0a746f6b656e2d616c65780c0000000101610100000000000000000000000005f5e100";
        let bytes = hex::decode(input).unwrap();
        let mut msg = ParsedObj::from_bytes(&bytes).unwrap();

        msg.read(&bytes).unwrap();

        ParsedObj::validate(&mut msg).unwrap();

        std::println!("tx: {:?}", msg);
    }
    
    /// The transaction from issue #238 -- a 145-bin DLMM withdrawal carrying 158 post-conditions
    /// (155 MaySend NFTs on one asset, two FT, one STX) -- as the zemu `wide-position` fixture.
    /// Before #240 it was rejected at parse; the snapshots pin every screen, and this pins the
    /// number: 27 display items, with the 155 NFTs collapsed into one aggregated block.
    #[test]
    fn test_issue_238_transaction_renders_27_items() {
        let fixtures = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests_zemu/tests/dlmm_post_conditions.json"
        ))
        .expect("zemu fixture file");
        let fixtures: serde_json::Value = serde_json::from_str(&fixtures).unwrap();
        let bytes = hex::decode(fixtures["wide-position"].as_str().unwrap()).unwrap();

        let mut obj = ParsedObj::from_bytes(&bytes).expect("must parse after #240");
        obj.read(&bytes).unwrap();
        let num_items = obj.transaction().unwrap().num_items().unwrap();
        assert_eq!(num_items, 27);

        let cstr = |buf: &[u8]| {
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            String::from_utf8_lossy(&buf[..end]).into_owned()
        };
        let mut items = Vec::new();
        for idx in 0..num_items {
            let mut key = [0u8; 64];
            let mut value = [0u8; 300];
            obj.get_item(idx, &mut key, &mut value, 0)
                .unwrap_or_else(|e| panic!("item {} must render: {:?}", idx, e));
            items.push((cstr(&key), cstr(&value)));
        }
        let keys: Vec<&str> = items.iter().map(|(k, _)| k.as_str()).collect();

        assert_eq!(
            keys[..7],
            [
                "Origin",
                "Nonce",
                "Fee (uSTX)",
                "Post-cond mode",
                "Contract address",
                "Contract name",
                "Function name"
            ]
        );
        assert_eq!(items[6].1, "withdraw-relative-liquidity-same-multi");
        assert_eq!(keys[7..12], ["arg0", "arg1", "arg2", "arg3", "arg4"]);
        // The 145-bin list is far past what fits one item per leaf, so it renders as its type.
        assert_eq!(items[7].1, "is List");
        // 155 conditions on one (principal, asset, MaySend) key are a single 4-item block.
        assert_eq!(
            keys[23..],
            ["Principal", "Asset name", "NonFungi. Code", "Count"]
        );
        assert_eq!(items[25].1, "MaySend");
        assert_eq!(items[26].1, "155");
    }

    const MODE_FIXTURE_HEX: &str = "000000000104009ef3889fd070159edcd8ef88a0ec87cea1592c83000000000000000000000000000f42400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000302000000060002169ef3889fd070159edcd8ef88a0ec87cea1592c830100000000000027100003167c5f674a8fd08efa61dd9b11121e046dd2c892730a756e6976322d636f72650300000000000000000103167c5f674a8fd08efa61dd9b11121e046dd2c892730a756e6976322d636f7265168c5e2f8d25627d6edebeb6d10fa3300f5acc8441086c6f6e67636f696e086c6f6e67636f696e0300000000000000000103167c5f674a8fd08efa61dd9b11121e046dd2c892730a756e6976322d636f7265168c5e2f8d25627d6edebeb6d10fa3300f5acc8441086c6f6e67636f696e086c6f6e67636f696e0300000000000000000102169ef3889fd070159edcd8ef88a0ec87cea1592c83168c5e2f8d25627d6edebeb6d10fa3300f5acc8441086c6f6e67636f696e086c6f6e67636f696e030000000000000000010316402da2c079e5d31d58b9cfc7286d1b1eb2f7834e0f616d6d2d7661756c742d76322d303116402da2c079e5d31d58b9cfc7286d1b1eb2f7834e0a746f6b656e2d616c657804616c65780300000000011c908a02162ec1a2dc2904ebc8b408598116c75e42c51afa2617726f757465722d76656c61722d616c65782d762d312d320d737761702d68656c7065722d6100000007010000000000000000000000000000271001000000000000000000000000011c908a040c00000002016106167c5f674a8fd08efa61dd9b11121e046dd2c892730477737478016206168c5e2f8d25627d6edebeb6d10fa3300f5acc8441086c6f6e67636f696e06167c5f674a8fd08efa61dd9b11121e046dd2c8927312756e6976322d73686172652d6665652d746f0c0000000201610616402da2c079e5d31d58b9cfc7286d1b1eb2f7834e0b746f6b656e2d776c6f6e6701620616402da2c079e5d31d58b9cfc7286d1b1eb2f7834e0a746f6b656e2d616c65780c0000000101610100000000000000000000000005f5e100";

    #[test]
    fn test_anchor_mode_invalid_rejected() {
        let mut bytes = hex::decode(MODE_FIXTURE_HEX).unwrap();
        assert_eq!(bytes[109], 0x03);
        bytes[109] = 0xFF;
        let mut msg = ParsedObj::from_bytes(&bytes).unwrap();
        assert!(msg.read(&bytes).is_err());
    }

    #[test]
    fn test_postcondition_mode_invalid_rejected() {
        let mut bytes = hex::decode(MODE_FIXTURE_HEX).unwrap();
        assert_eq!(bytes[110], 0x02);
        bytes[110] = 0xFF;
        let mut msg = ParsedObj::from_bytes(&bytes).unwrap();
        assert!(msg.read(&bytes).is_err());
    }

    #[test]
    fn test_postcondition_mode_zero_rejected() {
        let mut bytes = hex::decode(MODE_FIXTURE_HEX).unwrap();
        bytes[110] = 0x00;
        let mut msg = ParsedObj::from_bytes(&bytes).unwrap();
        assert!(msg.read(&bytes).is_err());
    }
}

/// The three ways a contract call can leave the parser, exercised end to end through
/// `ParsedObj` -- the same object the C layer drives -- rather than through the payload alone.
///
///   review      every item renders; `requires_blindsign` is false and all items are readable
///   blind sign  something cannot be shown; `requires_blindsign` is true, and the C layer then
///               refuses unless the user has opted in
///   rejected    the transaction does not parse, or its items overflow the display index; it
///               cannot be signed at all, and enabling blind signing does not change that
#[cfg(test)]
mod gate_paths {
    use super::*;
    use crate::parser::transaction::MAX_DISPLAY_ITEMS;
    use crate::parser::transaction_payload::{MAX_ARG_DISPLAY_ITEMS, MAX_VALUE_TEXT};
    use crate::parser::TX_DEPTH_LIMIT;
    use std::prelude::v1::*;

    /// The `Contract_call` fixture from tests/testcases.json: a standard single-sig `stack-stx`
    /// call with no post-conditions and five scalar arguments. Everything up to the argument
    /// count is a valid prefix for any argument list.
    const CONTRACT_CALL_FIXTURE: &str = "8080000000040060dbb32efe0c56e1d418c020f4cb71c556b6a60d0000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000302000000000216000000000000000000000000000000000000000003706f7809737461636b2d737478000000050100000000000000000000000000004e20051ad386442122c88878ae04c5726762477f4ef09ffe0100000000000000000000000000000002061ad386442122c88878ae04c5726762477f4ef09ffe12736f6d652d636f6e74726163742d6e616d65010000000000000000000000000000000a";
    /// version(1) chain(4) auth(1+1+20+8+8+1+65) anchor(1) pc-mode(1) pc-count(4) payload-type(1)
    /// address(21) "pox"(4) "stack-stx"(10)
    const ARG_COUNT_OFFSET: usize = 151;
    /// The `be_u32` post-condition count sits after anchor and post-condition mode.
    const PC_COUNT_OFFSET: usize = 111;

    fn contract_call_tx(args: &[Vec<u8>]) -> Vec<u8> {
        let fixture = hex::decode(CONTRACT_CALL_FIXTURE).unwrap();
        let mut tx = fixture[..ARG_COUNT_OFFSET].to_vec();
        tx.extend_from_slice(&(args.len() as u32).to_be_bytes());
        for arg in args {
            tx.extend_from_slice(arg);
        }
        tx
    }

    /// Splices `count` copies of an STX post-condition (3 display items each) into a
    /// contract-call transaction.
    fn with_stx_post_conditions(tx: &[u8], count: u32) -> Vec<u8> {
        // type(0=STX) principal-type(2=standard) version(1) hash(20) code(3=SentGe) amount(8)
        let mut cond = vec![0x00, 0x02, 0x1a];
        cond.extend_from_slice(&[0x11; 20]);
        cond.push(0x03);
        cond.extend_from_slice(&1u64.to_be_bytes());

        let mut out = tx[..PC_COUNT_OFFSET].to_vec();
        out.extend_from_slice(&count.to_be_bytes());
        for _ in 0..count {
            out.extend_from_slice(&cond);
        }
        out.extend_from_slice(&tx[PC_COUNT_OFFSET + 4..]);
        out
    }

    fn uint(v: u128) -> Vec<u8> {
        let mut b = vec![0x01];
        b.extend_from_slice(&v.to_be_bytes());
        b
    }

    fn tuple_of(pairs: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut b = vec![0x0c];
        b.extend_from_slice(&(pairs.len() as u32).to_be_bytes());
        for (name, value) in pairs {
            b.push(name.len() as u8);
            b.extend_from_slice(name.as_bytes());
            b.extend_from_slice(value);
        }
        b
    }

    fn list_of(items: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![0x0b];
        b.extend_from_slice(&(items.len() as u32).to_be_bytes());
        for item in items {
            b.extend_from_slice(item);
        }
        b
    }

    fn string_utf8(content: &str) -> Vec<u8> {
        let mut b = vec![0x0e];
        b.extend_from_slice(&(content.len() as u32).to_be_bytes());
        b.extend_from_slice(content.as_bytes());
        b
    }

    fn string_ascii(len: usize) -> Vec<u8> {
        let mut b = vec![0x0d];
        b.extend_from_slice(&(len as u32).to_be_bytes());
        b.resize(b.len() + len, b'a');
        b
    }

    #[derive(Debug, PartialEq)]
    enum Outcome {
        /// Rendered items as `(key, value)`, page 0 only.
        Review(Vec<(String, String)>),
        BlindSign,
        Rejected,
    }

    fn cstr(buf: &[u8]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    }

    /// Drives a transaction the way `parser_parse` + `parser_validate` do.
    fn outcome(tx: &[u8]) -> Outcome {
        let mut obj = match ParsedObj::from_bytes(tx) {
            Ok(obj) => obj,
            Err(_) => return Outcome::Rejected,
        };
        if obj.read(tx).is_err() {
            return Outcome::Rejected;
        }
        let transaction = obj.transaction().expect("a contract call is a transaction");
        if transaction.requires_blindsign().expect("the gate must decide") {
            return Outcome::BlindSign;
        }
        // parser_validate: every item has to be fetchable, or the transaction is refused.
        let Ok(count) = transaction.num_items() else {
            return Outcome::Rejected;
        };
        let mut items = Vec::new();
        for idx in 0..count {
            let mut key = [0u8; 64];
            let mut value = [0u8; MAX_VALUE_TEXT + 1];
            if obj.get_item(idx, &mut key, &mut value, 0).is_err() {
                return Outcome::Rejected;
            }
            items.push((cstr(&key), cstr(&value)));
        }
        Outcome::Review(items)
    }

    fn keys(items: &[(String, String)]) -> Vec<&str> {
        items.iter().map(|(k, _)| k.as_str()).collect()
    }

    // ---- review ---------------------------------------------------------------------------

    #[test]
    fn review_flattens_structured_arguments() {
        let tx = contract_call_tx(&[
            uint(7),
            tuple_of(&[("amount", uint(1)), ("ids", list_of(&[uint(2), uint(3)]))]),
        ]);
        let Outcome::Review(items) = outcome(&tx) else {
            panic!("expected a normal review");
        };
        // origin, nonce, fee, post-condition mode, contract address, contract name, function
        // name, then the leaves
        assert_eq!(
            keys(&items)[7..],
            ["stacked uSTX", "arg1.amount", "arg1.ids[0]", "arg1.ids[1]"]
        );
        assert_eq!(items[10].1, "3");
    }

    /// Scalars past the leaf budget: not flattened, but every argument renders on its own, so
    /// the review is the one-item-per-argument layout the previous version showed.
    #[test]
    fn review_falls_back_to_one_item_per_argument() {
        let args: Vec<Vec<u8>> = (0..MAX_ARG_DISPLAY_ITEMS as u16 + 1).map(|i| uint(i as u128)).collect();
        let tx = contract_call_tx(&args);
        let Outcome::Review(items) = outcome(&tx) else {
            panic!("expected a normal review");
        };
        assert_eq!(items.len(), 7 + args.len());
        assert_eq!(items[7].0, "stacked uSTX");
        assert_eq!(items[8].0, "arg1");
        assert_eq!(items.last().unwrap().1, MAX_ARG_DISPLAY_ITEMS.to_string());
    }

    /// Post-conditions and argument leaves share the display index, so the same list of leaves
    /// reviews or is gated depending on how much room the post-conditions leave it.
    #[test]
    fn review_depends_on_what_post_conditions_leave_room_for() {
        let leaves: Vec<Vec<u8>> = (0..MAX_ARG_DISPLAY_ITEMS).map(|_| uint(1)).collect();
        let call = contract_call_tx(&[list_of(&leaves)]);

        // 7 + 64 + 15 * 3 = 116 items: fits, so every leaf is shown.
        let Outcome::Review(items) = outcome(&with_stx_post_conditions(&call, 15)) else {
            panic!("expected a normal review");
        };
        assert_eq!(items.len(), 7 + MAX_ARG_DISPLAY_ITEMS as usize + 15 * 3);

        // 7 + 64 + 20 * 3 = 131 items: past MAX_DISPLAY_ITEMS. The fallback cannot show a list
        // either, so this is gated rather than reviewed with the leaves missing.
        assert_eq!(outcome(&with_stx_post_conditions(&call, 20)), Outcome::BlindSign);
    }

    // ---- blind sign ----------------------------------------------------------------------

    #[test]
    fn blindsign_when_a_leaf_cannot_be_rendered() {
        // Non-ASCII text has no faithful rendering in the device fonts, whether bare...
        let tx = contract_call_tx(&[uint(1), string_utf8("\u{20ac}")]);
        assert_eq!(outcome(&tx), Outcome::BlindSign);
        // ...or buried inside a tuple.
        let tx = contract_call_tx(&[tuple_of(&[("ok", uint(1)), ("bad", string_utf8("\u{20ac}"))])]);
        assert_eq!(outcome(&tx), Outcome::BlindSign);
    }

    #[test]
    fn blindsign_when_a_value_exceeds_the_render_budget() {
        let tx = contract_call_tx(&[string_ascii(MAX_VALUE_TEXT + 1)]);
        assert_eq!(outcome(&tx), Outcome::BlindSign);
    }

    #[test]
    fn blindsign_when_a_container_exceeds_the_leaf_budget() {
        let leaves: Vec<Vec<u8>> = (0..MAX_ARG_DISPLAY_ITEMS as u16 + 1).map(|_| uint(1)).collect();
        let tx = contract_call_tx(&[list_of(&leaves)]);
        assert_eq!(outcome(&tx), Outcome::BlindSign);
    }

    // ---- rejected ------------------------------------------------------------------------

    /// An argument the parser cannot decode fails the parse. That is a rejection, not a gate:
    /// there is no blind-signing path for it, because the parser cannot even find where the
    /// argument ends, and so cannot locate anything after it.
    #[test]
    fn rejected_when_an_argument_cannot_be_decoded() {
        // An unknown Clarity type tag.
        let tx = contract_call_tx(&[uint(1), vec![0x0f, 0x00]]);
        assert_eq!(outcome(&tx), Outcome::Rejected);

        // A buffer whose length prefix runs past the end of the transaction.
        let mut truncated = vec![0x02];
        truncated.extend_from_slice(&64u32.to_be_bytes());
        truncated.extend_from_slice(&[0xab; 3]);
        let tx = contract_call_tx(&[truncated]);
        assert_eq!(outcome(&tx), Outcome::Rejected);

        // A string-ascii carrying a non-ASCII byte.
        let mut bad_ascii = vec![0x0d];
        bad_ascii.extend_from_slice(&1u32.to_be_bytes());
        bad_ascii.push(0xe2);
        let tx = contract_call_tx(&[bad_ascii]);
        assert_eq!(outcome(&tx), Outcome::Rejected);
    }

    fn nested_lists(depth: usize) -> Vec<u8> {
        let mut nested = uint(1);
        for _ in 0..depth {
            nested = list_of(&[nested]);
        }
        nested
    }

    /// Nesting depth walks through all three outcomes, and in that order. Up to the display
    /// limit the leaves are flattened and reviewed. One level past it the transaction still
    /// parses -- the network would accept it -- but the display walk gives up, so it is gated:
    /// the "valid but undisplayable" band where blind signing is the right answer. Past the
    /// parser's own limit it is rejected outright, because the parser cannot find where the
    /// argument ends and there is nothing to blind-sign.
    #[test]
    fn nesting_depth_runs_review_then_blindsign_then_rejected() {
        let outcomes: Vec<(usize, Outcome)> = (1..=TX_DEPTH_LIMIT as usize + 3)
            .map(|depth| (depth, outcome(&contract_call_tx(&[nested_lists(depth)]))))
            .collect();

        for (depth, result) in &outcomes {
            match result {
                Outcome::Review(items) => assert_eq!(
                    items[7].0,
                    std::format!("arg0{}", "[0]".repeat(*depth)),
                    "depth {}: flattened key",
                    depth
                ),
                Outcome::BlindSign | Outcome::Rejected => {}
            }
        }

        // The order is monotone: once gated, never reviewed again; once rejected, never gated.
        let rank = |o: &Outcome| match o {
            Outcome::Review(_) => 0,
            Outcome::BlindSign => 1,
            Outcome::Rejected => 2,
        };
        for pair in outcomes.windows(2) {
            assert!(rank(&pair[0].1) <= rank(&pair[1].1), "not monotone at {:?}", pair);
        }

        // ...and all three outcomes actually occur, at these depths. `walk_value` refuses a leaf
        // at depth TX_DEPTH_LIMIT, so that many nested lists is the first to gate. The parser's
        // own counter only advances for same-type nesting and rejects past TX_DEPTH_LIMIT, which
        // works out to two levels further -- a two-level band where the transaction is valid,
        // parses, and can only be blind-signed.
        let first = |target: u8| outcomes.iter().find(|(_, o)| rank(o) == target).map(|(d, _)| *d);
        assert_eq!(first(0), Some(1));
        assert_eq!(first(1), Some(TX_DEPTH_LIMIT as usize), "display limit");
        assert_eq!(first(2), Some(TX_DEPTH_LIMIT as usize + 2), "parser limit");
    }

    /// The argument count walks off the end of the display index in one step. The ceiling is
    /// MAX_DISPLAY_ITEMS, not 255: zxlib passes the review screens an `int8_t` index, so item 128
    /// can never be fetched. 121 scalar arguments fill it exactly and everything past that is
    /// refused -- where before, from 253 up, the overflow was swallowed inside the payload and
    /// the call reviewed as its header items with every argument absent.
    #[test]
    fn rejected_when_arguments_overflow_the_display_index() {
        let scalars = |n: usize| (0..n).map(|i| uint(i as u128)).collect::<Vec<_>>();
        let most = MAX_DISPLAY_ITEMS as usize - 7;

        let Outcome::Review(items) = outcome(&contract_call_tx(&scalars(most))) else {
            panic!("{} arguments fit the index exactly", most)
        };
        assert_eq!(items.len(), MAX_DISPLAY_ITEMS as usize);
        assert_eq!(items[MAX_DISPLAY_ITEMS as usize - 1].0, std::format!("arg{}", most - 1));

        for n in [most + 1, most + 4, 200, 300] {
            assert_eq!(
                outcome(&contract_call_tx(&scalars(n))),
                Outcome::Rejected,
                "{} arguments",
                n
            );
        }
    }

    /// Too many display items for the u8 index is a rejection, and stays one: it must not be
    /// turned into a blind-signing prompt, because enabling the setting would not make the
    /// transaction signable.
    #[test]
    fn rejected_not_gated_when_items_overflow_the_display_index() {
        // 85 STX conditions * 3 = 255 items on their own; with origin and base items, overflow.
        let tx = with_stx_post_conditions(&contract_call_tx(&[uint(1)]), 85);
        assert_eq!(outcome(&tx), Outcome::Rejected);

        // The same with a flattenable tuple argument: still rejected, never "blind sign".
        let tx = with_stx_post_conditions(
            &contract_call_tx(&[tuple_of(&[("a", uint(1)), ("b", uint(2))])]),
            85,
        );
        assert_eq!(outcome(&tx), Outcome::Rejected);
    }
}
