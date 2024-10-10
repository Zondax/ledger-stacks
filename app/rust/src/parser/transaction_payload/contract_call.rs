use core::fmt::Write;

use nom::{bytes::complete::take, sequence::tuple};
use numtoa::NumToA;

use crate::{
    check_canary,
    parser::{
        c32, transaction_payload::arguments::Arguments, ApduPanic, ClarityName, ContractName,
        ParserError, PrincipalData, StacksAddress, ValueId, C32_ENCODED_ADDRS_LENGTH, HASH160_LEN,
    },
    zxformat,
};

pub const MAX_STRING_ASCII_TO_SHOW: usize = 60;
// The items in contract_call transactions are
// contract_address, contract_name and function_name
pub const CONTRACT_CALL_BASE_ITEMS: u8 = 3;
/// A transaction that calls into a smart contract
#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct TransactionContractCall<'a>(&'a [u8]);

impl<'a> TransactionContractCall<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let (rem, _) = StacksAddress::from_bytes(bytes)?;
        // get contract name and function name.
        let (rem, _) = tuple((
            ContractName::from_bytes,
            ClarityName::from_bytes,
            Arguments::from_bytes,
        ))(rem)?;

        let len = bytes.len() - rem.len();
        let (rem, data) = take(len)(bytes)?;

        check_canary!();

        Ok((rem, Self(data)))
    }

    pub fn contract_name(&'a self) -> Result<ContractName<'a>, ParserError> {
        let at = HASH160_LEN + 1;
        ContractName::from_bytes(&self.0[at..])
            .map(|(_, name)| name)
            .map_err(|e| e.into())
    }

    pub fn function_name(&self) -> Result<&[u8], ParserError> {
        ContractName::from_bytes(&self.0[(HASH160_LEN + 1)..])
            .and_then(|b| ClarityName::from_bytes(b.0))
            .map(|res| (res.1).0)
            .map_err(|_| ParserError::UnexpectedError)
    }

    pub fn function_args(&self) -> Result<Arguments<'a>, ParserError> {
        ContractName::from_bytes(&self.0[(HASH160_LEN + 1)..])
            .and_then(|b| ClarityName::from_bytes(b.0))
            .and_then(|c| Arguments::from_bytes(c.0))
            .map(|res| res.1)
            .map_err(|_| ParserError::InvalidArgumentId)
    }

    pub fn num_args(&self) -> Result<u32, ParserError> {
        self.function_args().and_then(|args| args.num_args())
    }

    #[inline(never)]
    pub fn contract_address(
        &self,
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        let version = self.0[0];
        c32::c32_address(version, &self.0[1..21])
    }

    // change label if it is a stacking contract call
    fn label_stacking_value(&self, key: &mut [u8]) -> Result<(), ParserError> {
        let addr = self.contract_address()?;
        let addr = addr.as_ref();
        let contract_name = self.contract_name()?;
        if (addr == "SP000000000000000000002Q6VF78".as_bytes()
            || addr == "ST000000000000000000002AMW42H".as_bytes())
            && contract_name.name() == "pox".as_bytes()
        {
            let name = self.function_name()?;
            if name == "stack-stx".as_bytes() {
                key.iter_mut().for_each(|v| *v = 0);
                let mut writer = zxformat::Writer::new(key);
                writer
                    .write_str("stacked uSTX")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
            } else if name == "delegate-stx".as_bytes() {
                key.iter_mut().for_each(|v| *v = 0);
                let mut writer = zxformat::Writer::new(key);
                writer
                    .write_str("delegated uSTX")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
            }
        }
        Ok(())
    }

    fn get_contract_call_args(
        &'a self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        if display_idx < CONTRACT_CALL_BASE_ITEMS {
            return Err(ParserError::DisplayIdxOutOfRange);
        }
        let arg_num = display_idx - CONTRACT_CALL_BASE_ITEMS;

        let args = self.function_args()?;

        let value = args.argument_at(arg_num as _)?;

        {
            let mut writer_key = zxformat::Writer::new(out_key);
            let mut arg_num_buff = [0u8; 3];
            let arg_num_str = arg_num.numtoa_str(10, &mut arg_num_buff);

            writer_key
                .write_str("arg")
                .map_err(|_| ParserError::UnexpectedBufferEnd)?;
            writer_key
                .write_str(arg_num_str)
                .map_err(|_| ParserError::UnexpectedBufferEnd)?;
        }

        // return the value content including the valueID
        let payload = value.payload();

        match value.value_id() {
            ValueId::Int => {
                let value = value.int().ok_or(ParserError::UnexpectedError)?;
                let mut buff = [0u8; 39];

                zxformat::pageString(
                    out_value,
                    value.numtoa_str(10, &mut buff).as_bytes(),
                    page_idx,
                )
            }
            ValueId::UInt => {
                let value = value.uint().ok_or(ParserError::UnexpectedError)?;
                let mut buff = [0u8; 39];

                if arg_num == 0 {
                    self.label_stacking_value(out_key)?;
                }

                zxformat::pageString(
                    out_value,
                    value.numtoa_str(10, &mut buff).as_bytes(),
                    page_idx,
                )
            }
            ValueId::BoolTrue => {
                zxformat::pageString(out_value, "is bool: true".as_bytes(), page_idx)
            }
            ValueId::BoolFalse => {
                zxformat::pageString(out_value, "is bool: false".as_bytes(), page_idx)
            }
            ValueId::OptionalNone => {
                zxformat::pageString(out_value, "is Option: None".as_bytes(), page_idx)
            }
            ValueId::OptionalSome => {
                zxformat::pageString(out_value, "is Option: Some".as_bytes(), page_idx)
            }
            ValueId::ResponseOk => {
                zxformat::pageString(out_value, "is Result: Ok".as_bytes(), page_idx)
            }
            ValueId::ResponseErr => {
                zxformat::pageString(out_value, "is Result: Err".as_bytes(), page_idx)
            }
            ValueId::StandardPrincipal => {
                let (_, principal) = PrincipalData::standard_from_bytes(payload)?;
                let address = principal.encoded_address()?;
                zxformat::pageString(out_value, &address[0..address.len()], page_idx)
            }
            ValueId::ContractPrincipal => {
                // holds principal_encoded address + '.' + contract_name
                let mut data = [0; C32_ENCODED_ADDRS_LENGTH + ClarityName::MAX_LEN as usize + 1];

                let (_, principal) = PrincipalData::contract_principal_from_bytes(payload)?;
                let address = principal.encoded_address()?;

                // should not fail as this was parsed in previous step
                let contract_name = principal.contract_name().apdu_unwrap();

                data.get_mut(..address.len())
                    .apdu_unwrap()
                    .copy_from_slice(&address[0..address.len()]);

                data[address.len()] = b'.';
                let len = address.len() + 1;

                // wont panic as we reserved enough space.
                data.get_mut(len..len + contract_name.len())
                    .apdu_unwrap()
                    .copy_from_slice(contract_name.name());

                zxformat::pageString(out_value, &data[0..len + contract_name.len()], page_idx)
            }
            ValueId::Buffer => zxformat::pageString(out_value, "is Buffer".as_bytes(), page_idx),
            ValueId::List => zxformat::pageString(out_value, "is List".as_bytes(), page_idx),
            ValueId::Tuple => zxformat::pageString(out_value, "is Tuple".as_bytes(), page_idx),
            ValueId::StringAscii => {
                // 4 bytes encode the length of the string
                let len = if payload.len() - 4 > MAX_STRING_ASCII_TO_SHOW {
                    MAX_STRING_ASCII_TO_SHOW
                } else {
                    payload.len()
                };
                zxformat::pageString(
                    out_value,
                    &payload[4..len], // omit the first 4-bytes as they are the string length
                    page_idx,
                )
            }

            ValueId::StringUtf8 => {
                zxformat::pageString(out_value, "is StringUtf8".as_bytes(), page_idx)
            }
        }
    }

    pub fn num_items(&self) -> Result<u8, ParserError> {
        // contract-address, contract-name, function-name
        // + the number of arguments
        let num_args = self.num_args()? as u8;
        num_args
            .checked_add(CONTRACT_CALL_BASE_ITEMS)
            .ok_or(ParserError::ValueOutOfRange)
    }

    fn get_base_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        if display_idx > CONTRACT_CALL_BASE_ITEMS {
            return Err(ParserError::DisplayIdxOutOfRange);
        }
        let mut writer_key = zxformat::Writer::new(out_key);
        match display_idx {
            // Contract-address
            0 => {
                writer_key
                    .write_str("Contract address")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let address = self.contract_address()?;
                check_canary!();
                zxformat::pageString(out_value, address.as_ref(), page_idx)
            }
            // Contract.name
            1 => {
                writer_key
                    .write_str("Contract name")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let name = self.contract_name()?;
                check_canary!();
                zxformat::pageString(out_value, name.name(), page_idx)
            }
            // Function-name
            2 => {
                writer_key
                    .write_str("Function name")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let name = self.function_name()?;
                check_canary!();
                zxformat::pageString(out_value, name, page_idx)
            }
            _ => Err(ParserError::DisplayIdxOutOfRange),
        }
    }

    pub fn get_contract_call_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        // display_idx was already normalize
        if display_idx < CONTRACT_CALL_BASE_ITEMS {
            self.get_base_items(display_idx, out_key, out_value, page_idx)
        } else {
            self.get_contract_call_args(display_idx, out_key, out_value, page_idx)
        }
    }

    pub fn raw_data(&self) -> &'a [u8] {
        self.0
    }
}
