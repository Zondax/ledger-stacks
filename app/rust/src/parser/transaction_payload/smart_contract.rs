use core::fmt::Write;

use nom::{
    bytes::complete::take,
    combinator::{flat_map, map},
    number::complete::{be_u32, be_u8},
    sequence::tuple,
};

use crate::{
    check_canary,
    parser::{ContractName, ParserError},
    zxformat,
};

/// A transaction that instantiates a smart contract
#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct TransactionSmartContract<'a>(&'a [u8]);

impl<'a> TransactionSmartContract<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<(&[u8], Self), ParserError> {
        check_canary!();

        // len prefixed contract name
        // len prefixed contract code
        let parse_length_1_byte = map(be_u8, |length| std::cmp::min(length, 128u8) as usize);
        let parse_length_4_bytes = flat_map(be_u32, take);

        let mut parser = tuple((flat_map(parse_length_1_byte, take), parse_length_4_bytes));
        let (_, (name, code)) = parser(bytes)?;

        // 1-byte name_len, name, 4-byte code_len, code
        let total_length = 1 + name.len() + 4 + code.len();
        let (rem, res) = take(total_length)(bytes)?;

        Ok((rem, Self(res)))
    }

    pub fn contract_name(&'a self) -> Result<ContractName<'a>, ParserError> {
        ContractName::from_bytes(self.0)
            .map(|(_, res)| res)
            .map_err(|e| e.into())
    }

    #[inline(never)]
    pub fn get_contract_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let mut writer_key = zxformat::Writer::new(out_key);

        match display_idx {
            0 => {
                writer_key
                    .write_str("Contract Name")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                check_canary!();
                let name = self.contract_name()?;
                zxformat::pageString(out_value, name.name(), page_idx)
            }
            _ => Err(ParserError::ValueOutOfRange),
        }
    }

    pub fn raw_data(&self) -> &'a [u8] {
        self.0
    }
}
