use core::fmt::Write;

use nom::{
    bytes::complete::take,
    combinator::{flat_map, map, verify},
    number::complete::{be_u32, be_u8},
    sequence::tuple,
};

use crate::{
    check_canary,
    parser::{ContractName, ParserError},
    zxformat,
};

/// A transaction that deploys a versioned smart contract
#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct VersionedSmartContract<'a>(&'a [u8]);

impl<'a> VersionedSmartContract<'a> {
    #[inline(never)]
    pub fn from_bytes(input: &'a [u8]) -> Result<(&'a [u8], Self), ParserError> {
        check_canary!();

        // clarity version
        // len prefixed contract name
        // len prefixed contract code
        // Any non-zero clarity version is accepted: the node is the authority on
        // which versions are valid, and the byte is rendered as a review item, so
        // future Clarity releases do not require an app update.
        let parse_version = verify(be_u8, |v: &u8| *v != 0);
        let parse_length_1_byte = map(be_u8, |length| std::cmp::min(length, 128u8) as usize);
        let parse_length_4_bytes = flat_map(be_u32, take);

        let mut parser = tuple((
            parse_version,
            flat_map(parse_length_1_byte, take),
            parse_length_4_bytes,
        ));
        let (_, (_, name, code)) = parser(input)?;

        // 1-byte version, 1-byte name_len, name, 4-byte code_len, code
        let total_length = 1 + 1 + name.len() + 4 + code.len();
        let (rem, res) = take(total_length)(input)?;

        Ok((rem, Self(res)))
    }

    pub fn clarity_version(&self) -> u8 {
        // safe: the version byte's presence was validated during parsing
        self.0[0]
    }

    pub fn contract_name(&'a self) -> Result<ContractName<'a>, ParserError> {
        // skip the version byte. safe because this was checked during parsing
        ContractName::from_bytes(&self.0[1..])
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
                zxformat::page_string(out_value, name.name(), page_idx)
            }
            1 => {
                writer_key
                    .write_str("Clarity Version")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                check_canary!();
                let mut version = [0u8; zxformat::U64_FORMATTED_SIZE_DECIMAL];
                let len =
                    zxformat::u64_to_str(&mut version, self.clarity_version() as u64)?.len();
                zxformat::page_string(out_value, &version[..len], page_idx)
            }
            _ => Err(ParserError::ValueOutOfRange),
        }
    }

    pub fn raw_data(&self) -> &'a [u8] {
        self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn payload(version: u8) -> std::vec::Vec<u8> {
        let name = b"hello-world";
        let code = b"(print \"hi\")";
        let mut data = std::vec![version, name.len() as u8];
        data.extend_from_slice(name);
        data.extend_from_slice(&(code.len() as u32).to_be_bytes());
        data.extend_from_slice(code);
        data
    }

    #[test]
    fn parse_any_nonzero_clarity_version() {
        // includes versions newer than any release known to the app
        for version in [1u8, 2, 3, 4, 6, 10, 255] {
            let data = payload(version);
            let (rem, parsed) = VersionedSmartContract::from_bytes(&data).unwrap();
            assert!(rem.is_empty());
            assert_eq!(parsed.clarity_version(), version);
            assert_eq!(parsed.contract_name().unwrap().name(), b"hello-world".as_ref());
        }
    }

    #[test]
    fn reject_clarity_version_zero() {
        let data = payload(0);
        assert!(VersionedSmartContract::from_bytes(&data).is_err());
    }
}
