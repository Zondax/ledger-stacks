use core::fmt::Write;

use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    combinator::{flat_map, map},
    number::complete::{be_u32, be_u8},
    sequence::tuple,
};

use crate::{
    check_canary,
    parser::{ContractName, FromBytes, ParserError},
    zxformat,
};

/// A transaction that deploys a versioned smart contract
#[repr(C)]
#[derive(Clone, PartialEq, Copy)]
#[cfg_attr(test, derive(Debug))]
pub struct VersionedSmartContract<'a>(&'a [u8]);

impl<'b> FromBytes<'b> for VersionedSmartContract<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        use core::ptr::addr_of_mut;

        check_canary!();

        if input.is_empty() {
            return Err(nom::Err::Error(ParserError::UnexpectedBufferEnd));
        }

        // Use the existing parsing logic
        let parse_tag = alt((tag(&[0x01]), tag(&[0x02])));
        let parse_length_1_byte = map(be_u8, |length| std::cmp::min(length, 128u8) as usize);
        let parse_length_4_bytes = flat_map(be_u32, take);
        let mut parser = tuple((
            parse_tag,
            flat_map(parse_length_1_byte, take),
            parse_length_4_bytes,
        ));

        // Parse the tag, contract name, and code
        let (rem, (_, name, code)) = parser(input).map_err(|e| e)?;

        // Calculate the total length of the versioned smart contract data
        let total_length = input.len() - rem.len();

        // Take the bytes for this versioned smart contract
        let (rem, data) = take(total_length)(input).map_err(|e| e)?;

        // Get a pointer to the uninitialized memory
        let out_ptr = out.as_mut_ptr();

        // Initialize the VersionedSmartContract field with the input bytes
        unsafe {
            addr_of_mut!((*out_ptr).0).write(data);
        }

        // Return the remaining bytes
        Ok(rem)
    }
}

impl<'a> VersionedSmartContract<'a> {
    pub fn contract_name(&'a self) -> Result<ContractName<'a>, ParserError> {
        // skip the tag. safe ecause this was checked during parsing
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
                zxformat::pageString(out_value, name.name(), page_idx)
            }
            _ => Err(ParserError::ValueOutOfRange),
        }
    }

    pub fn raw_data(&self) -> &'a [u8] {
        self.0
    }
}
