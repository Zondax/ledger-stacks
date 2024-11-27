use core::fmt::Write;

use arrayvec::ArrayVec;
use nom::{
    bytes::complete::take,
    number::complete::{be_u64, le_u8},
};

use crate::{
    check_canary,
    parser::{
        c32, ApduPanic, ParserError, PrincipalData, AMOUNT_LEN, C32_ENCODED_ADDRS_LENGTH, MEMO_LEN,
    },
    zxformat,
};

#[repr(u8)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub enum TokenTranferPrincipal {
    Standard = 0x05,
    Contract = 0x06,
}

impl TokenTranferPrincipal {
    fn from_u8(v: u8) -> Result<Self, ParserError> {
        match v {
            5 => Ok(Self::Standard),
            6 => Ok(Self::Contract),
            _ => Err(ParserError::InvalidTokenTransferPrincipal),
        }
    }
}

#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct StxTokenTransfer<'a>(&'a [u8]);

impl<'a> StxTokenTransfer<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let id = le_u8(bytes)?;
        let (raw, _) = match TokenTranferPrincipal::from_u8(id.1)? {
            TokenTranferPrincipal::Standard => PrincipalData::standard_from_bytes(id.0)?,
            TokenTranferPrincipal::Contract => PrincipalData::contract_principal_from_bytes(id.0)?,
        };
        // Besides principal we take 34-bytes being the MEMO message + 8-bytes amount of stx
        let len = bytes.len() - raw.len() + MEMO_LEN + AMOUNT_LEN;
        let (raw, data) = take(len)(bytes)?;
        Ok((raw, Self(data)))
    }

    pub fn memo(&self) -> &[u8] {
        let at = self.0.len() - MEMO_LEN;
        // safe to unwrap as parser checked for proper len
        self.0.get(at..).apdu_unwrap()
    }

    pub fn amount(&self) -> Result<u64, ParserError> {
        let at = self.0.len() - MEMO_LEN - AMOUNT_LEN;
        let amount = self.0.get(at..).ok_or(ParserError::NoData)?;
        be_u64::<_, ParserError>(amount)
            .map(|res| res.1)
            .map_err(|_| ParserError::UnexpectedBufferEnd)
    }

    pub fn raw_address(&self) -> &[u8] {
        // Skips the principal-id and hash_mode
        // is valid as this was check by the parser
        // safe to unwrap as this was checked at parsing
        self.0.get(2..22).apdu_unwrap()
    }

    pub fn encoded_address(
        &self,
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        // Skips the principal-id at [0] and uses hash_mode and the follow 20-bytes
        let version = self.0.get(1).ok_or(ParserError::NoData)?;
        c32::c32_address(
            *version,
            self.0.get(2..22).ok_or(ParserError::InvalidAddress)?,
        )
    }

    pub fn amount_stx(&self) -> Result<ArrayVec<[u8; zxformat::MAX_STR_BUFF_LEN]>, ParserError> {
        let mut output = ArrayVec::from([0u8; zxformat::MAX_STR_BUFF_LEN]);
        let amount = self.amount()?;
        let len = zxformat::u64_to_str(output.as_mut(), amount)?.len();
        unsafe {
            output.set_len(len);
        }
        check_canary!();
        Ok(output)
    }

    pub fn get_token_transfer_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let mut writer_key = zxformat::Writer::new(out_key);

        match display_idx {
            // Fomatting the amount in stx
            0 => {
                writer_key
                    .write_str("Amount uSTX")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let amount = self.amount_stx()?;
                check_canary!();
                zxformat::pageString(out_value, amount.as_ref(), page_idx)
            }
            // Recipient address
            1 => {
                writer_key
                    .write_str("To")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let recipient = self.encoded_address()?;
                check_canary!();
                zxformat::pageString(out_value, recipient.as_ref(), page_idx)
            }
            2 => {
                writer_key
                    .write_str("Memo")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                check_canary!();
                zxformat::pageString(out_value, self.memo(), page_idx)
            }
            _ => Err(ParserError::DisplayIdxOutOfRange),
        }
    }

    pub fn raw_data(&self) -> &'a [u8] {
        self.0
    }
}
