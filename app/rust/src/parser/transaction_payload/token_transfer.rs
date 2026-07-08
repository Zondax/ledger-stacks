use core::fmt::Write;

use arrayvec::ArrayVec;
use nom::{
    bytes::complete::take,
    number::complete::{be_u64, le_u8},
};

use crate::{
    check_canary,
    parser::{
        c32, ApduPanic, ClarityName, ContractName, ParserError, PrincipalData, AMOUNT_LEN,
        C32_ENCODED_ADDRS_LENGTH, MEMO_LEN,
    },
    zxformat,
};

// c32 address + '.' + contract name
const QUALIFIED_CONTRACT_ID_LEN: usize = C32_ENCODED_ADDRS_LENGTH + 1 + ClarityName::MAX_LEN as usize;

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
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self, ParserError> {
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

    /// Re-parses the recipient principal out of the raw payload.
    ///
    /// `self.0` is `[principal_id][version][hash160]([name_len][name])?[amount][memo]`, so the
    /// principal payload always starts at byte 1.
    #[inline(never)]
    fn principal(&self) -> Result<PrincipalData<'a>, ParserError> {
        let id = *self.0.first().ok_or(ParserError::NoData)?;
        let payload = self.0.get(1..).ok_or(ParserError::NoData)?;

        let (_, principal) = match TokenTranferPrincipal::from_u8(id)? {
            TokenTranferPrincipal::Standard => PrincipalData::standard_from_bytes(payload)?,
            TokenTranferPrincipal::Contract => PrincipalData::contract_principal_from_bytes(payload)?,
        };
        Ok(principal)
    }

    /// The contract name when the recipient is a contract principal, `None` for a standard one.
    ///
    /// STX transfers to `<deployer-address>.<contract-name>` are valid: consensus places no
    /// restriction on the recipient being a standard principal, and the STX land in the contract's
    /// balance. Rendering only the c32 address would make "send to Alice" and "send to a contract
    /// Alice deployed" look identical on screen, so the name has to be shown.
    pub fn contract_name(&self) -> Option<ContractName<'a>> {
        self.principal().ok()?.contract_name()
    }

    /// Renders the recipient: `SP...` for a standard principal, or the fully qualified
    /// `SP....contract-name` for a contract principal.
    fn render_recipient(&self, out_value: &mut [u8], page_idx: u8) -> Result<u8, ParserError> {
        let address = self.encoded_address()?;
        let address = address.as_ref();

        let Some(contract_name) = self.contract_name() else {
            return zxformat::page_string(out_value, address, page_idx);
        };

        let name = contract_name.name();
        let mut data = [0u8; QUALIFIED_CONTRACT_ID_LEN];
        let mut len = 0;

        data.get_mut(..address.len())
            .ok_or(ParserError::UnexpectedBufferEnd)?
            .copy_from_slice(address);
        len += address.len();

        *data.get_mut(len).ok_or(ParserError::UnexpectedBufferEnd)? = b'.';
        len += 1;

        data.get_mut(len..len + name.len())
            .ok_or(ParserError::UnexpectedBufferEnd)?
            .copy_from_slice(name);
        len += name.len();

        check_canary!();
        zxformat::page_string(out_value, &data[..len], page_idx)
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
                zxformat::page_string(out_value, amount.as_ref(), page_idx)
            }
            // Recipient: address, or `address.contract-name` when sending to a contract principal
            1 => {
                writer_key
                    .write_str("To")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                check_canary!();
                self.render_recipient(out_value, page_idx)
            }
            2 => {
                writer_key
                    .write_str("Memo")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                check_canary!();
                zxformat::page_string(out_value, self.memo(), page_idx)
            }
            _ => Err(ParserError::DisplayIdxOutOfRange),
        }
    }

    pub fn raw_data(&self) -> &'a [u8] {
        self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::prelude::v1::*;

    const VERSION: u8 = 26; // testnet single-sig -> "ST..."
    const HASH160: [u8; 20] = [0x11; 20];
    const AMOUNT: u64 = 1_000_000;

    /// `[0x05][version][hash160][amount: 8][memo: 34]`
    fn standard_payload() -> Vec<u8> {
        let mut b = vec![0x05, VERSION];
        b.extend_from_slice(&HASH160);
        b.extend_from_slice(&AMOUNT.to_be_bytes());
        b.extend_from_slice(&[0u8; MEMO_LEN]);
        b
    }

    /// `[0x06][version][hash160][name_len][name][amount: 8][memo: 34]`
    fn contract_payload(name: &str) -> Vec<u8> {
        let mut b = vec![0x06, VERSION];
        b.extend_from_slice(&HASH160);
        b.push(name.len() as u8);
        b.extend_from_slice(name.as_bytes());
        b.extend_from_slice(&AMOUNT.to_be_bytes());
        b.extend_from_slice(&[0u8; MEMO_LEN]);
        b
    }

    fn parse(bytes: &[u8]) -> StxTokenTransfer<'_> {
        StxTokenTransfer::from_bytes(bytes).expect("valid token transfer payload").1
    }

    /// Whatever the device shows for display item 1 ("To").
    fn rendered_recipient(bytes: &[u8]) -> String {
        let transfer = parse(bytes);
        let mut out_key = [0u8; 32];
        let mut out_value = [0u8; 200];
        transfer
            .get_token_transfer_items(1, &mut out_key, &mut out_value, 0)
            .expect("render failed");
        let end = out_value.iter().position(|&c| c == 0).unwrap_or(out_value.len());
        String::from_utf8(out_value[..end].to_vec()).expect("utf8")
    }

    #[test]
    fn test_standard_recipient_renders_bare_address() {
        let rendered = rendered_recipient(&standard_payload());
        assert!(rendered.starts_with("ST"), "got {:?}", rendered);
        assert!(!rendered.contains('.'), "standard principal must not gain a contract suffix");
    }

    /// The audit finding: a transfer to `<deployer>.<contract>` used to render exactly like a
    /// transfer to `<deployer>`, so the user could not tell the two apart on screen.
    #[test]
    fn test_contract_recipient_renders_qualified_contract_id() {
        let standard = rendered_recipient(&standard_payload());
        let contract = rendered_recipient(&contract_payload("my-contract"));

        assert_eq!(contract, format!("{standard}.my-contract"));
        assert_ne!(standard, contract, "the two recipients must be distinguishable");
    }

    #[test]
    fn test_contract_name_accessor() {
        assert!(parse(&standard_payload()).contract_name().is_none());

        let bytes = contract_payload("my-contract");
        let transfer = parse(&bytes);
        let name = transfer.contract_name().expect("contract principal");
        assert_eq!(name.name(), b"my-contract");
    }

    /// amount() and memo() index from the *end* of the payload, so a contract principal -- which
    /// is longer than a standard one -- is exactly the case that would break those offsets.
    #[test]
    fn test_amount_and_memo_survive_a_contract_principal() {
        for bytes in [standard_payload(), contract_payload("a-much-longer-contract-name")] {
            let transfer = parse(&bytes);
            assert_eq!(transfer.amount().unwrap(), AMOUNT);
            assert_eq!(transfer.memo().len(), MEMO_LEN);
        }
    }

    /// The c32 address is the deployer's address in both cases; only the suffix differs.
    #[test]
    fn test_encoded_address_is_the_deployer_for_both_principal_kinds() {
        let standard_bytes = standard_payload();
        let contract_bytes = contract_payload("my-contract");
        let standard = parse(&standard_bytes);
        let contract = parse(&contract_bytes);
        assert_eq!(
            standard.encoded_address().unwrap().as_ref(),
            contract.encoded_address().unwrap().as_ref()
        );
    }
}
