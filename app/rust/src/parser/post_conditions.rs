use arrayvec::ArrayVec;
use core::{convert::TryFrom, fmt::Write};
use nom::{
    bytes::complete::take,
    number::complete::{be_u64, le_u8},
};

mod fungible;
mod non_fungible;
mod post_condition_principal;
pub use fungible::FungibleConditionCode;
pub use non_fungible::NonfungibleConditionCode;

pub use post_condition_principal::{PostConditionPrincipal, PostConditionPrincipalId};

use super::error::ParserError;

use super::parser_common::{AssetInfo, C32_ENCODED_ADDRS_LENGTH, STX_DECIMALS, TX_DEPTH_LIMIT};
use crate::zxformat;
use crate::{bolos::c_zemu_log_stack, parser::value::Value};

/// Number of display items emitted for an aggregated run of identical NFT
/// post-conditions: Principal, Asset name, NonFungi. Code, Count.
pub const AGGREGATED_NFT_ITEMS: u8 = 4;

#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
pub enum PostConditionType {
    Stx = 0,
    FungibleToken = 1,
    NonFungibleToken = 2,
}

impl TryFrom<u8> for PostConditionType {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let t = match value {
            0 => Self::Stx,
            1 => Self::FungibleToken,
            2 => Self::NonFungibleToken,
            _ => return Err(ParserError::InvalidPostCondition),
        };

        Ok(t)
    }
}

/// Post-condition on a transaction
#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub enum TransactionPostCondition<'a> {
    Stx(&'a [u8]),
    Fungible(&'a [u8]),
    Nonfungible(&'a [u8]),
}

impl<'a> TransactionPostCondition<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self, ParserError> {
        let (raw, cond_type) = le_u8(bytes)?;
        let principal = PostConditionPrincipal::read_as_bytes(raw)?;
        let principal_len = raw.len() - principal.0.len();

        match PostConditionType::try_from(cond_type)? {
            PostConditionType::Stx => {
                let len = principal_len + 1 + 8;
                let (raw, inner) = take(len)(raw)?;
                Ok((raw, Self::Stx(inner)))
            }
            PostConditionType::FungibleToken => {
                let asset = AssetInfo::read_as_bytes(principal.0)?;
                let len = principal_len + asset.1.len() + 1 + 8;
                let (raw, inner) = take(len)(raw)?;
                Ok((raw, Self::Fungible(inner)))
            }
            PostConditionType::NonFungibleToken => {
                let asset = AssetInfo::read_as_bytes(principal.0)?;
                let value_len = Value::value_len::<TX_DEPTH_LIMIT>(asset.0)?;
                let len = principal_len + asset.1.len() + value_len + 1;
                let (raw, inner) = take(len)(raw)?;
                Ok((raw, Self::Nonfungible(inner)))
            }
        }
    }

    pub fn read_as_bytes(bytes: &'a [u8]) -> nom::IResult<&'a [u8], &'a [u8], ParserError> {
        let rem = bytes;
        let (rem, cond_type) = le_u8(rem)?;
        let (mut rem, _) = PostConditionPrincipal::read_as_bytes(rem)?;

        match PostConditionType::try_from(cond_type)? {
            PostConditionType::Stx => {
                // We take 9-bytes which comprises the 8-byte amount + 1-byte fungible code
                let (raw, _) = take(9usize)(rem)?;
                rem = raw;
            }
            PostConditionType::FungibleToken => {
                let (raw, _) = AssetInfo::read_as_bytes(rem)?;
                // We take 9-bytes which containf the 8-byte amount + 1-byte fungible code
                let (raw, _) = take(9usize)(raw)?;
                rem = raw;
            }
            PostConditionType::NonFungibleToken => {
                let (asset_raw, _) = AssetInfo::read_as_bytes(rem)?;
                let (raw, _) = Value::from_bytes::<TX_DEPTH_LIMIT>(asset_raw)?;
                let (raw, _) = take(1usize)(raw)?;
                rem = raw;
            }
        };
        crate::check_canary!();
        let len = bytes.len() - rem.len();
        take(len)(bytes)
    }

    pub fn is_origin_principal(&self) -> bool {
        match self {
            Self::Stx(principal) | Self::Fungible(principal) | Self::Nonfungible(principal) => {
                principal[0] == PostConditionPrincipalId::Origin as u8
            }
        }
    }

    pub fn is_standard_principal(&self) -> bool {
        match self {
            Self::Stx(principal) | Self::Fungible(principal) | Self::Nonfungible(principal) => {
                principal[0] == PostConditionPrincipalId::Standard as u8
            }
        }
    }

    pub fn is_contract_principal(&self) -> bool {
        match self {
            Self::Stx(principal) | Self::Fungible(principal) | Self::Nonfungible(principal) => {
                principal[0] == PostConditionPrincipalId::Origin as u8
            }
        }
    }

    #[inline(never)]
    pub fn get_principal_address(
        &self,
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        match self {
            Self::Stx(principal) | Self::Fungible(principal) | Self::Nonfungible(principal) => {
                let (_, principal) = PostConditionPrincipal::from_bytes(principal)
                    .map_err(|_| ParserError::InvalidPostCondition)?;
                principal.get_principal_address()
            }
        }
    }

    pub fn is_stx(&self) -> bool {
        matches!(self, Self::Stx(..))
    }

    pub fn is_fungible(&self) -> bool {
        matches!(self, Self::Fungible(..))
    }

    pub fn is_non_fungible(&self) -> bool {
        matches!(self, Self::Nonfungible(..))
    }

    pub fn tokens_amount(&self) -> Option<u64> {
        match *self {
            Self::Stx(inner) | Self::Fungible(inner) => {
                let at = inner.len() - 8;
                be_u64::<_, ParserError>(&inner[at..]).map(|res| res.1).ok()
            }
            _ => None,
        }
    }

    pub fn amount_stx(&self) -> Option<u64> {
        match self {
            Self::Stx(inner) => {
                let at = inner.len() - 8;
                be_u64::<_, ParserError>(&inner[at..]).map(|res| res.1).ok()
            }
            _ => None,
        }
    }

    pub fn tokens_amount_str(&self) -> Option<ArrayVec<[u8; zxformat::MAX_STR_BUFF_LEN]>> {
        let mut output = ArrayVec::from([0u8; zxformat::MAX_STR_BUFF_LEN]);

        let amount = self.tokens_amount()?;
        let len = zxformat::u64_to_str(output.as_mut(), amount).ok()?.len();
        unsafe {
            output.set_len(len);
        }
        Some(output)
    }

    pub fn amount_stx_str(&self) -> Option<ArrayVec<[u8; zxformat::U64_FORMATTED_SIZE_DECIMAL]>> {
        let amount = self.amount_stx()?;

        let mut output = ArrayVec::from([0u8; zxformat::U64_FORMATTED_SIZE_DECIMAL]);
        let len = zxformat::fpu64_to_str(output.as_mut(), amount, STX_DECIMALS).ok()? as usize;
        unsafe {
            output.set_len(len);
        }
        Some(output)
    }

    pub fn fungible_condition_code(&self) -> Option<FungibleConditionCode> {
        let code = match self {
            Self::Stx(inner) | Self::Fungible(inner) => inner[inner.len() - 9], // TODO: comment this 9
            _ => return None,
        };
        FungibleConditionCode::from_u8(code)
    }

    pub fn non_fungible_condition_code(&self) -> Option<NonfungibleConditionCode> {
        let code = match self {
            Self::Nonfungible(inner) => inner[inner.len() - 1],
            _ => return None,
        };
        NonfungibleConditionCode::from_u8(code)
    }

    pub fn asset_name(&self) -> Option<&[u8]> {
        match self {
            Self::Fungible(inner) | Self::Nonfungible(inner) => {
                PostConditionPrincipal::from_bytes(inner)
                    .and_then(|res| AssetInfo::from_bytes(res.0))
                    .map(|res| res.1.asset_name.0)
                    .ok()
            }
            _ => None,
        }
    }

    pub fn num_items(&self) -> u8 {
        match self {
            Self::Stx(..) | Self::Nonfungible(..) => 3,
            Self::Fungible(..) => 4,
        }
    }

    pub fn write_principal_address(
        &self,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        // The post condition principal address
        let mut writer_key = zxformat::Writer::new(out_key);
        writer_key
            .write_str("Principal")
            .map_err(|_| ParserError::UnexpectedBufferEnd)?;
        let addr = self.get_principal_address()?;
        let rs = zxformat::pageString(out_value, addr.as_ref(), page_idx);
        crate::check_canary!();
        rs
    }

    pub fn get_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let index = display_idx % self.num_items();

        if index == 0 {
            self.write_principal_address(out_key, out_value, page_idx)
        } else {
            match self {
                Self::Stx(..) => self.get_stx_items(index, out_key, out_value, page_idx),
                Self::Fungible(..) => self.get_fungible_items(index, out_key, out_value, page_idx),
                Self::Nonfungible(..) => {
                    self.get_non_fungible_items(index, out_key, out_value, page_idx)
                }
            }
        }
    }

    pub fn get_stx_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        c_zemu_log_stack("TransactionPostCondition::get_stx_items\x00");

        let mut writer_key = zxformat::Writer::new(out_key);
        match self {
            Self::Stx(..) => match display_idx {
                // PostCondition code
                1 => {
                    writer_key
                        .write_str("Fungi. Code")
                        .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                    let code = self
                        .fungible_condition_code()
                        .ok_or(ParserError::InvalidFungibleCode)?;
                    zxformat::pageString(out_value, code.to_str().as_bytes(), page_idx)
                }
                // Amount in stx
                2 => {
                    writer_key
                        .write_str("Stx amount")
                        .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                    let amount = self.amount_stx_str().unwrap();
                    zxformat::pageString(out_value, amount.as_ref(), page_idx)
                }
                _ => Err(ParserError::DisplayIdxOutOfRange),
            },
            _ => Err(ParserError::UnexpectedError),
        }
    }

    pub fn get_fungible_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        c_zemu_log_stack("TransactionPostCondition::get_fungible_items\x00");

        let mut writer_key = zxformat::Writer::new(out_key);
        match self {
            Self::Fungible(..) => {
                match display_idx {
                    // Asset-name
                    1 => {
                        writer_key
                            .write_str("Asset name")
                            .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                        let name = self.asset_name().ok_or(ParserError::InvalidAssetName)?;
                        crate::check_canary!();
                        zxformat::pageString(out_value, name, page_idx)
                    }
                    // Fungible code
                    2 => {
                        writer_key
                            .write_str("Fungi. Code")
                            .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                        let code = self
                            .fungible_condition_code()
                            .ok_or(ParserError::InvalidFungibleCode)?;
                        crate::check_canary!();
                        zxformat::pageString(out_value, code.to_str().as_bytes(), page_idx)
                    }
                    // Amount of tokens
                    3 => {
                        writer_key
                            .write_str("Token amount")
                            .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                        let token = self
                            .tokens_amount_str()
                            .ok_or(ParserError::UnexpectedValue)?;
                        crate::check_canary!();
                        zxformat::pageString(out_value, &token[..token.len()], page_idx)
                    }
                    _ => Err(ParserError::DisplayIdxOutOfRange),
                }
            }
            _ => Err(ParserError::UnexpectedError),
        }
    }

    pub fn get_non_fungible_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        c_zemu_log_stack("TransactionPostCondition::get_non_fungible_items\x00");

        let mut writer_key = zxformat::Writer::new(out_key);
        match self {
            Self::Nonfungible(..) => {
                match display_idx {
                    // Asset-name
                    1 => {
                        writer_key
                            .write_str("Asset name")
                            .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                        let name = self.asset_name().ok_or(ParserError::InvalidAssetName)?;
                        zxformat::pageString(out_value, name, page_idx)
                    }
                    // Fungible code
                    2 => {
                        writer_key
                            .write_str("NonFungi. Code")
                            .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                        let code = self
                            .non_fungible_condition_code()
                            .ok_or(ParserError::InvalidNonFungibleCode)?;
                        zxformat::pageString(out_value, code.to_str().as_bytes(), page_idx)
                    }
                    _ => Err(ParserError::DisplayIdxOutOfRange),
                }
            }
            _ => Err(ParserError::UnexpectedError),
        }
    }

    /// For an aggregatable non-fungible post-condition, returns the bytes that identify it
    /// apart from the per-token value: (principal, asset-info, condition-code). Two such
    /// conditions with the same key differ only in which token instance they reference, so
    /// they can be collapsed into a single aggregated display item.
    ///
    /// Only `MaySend` (the permissive code, always satisfied) is aggregated. `Sent` and
    /// `NotSent` are guarantees about specific tokens, so they are always rendered
    /// individually. Returns None for STX/FT and for non-MaySend NFT conditions.
    pub fn nft_group_key(&self) -> Option<(&'a [u8], &'a [u8], u8)> {
        match self {
            Self::Nonfungible(inner) => {
                let inner = *inner;
                let code = *inner.last()?;
                if code != NonfungibleConditionCode::MaySend as u8 {
                    return None;
                }
                let (after_principal, _) = PostConditionPrincipal::read_as_bytes(inner).ok()?;
                let principal = &inner[..inner.len() - after_principal.len()];
                let (after_asset, _) = AssetInfo::read_as_bytes(after_principal).ok()?;
                let asset = &after_principal[..after_principal.len() - after_asset.len()];
                Some((principal, asset, code))
            }
            _ => None,
        }
    }

    /// Render one display item of an aggregated run of `count` identical NFT
    /// post-conditions (see `nft_group_key`). Shows the shared principal/asset/code once
    /// plus the number of conditions collapsed.
    pub fn get_aggregated_nft_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
        count: u32,
    ) -> Result<u8, ParserError> {
        match display_idx {
            0 => self.write_principal_address(out_key, out_value, page_idx),
            1 => {
                let mut writer_key = zxformat::Writer::new(out_key);
                writer_key
                    .write_str("Asset name")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let name = self.asset_name().ok_or(ParserError::InvalidAssetName)?;
                zxformat::pageString(out_value, name, page_idx)
            }
            2 => {
                let mut writer_key = zxformat::Writer::new(out_key);
                writer_key
                    .write_str("NonFungi. Code")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let code = self
                    .non_fungible_condition_code()
                    .ok_or(ParserError::InvalidNonFungibleCode)?;
                zxformat::pageString(out_value, code.to_str().as_bytes(), page_idx)
            }
            3 => {
                let mut writer_key = zxformat::Writer::new(out_key);
                writer_key
                    .write_str("Count")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let mut buf = ArrayVec::from([0u8; zxformat::MAX_STR_BUFF_LEN]);
                let len = zxformat::u64_to_str(buf.as_mut(), count as u64)
                    .map_err(|_| ParserError::UnexpectedValue)?
                    .len();
                zxformat::pageString(out_value, &buf[..len], page_idx)
            }
            _ => Err(ParserError::DisplayIdxOutOfRange),
        }
    }

    #[cfg(test)]
    pub fn get_inner_bytes(&self) -> &[u8] {
        match self {
            Self::Stx(inner) | Self::Fungible(inner) | Self::Nonfungible(inner) => inner,
        }
    }
}

#[cfg(test)]
mod test {

    use crate::parser::StacksAddress;

    use super::*;
    use std::prelude::v1::*;

    // STX: type(0) | principal | code | amount(8). FT: type(1) | principal | asset | code |
    // amount(8). NFT: type(2) | principal | asset | value | code.
    fn stx_cond(code: u8) -> Vec<u8> {
        let mut v = vec![0u8, 2, 1];
        v.extend_from_slice(&[1u8; 20]);
        v.push(code);
        v.extend_from_slice(&[0u8; 8]);
        v
    }
    fn ft_cond(code: u8) -> Vec<u8> {
        let mut v = vec![1u8, 2, 1];
        v.extend_from_slice(&[1u8; 20]);
        v.push(1);
        v.extend_from_slice(&[0xBB; 20]);
        v.push(4);
        v.extend_from_slice(b"pool");
        v.push(3);
        v.extend_from_slice(b"tok");
        v.push(code);
        v.extend_from_slice(&[0u8; 8]);
        v
    }
    fn nft_cond(code: u8) -> Vec<u8> {
        let mut v = vec![2u8, 2, 1];
        v.extend_from_slice(&[1u8; 20]);
        v.push(1);
        v.extend_from_slice(&[0xBB; 20]);
        v.push(4);
        v.extend_from_slice(b"pool");
        v.push(3);
        v.extend_from_slice(b"tok");
        v.push(0x03); // value: bool (1 byte)
        v.push(code);
        v
    }

    #[test]
    fn test_maysend_code_cannot_leak_into_ft_or_stx() {
        // 0x12 (MaySend) is an NFT-only code. On an STX/FT condition it is not a valid
        // fungible code, so fungible_condition_code() rejects it (=> InvalidFungibleCode
        // at display, never silently accepted).
        let stx_bytes = stx_cond(0x12);
        let stx = TransactionPostCondition::from_bytes(&stx_bytes).unwrap().1;
        assert!(stx.fungible_condition_code().is_none());

        let ft_bytes = ft_cond(0x12);
        let ft = TransactionPostCondition::from_bytes(&ft_bytes).unwrap().1;
        assert!(ft.fungible_condition_code().is_none());

        // Conversely, a fungible code (0x02) on an NFT is not a valid non-fungible code.
        let nft_bytes = nft_cond(0x02);
        let nft_bad = TransactionPostCondition::from_bytes(&nft_bytes).unwrap().1;
        assert!(nft_bad.non_fungible_condition_code().is_none());
    }

    #[test]
    fn test_group_key_only_matches_maysend_nft() {
        // STX / FT / non-MaySend NFT are never aggregatable (group key is None);
        // only MaySend (0x12) yields a grouping key.
        let cases: &[(Vec<u8>, bool)] = &[
            (stx_cond(0x01), false),
            (ft_cond(0x01), false),
            (nft_cond(0x10), false), // Sent
            (nft_cond(0x11), false), // NotSent
            (nft_cond(0x12), true),  // MaySend
        ];
        for (bytes, expected) in cases {
            let pc = TransactionPostCondition::from_bytes(bytes).unwrap().1;
            assert_eq!(pc.nft_group_key().is_some(), *expected);
        }
    }

    #[test]
    fn test_stx_postcondition() {
        let bytes = [
            0u8, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0, 0, 0, 0,
            0, 0, 48, 57,
        ];
        let parsed1 = TransactionPostCondition::from_bytes(bytes.as_ref())
            .unwrap()
            .1;
        assert!(parsed1.is_stx());
        assert_eq!(parsed1.amount_stx().unwrap(), 12345);
        assert_eq!(
            parsed1.fungible_condition_code().unwrap(),
            FungibleConditionCode::SentGt
        );
        assert_eq!(parsed1.get_inner_bytes(), &bytes[1..]);

        let bytes2 = [
            0u8, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 11, 104, 101,
            108, 108, 111, 45, 119, 111, 114, 108, 100, 2, 0, 0, 0, 0, 0, 0, 48, 57,
        ];

        let parsed2 = TransactionPostCondition::from_bytes(bytes2.as_ref())
            .unwrap()
            .1;
        assert!(parsed2.is_stx());
        assert_eq!(parsed2.amount_stx().unwrap(), 12345);
        assert_eq!(
            parsed2.fungible_condition_code().unwrap(),
            FungibleConditionCode::SentGt
        );
        assert_eq!(parsed2.get_inner_bytes(), &bytes2[1..]);
    }

    #[test]
    fn test_fungible_postcondition() {
        let bytes = [
            1u8, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 13, 99, 111, 110, 116, 114, 97, 99, 116, 45, 110, 97, 109, 101, 11, 104, 101, 108,
            108, 111, 45, 97, 115, 115, 101, 116, 2, 0, 0, 0, 0, 0, 0, 91, 160,
        ];

        let parsed = TransactionPostCondition::from_bytes(bytes.as_ref())
            .unwrap()
            .1;
        assert!(parsed.is_fungible());
        assert_eq!(parsed.get_inner_bytes(), &bytes[1..]);
        assert_eq!(
            parsed.fungible_condition_code().unwrap(),
            FungibleConditionCode::SentGt
        );
        assert_eq!(parsed.asset_name().unwrap(), b"hello-asset".as_ref());
        assert_eq!(parsed.tokens_amount().unwrap(), 23456);

        let mut address = vec![2u8];
        address.extend_from_slice([2u8; 20].as_ref());

        let addr = StacksAddress(arrayref::array_ref!(address, 0, 21));
        let mut principal = vec![3u8];
        principal.extend_from_slice(addr.0);
        principal.push(11u8); // contract_name len
        principal.extend_from_slice(b"hello-world".as_ref());
        let bytes2 = [
            1u8, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 11, 104, 101,
            108, 108, 111, 45, 119, 111, 114, 108, 100, 1, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 13, 99, 111, 110, 116, 114,
            97, 99, 116, 45, 110, 97, 109, 101, 11, 104, 101, 108, 108, 111, 45, 97, 115, 115, 101,
            116, 2, 0, 0, 0, 0, 0, 0, 91, 160,
        ];
        let parsed2 = TransactionPostCondition::from_bytes(bytes2.as_ref())
            .unwrap()
            .1;
        assert!(parsed2.is_fungible());
        assert_eq!(parsed2.get_inner_bytes(), &bytes2[1..]);
        assert_eq!(
            parsed2.fungible_condition_code().unwrap(),
            FungibleConditionCode::SentGt
        );
        assert_eq!(parsed2.asset_name().unwrap(), b"hello-asset".as_ref());
        assert_eq!(parsed2.tokens_amount().unwrap(), 23456);
    }

    #[test]
    fn test_non_fungible_may_send_postcondition() {
        // Non-fungible post-condition with the SIP-040 MaySend (0x12) condition code.
        // Reuse the known-good fungible fixture's principal + asset-info prefix, then swap
        // the type byte (1->2 = NonFungibleToken) and the tail. A non-fungible condition
        // ends with: <clarity nft-value> <1-byte condition code> (no 8-byte amount).
        let mut bytes = vec![
            1u8, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 13, 99, 111, 110, 116, 114, 97, 99, 116, 45, 110, 97, 109, 101, 11, 104, 101, 108,
            108, 111, 45, 97, 115, 115, 101, 116,
        ];
        // type byte -> NonFungibleToken
        bytes[0] = 2;
        // nft value: BoolTrue (single-byte clarity value)
        bytes.push(0x03);
        // NonfungibleConditionCode::MaySend
        bytes.push(0x12);

        let parsed = TransactionPostCondition::from_bytes(bytes.as_ref())
            .unwrap()
            .1;
        assert!(parsed.is_non_fungible());
        assert_eq!(parsed.get_inner_bytes(), &bytes[1..]);
        assert_eq!(
            parsed.non_fungible_condition_code().unwrap(),
            NonfungibleConditionCode::MaySend
        );
        assert_eq!(
            parsed.non_fungible_condition_code().unwrap().to_str(),
            "MaySend"
        );
        assert_eq!(parsed.asset_name().unwrap(), b"hello-asset".as_ref());
    }
}
