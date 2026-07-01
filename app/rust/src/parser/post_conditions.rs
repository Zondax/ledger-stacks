use arrayvec::ArrayVec;
use core::{convert::TryFrom, fmt::Write};
use nom::{
    bytes::complete::take,
    number::complete::{be_u64, le_u8},
};

mod fungible;
mod non_fungible;
mod post_condition_principal;
mod pox;
pub use fungible::FungibleConditionCode;
pub use non_fungible::NonfungibleConditionCode;
pub use pox::PoxConditionCode;

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
    // Introduced in SIP-044 (Clarity 6 / epoch 4.0).
    Staking = 3,
    Pox = 4,
}

impl TryFrom<u8> for PostConditionType {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let t = match value {
            0 => Self::Stx,
            1 => Self::FungibleToken,
            2 => Self::NonFungibleToken,
            3 => Self::Staking,
            4 => Self::Pox,
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
    // SIP-044 (epoch 4.0). Staking body is byte-identical to Stx (principal + fungible
    // code + 8-byte amount); Pox body is principal + 1-byte PoX code (no amount).
    Staking(&'a [u8]),
    Pox(&'a [u8]),
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
            // Same body layout as Stx: principal + 1-byte fungible code + 8-byte amount.
            PostConditionType::Staking => {
                let len = principal_len + 1 + 8;
                let (raw, inner) = take(len)(raw)?;
                Ok((raw, Self::Staking(inner)))
            }
            // principal + 1-byte PoX condition code, no amount.
            PostConditionType::Pox => {
                let len = principal_len + 1;
                let (raw, inner) = take(len)(raw)?;
                Ok((raw, Self::Pox(inner)))
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
            PostConditionType::Staking => {
                // 8-byte amount + 1-byte fungible code, same as Stx.
                let (raw, _) = take(9usize)(rem)?;
                rem = raw;
            }
            PostConditionType::Pox => {
                // 1-byte PoX condition code, no amount.
                let (raw, _) = take(1usize)(rem)?;
                rem = raw;
            }
        };
        crate::check_canary!();
        let len = bytes.len() - rem.len();
        take(len)(bytes)
    }

    pub fn is_origin_principal(&self) -> bool {
        match self {
            Self::Stx(principal)
            | Self::Fungible(principal)
            | Self::Nonfungible(principal)
            | Self::Staking(principal)
            | Self::Pox(principal) => {
                principal[0] == PostConditionPrincipalId::Origin as u8
            }
        }
    }

    pub fn is_standard_principal(&self) -> bool {
        match self {
            Self::Stx(principal)
            | Self::Fungible(principal)
            | Self::Nonfungible(principal)
            | Self::Staking(principal)
            | Self::Pox(principal) => {
                principal[0] == PostConditionPrincipalId::Standard as u8
            }
        }
    }

    pub fn is_contract_principal(&self) -> bool {
        match self {
            Self::Stx(principal)
            | Self::Fungible(principal)
            | Self::Nonfungible(principal)
            | Self::Staking(principal)
            | Self::Pox(principal) => {
                principal[0] == PostConditionPrincipalId::Contract as u8
            }
        }
    }

    #[inline(never)]
    pub fn get_principal_address(
        &self,
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        match self {
            Self::Stx(principal)
            | Self::Fungible(principal)
            | Self::Nonfungible(principal)
            | Self::Staking(principal)
            | Self::Pox(principal) => {
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
            // Staking shares the Stx body: 8-byte uSTX amount at the tail.
            Self::Stx(inner) | Self::Staking(inner) => {
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
            // 1-byte code precedes the 8-byte amount, so it sits at len-9. Staking reuses
            // the fungible codes on the same body layout as Stx.
            Self::Stx(inner) | Self::Fungible(inner) | Self::Staking(inner) => {
                inner[inner.len() - 9]
            }
            _ => return None,
        };
        FungibleConditionCode::from_u8(code)
    }

    pub fn pox_condition_code(&self) -> Option<PoxConditionCode> {
        let code = match self {
            // PoX body is principal + 1-byte code, so the code is the last byte.
            Self::Pox(inner) => inner[inner.len() - 1],
            _ => return None,
        };
        PoxConditionCode::from_u8(code)
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
            // Staking: principal + code + amount. Pox: principal + code.
            Self::Stx(..) | Self::Nonfungible(..) | Self::Staking(..) => 3,
            Self::Fungible(..) => 4,
            Self::Pox(..) => 2,
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
                Self::Staking(..) => self.get_staking_items(index, out_key, out_value, page_idx),
                Self::Pox(..) => self.get_pox_items(index, out_key, out_value, page_idx),
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

    pub fn get_staking_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        c_zemu_log_stack("TransactionPostCondition::get_staking_items\x00");

        let mut writer_key = zxformat::Writer::new(out_key);
        match self {
            Self::Staking(..) => match display_idx {
                // PostCondition code (reuses the fungible codes)
                1 => {
                    writer_key
                        .write_str("Staking Code")
                        .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                    let code = self
                        .fungible_condition_code()
                        .ok_or(ParserError::InvalidFungibleCode)?;
                    zxformat::pageString(out_value, code.to_str().as_bytes(), page_idx)
                }
                // Amount in stx
                2 => {
                    writer_key
                        .write_str("Staked STX")
                        .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                    let amount = self.amount_stx_str().ok_or(ParserError::UnexpectedValue)?;
                    zxformat::pageString(out_value, amount.as_ref(), page_idx)
                }
                _ => Err(ParserError::DisplayIdxOutOfRange),
            },
            _ => Err(ParserError::UnexpectedError),
        }
    }

    pub fn get_pox_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        c_zemu_log_stack("TransactionPostCondition::get_pox_items\x00");

        let mut writer_key = zxformat::Writer::new(out_key);
        match self {
            Self::Pox(..) => match display_idx {
                // PoX condition code
                1 => {
                    writer_key
                        .write_str("PoX Code")
                        .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                    let code = self
                        .pox_condition_code()
                        .ok_or(ParserError::InvalidPoxCode)?;
                    zxformat::pageString(out_value, code.to_str().as_bytes(), page_idx)
                }
                _ => Err(ParserError::DisplayIdxOutOfRange),
            },
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
            Self::Stx(inner)
            | Self::Fungible(inner)
            | Self::Nonfungible(inner)
            | Self::Staking(inner)
            | Self::Pox(inner) => inner,
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

    // SIP-044 staking (0x03): type(3) | standard-principal | fungible code | amount(8).
    // Byte-identical to STX, only the type byte differs.
    fn staking_cond(code: u8, amount: u64) -> Vec<u8> {
        let mut v = vec![3u8, 2, 1];
        v.extend_from_slice(&[1u8; 20]);
        v.push(code);
        v.extend_from_slice(&amount.to_be_bytes());
        v
    }

    // SIP-044 PoX (0x04): type(4) | standard-principal | pox code. No amount.
    fn pox_cond(code: u8) -> Vec<u8> {
        let mut v = vec![4u8, 2, 1];
        v.extend_from_slice(&[1u8; 20]);
        v.push(code);
        v
    }

    fn val_str(buf: &[u8]) -> String {
        String::from_utf8_lossy(buf)
            .trim_end_matches('\0')
            .to_string()
    }

    #[test]
    fn test_staking_postcondition() {
        // Append a sentinel so the trailing remainder confirms read length math:
        // 1 (type) + 22 (principal) + 1 (code) + 8 (amount) = 32 bytes consumed.
        let mut bytes = staking_cond(0x03, 12345);
        bytes.push(0xEE);
        let (rem, parsed) = TransactionPostCondition::from_bytes(&bytes).unwrap();
        assert_eq!(rem, &[0xEE]);
        assert!(matches!(parsed, TransactionPostCondition::Staking(..)));
        assert_eq!(parsed.get_inner_bytes(), &bytes[1..bytes.len() - 1]);
        assert_eq!(parsed.amount_stx().unwrap(), 12345);
        assert_eq!(
            parsed.fungible_condition_code().unwrap(),
            FungibleConditionCode::SentGe
        );
        assert_eq!(parsed.num_items(), 3);
        // PoX accessor must not apply to a staking condition.
        assert!(parsed.pox_condition_code().is_none());
    }

    #[test]
    fn test_staking_display_items() {
        // 100 STX = 100_000_000 uSTX (STX has 6 decimals).
        let bytes = staking_cond(0x03, 100_000_000);
        let parsed = TransactionPostCondition::from_bytes(&bytes).unwrap().1;
        let mut key = [0u8; 64];
        let mut val = [0u8; 64];

        // item 1: staking condition code, rendered like the fungible codes.
        parsed.get_items(1, &mut key, &mut val, 0).unwrap();
        assert!(val_str(&key).starts_with("Staking Code"));
        assert_eq!(val_str(&val), "SentGe");

        // item 2: staked amount, rendered in STX (non-empty).
        parsed.get_items(2, &mut key, &mut val, 0).unwrap();
        assert!(val_str(&key).starts_with("Staked STX"));
        assert!(!val_str(&val).is_empty());
    }

    #[test]
    fn test_pox_postcondition() {
        let cases: &[(u8, PoxConditionCode, &str)] = &[
            (0x30, PoxConditionCode::MustNot, "PoX deny"),
            (0x31, PoxConditionCode::May, "PoX allow"),
            (0x32, PoxConditionCode::Must, "PoX required"),
        ];
        for &(byte, code, label) in cases {
            // Sentinel confirms read length: 1 (type) + 22 (principal) + 1 (code) = 24.
            let mut bytes = pox_cond(byte);
            bytes.push(0xEE);
            let (rem, parsed) = TransactionPostCondition::from_bytes(&bytes).unwrap();
            assert_eq!(rem, &[0xEE]);
            assert!(matches!(parsed, TransactionPostCondition::Pox(..)));
            assert_eq!(parsed.pox_condition_code().unwrap(), code);
            assert_eq!(parsed.pox_condition_code().unwrap().to_str(), label);
            assert_eq!(parsed.num_items(), 2);
            // Fungible/amount accessors must not apply to a PoX condition.
            assert!(parsed.fungible_condition_code().is_none());
            assert!(parsed.amount_stx().is_none());

            // item 1 renders the PoX code label.
            let mut key = [0u8; 64];
            let mut val = [0u8; 64];
            parsed.get_items(1, &mut key, &mut val, 0).unwrap();
            assert!(val_str(&key).starts_with("PoX Code"));
            assert_eq!(val_str(&val), label);
        }
    }

    #[test]
    fn test_invalid_pox_code_rejected_at_display() {
        // An out-of-range PoX code byte parses structurally (it is just a byte) but yields
        // no PoxConditionCode, so display reports InvalidPoxCode rather than signing a code
        // the device cannot name.
        let bytes = pox_cond(0x33); // not in {0x30, 0x31, 0x32}
        let parsed = TransactionPostCondition::from_bytes(&bytes).unwrap().1;
        assert!(parsed.pox_condition_code().is_none());

        let mut key = [0u8; 64];
        let mut val = [0u8; 64];
        let err = parsed.get_items(1, &mut key, &mut val, 0).unwrap_err();
        assert_eq!(err, ParserError::InvalidPoxCode);
    }
}
