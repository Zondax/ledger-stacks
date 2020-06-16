use nom::{
    bytes::complete::take,
    error::ErrorKind,
    number::complete::{be_u64, le_u8},
};

use crate::parser::parser_common::{
    u8_with_limits, AssetInfo, AssetInfoId, AssetName, ClarityName, ContractName, Hash160,
    ParserError, StacksAddress, MAX_STRING_LEN, NUM_SUPPORTED_POST_CONDITIONS,
};

#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
pub enum PostConditionPrincipalId {
    Origin = 0x01,
    Standard = 0x02,
    Contract = 0x03,
}

impl PostConditionPrincipalId {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Origin),
            2 => Some(Self::Standard),
            3 => Some(Self::Contract),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub enum PostConditionPrincipal<'a> {
    Origin,
    Standard(StacksAddress<'a>),
    Contract(StacksAddress<'a>, ContractName<'a>),
}

// The doc does not say if the principal contains 1-byte
// used to define if it is either an account or contract
// principal. Lets assume It does have this byte
impl<'a> PostConditionPrincipal<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let id = le_u8(bytes)?;
        let principal_id = PostConditionPrincipalId::from_u8(id.1)
            .ok_or(ParserError::parser_invalid_post_condition_principal)?;
        match principal_id {
            PostConditionPrincipalId::Origin => Ok((id.0, PostConditionPrincipal::Origin)),
            PostConditionPrincipalId::Standard => {
                let addrs = StacksAddress::from_bytes(id.0)?;
                Ok((addrs.0, PostConditionPrincipal::Standard(addrs.1)))
            }
            PostConditionPrincipalId::Contract => {
                let addrs = StacksAddress::from_bytes(id.0)?;
                let contract_name = ContractName::from_bytes(addrs.0)?;
                let condition = PostConditionPrincipal::Contract(addrs.1, contract_name.1);
                Ok((contract_name.0, condition))
            }
        }
    }
}

#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
pub enum FungibleConditionCode {
    SentEq = 0x01,
    SentGt = 0x02,
    SentGe = 0x03,
    SentLt = 0x04,
    SentLe = 0x05,
}

impl FungibleConditionCode {
    pub fn from_u8(b: u8) -> Option<FungibleConditionCode> {
        match b {
            0x01 => Some(FungibleConditionCode::SentEq),
            0x02 => Some(FungibleConditionCode::SentGt),
            0x03 => Some(FungibleConditionCode::SentGe),
            0x04 => Some(FungibleConditionCode::SentLt),
            0x05 => Some(FungibleConditionCode::SentLe),
            _ => None,
        }
    }

    pub fn check(&self, amount_sent_condition: u128, amount_sent: u128) -> bool {
        match *self {
            FungibleConditionCode::SentEq => amount_sent == amount_sent_condition,
            FungibleConditionCode::SentGt => amount_sent > amount_sent_condition,
            FungibleConditionCode::SentGe => amount_sent >= amount_sent_condition,
            FungibleConditionCode::SentLt => amount_sent < amount_sent_condition,
            FungibleConditionCode::SentLe => amount_sent <= amount_sent_condition,
        }
    }
}

#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
pub enum NonfungibleConditionCode {
    Sent = 0x10,
    NotSent = 0x11,
}

impl NonfungibleConditionCode {
    pub fn from_u8(b: u8) -> Option<NonfungibleConditionCode> {
        match b {
            0x10 => Some(NonfungibleConditionCode::Sent),
            0x11 => Some(NonfungibleConditionCode::NotSent),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
pub enum TransactionPostConditionMode {
    Allow = 0x01, // allow any other changes not specified
    Deny = 0x02,  // deny any other changes not specified
}

#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
pub enum PostConditionType {
    STX = 0,
    FungibleToken = 1,
    NonFungibleToken = 2,
}

impl PostConditionType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::STX),
            2 => Some(Self::FungibleToken),
            3 => Some(Self::NonFungibleToken),
            _ => None,
        }
    }
}

/// Post-condition on a transaction
#[repr(C)]
#[derive(Clone, Copy)]
pub enum TransactionPostCondition<'a> {
    STX(PostConditionPrincipal<'a>, FungibleConditionCode, u64),
    Fungible(
        PostConditionPrincipal<'a>,
        AssetInfo<'a>,
        FungibleConditionCode,
        u64,
    ),
    Nonfungible(
        PostConditionPrincipal<'a>,
        AssetInfo<'a>,
        AssetName<'a>, // Blocstacks uses her a Value, check this
        NonfungibleConditionCode,
    ),
}

impl<'a> TransactionPostCondition<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let cond_type = le_u8(bytes)?;
        let principal = PostConditionPrincipal::from_bytes(cond_type.0)?;
        match PostConditionType::from_u8(cond_type.1)
            .ok_or(ParserError::parser_invalid_post_condition)?
        {
            PostConditionType::STX => {
                let code = le_u8(principal.0)?;
                let fungible = FungibleConditionCode::from_u8(code.1)
                    .ok_or(ParserError::parser_invalid_fungible_code)?;
                let amount = be_u64(code.0)?;
                let condition = Self::STX(principal.1, fungible, amount.1);
                Ok((amount.0, condition))
            }
            PostConditionType::FungibleToken => {
                let asset = AssetInfo::from_bytes(principal.0)?;
                let code = le_u8(asset.0)?;
                let fungible = FungibleConditionCode::from_u8(code.1)
                    .ok_or(ParserError::parser_invalid_fungible_code)?;
                let amount = be_u64(code.0)?;
                let condition = Self::Fungible(principal.1, asset.1, fungible, amount.1);
                Ok((amount.0, condition))
            }
            PostConditionType::NonFungibleToken => {
                let asset = AssetInfo::from_bytes(principal.0)?;
                let name = AssetName::from_bytes(asset.0)?;
                let code = le_u8(name.0)?;
                let non_fungible = NonfungibleConditionCode::from_u8(code.1)
                    .ok_or(ParserError::parser_invalid_non_fungible_code)?;
                let condition = Self::Nonfungible(principal.1, asset.1, name.1, non_fungible);
                Ok((code.0, condition))
            }
        }
    }
}
