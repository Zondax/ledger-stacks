#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
#[cfg_attr(test, derive(Debug))]
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

    pub fn to_str(self) -> &'static str {
        match self {
            FungibleConditionCode::SentEq => "SentEq",
            FungibleConditionCode::SentGt => "SentGt",
            FungibleConditionCode::SentGe => "SentGe",
            FungibleConditionCode::SentLt => "SentLt",
            FungibleConditionCode::SentLe => "SentLe",
        }
    }
}
