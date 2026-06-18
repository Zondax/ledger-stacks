#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
#[cfg_attr(test, derive(Debug))]
pub enum PoxConditionCode {
    // Introduced in SIP-044 (Clarity 6 / epoch 4.0). These guard PoX state changes that
    // do not alter locking status, so they carry no amount (unlike the fungible codes).
    MustNot = 0x30, // account must not perform any PoX actions
    May = 0x31,     // account may perform PoX actions
    Must = 0x32,    // account must perform a PoX action
}

impl PoxConditionCode {
    pub fn from_u8(b: u8) -> Option<PoxConditionCode> {
        match b {
            0x30 => Some(PoxConditionCode::MustNot),
            0x31 => Some(PoxConditionCode::May),
            0x32 => Some(PoxConditionCode::Must),
            _ => None,
        }
    }

    pub fn to_str(self) -> &'static str {
        match self {
            Self::MustNot => "PoX deny",
            Self::May => "PoX allow",
            Self::Must => "PoX required",
        }
    }
}
