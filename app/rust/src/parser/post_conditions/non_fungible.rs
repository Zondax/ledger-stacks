#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
#[cfg_attr(test, derive(Debug))]
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

    pub fn to_str(self) -> &'static str {
        match self {
            Self::Sent => "Sent",
            Self::NotSent => "NotSent",
        }
    }
}
