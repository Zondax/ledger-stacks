use arrayvec::ArrayVec;
use nom::number::complete::{be_u32, le_u8};

use crate::{bolos::c_zemu_log_stack, check_canary, parser::TransactionPostCondition};

use super::{ParserError, NUM_SUPPORTED_POST_CONDITIONS};

#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
#[cfg_attr(test, derive(Debug))]
pub enum TransactionPostConditionMode {
    Allow = 0x01, // allow any other changes not specified
    Deny = 0x02,  // deny any other changes not specified
    // Introduced in SIP-040 (epoch 3.4): restrict only the origin account's assets,
    // allow any movements among other principals
    Originator = 0x03,
}

impl TransactionPostConditionMode {
    #[inline(never)]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Allow),
            2 => Some(Self::Deny),
            3 => Some(Self::Originator),
            _ => None,
        }
    }

    #[inline(never)]
    fn from_bytes(bytes: &[u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let mode = le_u8(bytes)?;
        let tx_mode = Self::from_u8(mode.1).ok_or(ParserError::UnexpectedError)?;
        check_canary!();
        Ok((mode.0, tx_mode))
    }
}

#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct PostConditions<'a> {
    pub(crate) conditions: ArrayVec<[&'a [u8]; NUM_SUPPORTED_POST_CONDITIONS]>,
    // The number of items to display to the user
    num_items: u8,
    // The number of post_conditions in our list
    num_conditions: usize,
}

impl<'a> PostConditions<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self, ParserError> {
        let (raw, len) = be_u32::<_, ParserError>(bytes)?;
        let conditions_len = len as usize;

        // Validate length
        if conditions_len > NUM_SUPPORTED_POST_CONDITIONS {
            return Err(nom::Err::Error(ParserError::ValueOutOfRange));
        }

        let mut conditions: ArrayVec<[&'a [u8]; NUM_SUPPORTED_POST_CONDITIONS]> = ArrayVec::new();
        let mut current_input = raw;

        // Safely iterate exactly len times
        for _ in 0..conditions_len {
            match TransactionPostCondition::read_as_bytes(current_input) {
                Ok((remaining, item)) => {
                    current_input = remaining;
                    // Safe push with error handling
                    if conditions.try_push(item).is_err() {
                        return Err(nom::Err::Error(ParserError::ValueOutOfRange));
                    }
                }
                Err(e) => return Err(e),
            }
        }

        if conditions.len() != conditions_len {
            return Err(nom::Err::Error(ParserError::ValueOutOfRange));
        }

        let num_items = Self::get_num_items(&conditions);
        check_canary!();

        let num_conditions = conditions.len();

        Ok((
            current_input,
            Self {
                conditions,
                num_items,
                num_conditions,
            },
        ))
    }

    pub fn get_num_items(conditions: &[&[u8]]) -> u8 {
        conditions
            .iter()
            .filter_map(|bytes| TransactionPostCondition::from_bytes(bytes).ok())
            .map(|condition| (condition.1).num_items())
            .sum()
    }

    pub fn get_postconditions(&self) -> &[&[u8]] {
        self.conditions.as_ref()
    }

    pub fn num_conditions(&self) -> usize {
        self.num_conditions
    }

    #[inline(never)]
    pub fn get_items(
        &mut self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
        num_items: u8,
    ) -> Result<u8, ParserError> {
        c_zemu_log_stack("PostConditions::get_items\x00");

        // The post-conditions occupy the last `self.num_items` display slots of the whole
        // transaction. Translate the global `display_idx` into an offset within the
        // post-conditions block, then walk the conditions (each contributing
        // `condition.num_items()` slots) to find which one owns that offset and which of
        // its sub-items to render. This is derived entirely from `display_idx`, so it is
        // correct for any number of post-conditions and re-entrant across paging calls.
        let pc_start = num_items
            .checked_sub(self.num_items)
            .ok_or(ParserError::DisplayIdxOutOfRange)?;
        let mut local = display_idx
            .checked_sub(pc_start)
            .ok_or(ParserError::DisplayIdxOutOfRange)?;

        for raw in self.conditions.iter() {
            let (_, condition) = TransactionPostCondition::from_bytes(raw)
                .map_err(|_| ParserError::PostConditionFailed)?;
            let items = condition.num_items();
            if local < items {
                return condition.get_items(local, out_key, out_value, page_idx);
            }
            local -= items;
        }

        Err(ParserError::DisplayIdxOutOfRange)
    }

    /// Returns the first post-condition. Used to decide whether SIP-10 transfer details
    /// should be hidden (see `Transaction::should_hide_sip10_details`).
    pub fn first_post_condition(&self) -> Result<TransactionPostCondition<'_>, ParserError> {
        let raw = self.conditions.first().ok_or(ParserError::ValueOutOfRange)?;

        TransactionPostCondition::from_bytes(raw)
            .map_err(|_| ParserError::PostConditionFailed)
            .map(|res| res.1)
    }

    pub fn num_items(&self) -> u8 {
        self.num_items
    }
}
