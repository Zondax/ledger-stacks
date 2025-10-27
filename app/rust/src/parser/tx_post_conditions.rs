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
}

impl TransactionPostConditionMode {
    #[inline(never)]
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Allow),
            2 => Some(Self::Deny),
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
    current_idx: u8,
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
                current_idx: 0,
                num_conditions,
            },
        ))
    }
    // pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
    //     let (raw, len) = be_u32::<_, ParserError>(bytes)?;
    //
    //     if len > NUM_SUPPORTED_POST_CONDITIONS as u32 {
    //         return Err(nom::Err::Error(ParserError::ValueOutOfRange));
    //     }
    //     let mut conditions: ArrayVec<[&'a [u8]; NUM_SUPPORTED_POST_CONDITIONS]> = ArrayVec::new();
    //     let mut iter = iterator(raw, TransactionPostCondition::read_as_bytes);
    //     iter.take(len as _).enumerate().for_each(|i| {
    //         conditions.push(i.1);
    //     });
    //     let res = iter.finish()?;
    //     let num_items = Self::get_num_items(&conditions[..len as usize]);
    //     check_canary!();
    //     Ok((
    //         res.0,
    //         Self {
    //             conditions,
    //             num_items,
    //             current_idx: 0,
    //             num_conditions: len as usize,
    //         },
    //     ))
    // }

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
    fn update_postcondition(
        &mut self,
        total_items: u8,
        display_idx: u8,
    ) -> Result<u8, ParserError> {
        // map display_idx to our range of items
        let in_start = total_items - self.num_items;
        let idx = self.map_idx(display_idx, in_start, total_items);

        let limit = self.get_current_limit();

        // get the current postcondition which is used to
        // check if it is time to change to the next/previous postconditions in our list
        // and if that is not the case, we use it to get its items
        let current_condition = self.current_post_condition()?;

        // before continuing we need to check if the current display_idx
        // correspond to the current, next or previous postcondition
        // if so, update it
        if idx >= (limit + current_condition.num_items()) {
            self.current_idx += 1;
            // this should not happen
            if self.current_idx > self.num_items {
                return Err(ParserError::UnexpectedError);
            }
        } else if idx < limit && idx > 0 {
            self.current_idx -= 1;
        }
        Ok(idx)
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

        let idx = self.update_postcondition(num_items, display_idx)?;
        let current_postcondition = self.current_post_condition()?;
        current_postcondition.get_items(idx, out_key, out_value, page_idx)
    }

    fn map_idx(&self, display_idx: u8, in_start: u8, in_end: u8) -> u8 {
        let slope = self.num_items / (in_end - in_start);
        slope * (display_idx - in_start)
    }

    fn get_current_limit(&self) -> u8 {
        let current = self.current_idx as usize;
        self.conditions[..current]
            .iter()
            .filter_map(|bytes| TransactionPostCondition::from_bytes(bytes).ok())
            .map(|condition| (condition.1).num_items())
            .sum()
    }

    pub fn current_post_condition(&self) -> Result<TransactionPostCondition<'_>, ParserError> {
        let raw_current = self
            .conditions
            .get(self.current_idx as usize)
            .ok_or(ParserError::ValueOutOfRange)?;

        TransactionPostCondition::from_bytes(raw_current)
            .map_err(|_| ParserError::PostConditionFailed)
            .map(|res| res.1)
    }

    pub fn num_items(&self) -> u8 {
        self.num_items
    }
}
