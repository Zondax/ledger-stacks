use arrayvec::ArrayVec;
use nom::number::complete::{be_u32, le_u8};

use crate::{bolos::c_zemu_log_stack, check_canary, parser::TransactionPostCondition};

use super::{object_list::ObjectList, FromBytes, ParserError};

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
}

// Also implement FromBytes for TransactionPostConditionMode
impl<'b> FromBytes<'b> for TransactionPostConditionMode {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        use core::ptr::addr_of_mut;

        // Extract the mode byte
        let (rem, mode_byte) = le_u8(input)?;

        // Convert to enum
        let mode = Self::from_u8(mode_byte).ok_or(nom::Err::Error(ParserError::UnexpectedError))?;

        check_canary!();

        // Get a pointer to the uninitialized memory
        let out_ptr = out.as_mut_ptr();

        // Initialize the TransactionPostConditionMode
        unsafe {
            addr_of_mut!((*out_ptr)).write(mode);
        }

        // Return the remaining bytes
        Ok(rem)
    }
}

#[repr(C)]
#[derive(Clone, PartialEq, Copy)]
#[cfg_attr(test, derive(Debug))]
pub struct PostConditions<'a> {
    pub(crate) conditions: ObjectList<'a, TransactionPostCondition<'a>>,
    // The number of items to display to the user
    num_items: u8,
    // The number of post_conditions in our list
    num_conditions: usize,
    current_idx: u8,
}

impl<'b> FromBytes<'b> for PostConditions<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        use core::ptr::addr_of_mut;

        // Get a pointer to the uninitialized memory
        let out_ptr = out.as_mut_ptr();

        c_zemu_log_stack("PostConditions::from_bytes_into\x00");

        // Parse the number of post conditions
        let (raw, len) = be_u32::<_, ParserError>(input)?;
        let conditions_len = len as usize;

        let mut rem = raw;
        let conditions_uninit = unsafe { &mut *addr_of_mut!((*out_ptr).conditions).cast() };

        let rem = ObjectList::new_into_with_len(rem, conditions_uninit, conditions_len as _)?;

        // Calculate the number of display items
        let conditions = unsafe { conditions_uninit.assume_init_ref() };
        let num_items = PostConditions::get_num_items(&conditions)?;
        check_canary!();

        let num_conditions = conditions_len as _;

        // Initialize the PostConditions fields
        unsafe {
            addr_of_mut!((*out_ptr).num_items).write(num_items);
            addr_of_mut!((*out_ptr).current_idx).write(0);
            addr_of_mut!((*out_ptr).num_conditions).write(num_conditions);
        }

        // Return the remaining bytes
        Ok(rem)
    }
}

impl PostConditions<'_> {
    pub fn get_num_items(
        conditions: &ObjectList<'_, TransactionPostCondition<'_>>,
    ) -> Result<u8, ParserError> {
        let num_items = conditions
            .iter()
            .map(|condition| condition.num_items())
            .sum();

        Ok(num_items)
    }

    pub fn get_postconditions(&self) -> &ObjectList<'_, TransactionPostCondition<'_>> {
        &self.conditions
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

        let (obj, idx) = self.current_post_condition(display_idx)?;
        obj.get_items(idx, out_key, out_value, page_idx)
    }

    // Returns the current post condition being
    // rendered and the mapped item_n to that object
    // error otherwise
    fn current_post_condition(
        &self,
        item_n: u8,
    ) -> Result<(TransactionPostCondition, u8), ParserError> {
        let mut count = 0usize;
        let mut obj_item_n = 0;

        let filter = |o: &TransactionPostCondition| -> bool {
            let n = o.num_items();

            for index in 0..n {
                obj_item_n = index;
                if count == item_n as usize {
                    return true;
                }
                count += 1;
            }
            false
        };

        let obj = self
            .conditions
            .get_obj_if(filter)
            .ok_or(ParserError::DisplayIdxOutOfRange)?;

        Ok((obj, obj_item_n))
    }

    pub fn num_items(&self) -> u8 {
        self.num_items
    }
}
