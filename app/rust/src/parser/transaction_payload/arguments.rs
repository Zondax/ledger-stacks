use nom::{bytes::complete::take, number::complete::be_u32};

use crate::{
    check_canary, is_expert_mode,
    parser::{ParserError, Value, TX_DEPTH_LIMIT},
};

// The number of contract call arguments we can handle.
// this can be adjusted, but keep in mind that higher values could
// hit stack overflows issues.
pub const MAX_NUM_ARGS: u32 = 10;

#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct Arguments<'a>(&'a [u8]);

impl<'a> Arguments<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<(&[u8], Self), nom::Err<ParserError>> {
        check_canary!();

        let (mut rem, num_args) = be_u32::<_, ParserError>(bytes)?;

        if num_args > MAX_NUM_ARGS && !is_expert_mode() {
            return Err(ParserError::InvalidTransactionPayload.into());
        }

        // Parse all arguments so we can be sure that at runtime when each
        // argument is retrieved it does not crashes
        for _ in 0..num_args {
            let (leftover, _) = Value::from_bytes::<TX_DEPTH_LIMIT>(rem)
                .map_err(|_| ParserError::InvalidArgumentId)?;

            rem = leftover;
        }

        let len = bytes.len() - rem.len();
        let (rem, args) = take(len)(bytes)?;

        // take all bytes as there must not be more data after the arguments
        // returning an empty remain data. NOTE: we use take(bytes.len()), to offset
        // the remainder bytes as it is used to set the tx.remainder, which is use
        // to calculate the last_tx_block during the transaction signing process
        Ok((rem, Self(args)))
    }

    pub fn num_args(&self) -> Result<u32, ParserError> {
        be_u32::<_, ParserError>(self.0)
            .map(|res| res.1)
            .map_err(|_| ParserError::UnexpectedError)
    }

    pub fn argument_at(&self, at: usize) -> Result<Value<'a>, ParserError> {
        check_canary!();

        let mut idx = 0;
        let num_args = self.num_args()?;

        // skip the first 4-bytes
        let mut leftover = &self.0[4..];

        while idx < num_args as usize {
            let (bytes, value) = Value::from_bytes::<TX_DEPTH_LIMIT>(leftover)
                .map_err(|_| ParserError::InvalidArgumentId)?;

            leftover = bytes;
            if idx == at {
                return Ok(value);
            }
            idx += 1;
        }
        Err(ParserError::DisplayIdxOutOfRange)
    }
}
