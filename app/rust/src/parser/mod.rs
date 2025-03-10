mod c32;
mod error;
mod ffi;
mod jwt;
mod message;
mod object_list;
mod parsed_obj;
// mod parsed_obj;
mod parser_common;
mod post_conditions;
mod principal;
mod spending_condition;
mod structured_msg;
mod transaction;
mod transaction_auth;
mod transaction_payload;
mod tx_post_conditions;
mod utils;
mod value;
pub use error::ParserError;
pub use ffi::{_getItem, _getNumItems, _parser_init, _read, fp_uint64_to_str};
pub use jwt::Jwt;
pub use message::{ByteString, Message};
pub use parsed_obj::{ParsedObj, Tag};
pub use parser_common::*;
pub use post_conditions::{FungibleConditionCode, TransactionPostCondition};
pub use principal::*;
pub use structured_msg::{Domain, StructuredMsg};
pub use transaction::Transaction;
pub use transaction_auth::TransactionAuth;
pub use tx_post_conditions::{PostConditions, TransactionPostConditionMode};
pub use utils::*;
pub use value::{Int128, Tuple, UInt128, Value, ValueId};

///This trait defines an useful interface to parse
///objects from bytes.
///this gives different objects in a transaction
///a way to define their own deserilization implementation, allowing higher level objects to generalize the
///parsing of their inner types
pub trait FromBytes<'b>: Sized {
    /// this method is avaliable for testing only, as the preferable
    /// option is to save stack by passing the memory where the object should
    /// store itself
    #[cfg(test)]
    fn from_bytes(input: &'b [u8]) -> Result<(&'b [u8], Self), nom::Err<ParserError>> {
        let mut out = core::mem::MaybeUninit::uninit();
        let rem = Self::from_bytes_into(input, &mut out)?;
        unsafe { Ok((rem, out.assume_init())) }
    }

    ///Main deserialization method
    ///`input` the input data that contains the serialized form in bytes of this object.
    ///`out` the memory where this object would be stored
    ///
    /// returns the remaining bytes on success
    ///
    /// `Safety` Dealing with uninitialize memory is undefine behavior
    /// even in rust, so implementors should follow the rust documentation
    /// for MaybeUninit and unsafe guidelines.
    ///
    /// It's a good idea to always put `#[inline(never)]` on top of this
    /// function's implementation
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>>;
}
