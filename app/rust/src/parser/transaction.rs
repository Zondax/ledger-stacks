use core::fmt::Write;
use nom::{
    branch::permutation,
    bytes::complete::take,
    combinator::iterator,
    number::complete::{be_u32, le_u8},
};

use arrayvec::ArrayVec;

use crate::parser::{
    error::ParserError,
    parser_common::{
        HashMode, SignerId, TransactionVersion, C32_ENCODED_ADDRS_LENGTH,
        NUM_SUPPORTED_POST_CONDITIONS,
    },
    post_condition::TransactionPostCondition,
    transaction_auth::TransactionAuth,
    transaction_payload::TransactionPayload,
};

use crate::{check_canary, zxformat};

// In multisig transactions the remainder should contain:
// 32-byte previous signer post_sig_hash
// 1-byte pubkey type
// 65-bytes vrs
const MULTISIG_PREVIOUS_SIGNER_DATA_LEN: usize = 98;

#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
#[cfg_attr(test, derive(Debug))]
pub enum TransactionAuthFlags {
    Standard = 0x04,
    Sponsored = 0x05,
}

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
        let tx_mode = Self::from_u8(mode.1).ok_or(ParserError::parser_unexpected_error)?;
        check_canary!();
        Ok((mode.0, tx_mode))
    }
}

#[repr(u8)]
#[derive(Clone, PartialEq, Copy)]
#[cfg_attr(test, derive(Debug))]
pub enum TransactionAnchorMode {
    OnChainOnly = 1,  // must be included in a StacksBlock
    OffChainOnly = 2, // must be included in a StacksMicroBlock
    Any = 3,          // either
}

impl TransactionAnchorMode {
    #[inline(never)]
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::OnChainOnly),
            2 => Some(Self::OffChainOnly),
            3 => Some(Self::Any),
            _ => None,
        }
    }

    #[inline(never)]
    fn from_bytes(bytes: &[u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let mode = le_u8(bytes)?;
        let tx_mode = Self::from_u8(mode.1).ok_or(ParserError::parser_unexpected_error)?;
        check_canary!();
        Ok((mode.0, tx_mode))
    }
}

#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct PostConditions<'a> {
    pub(crate) conditions: ArrayVec<[&'a [u8]; NUM_SUPPORTED_POST_CONDITIONS]>,
    num_items: u8,
    current_idx: u8,
}

impl<'a> PostConditions<'a> {
    #[inline(never)]
    fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let (raw, len) = be_u32(bytes)?;
        if len > NUM_SUPPORTED_POST_CONDITIONS as u32 {
            return Err(nom::Err::Error(ParserError::parser_value_out_of_range));
        }
        let mut conditions: ArrayVec<[&'a [u8]; NUM_SUPPORTED_POST_CONDITIONS]> = ArrayVec::new();
        let mut iter = iterator(raw, TransactionPostCondition::read_as_bytes);
        iter.take(len as _).enumerate().for_each(|i| {
            conditions.push(i.1);
        });
        let res = iter.finish()?;
        let num_items = Self::get_num_items(conditions.as_ref());
        check_canary!();
        Ok((
            res.0,
            Self {
                conditions,
                num_items,
                current_idx: 0,
            },
        ))
    }

    fn get_num_items(conditions: &[&[u8]]) -> u8 {
        conditions
            .iter()
            .filter_map(|bytes| TransactionPostCondition::from_bytes(bytes).ok())
            .map(|condition| (condition.1).num_items())
            .sum()
    }

    pub fn get_postconditions(&self) -> &[&[u8]] {
        self.conditions.as_ref()
    }

    pub fn num_items(&self) -> u8 {
        self.num_items
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
                return Err(ParserError::parser_unexpected_error);
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

    fn current_post_condition(&self) -> Result<TransactionPostCondition, ParserError> {
        TransactionPostCondition::from_bytes(self.conditions[self.current_idx as usize])
            .map_err(|_| ParserError::parser_post_condition_failed)
            .map(|res| res.1)
    }
}

pub type TxTuple<'a> = (
    TransactionVersion, // version number
    u32,                // chainId
    TransactionAuth<'a>,
    &'a [u8],
    PostConditions<'a>,
    TransactionPayload<'a>,
);

impl<'a> From<(&'a [u8], TxTuple<'a>)> for Transaction<'a> {
    fn from(raw: (&'a [u8], TxTuple<'a>)) -> Self {
        Self {
            version: (raw.1).0,
            chain_id: (raw.1).1,
            transaction_auth: (raw.1).2,
            transaction_modes: arrayref::array_ref!((raw.1).3, 0, 2),
            post_conditions: (raw.1).4,
            payload: (raw.1).5,
            // At this point the signer is unknown
            signer: SignerId::Invalid,
            remainder: raw.0,
        }
    }
}

#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct Transaction<'a> {
    pub version: TransactionVersion,
    pub chain_id: u32,
    pub transaction_auth: TransactionAuth<'a>,
    pub transaction_modes: &'a [u8; 2],
    pub post_conditions: PostConditions<'a>,
    pub payload: TransactionPayload<'a>,
    signer: SignerId,
    // If this is a multisig transaction this field should contain
    // the previous signer's post_sig_hash, pubkey type(compressed/uncom..), and the signature(vrs)
    // with them, we can construct the pre_sig_hash for the current signer
    // we would ideally verify it, but we can lend such responsability to the application
    // which has more resources
    // If this is not a multisig transaction, this field should be an empty array
    pub remainder: &'a [u8],
}

impl<'a> Transaction<'a> {
    fn update_remainder(&mut self, data: &'a [u8]) {
        self.remainder = data;
    }

    #[inline(never)]
    pub fn read(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        self.update_remainder(data);
        self.read_header()?;
        self.read_auth()?;
        self.read_transaction_modes()?;
        self.read_post_conditions()?;
        self.read_payload()?;

        let is_token_transfer = self.payload.is_token_transfer_payload();
        let is_standard_auth = self.transaction_auth.is_standard_auth();

        if is_token_transfer && !is_standard_auth {
            return Err(ParserError::parser_invalid_transaction_payload);
        }

        // At this point we do not know who the signer is
        self.signer = SignerId::Invalid;
        Ok(())
    }

    #[inline(never)]
    fn read_header(&mut self) -> Result<(), ParserError> {
        let (next_data, version) = TransactionVersion::from_bytes(self.remainder)
            .map_err(|_| ParserError::parser_unexpected_value)?;

        let (next_data, chain_id) = be_u32::<'a, ParserError>(next_data)
            .map_err(|_| ParserError::parser_unexpected_value)?;

        self.version = version;
        self.chain_id = chain_id;
        check_canary!();

        self.update_remainder(next_data);

        Ok(())
    }

    #[inline(never)]
    fn read_auth(&mut self) -> Result<(), ParserError> {
        let (next_data, auth) = TransactionAuth::from_bytes(self.remainder)
            .map_err(|_| ParserError::parser_invalid_auth_type)?;
        self.transaction_auth = auth;
        self.update_remainder(next_data);
        check_canary!();
        Ok(())
    }

    #[inline(never)]
    fn read_transaction_modes(&mut self) -> Result<(), ParserError> {
        // two modes are included here,
        // anchor mode and postcondition mode
        let (raw, _) = take::<_, _, ParserError>(2usize)(self.remainder)
            .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
        let modes = arrayref::array_ref!(self.remainder, 0, 2);
        self.transaction_modes = modes;
        self.update_remainder(raw);
        check_canary!();
        Ok(())
    }

    #[inline(never)]
    fn read_post_conditions(&mut self) -> Result<(), ParserError> {
        let (raw, conditions) = PostConditions::from_bytes(self.remainder)
            .map_err(|_| ParserError::parser_post_condition_failed)?;
        self.post_conditions = conditions;
        self.update_remainder(raw);
        check_canary!();
        Ok(())
    }

    #[inline(never)]
    fn read_payload(&mut self) -> Result<(), ParserError> {
        let (raw, payload) = TransactionPayload::from_bytes(self.remainder)
            .map_err(|_| ParserError::parser_invalid_transaction_payload)?;
        self.payload = payload;
        self.update_remainder(raw);
        check_canary!();
        Ok(())
    }

    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ParserError> {
        match permutation((
            TransactionVersion::from_bytes,
            be_u32,
            TransactionAuth::from_bytes,
            take(2usize),
            PostConditions::from_bytes,
            TransactionPayload::from_bytes,
        ))(bytes)
        {
            Ok(tx) => {
                // Note that if a transaction contains a token-transfer payload,
                // it MUST have only a standard authorization field. It cannot be sponsored.
                if (tx.1).5.is_token_transfer_payload() && !(tx.1).2.is_standard_auth() {
                    return Err(ParserError::parser_invalid_transaction_payload);
                }
                Ok(Self::from(tx))
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn payload_recipient_address(
        &self,
    ) -> Option<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>> {
        self.payload.recipient_address()
    }

    pub fn num_items(&self) -> Result<u8, ParserError> {
        // nonce + origin + fee-rate + payload + post-conditions
        3u8.checked_add(self.payload.num_items())
            .and_then(|res| res.checked_add(self.post_conditions.num_items))
            .ok_or(ParserError::parser_value_out_of_range)
    }

    fn get_origin_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let mut writer_key = zxformat::Writer::new(out_key);

        #[cfg(test)]
        let origin = self.transaction_auth.origin();

        #[cfg(not(test))]
        let origin = match self.signer {
            SignerId::Origin => self.transaction_auth.origin(),
            SignerId::Sponsor => self
                .transaction_auth
                .sponsor()
                .ok_or(ParserError::parser_invalid_auth_type)?,
            _ => return Err(ParserError::parser_invalid_auth_type),
        };

        match display_idx {
            // The address of who signed this transaction
            0 => {
                writer_key
                    .write_str("Origin")
                    .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                let origin_address = origin.signer_address(self.version)?;
                zxformat::pageString(out_value, origin_address.as_ref(), page_idx)
            }
            // The signer nonce
            1 => {
                writer_key
                    .write_str("Nonce")
                    .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                let nonce_str = origin.nonce_str()?;
                zxformat::pageString(out_value, nonce_str.as_ref(), page_idx)
            }
            // The signer fee-rate
            2 => {
                writer_key
                    .write_str("Fee (uSTX)")
                    .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
                let fee_str = origin.fee_str()?;
                zxformat::pageString(out_value, fee_str.as_ref(), page_idx)
            }

            _ => unreachable!(),
        }
    }

    #[inline(always)]
    fn get_other_items(
        &mut self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let num_items = self.num_items()?;
        let post_conditions_items = self.post_conditions.num_items;

        if display_idx >= (num_items - post_conditions_items) {
            if post_conditions_items == 0 {
                return Err(ParserError::parser_display_idx_out_of_range);
            }
            self.post_conditions.get_items(
                display_idx,
                out_key,
                out_value,
                page_idx,
                num_items as u8,
            )
        } else {
            self.payload.get_items(
                display_idx,
                out_key,
                out_value,
                page_idx,
                num_items - post_conditions_items, // we need to display the payload in order
            )
        }
    }

    pub fn get_item(
        &mut self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        if display_idx >= self.num_items()? {
            return Err(ParserError::parser_display_idx_out_of_range);
        }

        if display_idx < 3 {
            self.get_origin_items(display_idx, out_key, out_value, page_idx)
        } else {
            self.get_other_items(display_idx, out_key, out_value, page_idx)
        }
    }

    pub fn origin_fee(&self) -> u64 {
        self.transaction_auth.origin_fee()
    }

    pub fn origin_nonce(&self) -> u64 {
        self.transaction_auth.origin_nonce()
    }

    pub fn sponsor_fee(&self) -> Option<u64> {
        self.transaction_auth.sponsor_fee()
    }

    pub fn sponsor_nonce(&self) -> Option<u64> {
        self.transaction_auth.sponsor_nonce()
    }

    // Returns the transaction nonce according to
    // who the signer is. The signer could be the Origin, a sponsor
    // or Invalid that happens when its credentials are not present
    // in the transaction
    pub fn nonce(&self) -> Option<u64> {
        match self.signer {
            SignerId::Origin => Some(self.origin_nonce()),
            SignerId::Sponsor => self.sponsor_nonce(),
            SignerId::Invalid => None,
        }
    }

    // Returns the transaction fee according to
    // who the signer is. The signer could be the Origin, Sponsor
    // or Invalid, the later that happens when its credentials are not present
    // in the transaction
    pub fn fee(&self) -> Option<u64> {
        match self.signer {
            SignerId::Origin => Some(self.origin_fee()),
            SignerId::Sponsor => self.sponsor_fee(),
            SignerId::Invalid => None,
        }
    }

    pub fn auth_flag(&self) -> TransactionAuthFlags {
        if self.transaction_auth.is_standard_auth() {
            return TransactionAuthFlags::Standard;
        }
        TransactionAuthFlags::Sponsored
    }

    /// Checks if we can sign this transaction.
    /// If this is a singlesig transaction we should be either the origin or sponsor
    /// We will just pass the check if the transaction is multisig.
    pub fn check_signer_pk_hash(&mut self, signer_pk: &[u8]) -> ParserError {
        self.signer = self.transaction_auth.check_signer(signer_pk);
        if self.signer != SignerId::Invalid {
            return ParserError::parser_ok;
        }
        ParserError::parser_invalid_auth_type
    }

    // returns a slice of the last block to be used in the presighash calculation
    pub fn last_transaction_block(&self) -> &[u8] {
        unsafe {
            let len =
                (self.remainder.as_ptr() as usize - self.transaction_modes.as_ptr() as usize) as _;
            core::slice::from_raw_parts(self.transaction_modes.as_ptr(), len)
        }
    }

    pub fn previous_signer_data(&self) -> Option<&[u8]> {
        if self.is_multisig() && self.remainder.len() >= MULTISIG_PREVIOUS_SIGNER_DATA_LEN {
            return Some(&self.remainder[..MULTISIG_PREVIOUS_SIGNER_DATA_LEN]);
        }
        None
    }

    pub fn is_multisig(&self) -> bool {
        self.transaction_auth.is_multisig()
    }

    // check just for origin, meaning we support standard transaction only
    pub fn hash_mode(&self) -> Result<HashMode, ParserError> {
        self.transaction_auth.hash_mode()
    }
}
