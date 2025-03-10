use core::{convert::TryFrom, fmt::Write};
use nom::{
    bytes::complete::take,
    number::complete::{be_u32, le_u8},
};

use crate::{
    bolos::c_zemu_log_stack,
    parser::{
        error::ParserError,
        parser_common::{HashMode, SignerId, TransactionVersion, C32_ENCODED_ADDRS_LENGTH},
        transaction_auth::TransactionAuth,
        transaction_payload::TransactionPayload,
    },
};

use crate::{check_canary, zxformat};

use super::{FromBytes, PostConditions};

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
        let tx_mode = Self::from_u8(mode.1).ok_or(ParserError::UnexpectedError)?;
        check_canary!();
        Ok((mode.0, tx_mode))
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
        let mut remainder = None;
        if !raw.0.is_empty() {
            remainder = Some(raw.0);
        }

        Self {
            version: (raw.1).0,
            chain_id: (raw.1).1,
            transaction_auth: (raw.1).2,
            transaction_modes: arrayref::array_ref!((raw.1).3, 0, 2),
            post_conditions: (raw.1).4,
            payload: (raw.1).5,
            // At this point the signer is unknown
            signer: SignerId::Invalid,
            remainder,
        }
    }
}

#[repr(C)]
#[derive(Clone, PartialEq, Copy)]
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
    // If this is not a multisig transaction, this field should be None
    pub remainder: Option<&'a [u8]>,
}

impl<'b> FromBytes<'b> for Transaction<'b> {
    #[inline(never)]
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut core::mem::MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        use core::ptr::addr_of_mut;

        c_zemu_log_stack("Transaction::from_bytes_into\x00");

        if input.is_empty() {
            return Err(ParserError::NoData.into());
        }

        // Get a pointer to the uninitialized memory
        let out_ptr = out.as_mut_ptr();

        // Parse TransactionVersion
        let (rem, version_byte) = le_u8(input)?;
        let version = TransactionVersion::try_from(version_byte)?;

        // Parse chain_id
        let (rem, chain_id) = be_u32(rem)?;

        // Write version and chain_id
        unsafe {
            addr_of_mut!((*out_ptr).version).write(version);
            addr_of_mut!((*out_ptr).chain_id).write(chain_id);
        }

        // Parse TransactionAuth - get reference to uninitialized field and pass it
        // let auth_uninit = unsafe { &mut *addr_of_mut!((*out_ptr).transaction_auth).cast() };
        // let rem = TransactionAuth::from_bytes_into(rem, auth_uninit)?;
        let (rem, auth) = TransactionAuth::from_bytes(rem)?;
        unsafe { addr_of_mut!((*out_ptr).transaction_auth).write(auth) };

        // Parse transaction_modes (2 bytes)
        let (rem, modes_slice) = take::<_, _, ParserError>(2usize)(rem)
            .map_err(|_| nom::Err::Error(ParserError::UnexpectedBufferEnd))?;
        let transaction_modes = arrayref::array_ref!(modes_slice, 0, 2);

        // Write transaction_modes
        unsafe {
            addr_of_mut!((*out_ptr).transaction_modes).write(transaction_modes);
        }

        // Parse PostConditions - get reference to uninitialized field and pass it
        let post_conditions_uninit =
            unsafe { &mut *addr_of_mut!((*out_ptr).post_conditions).cast() };
        let rem = PostConditions::from_bytes_into(rem, post_conditions_uninit)?;

        // Parse TransactionPayload - get reference to uninitialized field and pass it
        let payload_uninit = unsafe { &mut *addr_of_mut!((*out_ptr).payload).cast() };
        let rem = TransactionPayload::from_bytes_into(rem, payload_uninit)?;

        // Now that we have initialized auth and payload, we can safely access them to check constraints
        let is_token_transfer: bool;
        let is_multisig: bool;
        let is_standard_auth: bool;

        unsafe {
            is_token_transfer = (*out_ptr).payload.is_token_transfer_payload();
            is_standard_auth = (*out_ptr).transaction_auth.is_standard_auth();
            is_multisig = (*out_ptr).transaction_auth.is_multisig();
        }

        // Validate token transfer payload constraints
        if is_token_transfer && !is_standard_auth {
            return Err(ParserError::InvalidTransactionPayload.into());
        }

        // Initialize the remaining fields
        unsafe {
            addr_of_mut!((*out_ptr).signer).write(SignerId::Invalid);

            // Set remainder field based on multisig check
            if is_multisig && !rem.is_empty() {
                addr_of_mut!((*out_ptr).remainder).write(Some(rem));
                Ok(&rem[0..0])
            } else {
                addr_of_mut!((*out_ptr).remainder).write(None);
                Ok(rem)
            }
        }
    }
}

impl<'a> Transaction<'a> {
    fn update_remainder(&mut self, data: &'a [u8]) {
        if !data.is_empty() {
            self.remainder = Some(data);
        } else {
            self.remainder = None;
        }
    }

    // #[inline(never)]
    // pub fn read(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
    //     c_zemu_log_stack("Transaction::read\x00");
    //     let rem = self.read_header(data)?;
    //     let rem = self.read_auth(rem)?;
    //     let rem = self.read_transaction_modes(rem)?;
    //     let rem = self.read_post_conditions(rem)?;
    //     let rem = self.read_payload(rem)?;
    //
    //     let is_token_transfer = self.payload.is_token_transfer_payload();
    //     let is_standard_auth = self.transaction_auth.is_standard_auth();
    //
    //     if is_token_transfer && !is_standard_auth {
    //         c_zemu_log_stack("Transaction::invalid_token_transfer!\x00");
    //         return Err(ParserError::InvalidTransactionPayload);
    //     }
    //
    //     // At this point we do not know who the signer is
    //     self.signer = SignerId::Invalid;
    //
    //     self.remainder = None;
    //
    //     // set the remainder if this is mutltisig
    //     if self.is_multisig() && !rem.is_empty() {
    //         self.update_remainder(rem);
    //     }
    //
    //     Ok(())
    // }

    // #[inline(never)]
    // fn read_header(&mut self, data: &'a [u8]) -> Result<&'a [u8], ParserError> {
    //     c_zemu_log_stack("Transaction::read_header\x00");
    //     let (rem, version) =
    //         TransactionVersion::from_bytes(data).map_err(|_| ParserError::UnexpectedValue)?;
    //
    //     let (rem, chain_id) =
    //         be_u32::<_, ParserError>(rem).map_err(|_| ParserError::UnexpectedValue)?;
    //
    //     self.version = version;
    //     self.chain_id = chain_id;
    //     check_canary!();
    //
    //     Ok(rem)
    // }

    // #[inline(never)]
    // fn read_auth(&mut self, data: &'a [u8]) -> Result<&'a [u8], ParserError> {
    //     c_zemu_log_stack("Transaction::read_auth\x00");
    //     let (rem, auth) =
    //         TransactionAuth::from_bytes(data).map_err(|_| ParserError::InvalidAuthType)?;
    //     self.transaction_auth = auth;
    //     check_canary!();
    //     Ok(rem)
    // }

    // #[inline(never)]
    // fn read_transaction_modes(&mut self, data: &'a [u8]) -> Result<&'a [u8], ParserError> {
    //     c_zemu_log_stack("Transaction::read_transaction_modes\x00");
    //     // two modes are included here,
    //     // anchor mode and postcondition mode
    //     let (rem, _) = take::<_, _, ParserError>(2usize)(data)
    //         .map_err(|_| ParserError::UnexpectedBufferEnd)?;
    //     let modes = arrayref::array_ref!(data, 0, 2);
    //     self.transaction_modes = modes;
    //     check_canary!();
    //     Ok(rem)
    // }

    // #[inline(never)]
    // fn read_post_conditions(&mut self, data: &'a [u8]) -> Result<&'a [u8], ParserError> {
    //     c_zemu_log_stack("Transaction::read_post_conditions\x00");
    //     let (rem, conditions) =
    //         PostConditions::from_bytes(data).map_err(|_| ParserError::PostConditionFailed)?;
    //     self.post_conditions = conditions;
    //     check_canary!();
    //     Ok(rem)
    // }
    //
    // #[inline(never)]
    // fn read_payload(&mut self, data: &'a [u8]) -> Result<&'a [u8], ParserError> {
    //     c_zemu_log_stack("Transaction::read_payload\x00");
    //     let (rem, payload) = TransactionPayload::from_bytes(data)
    //         .map_err(|_| ParserError::InvalidTransactionPayload)?;
    //     self.payload = payload;
    //     check_canary!();
    //     Ok(rem)
    // }

    pub fn payload_recipient_address(
        &self,
    ) -> Option<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>> {
        self.payload.recipient_address()
    }

    pub fn num_items(&self) -> Result<u8, ParserError> {
        c_zemu_log_stack("Transaction::num_items\x00");
        let num_items_post_conditions = self.post_conditions.num_items();

        // nonce + origin + fee-rate + payload + post-conditions
        3u8.checked_add(self.payload.num_items())
            .and_then(|res| res.checked_add(num_items_post_conditions))
            .ok_or(ParserError::ValueOutOfRange)
    }

    fn get_origin_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        c_zemu_log_stack("Transaction::get_origin_items\x00");
        let mut writer_key = zxformat::Writer::new(out_key);

        #[cfg(test)]
        let origin = self.transaction_auth.origin();

        #[cfg(not(test))]
        let origin = match self.signer {
            SignerId::Origin => self.transaction_auth.origin(),
            SignerId::Sponsor => self
                .transaction_auth
                .sponsor()
                .ok_or(ParserError::InvalidAuthType)?,
            _ => return Err(ParserError::InvalidAuthType),
        };

        match display_idx {
            // The address of who signed this transaction
            0 => {
                writer_key
                    .write_str("Origin")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let origin_address = origin.signer_address(self.version)?;
                zxformat::pageString(out_value, origin_address.as_ref(), page_idx)
            }
            // The signer nonce
            1 => {
                writer_key
                    .write_str("Nonce")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let nonce_str = origin.nonce_str()?;
                zxformat::pageString(out_value, nonce_str.as_ref(), page_idx)
            }
            // The signer fee-rate
            2 => {
                writer_key
                    .write_str("Fee (uSTX)")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
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
        c_zemu_log_stack("Transaction::get_other_items\x00");
        let num_items = self.num_items()?;
        let post_conditions_items = self.post_conditions.num_items();

        if display_idx >= (num_items - post_conditions_items) {
            if post_conditions_items == 0 {
                return Err(ParserError::DisplayIdxOutOfRange);
            }
            self.post_conditions
                .get_items(display_idx, out_key, out_value, page_idx, num_items)
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
        c_zemu_log_stack("Transaction::get_item\x00");
        if display_idx >= self.num_items()? {
            return Err(ParserError::DisplayIdxOutOfRange);
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
            return ParserError::ParserOk;
        }
        c_zemu_log_stack("Invalid transaction signer\x00");
        ParserError::InvalidAuthType
    }

    // returns a slice of the last block to be used in the presighash calculation
    pub fn last_transaction_block(&self) -> &[u8] {
        match self.remainder {
            Some(remainder) => {
                let remainder_ptr = remainder.as_ptr() as usize;
                let tx_modes_ptr = self.transaction_modes.as_ptr() as usize;

                unsafe {
                    let len = remainder_ptr - tx_modes_ptr;
                    core::slice::from_raw_parts(self.transaction_modes.as_ptr(), len)
                }
            }
            None => {
                // If there's no remainder, return everything from transaction_modes to the end of payload
                let payload = self.payload.raw_payload();
                unsafe {
                    let payload_end = payload.as_ptr().add(payload.len());
                    let len = payload_end as usize - self.transaction_modes.as_ptr() as usize;
                    core::slice::from_raw_parts(self.transaction_modes.as_ptr(), len)
                }
            }
        }
    }

    pub fn previous_signer_data(&self) -> Option<&[u8]> {
        let remainder = self.remainder?;

        if self.is_multisig() && remainder.len() >= MULTISIG_PREVIOUS_SIGNER_DATA_LEN {
            return Some(&remainder[..MULTISIG_PREVIOUS_SIGNER_DATA_LEN]);
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
