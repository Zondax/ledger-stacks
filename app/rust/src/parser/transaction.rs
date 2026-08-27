use core::fmt::Write;
use nom::{
    bytes::complete::take,
    number::complete::be_u32,
    sequence::tuple,
};

use crate::{
    bolos::c_zemu_log_stack,
    parser::{
        error::ParserError,
        parser_common::{HashMode, SignerId, TransactionVersion, C32_ENCODED_ADDRS_LENGTH},
        transaction_auth::TransactionAuth,
        transaction_payload::{DisplayMode, TransactionPayload, CONTRACT_CALL_BASE_ITEMS},
    },
};

use crate::{check_canary, zxformat};

use super::{PostConditions, TransactionPostConditionMode};

// In multisig transactions the remainder should contain:
// 32-byte previous signer post_sig_hash
// 1-byte pubkey type
// 65-bytes vrs
const MULTISIG_PREVIOUS_SIGNER_DATA_LEN: usize = 98;

// Every transaction shows an origin, a nonce and a fee before its payload.
const TX_ORIGIN_ITEMS: u8 = 3;

/// Most display items a transaction may have.
///
/// Not 255. zxlib hands the review screens their index through
/// `viewfunc_getItem_t(int8_t displayIdx, ..)` (deps/ledger-zxlib/app/ui/view.h), so index 128
/// and up arrive negative, `parser_getItem` compares them against `numItems` as an unsigned
/// value, and the item is refused. The ceiling belongs to the UI, not to the u8 the parser
/// counts with, and a transaction past it cannot be reviewed on any screen -- blind signing
/// included, since that shows the same items behind a warning. Refusing it is the honest answer.
pub const MAX_DISPLAY_ITEMS: u8 = 128;

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
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::OnChainOnly),
            2 => Some(Self::OffChainOnly),
            3 => Some(Self::Any),
            _ => None,
        }
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
    // If this is not a multisig transaction, this field should be None
    pub remainder: Option<&'a [u8]>,
}

impl<'a> Transaction<'a> {
    fn update_remainder(&mut self, data: &'a [u8]) {
        if !data.is_empty() {
            self.remainder = Some(data);
        } else {
            self.remainder = None;
        }
    }

    #[inline(never)]
    pub fn read(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        c_zemu_log_stack("Transaction::read\x00");
        let rem = self.read_header(data)?;
        let rem = self.read_auth(rem)?;
        let rem = self.read_transaction_modes(rem)?;
        let rem = self.read_post_conditions(rem)?;
        let rem = self.read_payload(rem)?;

        let is_token_transfer = self.payload.is_token_transfer_payload();
        let is_standard_auth = self.transaction_auth.is_standard_auth();

        if is_token_transfer && !is_standard_auth {
            c_zemu_log_stack("Transaction::invalid_token_transfer!\x00");
            return Err(ParserError::InvalidTransactionPayload);
        }

        // At this point we do not know who the signer is
        self.signer = SignerId::Invalid;

        self.remainder = None;

        // set the remainder if this is mutltisig
        if self.is_multisig() && !rem.is_empty() {
            self.update_remainder(rem);
        }

        Ok(())
    }

    #[inline(never)]
    fn read_header(&mut self, data: &'a [u8]) -> Result<&'a [u8], ParserError> {
        c_zemu_log_stack("Transaction::read_header\x00");
        let (rem, version) =
            TransactionVersion::from_bytes(data).map_err(|_| ParserError::UnexpectedValue)?;

        let (rem, chain_id) =
            be_u32::<_, ParserError>(rem).map_err(|_| ParserError::UnexpectedValue)?;

        self.version = version;
        self.chain_id = chain_id;
        check_canary!();

        Ok(rem)
    }

    #[inline(never)]
    fn read_auth(&mut self, data: &'a [u8]) -> Result<&'a [u8], ParserError> {
        c_zemu_log_stack("Transaction::read_auth\x00");
        let (rem, auth) =
            TransactionAuth::from_bytes(data).map_err(|_| ParserError::InvalidAuthType)?;
        self.transaction_auth = auth;
        check_canary!();
        Ok(rem)
    }

    #[inline(never)]
    fn read_transaction_modes(&mut self, data: &'a [u8]) -> Result<&'a [u8], ParserError> {
        c_zemu_log_stack("Transaction::read_transaction_modes\x00");
        // two modes are included here,
        // anchor mode and postcondition mode — both must be valid enum variants
        let (rem, _) = take::<_, _, ParserError>(2usize)(data)
            .map_err(|_| ParserError::UnexpectedBufferEnd)?;
        let modes = arrayref::array_ref!(data, 0, 2);
        TransactionAnchorMode::from_u8(modes[0]).ok_or(ParserError::UnexpectedValue)?;
        TransactionPostConditionMode::from_u8(modes[1]).ok_or(ParserError::UnexpectedValue)?;
        self.transaction_modes = modes;
        check_canary!();
        Ok(rem)
    }

    #[inline(never)]
    fn read_post_conditions(&mut self, data: &'a [u8]) -> Result<&'a [u8], ParserError> {
        c_zemu_log_stack("Transaction::read_post_conditions\x00");
        let (rem, conditions) =
            PostConditions::from_bytes(data).map_err(|_| ParserError::PostConditionFailed)?;
        self.post_conditions = conditions;
        check_canary!();
        Ok(rem)
    }

    #[inline(never)]
    fn read_payload(&mut self, data: &'a [u8]) -> Result<&'a [u8], ParserError> {
        c_zemu_log_stack("Transaction::read_payload\x00");
        let (rem, payload) = TransactionPayload::from_bytes(data)
            .map_err(|_| ParserError::InvalidTransactionPayload)?;
        self.payload = payload;
        check_canary!();
        Ok(rem)
    }

    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ParserError> {
        match tuple((
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
                    return Err(ParserError::InvalidTransactionPayload);
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

    /// Checks if SIP-10 token transfer details should be hidden
    /// This includes postconditions and contract call base items (address, name, function)
    ///
    /// Only for a recognised SIP-10 *transfer*: that is the one call `render_sip10_transfer_args`
    /// collapses to Amount / From / To / Memo, so it is the only one whose base items and
    /// post-condition are redundant. Keying this on the contract alone -- as it used to -- hid the
    /// post-conditions of any other function on a listed token, and since the renderer still spent
    /// three indices on the base items, the last three arguments were never shown either.
    fn should_hide_sip10_details(&self) -> Result<bool, ParserError> {
        if self.post_conditions.num_items() == 0 {
            return Ok(false);
        }

        let contract_call = match &self.payload {
            TransactionPayload::ContractCall(call) => call,
            _ => return Ok(false),
        };

        // Only a call the renderer actually shows as a compact SIP-10 transfer card may hide
        // items. `sip10_token_info()` alone matches on contract address and name, so a call to a
        // *registry* contract with any other function name would suppress the base items in
        // `num_items` while `get_contract_call_items` still rendered them -- silently dropping
        // the trailing arguments, the function name and every post-condition from the review.
        if !contract_call.is_sip10_transfer() {
            return Ok(false);
        }

        let token_info = match contract_call.sip10_token_info() {
            Some(info) => info,
            None => return Ok(false),
        };

        let expected_condition = match token_info.post_condition_code {
            Some(code) => code,
            None => return Ok(false),
        };

        let current_condition = match self.post_conditions.first_post_condition()?.fungible_condition_code() {
            Some(code) => code,
            None => return Ok(false),
        };

        // Skip rendering if expected condition is the current one
        if expected_condition == current_condition {
            c_zemu_log_stack("Hiding SIP-10 details\x00");
            return Ok(true);
        }

        Ok(false)
    }

    /// Whether this transaction commits to data the device cannot show the user.
    ///
    /// Drives the blind-signing gate in `parser_parse`: when true, the app refuses to sign unless
    /// the user has explicitly enabled blind signing, and then warns before signing.
    ///
    /// Deliberately independent of `should_hide_sip10_details`: hiding the SIP-10 base items and
    /// post-conditions changes *which* items are listed, never whether an argument's value can be
    /// rendered.
    pub fn requires_blindsign(&self) -> Result<bool, ParserError> {
        if let TransactionPayload::ContractCall(call) = &self.payload {
            // A SIP-10 transfer has its own fixed rendering; everything else is gated exactly
            // when its arguments cannot be shown one item per leaf.
            if !call.is_sip10_transfer() {
                // A transaction whose items do not fit the display index at all is *rejected* by
                // num_items(), and has been since before there was a gate -- 70 distinct
                // post-conditions is 280 items and the device will not sign it. Do not turn that
                // into a blind-signing prompt: enabling the setting would not make it signable,
                // so the prompt would be a lie and the real error would never be seen.
                if self.num_items().is_err() {
                    return Ok(false);
                }
                // Gated only when neither layout shows everything. The fallback -- one item per
                // argument -- is what the device showed before flattening existed, so a call it
                // rendered in full then must not need blind signing now.
                return Ok(!self.flatten_args()? && !call.single_items_render());
            }
        }
        self.payload.requires_blindsign()
    }

    /// Whether the contract call's arguments are displayed one item per leaf.
    ///
    /// Two things have to hold. Every leaf must render, which the contract call worked out at
    /// parse time and recorded as `flat_items`. And the items must fit alongside the rest of the
    /// transaction inside the u8 display index `_getNumItems` reports -- post-conditions and
    /// arguments share that space, and a wide DLMM withdrawal already spends 26 items on
    /// post-conditions alone, so the check cannot live in the payload by itself.
    ///
    /// When it does not hold, the arguments fall back to one item each -- the type placeholders
    /// this rendering replaced -- and `requires_blindsign` gates the transaction. So the fallback
    /// is never what a user silently signs: they have opted in to see it.
    fn flatten_args(&self) -> Result<bool, ParserError> {
        let TransactionPayload::ContractCall(call) = &self.payload else {
            return Ok(false);
        };
        let Some(leaves) = call.flat_items() else {
            return Ok(false);
        };

        let hide_sip10_details = self.should_hide_sip10_details()?;
        let (base_items, post_conditions) = if hide_sip10_details {
            (0, 0)
        } else {
            (CONTRACT_CALL_BASE_ITEMS, self.post_conditions.num_items())
        };

        Ok(TX_ORIGIN_ITEMS
            .checked_add(base_items)
            .and_then(|items| items.checked_add(leaves))
            .and_then(|items| items.checked_add(post_conditions))
            .is_some_and(|items| items <= MAX_DISPLAY_ITEMS))
    }

    /// The layout every item lookup in this transaction shares.
    fn display_mode(&self) -> Result<DisplayMode, ParserError> {
        Ok(DisplayMode {
            hide_sip10_details: self.should_hide_sip10_details()?,
            flatten_args: self.flatten_args()?,
        })
    }

    pub fn num_items(&self) -> Result<u8, ParserError> {
        let mode = self.display_mode()?;
        let num_items_post_conditions = if mode.hide_sip10_details {
            0
        } else {
            self.post_conditions.num_items()
        };

        // nonce + origin + fee-rate + payload + post-conditions
        TX_ORIGIN_ITEMS
            .checked_add(self.payload.num_items(mode)?)
            .and_then(|res| res.checked_add(num_items_post_conditions))
            .filter(|items| *items <= MAX_DISPLAY_ITEMS)
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

        #[cfg(any(test, feature = "cpp_test"))]
        let origin = self.transaction_auth.origin();

        #[cfg(not(any(test, feature = "cpp_test")))]
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
                zxformat::page_string(out_value, origin_address.as_ref(), page_idx)
            }
            // The signer nonce
            1 => {
                writer_key
                    .write_str("Nonce")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let nonce_str = origin.nonce_str()?;
                zxformat::page_string(out_value, nonce_str.as_ref(), page_idx)
            }
            // The signer fee-rate
            2 => {
                writer_key
                    .write_str("Fee (uSTX)")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let fee_str = origin.fee_str()?;
                zxformat::page_string(out_value, fee_str.as_ref(), page_idx)
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
        let mut post_conditions_items = self.post_conditions.num_items();
        let hide_sip10_details = self.should_hide_sip10_details()?;

        if hide_sip10_details {
            post_conditions_items = 0;
        }

        if display_idx >= (num_items - post_conditions_items) {
            if post_conditions_items == 0 {
                return Err(ParserError::DisplayIdxOutOfRange);
            }
            self.post_conditions
                .get_items(display_idx, out_key, out_value, page_idx, num_items)
        } else {
            let total_items = num_items - post_conditions_items;
            self.payload.get_items(
                display_idx,
                out_key,
                out_value,
                page_idx,
                total_items, // we need to display the payload in order
                self.display_mode()?,
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
        // For sponsored transactions, the auth_flag used in the presig_hash
        // depends on who is signing:
        // - Origin signer uses Standard (0x04)
        // - Sponsor signer uses Sponsored (0x05)
        match self.signer {
            SignerId::Origin => TransactionAuthFlags::Standard,
            _ => TransactionAuthFlags::Sponsored,
        }
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
    // pub fn last_transaction_block(&self) -> Option<&[u8]> {
    //     self.remainder.map(|remainder| {
    //         let remainder_ptr = remainder.as_ptr() as usize;
    //         let tx_modes_ptr = self.transaction_modes.as_ptr() as usize;
    //
    //         unsafe {
    //             let len = remainder_ptr - tx_modes_ptr;
    //             core::slice::from_raw_parts(self.transaction_modes.as_ptr(), len)
    //         }
    //     })
    // }

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
