use core::fmt::Write;

use nom::{bytes::complete::take, sequence::tuple};
use numtoa::NumToA;

use crate::{
    check_canary,
    parser::{
        c32,
        ffi::token_info::{get_token_info, TokenInfo, TOKEN_SYMBOL_MAX_LEN},
        transaction_payload::{arguments::Arguments, DisplayMode},
        ApduPanic, ClarityName, ContractName, ParserError, PrincipalData, StacksAddress, Value,
        ValueId, C32_ENCODED_ADDRS_LENGTH, HASH160_LEN, TX_DEPTH_LIMIT,
    },
    zxformat::{self, format_u128_decimals, MAX_U128_FORMATTED_SIZE_DECIMAL},
};

/// The display text of one value is built in a fixed stack buffer before being paged out, and
/// this is that buffer's size. It is the render budget: a value whose text does not fit is not
/// displayable, so the transaction falls back to the blind-signing gate instead of being shown
/// truncated. Whatever does fit, `page_string` spreads over as many pages as the device needs --
/// `pageCount` is a u8, so 255 pages, far more than this buffer can fill.
pub const MAX_VALUE_TEXT: usize = 256;

/// Buffers up to this many bytes render as `0x..` hex. Past that the hex is more screens of
/// noise than a user will read, and gating is the honest answer.
pub const MAX_BUFFER_BYTES_TO_SHOW: usize = 64;

/// How many `Some`/`Ok`/`Err` wrappers deep `write_value_text` unwraps before treating the value
/// as opaque. Bounds its recursion, which runs on the device stack.
const MAX_WRAPPER_DEPTH: u8 = 3;

/// Lowercase hex digits, for rendering buffers without a scratch buffer.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Most display items a contract call's arguments may expand to when flattened.
///
/// Bounds the walk so a crafted argument -- 256 entries per container, eight levels deep --
/// cannot be counted to an astronomical total. Whether that many items actually fit is decided
/// per transaction by `Transaction::flatten_args`, since post-conditions and arguments share the
/// display index.
///
/// Sized well under that ceiling on purpose. `render_flat_arg` restarts the walk for every screen,
/// so a review costs O(items x leaves): at 64 leaves that is a few thousand value reads, where 200
/// would have been forty thousand, on a 30 MHz chip, twice -- once for `parser_validate` and again
/// as the user pages. Real calls need far less: the reported swaps use one to six leaves, and the
/// largest fixture in this repo expands to 31.
pub const MAX_ARG_DISPLAY_ITEMS: u8 = 64;

/// Longest key a flattened leaf may carry, in bytes. A leaf whose path outgrows this is opaque,
/// and the transaction is gated.
///
/// Fixed rather than taken from the output buffer, so the gate does not depend on which device is
/// signing: the same transaction reviews the same way on a Nano and a Stax. Every shipped target
/// hands the parser a 64-byte key buffer (zxlib `MAX_CHARS_PER_KEY_LINE`; the 18-byte line is
/// the retired Nano S), so a path this long always arrives in full, and a Nano X/S+ then elides
/// the middle *visually* when it is too wide for the screen. It is wide enough for real Clarity
/// field names -- `min-amount-out`, `token-in` -- which would otherwise gate ordinary swaps, the
/// problem this rendering exists to fix.
const MAX_KEY_PATH: usize = 32;

/// The key of a flattened leaf -- `arg3.a`, `arg0[2].amount` -- built up as the walk descends and
/// rolled back as it returns.
#[derive(Clone, Copy)]
struct KeyPath {
    buf: [u8; MAX_KEY_PATH],
    len: usize,
}

impl KeyPath {
    const fn new() -> Self {
        Self {
            buf: [0; MAX_KEY_PATH],
            len: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Appends a segment. Failing here means the path outgrew the key line, which makes the leaf
    /// undisplayable and gates the transaction -- the same answer as a value that cannot render.
    fn push(&mut self, bytes: &[u8]) -> Result<(), ParserError> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(ParserError::ValueOutOfRange)?;
        self.buf
            .get_mut(self.len..end)
            .ok_or(ParserError::UnexpectedBufferEnd)?
            .copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    fn push_index(&mut self, index: u32) -> Result<(), ParserError> {
        let mut buff = [0u8; 10];
        self.push(index.numtoa_str(10, &mut buff).as_bytes())
    }

    fn truncate(&mut self, len: usize) {
        self.len = len;
    }
}

/// Carries the state of a walk over a contract call's arguments: either counting the display
/// items they expand to, or locating the one the device is about to render.
struct Walker<'a> {
    /// Leaves passed so far; the display item count once the walk finishes.
    seen: u8,
    /// The leaf to stop at, or `None` to count them all.
    target: Option<u8>,
    /// The leaf at `target`, once reached.
    found: Option<Value<'a>>,
    /// Path to the value currently being visited.
    path: KeyPath,
    /// Path to `found`.
    found_path: KeyPath,
}

impl<'a> Walker<'a> {
    fn counting() -> Self {
        Self {
            seen: 0,
            target: None,
            found: None,
            path: KeyPath::new(),
            found_path: KeyPath::new(),
        }
    }

    fn seeking(target: u8) -> Self {
        Self {
            target: Some(target),
            ..Self::counting()
        }
    }

    /// Whether the walk can stop early.
    fn done(&self) -> bool {
        self.found.is_some()
    }

    fn record(&mut self, value: &Value<'a>) -> Result<(), ParserError> {
        if self.target == Some(self.seen) {
            self.found = Some(*value);
            self.found_path = self.path;
        }
        self.seen = self
            .seen
            .checked_add(1)
            .ok_or(ParserError::ValueOutOfRange)?;
        if self.seen > MAX_ARG_DISPLAY_ITEMS {
            return Err(ParserError::ValueOutOfRange);
        }
        Ok(())
    }
}

/// The `be_u32` element count leading a List or Tuple payload.
fn container_count(payload: &[u8]) -> Result<u32, ParserError> {
    let count = payload.get(..4).ok_or(ParserError::UnexpectedBufferEnd)?;
    Ok(u32::from_be_bytes([count[0], count[1], count[2], count[3]]))
}

/// Whether this value is a container the walk descends into rather than rendering whole.
///
/// An *empty* container is not: `List: []` is the complete value, and descending would drop the
/// argument from the display entirely.
fn is_populated_container(value: &Value) -> Result<bool, ParserError> {
    match value.value_id() {
        ValueId::List | ValueId::Tuple => Ok(container_count(value.payload())? > 0),
        _ => Ok(false),
    }
}

/// Walks every argument in order.
fn walk_args<'a>(args: &Arguments<'a>, walker: &mut Walker<'a>) -> Result<(), ParserError> {
    let num_args = args.num_args()?;
    let mut rest = args.values()?;

    for idx in 0..num_args {
        let (rem, value) =
            Value::from_bytes::<TX_DEPTH_LIMIT>(rest).map_err(|_| ParserError::InvalidArgumentId)?;
        rest = rem;

        let mark = walker.path.len;
        walker.path.push(b"arg")?;
        walker.path.push_index(idx)?;
        walk_value(&value, walker, 0)?;
        walker.path.truncate(mark);

        if walker.done() {
            return Ok(());
        }
    }

    Ok(())
}

/// Walks one value, descending into containers so that every leaf becomes its own display item.
///
/// An `Err` means the arguments cannot be flattened at all -- a leaf the device cannot render, a
/// key path that outgrew the key line, nesting past `TX_DEPTH_LIMIT`, or more leaves than the
/// budget allows. The caller falls back to one item per argument and gates the transaction.
fn walk_value<'a>(
    value: &Value<'a>,
    walker: &mut Walker<'a>,
    depth: u8,
) -> Result<(), ParserError> {
    check_canary!();

    if depth >= TX_DEPTH_LIMIT {
        return Err(ParserError::RecursionLimit);
    }

    // Descend through a `Some`/`Ok`/`Err` only when it wraps a container: `Some(u1)` is a leaf
    // that `write_value_text` renders in full, but `Some((tuple ...))` would otherwise be opaque.
    let mut value = *value;
    if matches!(
        value.value_id(),
        ValueId::OptionalSome | ValueId::ResponseOk | ValueId::ResponseErr
    ) {
        let inner_bytes = value.payload();
        if inner_bytes.is_empty() {
            return Err(ParserError::UnexpectedBufferEnd);
        }
        let inner = Value(inner_bytes);
        if is_populated_container(&inner)? {
            walker.path.push(match value.value_id() {
                ValueId::OptionalSome => b".some".as_slice(),
                ValueId::ResponseOk => b".ok".as_slice(),
                _ => b".err".as_slice(),
            })?;
            value = inner;
        }
    }

    let payload = value.payload();

    match value.value_id() {
        // `[count: 4][values..]`
        ValueId::List if is_populated_container(&value)? => {
            let count = container_count(payload)?;
            let mut rest = payload.get(4..).ok_or(ParserError::UnexpectedBufferEnd)?;

            for idx in 0..count {
                let (rem, item) = Value::from_bytes::<TX_DEPTH_LIMIT>(rest)
                    .map_err(|_| ParserError::InvalidArgumentId)?;
                rest = rem;

                let mark = walker.path.len;
                walker.path.push(b"[")?;
                walker.path.push_index(idx)?;
                walker.path.push(b"]")?;
                walk_value(&item, walker, depth + 1)?;
                walker.path.truncate(mark);

                if walker.done() {
                    return Ok(());
                }
            }
        }

        // `[count: 4][(name_len, name, value)..]`
        ValueId::Tuple if is_populated_container(&value)? => {
            let count = container_count(payload)?;
            let mut rest = payload.get(4..).ok_or(ParserError::UnexpectedBufferEnd)?;

            for _ in 0..count {
                let (rem, name) =
                    ClarityName::from_bytes(rest).map_err(|_| ParserError::UnexpectedValue)?;
                let (rem, item) = Value::from_bytes::<TX_DEPTH_LIMIT>(rem)
                    .map_err(|_| ParserError::InvalidArgumentId)?;
                rest = rem;

                let mark = walker.path.len;
                walker.path.push(b".")?;
                walker.path.push(name.0)?;
                walk_value(&item, walker, depth + 1)?;
                walker.path.truncate(mark);

                if walker.done() {
                    return Ok(());
                }
            }
        }

        // A leaf. It has to render, or there is nothing to flatten into.
        _ => {
            if !TransactionContractCall::arg_is_fully_displayable(&value) {
                return Err(ParserError::UnexpectedType);
            }
            walker.record(&value)?;
        }
    }

    Ok(())
}
// The items in contract_call transactions are
// contract_address, contract_name and function_name
pub const CONTRACT_CALL_BASE_ITEMS: u8 = 3;
// A SIP-10 `transfer` takes (amount uint) (sender principal) (recipient principal)
// (memo (optional (buff 34))) -- the four items render_sip10_transfer_args displays.
const SIP10_TRANSFER_ARGS: u32 = 4;
const SIP10_MEMO_ARG_IDX: usize = 3;
// 1 for space, 1 for '(', 1 for ')'
// for example for ammount formatting:
// 123 (STX)
const EXTRA_CHARS_FOR_FORMAT: usize = 3;

const ADDR_STACKING1: &str = "SP000000000000000000002Q6VF78";
const ADDR_STACKING2: &str = "ST000000000000000000002AMW42H";
const FN_NAME_STACKING1: &str = "stack-stx";
const FN_NAME_STACKING2: &str = "delegate-stx";

/// Matches a boot PoX contract name: `pox` or `pox-N` (`pox-2`, `pox-3`, `pox-4`, ...).
/// Versioned so the friendly stacking labels keep applying to whichever PoX contract is
/// active at a given epoch, rather than pinning a single version.
fn is_pox_contract_name(name: &[u8]) -> bool {
    if name == b"pox" {
        return true;
    }
    match name.strip_prefix(b"pox-") {
        Some(rest) => !rest.is_empty() && rest.iter().all(u8::is_ascii_digit),
        None => false,
    }
}

#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
enum ContractType {
    SIP10,
    Other,
}

/// A transaction that calls into a smart contract
#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct TransactionContractCallWrapper<'a> {
    contract_type: ContractType,
    /// Display items the arguments expand to when flattened, or `None` when they cannot be.
    ///
    /// Computed once, here, because `num_items` runs on every screen the device draws: walking
    /// the argument bytes each time would cost O(payload) per page turn on a Nano.
    flat_items: Option<u8>,
    /// Whether the fallback layout -- one display item per argument -- shows every argument in
    /// full. True exactly when no argument is a populated container or otherwise opaque; this is
    /// the predicate the gate used before arguments were flattened, and keeping it means no
    /// transaction that reviewed normally then needs blind signing now.
    single_items_render: bool,
    tx: TransactionContractCall<'a>,
}

impl<'a> TransactionContractCallWrapper<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self, ParserError> {
        let (rem, tx) = TransactionContractCall::from_bytes(bytes)?;

        // Check if this is a SIP-10 transfer function with token info
        let is_sip10_transfer = tx.is_transfer_function() && tx.sip10_token_info().is_some();
        let contract_type = if is_sip10_transfer {
            ContractType::SIP10
        } else {
            ContractType::Other
        };

        // A SIP-10 transfer always renders through render_sip10_transfer_args, which shows a
        // fixed Amount / From / To / Memo; there is nothing to flatten.
        let (flat_items, single_items_render) = if contract_type == ContractType::SIP10 {
            (None, false)
        } else {
            (
                tx.flat_item_count().ok(),
                tx.function_args()?
                    .all(TransactionContractCall::arg_is_fully_displayable)?,
            )
        };

        check_canary!();
        Ok((
            rem,
            Self {
                contract_type,
                flat_items,
                single_items_render,
                tx,
            },
        ))
    }

    pub fn sip10_token_info(&self) -> Option<TokenInfo<'static>> {
        self.tx.sip10_token_info()
    }

    /// Whether this call is rendered through the compact SIP-10 transfer card.
    ///
    /// The renderer keys the compact card off `ContractType::SIP10`, which additionally requires
    /// the called function to be `transfer`. Any predicate that suppresses items must agree with
    /// it, or `num_items` and `get_item` disagree on how many slots the payload occupies.
    pub fn is_sip10_transfer(&self) -> bool {
        self.contract_type == ContractType::SIP10
    }

    pub fn contract_name(&'a self) -> Result<ContractName<'a>, ParserError> {
        self.tx.contract_name()
    }

    pub fn contract_address(
        &self,
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        self.tx.contract_address()
    }

    pub fn function_name(&self) -> Result<&[u8], ParserError> {
        self.tx.function_name()
    }

    pub fn num_args(&self) -> Result<u32, ParserError> {
        self.tx.num_args()
    }

    /// Display items the arguments expand to when flattened, or `None` when they cannot be.
    ///
    /// Whether that many items actually *fit* is not decided here: post-conditions and arguments
    /// share one u8 display index, so only the transaction can tell. See
    /// `Transaction::flatten_args`.
    pub fn flat_items(&self) -> Option<u8> {
        self.flat_items
    }

    pub fn is_sip10_transfer(&self) -> bool {
        self.contract_type == ContractType::SIP10
    }

    /// Whether the one-item-per-argument layout renders every argument in full.
    pub fn single_items_render(&self) -> bool {
        self.single_items_render
    }

    pub fn num_items(&self, mode: DisplayMode) -> Result<u8, ParserError> {
        self.tx
            .num_items(mode.hide_sip10_details, self.arg_items(mode)?)
    }

    /// Items the arguments contribute: one per leaf when flattening, otherwise one per argument.
    fn arg_items(&self, mode: DisplayMode) -> Result<u8, ParserError> {
        match self.flat_items {
            Some(items) if mode.flatten_args => Ok(items),
            _ => {
                let raw_args = self.tx.num_args()?;
                if raw_args > u8::MAX as u32 {
                    return Err(ParserError::ValueOutOfRange);
                }
                Ok(raw_args as u8)
            }
        }
    }

    /// Whether this contract call commits to data the device cannot show.
    ///
    /// For a SIP-10 transfer that is a question about the memo, the one item
    /// `render_sip10_transfer_args` can degrade. For everything else it is gated only when
    /// NEITHER layout shows everything: the arguments do not flatten into one item per leaf, and
    /// the one-item-per-argument fallback would have to print a placeholder. Both worked out at
    /// parse time.
    ///
    /// Note this does not consider whether those items *fit*: post-conditions and arguments share
    /// one u8 display index, so only the transaction can answer that. `Transaction::requires_blindsign`
    /// is the authority, and is strictly more conservative than this.
    pub fn requires_blindsign(&self) -> Result<bool, ParserError> {
        if self.contract_type != ContractType::SIP10 {
            return Ok(self.flat_items.is_none() && !self.single_items_render);
        }

        // render_sip10_transfer_args shows exactly Amount / From / To / Memo. It type-checks the
        // first three and errors if they are not a uint and two principals, so the memo is the
        // only item that can silently degrade (to "Complex memo value").
        if self.tx.num_args()? != SIP10_TRANSFER_ARGS {
            return Ok(true);
        }
        let memo = self.tx.function_args()?.argument_at(SIP10_MEMO_ARG_IDX)?;
        Ok(!TransactionContractCall::memo_is_fully_displayable(&memo))
    }

    pub fn get_contract_call_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
        mode: DisplayMode,
    ) -> Result<u8, ParserError> {
        // display_idx was already normalized
        if mode.hide_sip10_details && self.contract_type == ContractType::SIP10 {
            return self
                .tx
                .render_sip10_transfer_args(display_idx, out_key, out_value, page_idx);
        }

        if display_idx < CONTRACT_CALL_BASE_ITEMS {
            return self
                .tx
                .get_base_items(display_idx, out_key, out_value, page_idx);
        };

        let display_idx = display_idx - CONTRACT_CALL_BASE_ITEMS;

        match (&self.contract_type, self.flat_items) {
            (ContractType::SIP10, _) => {
                self.tx
                    .render_sip10_transfer_args(display_idx, out_key, out_value, page_idx)
            }
            // One item per leaf, keyed by the path that reaches it.
            (_, Some(_)) if mode.flatten_args => {
                self.tx
                    .render_flat_arg(display_idx, out_key, out_value, page_idx)
            }
            // Fallback: one item per argument, a type placeholder for anything structured. The
            // transaction is gated, so the user has accepted that it cannot all be shown.
            _ => self
                .tx
                .render_contract_call_args(display_idx, out_key, out_value, page_idx),
        }
    }

    pub fn raw_data(&self) -> &'a [u8] {
        self.tx.raw_data()
    }
}

#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct TransactionContractCall<'a>(&'a [u8]);

impl<'a> TransactionContractCall<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self, ParserError> {
        let (rem, _) = StacksAddress::from_bytes(bytes)?;
        // get contract name and function name.
        let (rem, _) = tuple((
            ContractName::from_bytes,
            ClarityName::from_bytes,
            Arguments::from_bytes,
        ))(rem)?;

        let len = bytes.len() - rem.len();
        let (rem, data) = take(len)(bytes)?;

        check_canary!();

        Ok((rem, Self(data)))
    }

    pub fn is_transfer_function(&self) -> bool {
        let transfer_function = "transfer".as_bytes();
        let function_name = self.function_name().unwrap_or_default();
        function_name == transfer_function
    }

    /// If this contract call is an known SIP-10, and
    /// it is recognized, return the token info.
    pub fn sip10_token_info(&self) -> Option<TokenInfo<'static>> {
        // Get the contract address as a C32-encoded string
        let address = self.contract_address().ok()?;

        // Get the contract name
        let contract_name = self.contract_name().ok()?;

        // Call our FFI function to look up the token info
        get_token_info(address, contract_name)
    }

    pub fn contract_name(&'a self) -> Result<ContractName<'a>, ParserError> {
        let at = HASH160_LEN + 1;
        ContractName::from_bytes(&self.0[at..])
            .map(|(_, name)| name)
            .map_err(|e| e.into())
    }

    pub fn function_name(&self) -> Result<&[u8], ParserError> {
        ContractName::from_bytes(&self.0[(HASH160_LEN + 1)..])
            .and_then(|b| ClarityName::from_bytes(b.0))
            .map(|res| (res.1).0)
            .map_err(|_| ParserError::UnexpectedError)
    }

    pub fn function_args(&self) -> Result<Arguments<'a>, ParserError> {
        ContractName::from_bytes(&self.0[(HASH160_LEN + 1)..])
            .and_then(|b| ClarityName::from_bytes(b.0))
            .and_then(|c| Arguments::from_bytes(c.0))
            .map(|res| res.1)
            .map_err(|_| ParserError::InvalidArgumentId)
    }

    pub fn num_args(&self) -> Result<u32, ParserError> {
        self.function_args().and_then(|args| args.num_args())
    }

    #[inline(never)]
    pub fn contract_address(
        &self,
    ) -> Result<arrayvec::ArrayVec<[u8; C32_ENCODED_ADDRS_LENGTH]>, ParserError> {
        let version = self.0[0];
        c32::c32_address(version, &self.0[1..21])
    }

    // change label if it is a stacking contract call
    fn label_stacking_value(&self, key: &mut [u8]) -> Result<(), ParserError> {
        let addr = self.contract_address()?;
        let addr = addr.as_ref();
        let contract_name = self.contract_name()?;
        if (addr == ADDR_STACKING1.as_bytes() || addr == ADDR_STACKING2.as_bytes())
            && is_pox_contract_name(contract_name.name())
        {
            let name = self.function_name()?;
            if name == FN_NAME_STACKING1.as_bytes() {
                key.iter_mut().for_each(|v| *v = 0);
                let mut writer = zxformat::Writer::new(key);
                writer
                    .write_str("stacked uSTX")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
            } else if name == FN_NAME_STACKING2.as_bytes() {
                key.iter_mut().for_each(|v| *v = 0);
                let mut writer = zxformat::Writer::new(key);
                writer
                    .write_str("delegated uSTX")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
            }
        }
        Ok(())
    }

    /// Whether the device can show this value in full.
    ///
    /// SINGLE SOURCE OF TRUTH for the blind-signing gate -- and it is the renderer itself:
    /// a value is displayable exactly when [`Self::write_value_text`] can write its text into
    /// the render budget. There is no second list of types to keep in step; teaching the
    /// renderer a new type teaches the gate at the same moment.
    pub fn arg_is_fully_displayable(value: &Value) -> bool {
        let mut text = [0u8; MAX_VALUE_TEXT];
        let mut writer = zxformat::Writer::new(&mut text);
        Self::write_value_text(value, &mut writer, 0).is_ok()
    }

    /// Writes the full display text of `value` into `writer`.
    ///
    /// `Err` means the value is opaque: either the device has no faithful way to show it (a
    /// populated tuple or list, a non-ASCII UTF-8 string, an oversized buffer) or its text does
    /// not fit the render budget. Callers render a type placeholder instead, and the transaction
    /// is gated behind the blind-signing opt-in.
    ///
    /// `depth` counts `Some`/`Ok`/`Err` wrappers already unwrapped, bounding the recursion.
    fn write_value_text(
        value: &Value,
        writer: &mut zxformat::Writer<'_>,
        depth: u8,
    ) -> Result<(), ParserError> {
        use core::fmt::Write as _;

        check_canary!();
        let payload = value.payload();

        match value.value_id() {
            ValueId::Int => {
                let value = value.int().ok_or(ParserError::UnexpectedError)?;
                let mut buff = [0u8; 41]; // 40 digits + possible sign

                // Handle i128::MIN specially as numtoa has a bug with it
                // (it causes underflow when computing the absolute value)
                let text = if value == i128::MIN {
                    "-170141183460469231731687303715884105728"
                } else {
                    value.numtoa_str(10, &mut buff)
                };
                writer.write_str(text).map_err(|_| ParserError::UnexpectedBufferEnd)
            }
            ValueId::UInt => {
                let value = value.uint().ok_or(ParserError::UnexpectedError)?;
                let mut buff = [0u8; 39];
                writer
                    .write_str(value.numtoa_str(10, &mut buff))
                    .map_err(|_| ParserError::UnexpectedBufferEnd)
            }
            ValueId::BoolTrue => writer
                .write_str("Bool: true")
                .map_err(|_| ParserError::UnexpectedBufferEnd),
            ValueId::BoolFalse => writer
                .write_str("Bool: false")
                .map_err(|_| ParserError::UnexpectedBufferEnd),
            ValueId::OptionalNone => writer
                .write_str("Option: None")
                .map_err(|_| ParserError::UnexpectedBufferEnd),
            ValueId::StandardPrincipal => {
                let (_, principal) = PrincipalData::standard_from_bytes(payload)?;
                let address = principal.encoded_address()?;
                Self::write_ascii(writer, address.as_ref())
            }
            ValueId::ContractPrincipal => {
                let (_, principal) = PrincipalData::contract_principal_from_bytes(payload)?;
                let address = principal.encoded_address()?;
                // should not fail as this was parsed in previous step
                let contract_name = principal.contract_name().apdu_unwrap();

                Self::write_ascii(writer, address.as_ref())?;
                writer
                    .write_char('.')
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                Self::write_ascii(writer, contract_name.name())
            }

            // A `Some`/`Ok`/`Err` wrapper hides the part that matters, so unwrap it and show the
            // inner value -- `Some(493568)` rather than `Option: Some`. The wrapper is kept in
            // the text: the user must see that they are signing `(some u493568)` and not `u493568`.
            ValueId::OptionalSome | ValueId::ResponseOk | ValueId::ResponseErr => {
                if depth >= MAX_WRAPPER_DEPTH {
                    return Err(ParserError::RecursionLimit);
                }
                if payload.is_empty() {
                    return Err(ParserError::UnexpectedBufferEnd);
                }
                let tag = match value.value_id() {
                    ValueId::OptionalSome => "Some(",
                    ValueId::ResponseOk => "Ok(",
                    _ => "Err(",
                };
                writer
                    .write_str(tag)
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                Self::write_value_text(&Value(payload), writer, depth + 1)?;
                writer
                    .write_char(')')
                    .map_err(|_| ParserError::UnexpectedBufferEnd)
            }

            // An empty container hides nothing -- `[]` *is* the complete value. A populated one
            // has no faithful single-screen rendering, and stays opaque until arguments are
            // flattened into one item per leaf.
            ValueId::List => match container_count(payload)? {
                0 => writer
                    .write_str("List: []")
                    .map_err(|_| ParserError::UnexpectedBufferEnd),
                _ => Err(ParserError::UnexpectedType),
            },
            ValueId::Tuple => match container_count(payload)? {
                0 => writer
                    .write_str("Tuple: {}")
                    .map_err(|_| ParserError::UnexpectedBufferEnd),
                _ => Err(ParserError::UnexpectedType),
            },

            // `[len: 4][bytes]`, rendered as hex so the user sees the actual bytes signed.
            ValueId::Buffer => {
                let bytes = payload.get(4..).ok_or(ParserError::UnexpectedBufferEnd)?;
                if bytes.len() > MAX_BUFFER_BYTES_TO_SHOW {
                    return Err(ParserError::ValueOutOfRange);
                }
                writer
                    .write_str("0x")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                for byte in bytes {
                    writer
                        .write_char(HEX_DIGITS[(byte >> 4) as usize] as char)
                        .and_then(|_| writer.write_char(HEX_DIGITS[(byte & 0x0f) as usize] as char))
                        .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                }
                Ok(())
            }

            // `[len: 4][chars]`. Written in full and paged; the parser has already checked that
            // a StringAscii really is ASCII.
            ValueId::StringAscii => {
                let content = payload.get(4..).ok_or(ParserError::UnexpectedBufferEnd)?;
                Self::write_text_content(writer, content)
            }

            // Device fonts cover ASCII, so a UTF-8 string whose bytes happen to be ASCII is shown
            // like any other string. Anything else would render as mojibake or blanks, which is
            // worse than admitting the device cannot show it.
            ValueId::StringUtf8 => {
                let content = payload.get(4..).ok_or(ParserError::UnexpectedBufferEnd)?;
                if !content.is_ascii() {
                    return Err(ParserError::UnexpectedType);
                }
                Self::write_text_content(writer, content)
            }
        }
    }

    /// Writes string content, standing in for the empty string so that `page_string` -- which
    /// rejects an empty input -- is never handed nothing to page. Before this, an empty
    /// `string-ascii` argument failed the whole parse and the transaction could not be signed.
    fn write_text_content(
        writer: &mut zxformat::Writer<'_>,
        content: &[u8],
    ) -> Result<(), ParserError> {
        use core::fmt::Write as _;

        if content.is_empty() {
            return writer
                .write_str("(empty)")
                .map_err(|_| ParserError::UnexpectedBufferEnd);
        }
        Self::write_ascii(writer, content)
    }

    /// Writes bytes the parser has already established are ASCII.
    fn write_ascii(writer: &mut zxformat::Writer<'_>, bytes: &[u8]) -> Result<(), ParserError> {
        use core::fmt::Write as _;

        let text = core::str::from_utf8(bytes).map_err(|_| ParserError::InvalidUnicode)?;
        writer
            .write_str(text)
            .map_err(|_| ParserError::UnexpectedBufferEnd)
    }

    /// The text shown in place of a value [`Self::write_value_text`] cannot render. Kept
    /// exhaustive so a new `ValueId` has to be given one.
    fn type_placeholder(value: &Value) -> &'static [u8] {
        match value.value_id() {
            ValueId::Buffer => b"is Buffer",
            ValueId::List => b"is List",
            ValueId::Tuple => b"is Tuple",
            ValueId::StringAscii => b"is StringAscii",
            ValueId::StringUtf8 => b"is StringUtf8",
            ValueId::OptionalSome => b"Option: Some",
            ValueId::ResponseOk => b"Result: Ok",
            ValueId::ResponseErr => b"Result: Err",
            // Scalars always fit the render budget; unreachable in practice.
            ValueId::Int
            | ValueId::UInt
            | ValueId::BoolTrue
            | ValueId::BoolFalse
            | ValueId::OptionalNone
            | ValueId::StandardPrincipal
            | ValueId::ContractPrincipal => b"is Value",
        }
    }

    /// Whether [`Self::render_memo_value`] can show this memo in full.
    ///
    /// The memo path unwraps `Some(..)` and shows the inner value bare -- a memo is a payload,
    /// not a Clarity expression the user reasons about -- where the generic argument path keeps
    /// the `Some(..)` around it. Past that unwrap both go through `write_value_text`, so a
    /// `(buff 34)` memo renders as hex instead of forcing the whole transfer to be blind-signed.
    pub fn memo_is_fully_displayable(memo: &Value) -> bool {
        match memo.value_id() {
            ValueId::OptionalNone => true,
            ValueId::OptionalSome => Self::memo_inner(memo)
                .map(|inner| Self::arg_is_fully_displayable(&inner))
                .unwrap_or(false),
            // render_memo_value errors on a non-Optional memo; be conservative.
            _ => false,
        }
    }

    /// The value carried inside a `Some(..)` memo.
    fn memo_inner<'b>(memo: &Value<'b>) -> Option<Value<'b>> {
        let inner = memo.payload();
        (!inner.is_empty()).then_some(Value(inner))
    }

    fn render_contract_call_args(
        &'a self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let arg_num = display_idx;

        let args = self.function_args()?;

        let value = args.argument_at(arg_num as _)?;

        {
            let mut writer_key = zxformat::Writer::new(out_key);
            let mut arg_num_buff = [0u8; 3];
            let arg_num_str = arg_num.numtoa_str(10, &mut arg_num_buff);

            writer_key
                .write_str("arg")
                .map_err(|_| ParserError::UnexpectedBufferEnd)?;
            writer_key
                .write_str(arg_num_str)
                .map_err(|_| ParserError::UnexpectedBufferEnd)?;
        }

        // The first uint argument of a PoX stack-stx/delegate-stx call gets a friendlier key.
        if arg_num == 0 && value.value_id() == ValueId::UInt {
            self.label_stacking_value(out_key)?;
        }

        Self::render_value(&value, out_value, page_idx)
    }

    /// Renders a single contract-call argument value into `out_value`.
    ///
    /// Builds the complete display text first, then pages it out. A value whose text does not fit
    /// the render budget -- or that has no faithful rendering at all -- falls back to
    /// [`Self::render_opaque`], which is exactly the case `arg_is_fully_displayable` gates behind
    /// the blind-signing opt-in. The two share [`Self::write_value_text`], so they cannot disagree.
    fn render_value(value: &Value, out_value: &mut [u8], page_idx: u8) -> Result<u8, ParserError> {
        let mut text = [0u8; MAX_VALUE_TEXT];
        let written = {
            let mut writer = zxformat::Writer::new(&mut text);
            Self::write_value_text(value, &mut writer, 0).map(|_| writer.offset)
        };

        match written {
            Ok(len) => zxformat::page_string(out_value, &text[..len], page_idx),
            Err(_) => Self::render_opaque(value, out_value, page_idx),
        }
    }

    /// What the blind-signing review shows for a value `write_value_text` could not render.
    ///
    /// Text that is merely too long is shown up to the render budget with an explicit `...`, so
    /// the user still sees what the previous version showed them (its first characters) and now
    /// also sees that it was cut. Everything else is a type placeholder.
    fn render_opaque(value: &Value, out_value: &mut [u8], page_idx: u8) -> Result<u8, ParserError> {
        const ELLIPSIS: &[u8] = b"...";

        if let Some(content) = Self::overlong_ascii_text(value) {
            let mut text = [0u8; MAX_VALUE_TEXT + ELLIPSIS.len()];
            text[..MAX_VALUE_TEXT].copy_from_slice(&content[..MAX_VALUE_TEXT]);
            text[MAX_VALUE_TEXT..].copy_from_slice(ELLIPSIS);
            return zxformat::page_string(out_value, &text, page_idx);
        }

        zxformat::page_string(out_value, Self::type_placeholder(value), page_idx)
    }

    /// The content of a string argument that is ASCII -- so it *could* be shown -- but longer
    /// than the render budget. `None` for anything else.
    fn overlong_ascii_text<'b>(value: &Value<'b>) -> Option<&'b [u8]> {
        match value.value_id() {
            ValueId::StringAscii | ValueId::StringUtf8 => {
                let content = value.payload().get(4..)?;
                (content.is_ascii() && content.len() > MAX_VALUE_TEXT).then_some(content)
            }
            _ => None,
        }
    }

    fn render_sip10_transfer_args(
        &self,
        arg_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let args = self.function_args()?;
        let token_info = self
            .sip10_token_info()
            .ok_or(ParserError::UnexpectedError)?;

        let key_strings = ["Amount", "From", "To", "Memo"];

        // Check if arg_idx is within bounds
        if arg_idx as usize >= key_strings.len() {
            return Err(ParserError::DisplayIdxOutOfRange);
        }

        // Copy the key string to out_key
        let key = key_strings[arg_idx as usize].as_bytes();
        if key.len() > out_key.len() {
            return Err(ParserError::UnexpectedBufferEnd);
        }
        out_key[..key.len()].copy_from_slice(key);

        match arg_idx {
            0 => {
                // Amount
                let amount_value = args.argument_at(0)?;
                if amount_value.value_id() != ValueId::UInt {
                    return Err(ParserError::UnexpectedError);
                }

                let amount = amount_value.uint().ok_or(ParserError::UnexpectedError)?;

                // Format amount with decimals
                let formatted_amount = format_u128_decimals(amount, token_info.decimals)
                    .ok_or(ParserError::UnexpectedError)?;

                // Create a buffer for the formatted display
                let mut display_buffer =
                    [0u8; MAX_U128_FORMATTED_SIZE_DECIMAL + TOKEN_SYMBOL_MAX_LEN + EXTRA_CHARS_FOR_FORMAT];
                let mut pos = 0;

                // Copy the formatted amount
                if formatted_amount.len() > display_buffer.len() - EXTRA_CHARS_FOR_FORMAT - token_info.token_symbol.len()
                {
                    return Err(ParserError::UnexpectedBufferEnd);
                }

                // Copy formatted amount
                display_buffer[pos..pos + formatted_amount.len()]
                    .copy_from_slice(&formatted_amount);
                pos += formatted_amount.len();

                // Add space
                display_buffer[pos] = b' ';
                pos += 1;

                // Add '('
                display_buffer[pos] = b'(';
                pos += 1;

                // Copy token symbol
                display_buffer[pos..pos + token_info.token_symbol.len()]
                    .copy_from_slice(token_info.token_symbol);
                pos += token_info.token_symbol.len();

                // Add ')'
                display_buffer[pos] = b')';
                pos += 1;

                // Page the formatted string
                zxformat::page_string(out_value, &display_buffer[..pos], page_idx)
            }
            1 => {
                // Sender principal
                let sender_value = args.argument_at(1)?;
                let payload = sender_value.payload();

                match sender_value.value_id() {
                    ValueId::StandardPrincipal => {
                        let (_, principal) = PrincipalData::standard_from_bytes(payload)?;
                        let address = principal.encoded_address()?;
                        zxformat::page_string(out_value, &address[..address.len()], page_idx)
                    }
                    ValueId::ContractPrincipal => {
                        // holds principal_encoded address + '.' + contract_name + null terminator
                        let mut data =
                            [0; C32_ENCODED_ADDRS_LENGTH + ClarityName::MAX_LEN as usize + 1];
                        let (_, principal) = PrincipalData::contract_principal_from_bytes(payload)?;
                        let address = principal.encoded_address()?;
                        let contract_name = principal.contract_name().apdu_unwrap();

                        data.get_mut(..address.len())
                            .apdu_unwrap()
                            .copy_from_slice(&address[..address.len()]);

                        data[address.len()] = b'.';
                        let len = address.len() + 1;

                        data.get_mut(len..len + contract_name.len())
                            .apdu_unwrap()
                            .copy_from_slice(contract_name.name());

                        zxformat::page_string(
                            out_value,
                            &data[..len + contract_name.len()],
                            page_idx,
                        )
                    }
                    _ => Err(ParserError::UnexpectedError),
                }
            }
            2 => {
                // Recipient principal
                // Sender principal
                let recipient_value = args.argument_at(2)?;
                let payload = recipient_value.payload();

                match recipient_value.value_id() {
                    ValueId::StandardPrincipal => {
                        let (_, principal) = PrincipalData::standard_from_bytes(payload)?;
                        let address = principal.encoded_address()?;
                        zxformat::page_string(out_value, &address[..address.len()], page_idx)
                    }
                    ValueId::ContractPrincipal => {
                        let mut data =
                            [0; C32_ENCODED_ADDRS_LENGTH + ClarityName::MAX_LEN as usize + 1];
                        let (_, principal) = PrincipalData::contract_principal_from_bytes(payload)?;
                        let address = principal.encoded_address()?;
                        let contract_name = principal.contract_name().apdu_unwrap();

                        data.get_mut(..address.len())
                            .apdu_unwrap()
                            .copy_from_slice(&address[..address.len()]);

                        data[address.len()] = b'.';
                        let len = address.len() + 1;

                        data.get_mut(len..len + contract_name.len())
                            .apdu_unwrap()
                            .copy_from_slice(contract_name.name());

                        zxformat::page_string(
                            out_value,
                            &data[..len + contract_name.len()],
                            page_idx,
                        )
                    }
                    _ => Err(ParserError::UnexpectedError),
                }
            }
            3 => {
                // Memo (optional)
                let memo_value = args.argument_at(3)?;
                self.render_memo_value(&memo_value, out_value, page_idx)
            }
            _ => Err(ParserError::DisplayIdxOutOfRange),
        }
    }

    /// Renders the content of a memo field (which is an Optional type)
    /// If it's None, renders "None"
    /// If it's Some, unwraps and renders the inner value
    /// If the inner value is a complex type, renders a generic message
    fn render_memo_value(
        &self,
        memo_value: &Value<'_>,
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        match memo_value.value_id() {
            ValueId::OptionalNone => {
                // Simply render "None"
                zxformat::page_string(out_value, "None".as_bytes(), page_idx)
            }
            ValueId::OptionalSome => {
                let inner = Self::memo_inner(memo_value).ok_or(ParserError::UnexpectedBufferEnd)?;

                // A memo shows its inner value bare -- no `Some(..)` wrapper around it, unlike a
                // contract-call argument, where the wrapper is part of what the user is signing.
                let mut text = [0u8; MAX_VALUE_TEXT];
                let written = {
                    let mut writer = zxformat::Writer::new(&mut text);
                    Self::write_value_text(&inner, &mut writer, 0).map(|_| writer.offset)
                };

                match written {
                    Ok(len) => zxformat::page_string(out_value, &text[..len], page_idx),
                    // A memo that is only too long still shows its start; anything else is opaque.
                    Err(_) if Self::overlong_ascii_text(&inner).is_some() => {
                        Self::render_opaque(&inner, out_value, page_idx)
                    }
                    Err(_) => {
                        zxformat::page_string(out_value, "Complex memo value".as_bytes(), page_idx)
                    }
                }
            }
            // If it's not an Optional type at all
            _ => Err(ParserError::UnexpectedError),
        }
    }

    /// Total items, given how many the arguments contribute -- which depends on whether they are
    /// flattened, a decision the transaction makes and passes down.
    pub fn num_items(&self, hide_sip10_details: bool, arg_items: u8) -> Result<u8, ParserError> {
        if hide_sip10_details {
            Ok(arg_items)
        } else {
            // + contract-address, contract-name, function-name
            arg_items
                .checked_add(CONTRACT_CALL_BASE_ITEMS)
                .ok_or(ParserError::ValueOutOfRange)
        }
    }

    /// How many display items the arguments expand to when every leaf gets its own.
    ///
    /// `Err` means they cannot be flattened; see [`walk_value`] for what disqualifies them.
    fn flat_item_count(&self) -> Result<u8, ParserError> {
        let args = self.function_args()?;
        let mut walker = Walker::counting();
        walk_args(&args, &mut walker)?;
        Ok(walker.seen)
    }

    /// Renders the `display_idx`-th leaf of the flattened arguments, keyed by the path that
    /// reaches it.
    fn render_flat_arg(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        let args = self.function_args()?;
        let mut walker = Walker::seeking(display_idx);
        walk_args(&args, &mut walker)?;

        let value = walker.found.ok_or(ParserError::DisplayIdxOutOfRange)?;

        // Cut the key to the caller's buffer rather than failing. Every shipped device passes 64
        // bytes, more than MAX_KEY_PATH, so this only engages for a smaller caller (the host
        // validator walks items with 30-byte buffers). Truncating a label is a legible loss --
        // the value beside it is still shown in full -- where erroring would make the
        // transaction unsignable outright.
        let path = walker.found_path.as_bytes();
        let room = out_key.len().saturating_sub(1);
        let copied = path.len().min(room);
        out_key
            .get_mut(..copied)
            .ok_or(ParserError::UnexpectedBufferEnd)?
            .copy_from_slice(&path[..copied]);
        out_key
            .get_mut(copied..)
            .ok_or(ParserError::UnexpectedBufferEnd)?
            .iter_mut()
            .for_each(|byte| *byte = 0);

        // An un-nested first uint argument of a PoX stack-stx/delegate-stx call keeps its
        // friendlier key, exactly as it does without flattening.
        if walker.found_path.as_bytes() == b"arg0" && value.value_id() == ValueId::UInt {
            self.label_stacking_value(out_key)?;
        }

        Self::render_value(&value, out_value, page_idx)
    }

    fn get_base_items(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        if display_idx > CONTRACT_CALL_BASE_ITEMS {
            return Err(ParserError::DisplayIdxOutOfRange);
        }
        let mut writer_key = zxformat::Writer::new(out_key);
        match display_idx {
            // Contract-address
            0 => {
                writer_key
                    .write_str("Contract address")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let address = self.contract_address()?;
                check_canary!();
                zxformat::page_string(out_value, address.as_ref(), page_idx)
            }
            // Contract.name
            1 => {
                writer_key
                    .write_str("Contract name")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let name = self.contract_name()?;
                check_canary!();
                zxformat::page_string(out_value, name.name(), page_idx)
            }
            // Function-name
            2 => {
                writer_key
                    .write_str("Function name")
                    .map_err(|_| ParserError::UnexpectedBufferEnd)?;
                let name = self.function_name()?;
                check_canary!();
                zxformat::page_string(out_value, name, page_idx)
            }
            _ => Err(ParserError::DisplayIdxOutOfRange),
        }
    }

    pub fn raw_data(&self) -> &'a [u8] {
        self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::parser::TX_DEPTH_LIMIT;
    use std::prelude::v1::*;

    /// Exactly the strings `render_value` emits in place of a value it cannot show; mirrors
    /// `type_placeholder`.
    const PLACEHOLDERS: &[&str] = &[
        "is Buffer",
        "is List",
        "is Tuple",
        "is StringAscii",
        "is StringUtf8",
        "Option: Some",
        "Result: Ok",
        "Result: Err",
        "is Value",
    ];

    fn int(v: i128) -> Vec<u8> {
        let mut b = vec![0x00];
        b.extend_from_slice(&v.to_be_bytes());
        b
    }

    fn uint(v: u128) -> Vec<u8> {
        let mut b = vec![0x01];
        b.extend_from_slice(&v.to_be_bytes());
        b
    }

    fn buffer() -> Vec<u8> {
        let mut b = vec![0x02, 0, 0, 0, 3];
        b.extend_from_slice(b"abc");
        b
    }

    /// `[0x02][len: 4][bytes]` of `len` filler bytes.
    fn buffer_of(len: usize) -> Vec<u8> {
        let mut b = vec![0x02];
        b.extend_from_slice(&(len as u32).to_be_bytes());
        b.resize(b.len() + len, 0xab);
        b
    }

    fn std_principal() -> Vec<u8> {
        let mut b = vec![0x05, 26];
        b.extend_from_slice(&[0x11; 20]);
        b
    }

    fn contract_principal() -> Vec<u8> {
        let mut b = vec![0x06, 26];
        b.extend_from_slice(&[0x11; 20]);
        b.push(13);
        b.extend_from_slice(b"some-contract");
        b
    }

    /// `[0x0b][num_items: 4][values..]`
    fn list() -> Vec<u8> {
        let mut b = vec![0x0b, 0, 0, 0, 2];
        b.extend_from_slice(&uint(1));
        b.extend_from_slice(&uint(2));
        b
    }

    /// `[0x0c][num_pairs: 4][(name_len, name, value)..]` -- shaped like a PoX `pox-addr`.
    fn tuple() -> Vec<u8> {
        let mut b = vec![0x0c, 0, 0, 0, 1];
        b.push(7);
        b.extend_from_slice(b"version");
        b.extend_from_slice(&uint(1));
        b
    }

    fn string_ascii(len: usize) -> Vec<u8> {
        let mut b = vec![0x0d];
        b.extend_from_slice(&(len as u32).to_be_bytes());
        b.resize(b.len() + len, b'a');
        b
    }

    /// A string-utf8 the device fonts cannot render.
    fn string_utf8_non_ascii() -> Vec<u8> {
        let mut b = vec![0x0e, 0, 0, 0, 3];
        b.extend_from_slice("\u{20ac}".as_bytes());
        b
    }

    fn string_utf8() -> Vec<u8> {
        let mut b = vec![0x0e, 0, 0, 0, 3];
        b.extend_from_slice("abc".as_bytes());
        b
    }

    /// Wraps `inner` in a single-byte-tagged container (OptionalSome / ResponseOk / ResponseErr).
    fn wrap(id: u8, inner: Vec<u8>) -> Vec<u8> {
        let mut b = vec![id];
        b.extend_from_slice(&inner);
        b
    }

    /// One valid encoding per ValueId variant.
    fn samples() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("Int", int(-1)),
            ("UInt", uint(7)),
            ("Buffer", buffer()),
            ("BoolTrue", vec![0x03]),
            ("BoolFalse", vec![0x04]),
            ("StandardPrincipal", std_principal()),
            ("ContractPrincipal", contract_principal()),
            ("ResponseOk", wrap(0x07, uint(1))),
            ("ResponseErr", wrap(0x08, uint(1))),
            ("OptionalNone", vec![0x09]),
            ("OptionalSome", wrap(0x0a, uint(1))),
            ("List", list()),
            ("Tuple", tuple()),
            ("StringAscii", string_ascii(10)),
            ("StringUtf8", string_utf8()),
        ]
    }

    fn parse(bytes: &[u8]) -> Value<'_> {
        Value::from_bytes::<TX_DEPTH_LIMIT>(bytes)
            .expect("sample must be a valid Clarity value")
            .1
    }

    fn render(bytes: &[u8]) -> String {
        let value = parse(bytes);
        // Room for a maximal value plus the `...` an over-long string carries, on one page.
        let mut out = [0u8; MAX_VALUE_TEXT + 4];
        TransactionContractCall::render_value(&value, &mut out, 0).expect("render_value failed");
        let end = out.iter().position(|&c| c == 0).unwrap_or(out.len());
        String::from_utf8(out[..end].to_vec()).expect("rendered value must be utf8")
    }

    fn displayable(bytes: &[u8]) -> bool {
        TransactionContractCall::arg_is_fully_displayable(&parse(bytes))
    }

    /// The blind-signing gate is only sound if `arg_is_fully_displayable` returns false for
    /// *exactly* the values `render_value` degrades to a placeholder. Teaching the renderer a new
    /// type without updating the predicate would silently sign un-displayed data with no warning;
    /// the reverse would gate transactions the user can actually review.
    #[test]
    fn test_displayable_predicate_matches_renderer() {
        for (name, bytes) in samples() {
            let rendered = render(&bytes);
            let is_placeholder = PLACEHOLDERS.contains(&rendered.as_str());
            assert_eq!(
                displayable(&bytes),
                !is_placeholder,
                "{name}: predicate disagrees with renderer (rendered {rendered:?})"
            );
        }
    }

    /// `write_value_text` matches exhaustively on ValueId, so a new variant breaks the build
    /// there. This keeps the sample table above honest about covering every variant.
    #[test]
    fn test_samples_cover_every_value_id() {
        assert_eq!(samples().len(), 15);
    }

    #[test]
    fn test_placeholders_are_the_opaque_types() {
        for (name, bytes) in samples() {
            // Every sample is small and simple, so only a populated container is left without a
            // faithful rendering. Before the render budget replaced the type check, seven of the
            // fifteen were opaque.
            let opaque = matches!(name, "List" | "Tuple");
            assert_eq!(displayable(&bytes), !opaque, "{name} classified wrongly");
        }
    }

    /// An empty container hides nothing -- `[]` is the whole value -- so it must not drag the
    /// transaction into blind signing. This is the testnet false positive from the field report:
    /// `arg0` was an empty list and the gate fired on the type alone.
    #[test]
    fn test_empty_containers_are_displayable() {
        let empty_list = vec![0x0b, 0, 0, 0, 0];
        assert!(displayable(&empty_list));
        assert_eq!(render(&empty_list), "List: []");

        let empty_tuple = vec![0x0c, 0, 0, 0, 0];
        assert!(displayable(&empty_tuple));
        assert_eq!(render(&empty_tuple), "Tuple: {}");

        // A populated one still is not, until arguments are flattened into one item per leaf.
        assert!(!displayable(&list()));
        assert!(!displayable(&tuple()));
    }

    /// `Some`/`Ok`/`Err` show what they wrap. The wrapper stays in the text: approving
    /// `(some u1)` is not the same as approving `u1`, and the user has to see which one it is.
    #[test]
    fn test_wrappers_are_unwrapped() {
        assert_eq!(render(&wrap(0x0a, uint(1))), "Some(1)");
        assert_eq!(render(&wrap(0x07, uint(1))), "Ok(1)");
        assert_eq!(render(&wrap(0x08, int(-1))), "Err(-1)");
        assert_eq!(render(&wrap(0x0a, vec![0x09])), "Some(Option: None)");

        // The alexlab swap argument that forced blind signing on an ordinary swap.
        assert!(displayable(&wrap(0x0a, uint(493568))));
    }

    /// The unwrap recurses on the device stack, so it is bounded rather than following a
    /// crafted argument down as far as the value parser allows.
    #[test]
    fn test_wrapper_nesting_is_bounded() {
        let mut nested = uint(1);
        for _ in 0..MAX_WRAPPER_DEPTH {
            nested = wrap(0x0a, nested);
        }
        assert!(
            displayable(&nested),
            "{} wrappers must still render",
            MAX_WRAPPER_DEPTH
        );

        // One deeper is opaque -- gated, never unbounded recursion.
        assert!(!displayable(&wrap(0x0a, nested)));
    }

    /// Buffers render as hex, so the user sees the bytes actually being signed.
    #[test]
    fn test_buffers_render_as_hex() {
        assert!(displayable(&buffer()));
        assert_eq!(render(&buffer()), "0x616263");

        assert!(displayable(&buffer_of(MAX_BUFFER_BYTES_TO_SHOW)));

        // Past the cap the hex is more screens of noise than a user will read, so it stays
        // opaque and the transaction is gated.
        let over_cap = buffer_of(MAX_BUFFER_BYTES_TO_SHOW + 1);
        assert!(!displayable(&over_cap));
        assert_eq!(render(&over_cap), "is Buffer");
    }

    /// Long strings are paged, not silently cut short. The old 60-char cap truncated with no
    /// ellipsis -- and through an off-by-four on the length prefix, actually at 56 characters.
    #[test]
    fn test_long_strings_are_paged_not_truncated() {
        let long = string_ascii(200);
        assert!(displayable(&long));
        assert_eq!(render(&long).len(), 200);

        // Beyond the render budget it is opaque, and the gate fires. The blind-signing review
        // still shows its start -- what the previous version showed, silently cut at 56 -- and
        // now says so.
        let over = string_ascii(MAX_VALUE_TEXT + 1);
        assert!(!displayable(&over));
        let shown = render(&over);
        assert_eq!(shown.len(), MAX_VALUE_TEXT + 3);
        assert!(shown.starts_with(&"a".repeat(MAX_VALUE_TEXT)));
        assert!(shown.ends_with("..."));

        // Non-ASCII text gets no prefix: there is nothing the fonts can show.
        let content = "\u{20ac}".repeat(MAX_VALUE_TEXT / 3 + 1);
        let mut euro = vec![0x0e];
        euro.extend_from_slice(&(content.len() as u32).to_be_bytes());
        euro.extend_from_slice(content.as_bytes());
        assert_eq!(render(&euro), "is StringUtf8");
    }

    /// An empty `string-ascii` made `page_string` fail with NoData, which failed the whole parse:
    /// the transaction could not be signed at all, blind signing enabled or not.
    #[test]
    fn test_empty_string_renders() {
        let empty = string_ascii(0);
        assert!(displayable(&empty));
        assert_eq!(render(&empty), "(empty)");
    }

    /// A UTF-8 string whose bytes are ASCII renders like any other string. Anything else would
    /// be mojibake in the device fonts, which is worse than admitting it cannot be shown.
    #[test]
    fn test_utf8_strings_render_when_ascii() {
        assert!(displayable(&string_utf8()));
        assert_eq!(render(&string_utf8()), "abc");

        let mut euro = vec![0x0e, 0, 0, 0, 3];
        euro.extend_from_slice("\u{20ac}".as_bytes());
        assert!(!displayable(&euro));
        assert_eq!(render(&euro), "is StringUtf8");
    }

    /// A contract-call payload: `[address][contract-name][function-name][arg count][args]`.
    fn contract_call_payload(args: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![26]; // address version byte
        b.extend_from_slice(&[0x11; 20]);
        b.push(9);
        b.extend_from_slice(b"swap-pool");
        b.push(11);
        b.extend_from_slice(b"swap-helper");
        b.extend_from_slice(&(args.len() as u32).to_be_bytes());
        for arg in args {
            b.extend_from_slice(arg);
        }
        b
    }

    fn requires_blindsign(args: &[Vec<u8>]) -> bool {
        let bytes = contract_call_payload(args);
        let (_, call) =
            TransactionContractCallWrapper::from_bytes(&bytes).expect("payload must parse");
        call.requires_blindsign().expect("the gate must reach a decision")
    }

    /// The gate is a property of the whole transaction, so exercise it through
    /// `requires_blindsign` on a real contract-call payload rather than on values alone. These
    /// are the argument shapes reported from the field as false positives: ordinary swaps that
    /// demanded blind signing while hiding nothing.
    #[test]
    fn test_reported_false_positives_are_no_longer_gated() {
        // testnet call whose only argument was an empty list.
        assert!(!requires_blindsign(&[vec![0x0b, 0, 0, 0, 0]]));
        // alexlab swap-helper, whose last argument is `(some u493568)`.
        assert!(!requires_blindsign(&[
            std_principal(),
            uint(100000000),
            wrap(0x0a, uint(493568)),
        ]));
        // A small buffer argument, rendered as hex.
        assert!(!requires_blindsign(&[buffer()]));

        // A populated tuple is flattened into one item per leaf, so it is not gated either.
        assert!(!requires_blindsign(&[tuple()]));

        // A value the render budget cannot hold still is.
        assert!(requires_blindsign(&[string_ascii(MAX_VALUE_TEXT + 1)]));
    }

    /// Renders the flattened arguments, one `(key, value)` per display item.
    fn flattened(args: &[Vec<u8>]) -> Vec<(String, String)> {
        let bytes = contract_call_payload(args);
        let (_, call) =
            TransactionContractCallWrapper::from_bytes(&bytes).expect("payload must parse");
        let count = call.flat_items().expect("arguments must flatten");

        (0..count)
            .map(|idx| {
                let mut key = [0u8; MAX_KEY_PATH + 1];
                let mut value = [0u8; MAX_VALUE_TEXT + 1];
                call.get_contract_call_items(
                    idx + CONTRACT_CALL_BASE_ITEMS,
                    &mut key,
                    &mut value,
                    0,
                    DisplayMode {
                        hide_sip10_details: false,
                        flatten_args: true,
                    },
                )
                .expect("every counted item must render");
                (cstr(&key), cstr(&value))
            })
            .collect()
    }

    fn cstr(buf: &[u8]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf8(buf[..end].to_vec()).expect("rendered text must be utf8")
    }

    /// `[0x0c][1 pair][name][value]`
    fn tuple_of(pairs: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut b = vec![0x0c];
        b.extend_from_slice(&(pairs.len() as u32).to_be_bytes());
        for (name, value) in pairs {
            b.push(name.len() as u8);
            b.extend_from_slice(name.as_bytes());
            b.extend_from_slice(value);
        }
        b
    }

    /// `[0x0b][count][values..]`
    fn list_of(items: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![0x0b];
        b.extend_from_slice(&(items.len() as u32).to_be_bytes());
        for item in items {
            b.extend_from_slice(item);
        }
        b
    }

    /// A tuple argument becomes one display item per field, keyed by the path that reaches it.
    /// This is the bitflow swap: two tuples of contract principals, nothing else, and it used to
    /// demand blind signing on the strength of the word "Tuple".
    #[test]
    fn test_tuple_arguments_flatten_into_one_item_per_field() {
        let items = flattened(&[
            uint(10000),
            uint(2),
            vec![0x09],
            tuple_of(&[("a", contract_principal()), ("b", contract_principal())]),
            tuple_of(&[("a", contract_principal())]),
        ]);

        let keys: Vec<&str> = items.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            ["arg0", "arg1", "arg2", "arg3.a", "arg3.b", "arg4.a"]
        );
        assert_eq!(items[0].1, "10000");
        assert_eq!(items[2].1, "Option: None");
        assert!(items[3].1.ends_with(".some-contract"));
    }

    /// List entries are keyed by index, and nesting composes.
    #[test]
    fn test_lists_and_nesting_are_keyed_by_path() {
        let items = flattened(&[list_of(&[uint(1), uint(2)])]);
        let keys: Vec<&str> = items.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["arg0[0]", "arg0[1]"]);
        assert_eq!(items[1].1, "2");

        let nested = flattened(&[tuple_of(&[(
            "xs",
            list_of(&[tuple_of(&[("n", uint(7))])]),
        )])]);
        assert_eq!(nested.len(), 1);
        assert_eq!(nested[0].0, "arg0.xs[0].n");
        assert_eq!(nested[0].1, "7");
    }

    /// `Some((tuple ...))` is descended into rather than left opaque, but `Some(u1)` stays a
    /// single item -- `write_value_text` shows it in full already.
    #[test]
    fn test_wrappers_around_containers_are_descended() {
        let items = flattened(&[wrap(0x0a, tuple_of(&[("n", uint(7))]))]);
        assert_eq!(items[0].0, "arg0.some.n");
        assert_eq!(items[0].1, "7");

        let scalar = flattened(&[wrap(0x0a, uint(7))]);
        assert_eq!(scalar[0].0, "arg0");
        assert_eq!(scalar[0].1, "Some(7)");
    }

    /// An empty container is one item, not zero. Descending into it would drop the argument from
    /// the review entirely, and the user would never see that it was passed.
    #[test]
    fn test_empty_container_stays_a_single_item() {
        let items = flattened(&[list_of(&[]), uint(1)]);
        let keys: Vec<&str> = items.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["arg0", "arg1"]);
        assert_eq!(items[0].1, "List: []");
    }

    /// A path is allowed up to MAX_KEY_PATH; past that the leaf is opaque and the transaction is
    /// gated, rather than the walk running on an unbounded key buffer.
    #[test]
    fn test_key_path_budget_is_enforced() {
        let name = "a".repeat(MAX_KEY_PATH - "arg0.".len());
        let fits = tuple_of(&[(name.as_str(), uint(1))]);
        assert_eq!(flattened(&[fits])[0].0.len(), MAX_KEY_PATH);

        let longer = "a".repeat(MAX_KEY_PATH - "arg0.".len() + 1);
        assert!(requires_blindsign(&[tuple_of(&[(longer.as_str(), uint(1))])]));
    }

    /// A key too long for the device is cut to the key line. The value beside it is still shown
    /// in full -- that is what the user approves -- so this loses a label, not data.
    #[test]
    fn test_key_is_truncated_to_the_device_key_line() {
        let bytes = contract_call_payload(&[tuple_of(&[("min-amount-out", uint(7))])]);
        let (_, call) =
            TransactionContractCallWrapper::from_bytes(&bytes).expect("payload must parse");

        // A Nano key line: 17 characters and a terminator.
        let mut key = [0u8; 18];
        let mut value = [0u8; MAX_VALUE_TEXT + 1];
        call.get_contract_call_items(
            CONTRACT_CALL_BASE_ITEMS,
            &mut key,
            &mut value,
            0,
            DisplayMode {
                hide_sip10_details: false,
                flatten_args: true,
            },
        )
        .expect("item must render");

        assert_eq!(cstr(&key), "arg0.min-amount-o");
        assert_eq!(cstr(&value), "7");
    }

    /// The walk stops counting rather than following a crafted argument to an astronomical total.
    #[test]
    fn test_item_budget_is_enforced() {
        let at_budget: Vec<Vec<u8>> = (0..MAX_ARG_DISPLAY_ITEMS).map(|_| uint(1)).collect();
        assert!(!requires_blindsign(&at_budget));

        // Past the budget, a container cannot be flattened and has no other rendering.
        let over_budget: Vec<Vec<u8>> = (0..MAX_ARG_DISPLAY_ITEMS as u16 + 1)
            .map(|_| uint(1))
            .collect();
        assert!(requires_blindsign(&[list_of(&over_budget)]));
    }

    /// Exceeding the leaf budget with bare scalars is NOT gated: the one-item-per-argument
    /// layout shows each of them in full, exactly as it did before flattening existed. Gating
    /// here would have made a transaction that reviewed normally on the previous version demand
    /// blind signing on this one.
    #[test]
    fn test_scalars_past_the_leaf_budget_fall_back_without_gating() {
        let many_scalars: Vec<Vec<u8>> = (0..MAX_ARG_DISPLAY_ITEMS as u16 + 1)
            .map(|_| uint(1))
            .collect();
        let bytes = contract_call_payload(&many_scalars);
        let (_, call) =
            TransactionContractCallWrapper::from_bytes(&bytes).expect("payload must parse");

        assert!(call.flat_items().is_none(), "over the leaf budget, so not flattened");
        assert!(call.single_items_render(), "but every argument renders on its own");
        assert!(!call.requires_blindsign().expect("gate must decide"));
    }

    /// The gate is fail-closed. Every way the walk can end badly -- a value with no rendering, a
    /// key path that outgrew the budget, nesting past the depth limit, more leaves than the
    /// budget allows -- lands in the same place: `flat_items` is empty, and an empty `flat_items`
    /// is exactly what `requires_blindsign` reports. Nothing falls through to being displayed.
    #[test]
    fn test_every_walk_failure_gates() {
        let mut too_deep = uint(1);
        for _ in 0..TX_DEPTH_LIMIT {
            too_deep = list_of(&[too_deep]);
        }

        let cases: Vec<(&str, Vec<Vec<u8>>)> = vec![
            ("non-ascii string-utf8", vec![string_utf8_non_ascii()]),
            ("oversized buffer", vec![buffer_of(MAX_BUFFER_BYTES_TO_SHOW + 1)]),
            ("string past the render budget", vec![string_ascii(MAX_VALUE_TEXT + 1)]),
            (
                "key path past the budget",
                vec![tuple_of(&[("a".repeat(MAX_KEY_PATH).as_str(), uint(1))])],
            ),
            ("nesting past the depth limit", vec![too_deep]),
            (
                "more leaves than the budget",
                vec![list_of(
                    &(0..MAX_ARG_DISPLAY_ITEMS as u16 + 1)
                        .map(|_| uint(1))
                        .collect::<Vec<_>>(),
                )],
            ),
            // An opaque leaf buried inside a container gates the whole call, not just itself:
            // flattening is all or nothing, so a partial view is never shown.
            (
                "opaque leaf inside a tuple",
                vec![tuple_of(&[("ok", uint(1)), ("bad", string_utf8_non_ascii())])],
            ),
        ];

        for (name, args) in cases {
            let bytes = contract_call_payload(&args);
            let (_, call) =
                TransactionContractCallWrapper::from_bytes(&bytes).expect("payload must parse");
            assert!(call.flat_items().is_none(), "{}: should not flatten", name);
            assert!(
                !call.single_items_render(),
                "{}: the fallback must not claim to render it either",
                name
            );
            assert!(
                call.requires_blindsign().expect("gate must decide"),
                "{}: should be gated",
                name
            );
        }
    }

    /// The converse, and the reason the fallback rendering is never a silent one: whenever the
    /// arguments *do* flatten, the item count is sound, so no path reports a short count and
    /// quietly drops the rest.
    #[test]
    fn test_flattening_implies_a_sound_item_count() {
        let args = vec![
            uint(1),
            tuple_of(&[("a", contract_principal()), ("b", buffer())]),
            list_of(&[uint(1), uint(2), uint(3)]),
        ];
        let bytes = contract_call_payload(&args);
        let (_, call) =
            TransactionContractCallWrapper::from_bytes(&bytes).expect("payload must parse");

        let leaves = call.flat_items().expect("arguments must flatten");
        assert!(!call.requires_blindsign().expect("gate must decide"));

        let mode = DisplayMode {
            hide_sip10_details: false,
            flatten_args: true,
        };
        assert_eq!(
            call.num_items(mode).expect("count must be sound"),
            leaves + CONTRACT_CALL_BASE_ITEMS
        );
        // ...and every counted item renders.
        assert_eq!(flattened(&args).len(), leaves as usize);
    }

    /// Nesting past the parser's depth limit is gated, not walked.
    #[test]
    fn test_depth_limit_is_enforced() {
        let mut nested = uint(1);
        for _ in 0..TX_DEPTH_LIMIT {
            nested = list_of(&[nested]);
        }
        assert!(requires_blindsign(&[nested]));
    }

    /// The SIP-10 memo path unwraps `Some(..)` and renders the inner value bare, where the
    /// generic argument path keeps the wrapper. Past that unwrap both go through
    /// `write_value_text`, so they agree on what is displayable.
    #[test]
    fn test_memo_predicate_unwraps_optional_some() {
        let some_uint = wrap(0x0a, uint(1));
        assert!(TransactionContractCall::memo_is_fully_displayable(&parse(&some_uint)));
        assert!(TransactionContractCall::arg_is_fully_displayable(&parse(&some_uint)));

        // SIP-10 memos are `(optional (buff 34))`. Rendering the buffer as hex takes every
        // sBTC transfer carrying one back out of blind signing.
        let some_buff = wrap(0x0a, buffer());
        assert!(TransactionContractCall::memo_is_fully_displayable(&parse(&some_buff)));

        let some_big_buff = wrap(0x0a, buffer_of(MAX_BUFFER_BYTES_TO_SHOW + 1));
        assert!(!TransactionContractCall::memo_is_fully_displayable(&parse(&some_big_buff)));

        let none = vec![0x09u8];
        assert!(TransactionContractCall::memo_is_fully_displayable(&parse(&none)));
    }
}
