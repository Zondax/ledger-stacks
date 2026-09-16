use arrayvec::ArrayVec;
use nom::number::complete::be_u32;

use crate::{bolos::c_zemu_log_stack, check_canary, parser::TransactionPostCondition};

use super::post_conditions::AGGREGATED_NFT_ITEMS;
use super::{ParserError, NUM_SUPPORTED_POST_CONDITIONS};

/// Upper bound on the number of *distinct* aggregatable NFT groups a transaction may
/// carry. Every such group renders at least 3 display items (see
/// `TransactionPostCondition::num_items`) and the device's display-item counter is a
/// `u8`, so at most `255 / 3 = 85` of them can ever be shown: sized above that, this
/// table is never the binding constraint — the display ceiling always bites first.
/// (96 rather than 85 because `arrayvec` 0.5 only implements `Array` for select sizes.)
const MAX_NFT_GROUPS: usize = 96;

/// NFT grouping key `(principal, asset, code)`; see `TransactionPostCondition::nft_group_key`.
type NftKey<'a> = (&'a [u8], &'a [u8], u8);

/// Offsets, into the post-condition block, of the first condition of each distinct
/// aggregatable NFT group, in first-occurrence order.
type NftGroups = ArrayVec<[u32; MAX_NFT_GROUPS]>;

/// Walks a serialized post-condition block, yielding `(offset within the block, raw
/// condition bytes)` for each condition. Conditions are variable-length, so this is the
/// only way to address them: nothing is stored per condition (see [`PostConditions`]).
struct Conditions<'a> {
    data: &'a [u8],
    rest: &'a [u8],
    left: usize,
}

impl<'a> Conditions<'a> {
    fn new(data: &'a [u8], num_conditions: usize) -> Self {
        Self {
            data,
            rest: data,
            left: num_conditions,
        }
    }
}

impl<'a> Iterator for Conditions<'a> {
    type Item = (u32, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        let offset = (self.data.len() - self.rest.len()) as u32;
        // `PostConditions::from_bytes` already walked the whole block, so this re-parse
        // cannot fail; end the walk rather than panic should that ever stop holding.
        let (rest, item) = TransactionPostCondition::read_as_bytes(self.rest).ok()?;
        self.rest = rest;
        self.left -= 1;
        Some((offset, item))
    }
}

/// Parse a serialized condition. `bytes` may run past its end — the parser takes only
/// what the condition itself declares.
fn parse_condition(bytes: &[u8]) -> Result<TransactionPostCondition<'_>, ParserError> {
    TransactionPostCondition::from_bytes(bytes)
        .map(|(_, c)| c)
        .map_err(|_| ParserError::PostConditionFailed)
}

/// The NFT grouping key of a serialized condition, or None for anything that is not
/// aggregatable (STX, fungible, non-`MaySend` NFT).
fn nft_key(bytes: &[u8]) -> Option<NftKey<'_>> {
    parse_condition(bytes).ok()?.nft_group_key()
}

/// The NFT grouping key of the condition starting at `offset` in the block.
fn nft_key_at(data: &[u8], offset: u32) -> Option<NftKey<'_>> {
    nft_key(data.get(offset as usize..)?)
}

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
}

#[repr(C)]
#[derive(Clone, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub struct PostConditions<'a> {
    /// The serialized post-conditions, back to back, with the leading `be_u32` count
    /// already consumed. Conditions are re-parsed on demand (`Conditions`) rather than
    /// stored one slice each, so `ParsedObj` — and with it the fixed C-side parser
    /// buffer — does not grow with the number of post-conditions in a transaction.
    data: &'a [u8],
    /// First occurrence of each distinct aggregatable NFT group. A condition whose
    /// offset appears here opens a display unit; every later condition sharing its key
    /// is folded into that unit instead of being displayed again.
    groups: NftGroups,
    // The number of items to display to the user
    num_items: u8,
    // The number of post_conditions in our list
    num_conditions: usize,
}

impl<'a> PostConditions<'a> {
    #[inline(never)]
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self, ParserError> {
        let (raw, len) = be_u32::<_, ParserError>(bytes)?;
        let num_conditions = len as usize;

        // Validate length
        if num_conditions > NUM_SUPPORTED_POST_CONDITIONS {
            return Err(nom::Err::Error(ParserError::ValueOutOfRange));
        }

        // Walk the block once to validate every condition and find where it ends.
        let mut current_input = raw;
        for _ in 0..num_conditions {
            let (remaining, _) = TransactionPostCondition::read_as_bytes(current_input)?;
            current_input = remaining;
        }
        let data = &raw[..raw.len() - current_input.len()];

        let (groups, num_items) = Self::scan(data, num_conditions).map_err(nom::Err::Error)?;
        check_canary!();

        Ok((
            current_input,
            Self {
                data,
                groups,
                num_items,
                num_conditions,
            },
        ))
    }

    /// How many conditions in the block share `key`.
    fn group_count(data: &[u8], num_conditions: usize, key: NftKey) -> u32 {
        Conditions::new(data, num_conditions)
            .filter(|&(_, bytes)| nft_key(bytes) == Some(key))
            .count() as u32
    }

    /// Single pass over the block that both collects the aggregatable NFT groups and
    /// totals the display items. Runs once, at parse time.
    ///
    /// Grouping is global rather than per run: an NFT condition opens a display unit only
    /// at the FIRST offset where its key appears, and later occurrences anywhere in the
    /// block contribute nothing. That keeps the display correct for interleaved groups
    /// (A,B,A,B…) and collapses transactions with many near-duplicate post-conditions to
    /// a handful of screens.
    fn scan(data: &[u8], num_conditions: usize) -> Result<(NftGroups, u8), ParserError> {
        let mut groups = NftGroups::new();
        let mut num_items: u8 = 0;

        for (offset, bytes) in Conditions::new(data, num_conditions) {
            let condition = parse_condition(bytes)?;
            let items = match condition.nft_group_key() {
                // Not aggregatable: always its own display unit.
                None => condition.num_items(),
                Some(key) => {
                    // A key already opened by an earlier condition: nothing to display.
                    if groups.iter().any(|&o| nft_key_at(data, o) == Some(key)) {
                        continue;
                    }
                    groups
                        .try_push(offset)
                        .map_err(|_| ParserError::ValueOutOfRange)?;
                    if Self::group_count(data, num_conditions, key) >= 2 {
                        AGGREGATED_NFT_ITEMS
                    } else {
                        condition.num_items()
                    }
                }
            };
            // Saturate rather than wrap: `Transaction::num_items` rejects the transaction
            // when the total overflows, so conditions can never be signed undisplayed.
            num_items = num_items.saturating_add(items);
        }

        Ok((groups, num_items))
    }

    /// The display unit opened by the condition at `offset`, or None if that condition is
    /// a later occurrence of an already-opened NFT group. Returns
    /// `(display_item_count, group_size)`.
    fn display_unit(&self, offset: u32, bytes: &'a [u8]) -> Result<Option<(u8, u32)>, ParserError> {
        let condition = parse_condition(bytes)?;
        let key = match condition.nft_group_key() {
            None => return Ok(Some((condition.num_items(), 1))),
            Some(key) => key,
        };
        if !self.groups.contains(&offset) {
            return Ok(None); // folded into an earlier occurrence of the same group
        }
        let count = Self::group_count(self.data, self.num_conditions, key);
        let items = if count >= 2 {
            AGGREGATED_NFT_ITEMS
        } else {
            condition.num_items()
        };
        Ok(Some((items, count)))
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
        // post-conditions block, then walk the conditions (each display unit contributing
        // `items` slots) to find which one owns that offset and which of its sub-items to
        // render. This is derived entirely from `display_idx`, so it is correct for any
        // number of post-conditions and re-entrant across paging calls.
        let pc_start = num_items
            .checked_sub(self.num_items)
            .ok_or(ParserError::DisplayIdxOutOfRange)?;
        let mut local = display_idx
            .checked_sub(pc_start)
            .ok_or(ParserError::DisplayIdxOutOfRange)?;

        for (offset, bytes) in Conditions::new(self.data, self.num_conditions) {
            let (items, count) = match self.display_unit(offset, bytes)? {
                Some(unit) => unit,
                None => continue, // later occurrence of an already-shown NFT group
            };
            if local < items {
                let condition = parse_condition(bytes)?;
                return if count >= 2 {
                    condition.get_aggregated_nft_items(local, out_key, out_value, page_idx, count)
                } else {
                    condition.get_items(local, out_key, out_value, page_idx)
                };
            }
            local -= items;
        }

        Err(ParserError::DisplayIdxOutOfRange)
    }

    /// Returns the first post-condition. Used to decide whether SIP-10 transfer details
    /// should be hidden (see `Transaction::should_hide_sip10_details`).
    pub fn first_post_condition(&self) -> Result<TransactionPostCondition<'a>, ParserError> {
        if self.num_conditions == 0 {
            return Err(ParserError::ValueOutOfRange);
        }
        parse_condition(self.data)
    }

    pub fn num_items(&self) -> u8 {
        self.num_items
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::prelude::v1::*;

    // Serialize a post-condition block the way a transaction carries it: be_u32 count
    // followed by the conditions back to back.
    fn block(conditions: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = (conditions.len() as u32).to_be_bytes().to_vec();
        for c in conditions {
            bytes.extend_from_slice(c);
        }
        bytes
    }

    fn num_items(conditions: &[Vec<u8>]) -> u8 {
        let bytes = block(conditions);
        PostConditions::from_bytes(&bytes).unwrap().1.num_items()
    }

    // Build an NFT post-condition: type(2) | standard-principal | asset-info | value | code.
    // `value_byte` is a 1-byte clarity value (bool); the group key excludes it.
    fn nft_cond(value_byte: u8, code: u8) -> Vec<u8> {
        let mut v = vec![2u8, 2, 1];
        v.extend_from_slice(&[1u8; 20]); // principal key hash
        v.push(1); // asset issuer address version
        v.extend_from_slice(&[1u8; 20]); // asset issuer key hash
        v.push(13);
        v.extend_from_slice(b"contract-name");
        v.push(11);
        v.extend_from_slice(b"hello-asset");
        v.push(value_byte); // clarity value (bool, 1 byte)
        v.push(code);
        v
    }

    // Fungible post-condition (always 4 display items, never aggregated).
    fn ft_cond() -> Vec<u8> {
        let mut v = vec![1u8, 2, 1];
        v.extend_from_slice(&[0x11; 20]); // principal key hash
        v.push(1);
        v.extend_from_slice(&[0xBB; 20]); // asset issuer key hash
        v.push(4);
        v.extend_from_slice(b"pool"); // contract-name
        v.push(3);
        v.extend_from_slice(b"tok"); // asset-name
        v.push(0x01); // FungibleConditionCode::SentEq
        v.extend_from_slice(&[0u8; 8]); // amount
        v
    }

    #[test]
    fn test_many_distinct_items_saturate_not_wrap() {
        // 70 FT conditions => 280 display items. num_items must SATURATE at 255, not
        // wrap to a small value (which would let conditions be signed without display).
        // The transaction-level checked_add(base+payload) then rejects (see num_items()).
        let owned: Vec<Vec<u8>> = (0..70).map(|_| ft_cond()).collect();
        assert_eq!(num_items(&owned), u8::MAX);
    }

    #[test]
    fn test_identical_nfts_aggregate() {
        // Two NFT conditions with same principal/asset/code, differing only in value:
        // collapse to a single aggregated unit (AGGREGATED_NFT_ITEMS).
        let owned = vec![nft_cond(0x03, 0x12), nft_cond(0x04, 0x12)];
        assert_eq!(num_items(&owned), AGGREGATED_NFT_ITEMS);
    }

    #[test]
    fn test_different_code_nfts_not_aggregated() {
        // Different condition code => different key => rendered individually (3 + 3).
        let owned = vec![nft_cond(0x03, 0x12), nft_cond(0x03, 0x10)]; // MaySend, Sent
        assert_eq!(num_items(&owned), 6);
    }

    #[test]
    fn test_sent_nfts_not_aggregated() {
        // Only MaySend aggregates. Two identical Sent (0x10) conditions are guarantees
        // about specific tokens, so they render individually (3 + 3), not as a count.
        let owned = vec![nft_cond(0x03, 0x10), nft_cond(0x04, 0x10)];
        assert_eq!(num_items(&owned), 6);

        // The same two as MaySend *do* aggregate, for contrast.
        let owned2 = vec![nft_cond(0x03, 0x12), nft_cond(0x04, 0x12)];
        assert_eq!(num_items(&owned2), AGGREGATED_NFT_ITEMS);
    }

    // NFT condition with a chosen principal hash, asset name, code and 1-byte value,
    // so we can build distinct groups.
    fn nft_group_cond(principal: u8, asset: &[u8], code: u8, value_byte: u8) -> Vec<u8> {
        let mut v = vec![2u8, 2, 1];
        v.extend_from_slice(&[principal; 20]); // principal key hash
        v.push(1);
        v.extend_from_slice(&[principal; 20]); // asset issuer key hash
        v.push(4);
        v.extend_from_slice(b"pool");
        v.push(asset.len() as u8);
        v.extend_from_slice(asset);
        v.push(value_byte);
        v.push(code);
        v
    }

    fn read(pcs: &mut PostConditions, idx: u8, total: u8) -> std::string::String {
        let mut key = [0u8; 64];
        let mut val = [0u8; 64];
        pcs.get_items(idx, &mut key, &mut val, 0, total).unwrap();
        std::string::String::from_utf8_lossy(&val)
            .trim_end_matches('\0')
            .to_string()
    }

    #[test]
    fn test_two_distinct_groups_aggregate_independently() {
        // Group A: 13 MaySend NFTs (principal 0xAA, asset "asset-a"), varying value.
        // Group B: 20 MaySend NFTs (principal 0xCC, asset "asset-b"), varying value.
        // Each distinct (principal, asset) MaySend run collapses to its own 4-item block.
        let mut owned: Vec<Vec<u8>> = Vec::new();
        for i in 0..13u8 {
            owned.push(nft_group_cond(0xAA, b"asset-a", 0x12, 0x03 + (i & 1)));
        }
        for i in 0..20u8 {
            owned.push(nft_group_cond(0xCC, b"asset-b", 0x12, 0x03 + (i & 1)));
        }

        let bytes = block(&owned);
        let (_, mut pcs) = PostConditions::from_bytes(&bytes).unwrap();

        // Two aggregated groups => 4 + 4 = 8 display items, and the per-group counts are
        // rendered as 13 and 20.
        let total = pcs.num_items();
        assert_eq!(total, AGGREGATED_NFT_ITEMS * 2);

        // Count items are the 4th item of each group (idx 3 and idx 7).
        assert_eq!(read(&mut pcs, 3, total), "13");
        assert_eq!(read(&mut pcs, 7, total), "20");
    }

    #[test]
    fn test_interleaved_groups_aggregate_globally() {
        // Interleaved A,B,A,B,A: grouping is global, so A collapses (count 3) and B
        // collapses (count 2) regardless of ordering. Display order follows first
        // occurrence: A (idx 0) then B (idx 1) => 4 + 4 = 8 items.
        let order = [
            (0xAAu8, &b"asset-a"[..], 0x12u8),
            (0xCC, &b"asset-b"[..], 0x12),
            (0xAA, &b"asset-a"[..], 0x12),
            (0xCC, &b"asset-b"[..], 0x12),
            (0xAA, &b"asset-a"[..], 0x12),
        ];
        let owned: Vec<Vec<u8>> = order
            .iter()
            .enumerate()
            .map(|(i, (p, a, c))| nft_group_cond(*p, a, *c, 0x03 + (i as u8 & 1)))
            .collect();

        let bytes = block(&owned);
        let (_, mut pcs) = PostConditions::from_bytes(&bytes).unwrap();

        let total = pcs.num_items();
        assert_eq!(total, AGGREGATED_NFT_ITEMS * 2);

        assert_eq!(read(&mut pcs, 3, total), "3"); // group A: 3 occurrences
        assert_eq!(read(&mut pcs, 7, total), "2"); // group B: 2 occurrences
    }

    #[test]
    fn test_beyond_old_cap_is_accepted() {
        // Regression for issue #238: a 145-bin DLMM withdrawal carries 158 post-conditions
        // (155 NFT MaySend + 2 FT + 1 STX). The old 128-slice cap rejected it at parse.
        // Nothing is stored per condition now, so it parses and still shows one aggregated
        // NFT block (4) plus the two fungible conditions (4 each).
        let mut owned: Vec<Vec<u8>> = (0..155u32)
            .map(|i| nft_group_cond(0xAA, b"asset-a", 0x12, 0x03 + (i as u8 & 1)))
            .collect();
        owned.push(ft_cond());
        owned.push(ft_cond());

        let bytes = block(&owned);
        let (_, mut pcs) = PostConditions::from_bytes(&bytes).unwrap();
        assert_eq!(pcs.num_conditions(), 157);

        let total = pcs.num_items();
        assert_eq!(total, AGGREGATED_NFT_ITEMS + 4 + 4);
        assert_eq!(read(&mut pcs, 3, total), "155");
    }

    /// The cap is inclusive: exactly NUM_SUPPORTED_POST_CONDITIONS conditions parse. Pinned so
    /// the boundary is tested from both sides, not only the rejecting one below.
    #[test]
    fn test_at_cap_is_accepted() {
        let owned: Vec<Vec<u8>> = (0..NUM_SUPPORTED_POST_CONDITIONS)
            .map(|_| ft_cond())
            .collect();
        let bytes = block(&owned);
        let (rem, conditions) = PostConditions::from_bytes(&bytes).expect("at the cap must parse");
        assert!(rem.is_empty());
        assert_eq!(conditions.num_conditions(), NUM_SUPPORTED_POST_CONDITIONS);
        // 512 * 4 display items is far past the u8 index; the count saturates rather than
        // wrapping, and it is `Transaction::num_items` that refuses the transaction.
        assert_eq!(conditions.num_items(), u8::MAX);
    }

    // A MaySend NFT condition in its own aggregation group: the asset issuer hash is what sets
    // the group apart, since the key is (principal, asset-info, code).
    fn maysend_nft_in_group(group: u8) -> Vec<u8> {
        let mut v = vec![2u8, 2, 1];
        v.extend_from_slice(&[1u8; 20]); // principal key hash
        v.push(1); // asset issuer address version
        v.extend_from_slice(&[group; 20]); // asset issuer key hash -- the distinguishing part
        v.push(13);
        v.extend_from_slice(b"contract-name");
        v.push(11);
        v.extend_from_slice(b"hello-asset");
        v.push(3); // clarity value: bool true
        v.push(0x12); // NonfungibleConditionCode::MaySend
        v
    }

    /// The group-opener table holds MAX_NFT_GROUPS entries. Exactly that many distinct MaySend
    /// groups parse; one more fails at parse with ValueOutOfRange. In practice the display
    /// ceiling trips first (86 singleton groups are already 258 items), so this only pins that
    /// the table bound is a clean rejection rather than a silent truncation.
    #[test]
    fn test_nft_group_table_bound() {
        let at_bound: Vec<Vec<u8>> = (0..MAX_NFT_GROUPS as u8)
            .map(maysend_nft_in_group)
            .collect();
        let bytes = block(&at_bound);
        let (_, conditions) =
            PostConditions::from_bytes(&bytes).expect("MAX_NFT_GROUPS distinct groups must parse");
        assert_eq!(conditions.num_conditions(), MAX_NFT_GROUPS);

        let over: Vec<Vec<u8>> = (0..MAX_NFT_GROUPS as u8 + 1)
            .map(maysend_nft_in_group)
            .collect();
        let bytes = block(&over);
        assert!(matches!(
            PostConditions::from_bytes(&bytes),
            Err(nom::Err::Error(ParserError::ValueOutOfRange))
        ));
    }

    #[test]
    fn test_above_cap_is_rejected() {
        // The cap is a time bound now, not a memory one, but it still rejects at parse.
        let owned: Vec<Vec<u8>> = (0..NUM_SUPPORTED_POST_CONDITIONS + 1)
            .map(|_| ft_cond())
            .collect();
        let bytes = block(&owned);
        assert!(PostConditions::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_truncated_block_is_rejected() {
        // A declared count larger than the bytes actually present must fail at parse
        // rather than silently yielding fewer conditions.
        let owned = vec![ft_cond(), ft_cond()];
        let mut bytes = block(&owned);
        bytes.truncate(bytes.len() - 1);
        assert!(PostConditions::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_trailing_bytes_are_left_for_the_caller() {
        // `from_bytes` must consume exactly the declared conditions and hand the rest
        // back: the payload follows the post-condition block in a transaction.
        let owned = vec![ft_cond(), nft_cond(0x03, 0x12)];
        let mut bytes = block(&owned);
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let (rem, pcs) = PostConditions::from_bytes(&bytes).unwrap();
        assert_eq!(rem, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(pcs.num_conditions(), 2);
    }

    #[test]
    fn test_every_display_index_is_reachable() {
        // Walking 0..num_items must never skip or repeat a slot, whatever the mix of
        // aggregated groups, singleton NFTs and fungible conditions.
        let mut owned: Vec<Vec<u8>> = vec![ft_cond()];
        owned.extend((0..7u8).map(|i| nft_group_cond(0xAA, b"asset-a", 0x12, 0x03 + (i & 1))));
        owned.push(nft_group_cond(0xBB, b"solo", 0x12, 0x03)); // singleton => 3 items
        owned.extend((0..4u8).map(|i| nft_group_cond(0xCC, b"asset-b", 0x12, 0x03 + (i & 1))));
        owned.push(ft_cond());

        let bytes = block(&owned);
        let (_, mut pcs) = PostConditions::from_bytes(&bytes).unwrap();
        let total = pcs.num_items();
        assert_eq!(
            total,
            4 + AGGREGATED_NFT_ITEMS + 3 + AGGREGATED_NFT_ITEMS + 4
        );

        for idx in 0..total {
            let mut key = [0u8; 64];
            let mut val = [0u8; 64];
            pcs.get_items(idx, &mut key, &mut val, 0, total).unwrap();
        }
        // One past the last item is out of range, not a wrap onto the first.
        let mut key = [0u8; 64];
        let mut val = [0u8; 64];
        assert!(pcs.get_items(total, &mut key, &mut val, 0, total).is_err());
    }

    /// Straightforward O(n^2) reference for the aggregation rules, written against the
    /// individual conditions rather than the block walk, so a bug in the offset
    /// bookkeeping shows up as a disagreement.
    fn reference_num_items(conditions: &[Vec<u8>]) -> u8 {
        let key_of = |c: &Vec<u8>| nft_key(c).map(|(p, a, code)| (p.to_vec(), a.to_vec(), code));
        let mut total: u8 = 0;
        for (i, c) in conditions.iter().enumerate() {
            let items = match key_of(c) {
                None => parse_condition(c).unwrap().num_items(),
                Some(key) => {
                    if conditions[..i]
                        .iter()
                        .any(|o| key_of(o) == Some(key.clone()))
                    {
                        continue;
                    }
                    let count = conditions
                        .iter()
                        .filter(|o| key_of(o) == Some(key.clone()))
                        .count();
                    if count >= 2 {
                        AGGREGATED_NFT_ITEMS
                    } else {
                        parse_condition(c).unwrap().num_items()
                    }
                }
            };
            total = total.saturating_add(items);
        }
        total
    }

    #[test]
    fn test_matches_reference_on_random_mixes() {
        // Deterministic LCG: random mixes of aggregatable NFTs (several groups), Sent
        // NFTs, and fungible conditions, in random order. The block walk must agree with
        // the reference on the item total, and every display index must resolve.
        let mut seed: u32 = 0x1234_5678;
        let mut next = move || {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (seed >> 16) as usize
        };

        for _ in 0..64 {
            let n = 1 + next() % 40;
            let owned: Vec<Vec<u8>> = (0..n)
                .map(|i| match next() % 4 {
                    0 => ft_cond(),
                    1 => nft_group_cond(0xAA, b"asset-a", 0x10, 0x03 + (i as u8 & 1)), // Sent
                    2 => nft_group_cond(0xBB, b"asset-b", 0x12, 0x03 + (i as u8 & 1)),
                    _ => nft_group_cond(0xCC, b"asset-c", 0x12, 0x03 + (i as u8 & 1)),
                })
                .collect();

            let bytes = block(&owned);
            let (_, mut pcs) = PostConditions::from_bytes(&bytes).unwrap();
            let total = pcs.num_items();
            assert_eq!(total, reference_num_items(&owned), "n = {}", n);

            for idx in 0..total {
                let mut key = [0u8; 64];
                let mut val = [0u8; 64];
                pcs.get_items(idx, &mut key, &mut val, 0, total)
                    .unwrap_or_else(|e| panic!("idx {} of {} failed: {:?}", idx, total, e));
            }
        }
    }

    #[test]
    fn test_empty_post_conditions() {
        let bytes = block(&[]);
        let (_, pcs) = PostConditions::from_bytes(&bytes).unwrap();
        assert_eq!(pcs.num_conditions(), 0);
        assert_eq!(pcs.num_items(), 0);
        assert!(pcs.first_post_condition().is_err());
    }
}
