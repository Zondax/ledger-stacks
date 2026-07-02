use arrayvec::ArrayVec;
use nom::number::complete::be_u32;

use crate::{bolos::c_zemu_log_stack, check_canary, parser::TransactionPostCondition};

use super::post_conditions::AGGREGATED_NFT_ITEMS;
use super::{ParserError, NUM_SUPPORTED_POST_CONDITIONS};

/// NFT grouping key (principal, asset, code) for condition `idx`, or None for STX/FT.
fn nft_key_at<'a>(conditions: &'a [&'a [u8]], idx: usize) -> Option<(&'a [u8], &'a [u8], u8)> {
    TransactionPostCondition::from_bytes(conditions[idx])
        .ok()
        .and_then(|(_, c)| c.nft_group_key())
}

/// Classify condition `idx` as a *display unit*. Grouping is global (not just consecutive
/// runs): an NFT condition is a display unit only at the FIRST index where its key
/// appears; later occurrences anywhere in the list contribute nothing. This makes the
/// display robust against interleaved groups (A,B,A,B…).
///
/// Returns None if `idx` is a later occurrence of an already-seen NFT key. Otherwise
/// returns (display_item_count, group_size): for an NFT key seen `n >= 2` times the unit
/// is the aggregated block; everything else renders individually.
fn display_unit(conditions: &[&[u8]], idx: usize) -> Option<(u8, u32)> {
    let (_, condition) = TransactionPostCondition::from_bytes(conditions[idx]).ok()?;
    match condition.nft_group_key() {
        None => Some((condition.num_items(), 1)),
        Some(key) => {
            // Later occurrence of an earlier key -> not a display unit.
            if (0..idx).any(|j| nft_key_at(conditions, j) == Some(key)) {
                return None;
            }
            // First occurrence: count every condition sharing this key.
            let count = (0..conditions.len())
                .filter(|&j| nft_key_at(conditions, j) == Some(key))
                .count() as u32;
            let items = if count >= 2 {
                AGGREGATED_NFT_ITEMS
            } else {
                condition.num_items()
            };
            Some((items, count))
        }
    }
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
        // Sum display units. Runs of NFT conditions sharing (principal, asset, code) are
        // collapsed into one aggregated unit (globally, regardless of ordering) so a
        // transaction with many near-duplicate post-conditions stays well under the
        // device's display-item ceiling.
        let mut total: u8 = 0;
        for i in 0..conditions.len() {
            if let Some((items, _)) = display_unit(conditions, i) {
                total = total.saturating_add(items);
            }
        }
        total
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

        let conditions = self.conditions.as_ref();
        for i in 0..conditions.len() {
            let (items, count) = match display_unit(conditions, i) {
                Some(unit) => unit,
                None => continue, // later occurrence of an already-shown NFT group
            };
            if local < items {
                let (_, condition) = TransactionPostCondition::from_bytes(conditions[i])
                    .map_err(|_| ParserError::PostConditionFailed)?;
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

#[cfg(test)]
mod test {
    use super::*;
    use std::prelude::v1::*;

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
        // 70 FT conditions => 280 display items. get_num_items must SATURATE at 255, not
        // wrap to a small value (which would let conditions be signed without display).
        // The transaction-level checked_add(base+payload) then rejects (see num_items()).
        let owned: Vec<Vec<u8>> = (0..70).map(|_| ft_cond()).collect();
        let conds: Vec<&[u8]> = owned.iter().map(|c| c.as_slice()).collect();
        assert_eq!(PostConditions::get_num_items(&conds), u8::MAX);
    }

    #[test]
    fn test_identical_nfts_aggregate() {
        // Two NFT conditions with same principal/asset/code, differing only in value:
        // collapse to a single aggregated unit (AGGREGATED_NFT_ITEMS).
        let a = nft_cond(0x03, 0x12);
        let b = nft_cond(0x04, 0x12);
        let conds = [a.as_slice(), b.as_slice()];
        assert_eq!(PostConditions::get_num_items(&conds), AGGREGATED_NFT_ITEMS);
    }

    #[test]
    fn test_different_code_nfts_not_aggregated() {
        // Different condition code => different key => rendered individually (3 + 3).
        let a = nft_cond(0x03, 0x12); // MaySend
        let b = nft_cond(0x03, 0x10); // Sent
        let conds = [a.as_slice(), b.as_slice()];
        assert_eq!(PostConditions::get_num_items(&conds), 6);
    }

    #[test]
    fn test_sent_nfts_not_aggregated() {
        // Only MaySend aggregates. Two identical Sent (0x10) conditions are guarantees
        // about specific tokens, so they render individually (3 + 3), not as a count.
        let a = nft_cond(0x03, 0x10); // Sent
        let b = nft_cond(0x04, 0x10); // Sent (different value)
        let conds = [a.as_slice(), b.as_slice()];
        assert_eq!(PostConditions::get_num_items(&conds), 6);

        // The same two as MaySend *do* aggregate, for contrast.
        let c = nft_cond(0x03, 0x12);
        let d = nft_cond(0x04, 0x12);
        let conds2 = [c.as_slice(), d.as_slice()];
        assert_eq!(PostConditions::get_num_items(&conds2), AGGREGATED_NFT_ITEMS);
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

        // Build the serialized post-condition section: be_u32 count + conditions.
        let mut bytes = (owned.len() as u32).to_be_bytes().to_vec();
        for c in &owned {
            bytes.extend_from_slice(c);
        }
        let (_, pcs) = PostConditions::from_bytes(&bytes).unwrap();

        // Two aggregated groups => 4 + 4 = 8 display items, and the per-group counts are
        // rendered as 13 and 20.
        let total = pcs.num_items();
        assert_eq!(total, AGGREGATED_NFT_ITEMS * 2);

        let mut pcs_mut = pcs;
        let read = |pcs: &mut PostConditions, idx: u8| -> std::string::String {
            let mut key = [0u8; 64];
            let mut val = [0u8; 64];
            pcs.get_items(idx, &mut key, &mut val, 0, total).unwrap();
            let v = std::string::String::from_utf8_lossy(&val);
            v.trim_end_matches('\0').to_string()
        };
        // Count items are the 4th item of each group (idx 3 and idx 7).
        assert_eq!(read(&mut pcs_mut, 3), "13");
        assert_eq!(read(&mut pcs_mut, 7), "20");
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

        let mut bytes = (owned.len() as u32).to_be_bytes().to_vec();
        for c in &owned {
            bytes.extend_from_slice(c);
        }
        let (_, pcs) = PostConditions::from_bytes(&bytes).unwrap();

        let total = pcs.num_items();
        assert_eq!(total, AGGREGATED_NFT_ITEMS * 2);

        let mut pcs_mut = pcs;
        let read = |pcs: &mut PostConditions, idx: u8| -> std::string::String {
            let mut key = [0u8; 64];
            let mut val = [0u8; 64];
            pcs.get_items(idx, &mut key, &mut val, 0, total).unwrap();
            std::string::String::from_utf8_lossy(&val)
                .trim_end_matches('\0')
                .to_string()
        };
        assert_eq!(read(&mut pcs_mut, 3), "3"); // group A: 3 occurrences
        assert_eq!(read(&mut pcs_mut, 7), "2"); // group B: 2 occurrences
    }
}
