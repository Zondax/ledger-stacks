use crate::parser::{ClarityName, ParserError, Value, ValueId, MAX_DEPTH};
use nom::number::complete::be_u32;

// This type is meant to get from the Value type
#[repr(C)]
#[derive(Clone, PartialEq, Copy)]
#[cfg_attr(test, derive(Debug))]
pub struct Tuple<'a>(pub &'a [u8]);

impl<'a> Tuple<'a> {
    // Takes in a Value type containing a full-parsed clarity tuple,
    // That is wrapped-up here to better access/handle tuple fields/operations
    pub(crate) fn new(value: &'a Value) -> Result<Tuple<'a>, ParserError> {
        if !matches!(value.value_id(), ValueId::Tuple) {
            return Err(ParserError::UnexpectedType);
        }

        // Omit the type
        Ok(Self(value.payload()))
    }

    pub fn num_elements(&self) -> usize {
        // This wont panic as this type was already parsed.
        // and is wrapped-up here to better access its fields.
        be_u32::<_, ParserError>(self.0)
            .map(|(_, len)| len as usize)
            .unwrap()
    }

    // Skip the bytes that indicates the number of elements in this tuple
    pub fn payload(&'a self) -> &'a [u8] {
        &self.0[4..]
    }

    // Returns an iterator over Tuple items which consists of:
    // the field name(ClarityName) and its field(another ClarityValue type)
    pub fn iter(&'a self) -> impl Iterator<Item = (ClarityName<'a>, Value<'a>)> {
        TupleIter {
            data: self.payload(),
            read: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, PartialEq, Copy)]
#[cfg_attr(test, derive(Debug))]
pub struct TupleIter<'a> {
    data: &'a [u8],
    read: usize,
}

impl<'a> Iterator for TupleIter<'a> {
    type Item = (ClarityName<'a>, Value<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.read < self.data.len() {
            // We unwrap here as all the inner fields of this tuple were already parsed
            let (rem, name) = ClarityName::from_bytes(&self.data[self.read..]).ok()?;
            // limit recursion to MAX_DEPTH
            let (rem, value) = Value::from_bytes::<MAX_DEPTH>(rem).ok()?;
            self.read = self.data.len() - rem.len();

            Some((name, value))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::hash_set::HashSet;

    #[test]
    fn test_iter_tuples() {
        // A tuple where all of its inner fields are tuples
        let domain = "0c0000000308636861696e2d69640c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e30046e616d650c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300776657273696f6e0c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e30";

        // Hash with the expected tuple field names
        let mut names = HashSet::new();

        let set = [b"name".to_vec(), b"version".to_vec(), b"chain-id".to_vec()];
        for item in set.iter() {
            names.insert(item);
        }

        let bytes = hex::decode(domain).unwrap();

        let (_, value) = Value::from_bytes::<50>(&bytes).unwrap();
        let tuple = value.tuple().unwrap();

        let mut count = 0;
        for (name, _) in tuple.iter() {
            count += 1;
            let key = name.name().to_vec();
            assert!(names.contains(&key));
        }

        assert_eq!(count, tuple.num_elements());
    }

    #[test]
    fn test_tuple_list_iter() {
        let domain = "0c0000000308636861696e2d69640c0000000308636861696e2d69640100000000000000000000000000025983046e616d650c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300776657273696f6e0b000000050c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e30046e616d650c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300776657273696f6e0b000000020c0000000308636861696e2d69640100000000000000000000000000025983046e616d650c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300776657273696f6e0b000000050c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300776657273696f6e0b000000050c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e300c0000000308636861696e2d69640100000000000000000000000000025983046e616d650d00000006537461636b730776657273696f6e0d00000005312e302e30";

        let mut names = HashSet::new();

        let set = [b"name".to_vec(), b"version".to_vec(), b"chain-id".to_vec()];
        for item in set.iter() {
            names.insert(item);
        }

        let bytes = hex::decode(domain).unwrap();

        let (_, value) = Value::from_bytes::<5>(&bytes).unwrap();
        let tuple = value.tuple().unwrap();
        let mut count = 0;
        for (name, _) in tuple.iter() {
            count += 1;
            let key = name.name().to_vec();
            assert!(names.contains(&key));
        }
        assert_eq!(count, tuple.num_elements());
    }
}
