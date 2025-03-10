/*******************************************************************************
*   (c) 2021 Zondax GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
use crate::parser::utils::ApduPanic;
use core::{marker::PhantomData, mem::MaybeUninit, ptr::addr_of_mut};
use nom::{bytes::complete::take, number::complete::be_u32};

use crate::parser::{FromBytes, ParserError};

/// Represents an object list
///
/// The number of objects is prepended as a BE u32 to the objects bytes
#[derive(Debug, Clone, Copy)]
pub struct ObjectList<'b, Obj> {
    data: &'b [u8],
    // counter used to track the amount of bytes
    // that were read when parsing a inner element in the list
    read: usize,
    // type of object that the ObjectList contains
    _phantom: PhantomData<Obj>,
}

impl<'b, Obj: FromBytes<'b>> PartialEq for ObjectList<'_, Obj>
where
    Obj: FromBytes<'b>,
{
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<'b, Obj> ObjectList<'b, Obj>
where
    Obj: FromBytes<'b> + Copy,
{
    #[cfg(test)]
    pub fn new(input: &'b [u8]) -> Result<(&'b [u8], Self), nom::Err<ParserError>> {
        let mut list = MaybeUninit::uninit();
        let rem = ObjectList::new_into(input, &mut list)?;
        let list = unsafe { list.assume_init() };
        Ok((rem, list))
    }

    /// Attempt to parse the provided input as an [`ObjectList`] of the given `Obj` type.
    /// The number of elements in the list should be provided. This is useful in cases
    /// where the number of elements has an arbitrary type or is not part of the input
    /// buffer.
    ///
    /// Will fail if the input bytes are not properly encoded for the list or if any of the objects inside fail to parse.
    /// This also means accessing any inner objects shouldn't fail to parse
    #[inline(never)]
    pub fn new_into_with_len(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
        num_objs: usize,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        let mut len = input.len();
        let mut bytes_left = input;
        let mut object = MaybeUninit::uninit();

        // we are not saving parsed data but ensuring everything
        // parsed correctly.
        for _ in 0..num_objs {
            bytes_left = Obj::from_bytes_into(bytes_left, &mut object)?;
        }

        // this calculates the length in bytes of the list of objects
        // using the amount of bytes left after iterating over each parsed element.
        // This does not include the bytes
        // used to read the number of such objects as we already skip them
        len -= bytes_left.len();

        let (rem, data) = take(len)(input)?;

        //good ptr and no uninit reads
        let out = out.as_mut_ptr();
        unsafe {
            addr_of_mut!((*out).read).write(0);
            addr_of_mut!((*out).data).write(data);
        }

        Ok(rem)
    }

    #[inline(never)]
    /// Attempt to parse the provided input as an [`ObjectList`] of the given `Obj` type.
    /// This method would read the number of objects as a u32 from the input buffer.
    ///
    /// Will fail if the input bytes are not properly encoded for the list or if any of the objects inside fail to parse.
    /// This also means accessing any inner objects shouldn't fail to parse
    pub fn new_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        if input.is_empty() {
            return Err(ParserError::UnexpectedBufferEnd.into());
        }

        let (rem, num_objects) = be_u32(input)?;

        Self::new_into_with_len(rem, out, num_objects as _)
    }

    #[inline(never)]
    /// Parses an object into the given location, returning the amount of bytes read.
    ///
    /// If no bytes could be read (for example, end of list), then None is returned.
    ///
    /// # Note
    /// Does not move the internal cursor forward, useful for peeking
    fn parse_into(&self, out: &mut MaybeUninit<Obj>) -> Option<usize> {
        let data = &self.data[self.read..];
        if data.is_empty() {
            return None;
        }

        //ok to panic as we parsed beforehand
        let rem = Obj::from_bytes_into(data, out).apdu_unwrap();

        Some(self.data.len() - rem.len())
    }

    /// Parses an object into the given location.
    ///
    /// If no bytes could be read, then None is returned.
    pub fn parse_next(&mut self, out: &mut MaybeUninit<Obj>) -> Option<()> {
        match self.parse_into(out) {
            Some(read) => {
                self.read = read;
                Some(())
            }
            None => None,
        }
    }

    /// Looks for the first object in the list that meets
    /// the condition defined by the closure `f`.
    ///
    /// it is like iter().filter(), but memory efficient.
    /// `None` is returned if no object meets that condition
    ///
    /// This function does not change the internal state.
    pub fn get_obj_if<F>(&self, mut f: F) -> Option<Obj>
    where
        F: FnMut(&Obj) -> bool,
    {
        let mut out = MaybeUninit::uninit();
        // lets clone and start from the begining
        let mut this = *self;
        unsafe {
            this.set_data_index(0);
        }
        while let Some(()) = this.parse_next(&mut out) {
            let obj_ptr = out.as_mut_ptr();
            // valid read as memory was initialized
            if f(unsafe { &*obj_ptr }) {
                return Some(unsafe { out.assume_init() });
            }
            // drop the object, this is safe
            // as user does not longer hold a reference
            // to this object.
            unsafe {
                obj_ptr.drop_in_place();
            }
        }
        None
    }

    /// Iterates and calls `f` passing each object
    /// in the list. This is intended to reduce stack by reusing the same
    /// memory. The closure F gives the user the option to compute
    /// any require data from each item.
    ///
    /// This function does not change the internal state.
    pub fn iterate_with<F>(&self, mut f: F)
    where
        F: FnMut(&Obj),
    {
        let mut out = MaybeUninit::uninit();
        // lets clone and start from the begining
        let mut this = *self;
        unsafe {
            this.set_data_index(0);
        }
        while let Some(()) = this.parse_next(&mut out) {
            let obj_ptr = out.as_mut_ptr();
            unsafe {
                // valid read as memory was initialized
                f(&*obj_ptr);
                // drop the object, this is safe
                // as user does not longer hold a reference
                // to obj.
                obj_ptr.drop_in_place();
            }
        }
    }

    /// Parses an object into the given location, without moving forward the internal cursor.
    ///
    /// See also [`ObjList::parse_next`].
    pub fn peek_next(&mut self, out: &mut MaybeUninit<Obj>) -> Option<()> {
        self.parse_into(out).map(|_| ())
    }

    /// Returns the internal cursor position
    pub fn data_index(&self) -> usize {
        self.read
    }

    /// Overwrite the internal cursor position
    ///
    /// Intended to be used as a way to reset the cursor, see below.
    ///
    /// # Safety
    /// Setting `read` to a position that is inside an object will render
    /// further reading impossible.
    ///
    /// If you start to panic when parsing object incorrect usage
    /// of this method is most likely the cause
    pub unsafe fn set_data_index(&mut self, read: usize) {
        self.read = read;
    }
}

impl<'b, Obj> ObjectList<'b, Obj>
where
    Obj: FromBytes<'b> + 'b + Copy,
{
    /// Creates an [`ObjectListIterator`] for object out of the given object list
    pub fn iter(&self) -> impl Iterator<Item = Obj> + 'b {
        ObjectListIterator::new(self)
    }
}

struct ObjectListIterator<'b, Obj: FromBytes<'b>> {
    list: ObjectList<'b, Obj>,
}

impl<'b, Obj> ObjectListIterator<'b, Obj>
where
    Obj: FromBytes<'b> + Copy,
{
    /// Creates a new [`ObjectListIterator`] by copying the given list
    ///
    /// Iteration will always start from the beginning as the internal cursor
    /// of the copied list is reset
    fn new(list: &ObjectList<'b, Obj>) -> Self {
        // we do not want to change the state
        // of the passed in list, as a result, we just
        // make a copy, so we can reset the read index,
        // so iteration always starts from the beginning
        let mut list = *list;
        unsafe {
            // this is safe as we do have not used the current index
            // and setting it at the start of the list is always safe
            list.set_data_index(0);
        }
        Self { list }
    }
}

impl<'b, Obj> Iterator for ObjectListIterator<'b, Obj>
where
    Obj: FromBytes<'b> + Copy,
{
    type Item = Obj;

    fn next(&mut self) -> Option<Self::Item> {
        let mut output = MaybeUninit::uninit();
        self.list
            .parse_next(&mut output)
            .map(|_| unsafe { output.assume_init() })
    }
}
