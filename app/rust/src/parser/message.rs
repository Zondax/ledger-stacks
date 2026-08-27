use super::{error::ParserError, read_varint};
use crate::zxformat::{page_string, page_string_with, Writer};
use core::fmt::Write;
use nom::bytes::complete::take;

// The lenght of \x17Stacks Signed Message:
const BYTE_STRING_HEADER_LEN: usize = "\x17Stacks Signed Message:\n".len();
// Truncates an ascii
// message to around this size, as we need to change special characters
// like /t or /r with spaces.
const MAX_ASCII_LEN: usize = 270;

// Longest message the device pages through in full.
//
// The signature covers the whole message, so anything the review cannot show has to go through
// the blind-signing gate instead. The bound exists because `page_string` counts pages in a `u8`
// and the narrowest buffer the app pages into is the 30-byte scratch `parser_validate` uses:
// 4 KiB needs 142 pages there, comfortably inside a `u8`.
const MAX_DISPLAYABLE_LEN: usize = 4096;

#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct Message<'a>(ByteString<'a>);

impl<'a> Message<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ParserError> {
        ByteString::from_bytes(data).map(Self)
    }

    pub fn read(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        ByteString::from_bytes(data).map(|msg| {
            self.0 = msg;
        })
    }

    pub fn is_message(data: &'a [u8]) -> bool {
        ByteString::is_msg(data)
    }

    pub fn num_items(&self) -> u8 {
        self.0.num_items()
    }

    /// Whether this message commits to text the review cannot show in full.
    pub fn requires_blindsign(&self) -> bool {
        self.0.requires_blindsign()
    }

    pub fn get_item(
        &mut self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        self.0.get_item(display_idx, out_key, out_value, page_idx)
    }
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq)]
pub struct ByteString<'a>(&'a [u8]);

#[cfg(test)]
impl core::fmt::Debug for ByteString<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ByteString(\"")?;
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "\")")
    }
}

impl<'a> ByteString<'a> {
    pub fn is_msg(data: &'a [u8]) -> bool {
        Self::contain_header(data)
    }

    // Checks if the input data contain the byte_string heades at the first bytes
    fn contain_header(data: &[u8]) -> bool {
        let header = "\x17Stacks Signed Message:\n".as_bytes();
        data.len() > BYTE_STRING_HEADER_LEN && &data[..BYTE_STRING_HEADER_LEN] == header
    }

    // returns the message content
    fn get_msg(data: &'a [u8]) -> Result<&'a [u8], ParserError> {
        if data.is_empty() {
            return Err(ParserError::UnexpectedBufferEnd);
        }

        let (rem, len) = read_varint(data).map_err(|_| ParserError::InvalidBytestrMessage)?;

        let (tail, message_content) = take::<_, _, ParserError>(len as usize)(rem)
            .map_err(|_| ParserError::InvalidBytestrMessage)?;

        if !tail.is_empty() {
            return Err(ParserError::InvalidBytestrMessage);
        }

        if !message_content.is_ascii() {
            return Err(ParserError::InvalidBytestrMessage);
        }

        Ok(message_content)
    }

    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ParserError> {
        if !Self::contain_header(data) {
            return Err(ParserError::InvalidBytestrMessage);
        }
        let message = Self::get_msg(&data[BYTE_STRING_HEADER_LEN..])?;
        Ok(Self(message))
    }

    pub const fn num_items(&self) -> u8 {
        //One ByteString message to show at least partially
        1
    }

    /// Whether the message is longer than the review can page through.
    ///
    /// Messages above [`MAX_DISPLAYABLE_LEN`] are shown as a leading excerpt only, so signing one
    /// has to be gated on blind signing: the digest covers every byte, including the ones the
    /// excerpt drops.
    pub fn requires_blindsign(&self) -> bool {
        self.0.len() > MAX_DISPLAYABLE_LEN
    }

    // Control characters [\b..=\r] would break the layout, so they render as spaces.
    #[inline(always)]
    fn printable(byte: u8) -> u8 {
        if (0x08..=b'\r').contains(&byte) {
            b' '
        } else {
            byte
        }
    }

    pub fn get_item(
        &mut self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        if display_idx != 0 {
            return Err(ParserError::DisplayIdxOutOfRange);
        }

        let mut writer_key = Writer::new(out_key);
        writer_key
            .write_str("Sign Message")
            .map_err(|_| ParserError::UnexpectedBufferEnd)?;

        if !self.requires_blindsign() {
            // Page over the message itself. Rewriting each page as it is copied out keeps the
            // whole text reviewable without a stack buffer the size of the message.
            return page_string_with(out_value, self.0, page_idx, Self::printable);
        }

        // Past the paging limit the user has already accepted blind signing, so show as much of
        // the message as fits and mark it as cut short.
        let mut msg = [0; MAX_ASCII_LEN + 3];
        let suffix = [b'.'; 3];

        let m = msg
            .get_mut(MAX_ASCII_LEN..MAX_ASCII_LEN + suffix.len())
            .ok_or(ParserError::UnexpectedBufferEnd)?;
        m.copy_from_slice(&suffix[..]);

        msg.iter_mut()
            .take(MAX_ASCII_LEN)
            .zip(self.0.iter().map(|c| Self::printable(*c)))
            .for_each(|(r, m)| *r = m);

        page_string(out_value, &msg[..MAX_ASCII_LEN + suffix.len()], page_idx)
    }
}

#[cfg(test)]
mod test {
    use std::prelude::v1::*;

    use super::*;

    fn built_message(len: usize, data: &str) -> Vec<u8> {
        let header = "\x17Stacks Signed Message:\n".as_bytes();
        let mut vec = vec![];
        vec.extend_from_slice(header);
        vec.push(len as u8);
        vec.extend_from_slice(data.as_bytes());
        vec
    }

    /// Builds a signed-message blob whose length prefix is a real varint, so the helper works
    /// past the 252-byte single-byte form.
    fn built_long_message(data: &str) -> Vec<u8> {
        let header = "\x17Stacks Signed Message:\n".as_bytes();
        let mut vec = vec![];
        vec.extend_from_slice(header);
        let len = data.len();
        if len < 0xFD {
            vec.push(len as u8);
        } else if len <= u16::MAX as usize {
            vec.push(0xFD);
            vec.extend_from_slice(&(len as u16).to_le_bytes());
        } else {
            vec.push(0xFE);
            vec.extend_from_slice(&(len as u32).to_le_bytes());
        }
        vec.extend_from_slice(data.as_bytes());
        vec
    }

    /// Reads back every page of the single review item.
    fn rendered(msg: &mut ByteString<'_>, page_width: usize) -> String {
        let mut key = [0u8; 32];
        let mut value = std::vec![0u8; page_width];
        let pages = msg.get_item(0, &mut key, &mut value, 0).unwrap();

        let mut out = String::new();
        for page in 0..pages {
            let mut value = std::vec![0u8; page_width];
            msg.get_item(0, &mut key, &mut value, page).unwrap();
            out.push_str(core::str::from_utf8(&value).unwrap().trim_end_matches('\0'));
        }
        out
    }

    /// A message the review can page through is rendered whole, not cut at 270 bytes.
    ///
    /// The excerpt used to stop at `MAX_ASCII_LEN` and append "...", while the signature covered
    /// every byte -- so a wallet could hide arbitrary text behind an approval. Real sign-in
    /// messages sit just past that limit; this one is the 284-byte Gamma prompt.
    #[test]
    fn test_message_past_the_excerpt_limit_renders_in_full() {
        let data = "Welcome!\nSign this message to access Gamma's full feature set.\nAs always, by using Gamma, you agree to our terms of use: https://gamma.io/terms\nDomain: gamma.io\nAccount: SP2PH3XAPDMSKXQVS1WZ80JGZACY713JQQEE1DY48\nNonce: c83024f9e9aef40f5d72076e883054c07100035112826b14f78e5a893d62b1bf\n";
        assert!(data.len() > MAX_ASCII_LEN);
        assert!(data.len() <= MAX_DISPLAYABLE_LEN);

        let blob = built_long_message(data);
        let mut msg = ByteString::from_bytes(&blob).unwrap();

        assert!(!msg.requires_blindsign());

        let shown = rendered(&mut msg, 40);
        let expected: String = data
            .chars()
            .map(|c| {
                if ('\u{08}'..='\r').contains(&c) {
                    ' '
                } else {
                    c
                }
            })
            .collect();
        assert_eq!(shown, expected);
        assert!(!shown.ends_with("..."));
    }

    /// Past the paging limit the message is excerpted, and signing it needs blind signing.
    #[test]
    fn test_message_beyond_paging_limit_requires_blindsign() {
        let data = "A".repeat(MAX_DISPLAYABLE_LEN + 1);
        let blob = built_long_message(&data);
        let mut msg = ByteString::from_bytes(&blob).unwrap();

        assert!(msg.requires_blindsign());

        let shown = rendered(&mut msg, 40);
        assert!(shown.ends_with("..."), "{shown}");
        assert_eq!(shown.len(), MAX_ASCII_LEN + 3);
    }

    /// A short message keeps rendering exactly as before.
    #[test]
    fn test_short_message_is_not_gated() {
        let data = "hello there";
        let blob = built_long_message(data);
        let mut msg = ByteString::from_bytes(&blob).unwrap();

        assert!(!msg.requires_blindsign());
        assert_eq!(rendered(&mut msg, 40), data);
    }

    #[test]
    fn test_non_ascii_byte_string() {
        let no_ascii = "Test-love: ❤️";
        let no_ascii = built_message(no_ascii.len(), no_ascii);
        let msg = ByteString::from_bytes(&no_ascii);
        assert!(msg.is_err());
    }

    #[test]
    fn test_valid_byte_string() {
        let data = "byte_string_valid";
        let m = built_message(data.len(), data);
        let msg = ByteString::from_bytes(&m);
        assert!(msg.is_ok());
        let msg = msg.unwrap();
        assert_eq!(msg.0, data.as_bytes());
    }

    #[test]
    fn test_valid_starts_with_number() {
        let data = "1_byte_string_valid";
        let m = built_message(data.len(), data);
        let msg = ByteString::from_bytes(&m);
        assert!(msg.is_ok());
        let msg = msg.unwrap();
        assert_eq!(msg.0, data.as_bytes());
    }

    #[test]
    fn test_empty_byte_string() {
        let data = "";
        let m = built_message(data.len(), data);
        let msg = ByteString::from_bytes(&m);
        assert!(msg.is_ok());
        let msg = msg.unwrap();
        assert_eq!(msg.0, data.as_bytes());
    }

    #[test]
    fn test_wrong_len_byte_string() {
        let m = "byte_string_valid";
        let m = built_message(34, m);
        let msg = ByteString::from_bytes(&m);
        assert!(msg.is_err());
    }

    #[test]
    fn test_only_text() {
        let msg = ByteString::from_bytes("\x17Stacks Signed Message:\nHello_world".as_bytes());
        assert!(msg.is_err());
    }

    #[test]
    fn test_only_header() {
        let msg = ByteString::from_bytes("\x17Stacks Signed Message:\n".as_bytes());
        assert!(msg.is_err());
    }

    #[test]
    fn test_reject_trailing_bytes_after_message() {
        let visible = "benign";
        let hidden = b"\xDEADBEEF-hidden-suffix";
        let mut m = built_message(visible.len(), visible);
        m.extend_from_slice(hidden);
        let msg = ByteString::from_bytes(&m);
        assert!(msg.is_err());
    }

    #[test]
    fn test_reject_single_trailing_byte() {
        let visible = "abc";
        let mut m = built_message(visible.len(), visible);
        m.push(0x00);
        let msg = ByteString::from_bytes(&m);
        assert!(msg.is_err());
    }
}
