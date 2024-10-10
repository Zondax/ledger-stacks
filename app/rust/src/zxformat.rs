#![allow(non_snake_case)]

use core::fmt::{self, Write};

use crate::parser::ParserError;
use lexical_core::Number;

pub const MAX_STR_BUFF_LEN: usize = 30;

pub struct Writer<'a> {
    buf: &'a mut [u8],
    pub(crate) offset: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Writer { buf, offset: 0 }
    }
}

impl<'a> fmt::Write for Writer<'a> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let remainder = &mut self.buf[self.offset..];

        if remainder.len() < bytes.len() {
            return Err(core::fmt::Error);
            // overflow wit zero decimals
        }
        let remainder = &mut remainder[..bytes.len()];
        remainder.copy_from_slice(bytes);
        // Update offset to avoid overwriting
        self.offset += bytes.len();

        Ok(())
    }
}

macro_rules! num_to_str {
    // we can use a procedural macro to "attach " the type name to the function name
    // but lets do it later.
    ($int_type:ty, $_name: ident) => {
        pub fn $_name(output: &mut [u8], number: $int_type) -> Result<&mut [u8], ParserError> {
            if output.len() < <$int_type>::FORMATTED_SIZE_DECIMAL {
                return Err(ParserError::UnexpectedBufferEnd);
            }

            if number == 0 {
                output[0] = b'0';
                return Ok(&mut output[..1]);
            }

            let mut offset = 0;
            let mut number = number;
            while number != 0 {
                let rem = number % 10;
                output[offset] = b'0' + rem as u8;
                offset += 1;
                number /= 10;
            }

            // swap values
            let len = offset;
            let mut idx = 0;
            while idx < offset {
                offset -= 1;
                output.swap(idx, offset);
                idx += 1;
            }

            Ok(&mut output[..len])
        }
    };
}

num_to_str!(u64, u64_to_str);
num_to_str!(u32, u32_to_str);
num_to_str!(u8, u8_to_str);
num_to_str!(i64, i64_to_str);

/// Fixed point u64 number with native/test support
///
/// Converts an u64 number into its fixed point string representation
/// using #decimals padding zeros. This functions is intended to be used where
/// linking to the native zxformat library is needed, and also be able to run tests
/// which dont have access to this native library.
/// # Arguments
/// * * `out`: the output buffer where the conversion result is written
/// * `value`: The number to convert to
/// * `decimals`: the number of decimals after the decimal point
/// # Returns
/// The number of bytes written if success or Error otherwise
pub fn fpu64_to_str(out: &mut [u8], value: u64, decimals: u8) -> Result<usize, ParserError> {
    #[cfg(any(test, fuzzing))]
    {
        let mut temp = [0u8; u64::FORMATTED_SIZE_DECIMAL];
        let value = u64_to_str(temp.as_mut(), value)?;
        fpstr_to_str(out, value, decimals)
    }
    #[cfg(not(any(test, fuzzing)))]
    unsafe {
        Ok(crate::parser::fp_uint64_to_str(
            out.as_mut_ptr() as *mut i8,
            out.len() as u16,
            value,
            decimals,
        ) as usize)
    }
}

pub(crate) fn fpstr_to_str(
    out: &mut [u8],
    value: &[u8],
    decimals: u8,
) -> Result<usize, ParserError> {
    // zeroing memory
    for i in out.iter_mut() {
        *i = 0;
    }

    // Our buffer writer
    let mut writer = Writer::new(out);

    // Reproduce our input value as a str
    let str = core::str::from_utf8(value).map_err(|_| ParserError::ContextInvalidChars)?;
    let in_len = str.len();

    // edge case when no decimals
    // we should just copy whether zero
    // or the input value
    if decimals == 0 {
        if in_len == 0 {
            return writer
                .write_char('0')
                .map(|_| 1)
                .map_err(|_| ParserError::UnexpectedBufferEnd);
        }
        return writer
            .write_str(str)
            .map(|_| writer.offset)
            .map_err(|_| ParserError::UnexpectedBufferEnd);
    }

    if in_len <= decimals as usize {
        if str.starts_with('-') {
            // we need to remove the sign before continuing
            let remainder = str.get(1..).ok_or(ParserError::UnexpectedCharacters)?;
            return write!(&mut writer, "-0.{:0>1$}", remainder, decimals as usize)
                .map(|_| writer.offset)
                .map_err(|_| ParserError::UnexpectedBufferEnd);
        }
        return write!(&mut writer, "0.{:0>1$}", str, decimals as usize)
            .map(|_| writer.offset)
            .map_err(|_| ParserError::UnexpectedBufferEnd);
    }

    let fp = in_len - decimals as usize;
    let left = str.get(0..fp).ok_or(ParserError::UnexpectedBufferEnd)?;
    let right = str
        .get(fp..in_len)
        .ok_or(ParserError::UnexpectedBufferEnd)?;

    write!(&mut writer, "{}.{}", left, right)
        .map(|_| writer.offset)
        .map_err(|_| ParserError::UnexpectedBufferEnd)
}

#[inline(never)]
pub fn pageString(out_value: &mut [u8], in_value: &[u8], page_idx: u8) -> Result<u8, ParserError> {
    // Just ensure the buffer is clear
    for i in out_value.iter_mut() {
        *i = 0u8;
    }
    let mut page_count;
    let out_len = out_value.len() - 1;
    let output = &mut out_value[..out_len];

    let in_len = in_value.len();

    if out_len == 0 || in_len == 0 {
        return Err(ParserError::NoData);
    }
    page_count = (in_len / out_len) as u8;
    let last_chunk_len = in_len % out_len;

    if last_chunk_len > 0 {
        page_count += 1;
    }

    if page_idx < page_count {
        let idx = page_idx as usize * out_len;
        let last = if last_chunk_len > 0 && page_idx == page_count - 1 {
            idx + last_chunk_len
        } else {
            idx + out_len
        };
        let len = last - idx;
        (output[..len]).copy_from_slice(&in_value[idx..last]);
    }

    Ok(page_count)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_u64_to_str() {
        let mut output = [0u8; u64::FORMATTED_SIZE_DECIMAL];
        let value = u64_to_str(output.as_mut(), 125_550).unwrap();
        std::println!("value: {}", core::str::from_utf8(value).unwrap());
        assert_eq!(&value, b"125550");
        // overflow
        assert!(u64_to_str(&mut output[..10], 12_521_547_982).is_err());
    }

    #[test]
    fn test_fpu64_8decimals() {
        let mut output = [0u8; 15];
        let len = fpu64_to_str(output.as_mut(), 1_234_567, 8).unwrap();
        let result = core::str::from_utf8(&output[..len]).unwrap();
        assert_eq!(result, "0.01234567");
    }

    #[test]
    fn test_fpu64_10decimals() {
        let mut output = [0u8; 15];
        // With 10 decimals
        let len = fpu64_to_str(output.as_mut(), 1_234_567, 10).unwrap();
        let result = core::str::from_utf8(&output[..len]).unwrap();
        assert_eq!(result, "0.0001234567");
    }

    #[test]
    fn test_fpu64_0decimals() {
        let mut output = [0u8; 15];
        // 0 decimals
        let len = fpu64_to_str(output.as_mut(), 1_234_567, 0).unwrap();
        let result = core::str::from_utf8(&output[..len]).unwrap();
        assert_eq!(result, "1234567");
    }

    #[test]
    fn test_fpu64_4decimals() {
        let mut output = [0u8; 15];
        let len = fpu64_to_str(output.as_mut(), 1_234_567, 4).unwrap();
        let result = core::str::from_utf8(&output[..len]).unwrap();
        assert_eq!(result, "123.4567");
    }

    #[test]
    fn test_fpu64_overflow() {
        let mut output = [0u8; 5];
        let result = fpu64_to_str(output.as_mut(), 1_234_567, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_paging_string() {
        let inValue = b"abcdabcdabcd";
        let mut outValue = [0u8; 6];
        // the pageString will left over the last byte
        // as a string terminator, so we make chunks of outValue.len() - 1
        for (idx, chunk) in inValue.chunks(outValue.len() - 1).enumerate() {
            pageString(outValue.as_mut(), inValue.as_ref(), idx as u8).unwrap();
            assert_eq!(outValue[..chunk.len()].as_ref(), chunk);
        }
    }
}
