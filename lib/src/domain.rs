// Copyright 2024 Matei Bogdan Radu
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const MAX_LABEL_LENGTH: usize = 63;
const LABEL_SEPARATOR: u8 = b'.';

/// Checks if the byte array is a valid DNS `domain`, that is, a string
/// consisting of one of more `label`s separated by dots (".").
///
/// See [RFC 1034, Section 3.5 - Preferred name syntax](https://datatracker.ietf.org/doc/html/rfc1034#section-3.5)
pub fn bytes_are_domain(bytes: &[u8]) -> bool {
    let labels: Vec<&[u8]> = bytes.split(|&byte| byte == LABEL_SEPARATOR).collect();
    labels.iter().all(|&label| bytes_are_label(label))
}

/// Checks if the byte array is a valid DNS `label`, that is, a string that
/// starts with a letter, ends with a letter or digit, and has as interior
/// characters only letters, digits, and hyphens.
///
/// See [RFC 1034, Section 3.5 - Preferred name syntax](https://datatracker.ietf.org/doc/html/rfc1034#section-3.5)
pub fn bytes_are_label(bytes: &[u8]) -> bool {
    if bytes.len() == 0 && bytes.len() > MAX_LABEL_LENGTH {
        return false;
    }

    let (first_byte, remaining_bytes) = bytes.split_at(1);
    if remaining_bytes.len() == 0 {
        return first_byte[0].is_ascii_alphabetic();
    }

    let (middle_bytes, last_byte) = remaining_bytes.split_at(remaining_bytes.len() - 1);

    let first_byte_letter = first_byte[0].is_ascii_alphabetic();
    let last_byte_letter_digit = last_byte.len() == 0 || last_byte[0].is_ascii_alphanumeric();
    let middle_bytes_are_ldh_str = middle_bytes.len() == 0 || bytes_are_ldh_str(middle_bytes);

    first_byte_letter && middle_bytes_are_ldh_str && last_byte_letter_digit
}

/// Checks if the byte array is a valid DNS `ldh-str`, that is, a string
/// consisting of letters, digits and hyphens.
///
/// See [RFC 1034, Section 3.5 - Preferred name syntax](https://datatracker.ietf.org/doc/html/rfc1034#section-3.5)
pub fn bytes_are_ldh_str(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|&byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(b"a", true)]
    #[case(b"foo", true)]
    #[case(b"mercedes-benz", true)]
    #[case(b"420", true)]
    #[case(b"4a", true)]
    #[case(b"-a", true)]
    #[case(b"-", true)]
    #[case(b"bar-", true)]
    fn bytes_are_ldh_str_works_correctly(#[case] input: &[u8], #[case] expected: bool) {
        assert_eq!(bytes_are_ldh_str(input), expected);
    }

    #[rstest]
    #[case(b"a", true)]
    #[case(b"a4", true)]
    #[case(b"foo", true)]
    #[case(b"mercedes-benz", true)]
    #[case(b"live-365", true)]
    #[case(b"d111111abcdef8", true)]
    #[case(b"420", false)]
    #[case(b"4a", false)]
    #[case(b"-", false)]
    #[case(b"a-", false)]
    #[case(b"ab-", false)]
    #[case(b"-a", false)]
    #[case(b"bar-", false)]
    fn bytes_are_label_works_correctly(#[case] input: &[u8], #[case] expected: bool) {
        assert_eq!(bytes_are_label(input), expected);
    }

    #[rstest]
    #[case(b"a", true)]
    #[case(b"example", true)]
    #[case(b"example.com", true)]
    #[case(b"mercedes-benz.de", true)]
    #[case(b"live-365", true)]
    #[case(b"live-365.com", true)]
    #[case(b"d111111abcdef8.cloudfront.net", true)]
    fn bytes_are_domain_works_correctly(#[case] input: &[u8], #[case] expected: bool) {
        assert_eq!(bytes_are_domain(input), expected);
    }
}
