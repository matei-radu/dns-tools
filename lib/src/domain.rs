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
const LABEL_SEPARATOR: char = '.';

#[derive(Debug)]
pub struct InvalidDomainError;

/// Representation of a DNS domain name.
///
/// A domain name consists of one or more labels. Each label starts with a
/// letter, ends with a letter or digit, and can contain letters, digits,
/// and hyphens in between.
///
/// When represented as a string, each label is separated by dots (`.`):
///
/// > `www.example.com`
///
/// For more details, see [RFC 1034, Section 3.5].
///
/// [RFC 1034, Section 3.5]: https://datatracker.ietf.org/doc/html/rfc1034#section-3.5
#[derive(Debug, PartialEq)]
pub struct Domain {
    labels: Vec<String>,
}

impl TryFrom<String> for Domain {
    type Error = InvalidDomainError;

    /// Tries to convert a [`String`] into a `Domain`.
    ///
    /// A valid DNS domain name string consists of one or more labels separated
    /// by dots (`.`). Each label starts with a letter, ends with a letter or
    /// digit, and can contain letters, digits, and hyphens in between.
    ///
    /// For more details, see [RFC 1034, Section 3.5].
    ///
    /// # Example
    /// ```
    /// use dns_lib::domain::Domain;
    ///
    /// let valid_domain = "example.com".to_string();
    /// assert!(Domain::try_from(valid_domain).is_ok());
    ///
    /// let invalid_domain = "foo-..bar".to_string();
    /// assert!(Domain::try_from(invalid_domain).is_err());
    /// ```
    ///
    /// [RFC 1034, Section 3.5]: https://datatracker.ietf.org/doc/html/rfc1034#section-3.5
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let labels: Vec<String> = value
            .split(|character| character == LABEL_SEPARATOR)
            .map(String::from)
            .collect();

        if labels.is_empty() {
            return Err(InvalidDomainError);
        }

        for label in &labels {
            if !bytes_are_label(label.as_bytes()) {
                return Err(InvalidDomainError);
            }
        }

        Ok(Domain { labels })
    }
}

/// Checks if the byte array is a valid DNS `label`, that is, a string that
/// starts with a letter, ends with a letter or digit, and has as interior
/// characters only letters, digits, and hyphens.
///
/// See [RFC 1034, Section 3.5 - Preferred name syntax](https://datatracker.ietf.org/doc/html/rfc1034#section-3.5)
pub fn bytes_are_label(bytes: &[u8]) -> bool {
    if bytes.len() == 0 || bytes.len() > MAX_LABEL_LENGTH {
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
    #[case(b"", false)]
    #[case(
        b"a-label-that-is-exactly-sixty-three-characters-long-as-per-spec",
        true
    )]
    #[case(
        b"a-label-that-exceeds-the-allowed-limit-of-sixty-three-characters",
        false
    )]
    fn bytes_are_label_works_correctly(#[case] input: &[u8], #[case] expected: bool) {
        assert_eq!(bytes_are_label(input), expected);
    }

    #[rstest]
    #[case("a", Domain{ labels: vec!["a".to_string()]})]
    #[case("example", Domain{ labels: vec!["example".to_string()]})]
    #[case("example.com", Domain{ labels: vec!["example".to_string(), "com".to_string()]})]
    #[case("mercedes-benz.de", Domain{ labels: vec!["mercedes-benz".to_string(), "de".to_string()]})]
    #[case("live-365", Domain{ labels: vec!["live-365".to_string()]})]
    #[case("live-365.com", Domain{ labels: vec!["live-365".to_string(), "com".to_string()]})]
    #[case("d111111abcdef8.cloudfront.net", Domain{ labels: vec!["d111111abcdef8".to_string(), "cloudfront".to_string(), "net".to_string()]})]
    fn domain_try_from_succeeds(#[case] input: String, #[case] ok: Domain) {
        let result = Domain::try_from(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ok);
    }
}
