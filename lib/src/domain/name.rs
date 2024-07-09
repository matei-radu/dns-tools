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

use crate::domain::error::TryFromError;
use std::fmt;

pub const MAX_LABEL_LENGTH: usize = 63;
const LABEL_SEPARATOR: char = '.';

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
    type Error = TryFromError;

    /// Tries to convert a [`String`] into a `Domain`.
    ///
    /// A valid DNS domain name consists of one or more labels separated by
    /// dots (`.`). Each label starts with a letter, ends with a letter or
    /// digit, and can contain letters, digits, and hyphens in between.
    ///
    /// For more details, see [RFC 1034, Section 3.5].
    ///
    /// # Example
    /// ```
    /// use dns_lib::Domain;
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
        Domain::try_from(value.as_bytes())
    }
}

impl TryFrom<&[u8]> for Domain {
    type Error = TryFromError;

    /// Tries to convert a slice `&[u8]` into a `Domain`.
    ///
    /// A valid DNS domain name consists of one or more labels separated by
    /// dots (`.`). Each label starts with a letter, ends with a letter or
    /// digit, and can contain letters, digits, and hyphens in between.
    ///
    /// For more details, see [RFC 1034, Section 3.5].
    ///
    /// # Example
    /// ```
    /// use dns_lib::Domain;
    ///
    /// let valid_domain = b"example.com" as &[u8];
    /// assert!(Domain::try_from(valid_domain).is_ok());
    ///
    /// let invalid_domain = b"foo-..bar" as &[u8];
    /// assert!(Domain::try_from(invalid_domain).is_err());
    /// ```
    ///
    /// [RFC 1034, Section 3.5]: https://datatracker.ietf.org/doc/html/rfc1034#section-3.5
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(TryFromError::DomainEmpty);
        }

        let raw_labels: Vec<&[u8]> = value.split(|&byte| byte == LABEL_SEPARATOR as u8).collect();

        let parsed_labels_result: Result<Vec<String>, TryFromError> =
            raw_labels.iter().map(|&slice| parse_label(slice)).collect();

        match parsed_labels_result {
            Ok(labels) => Ok(Domain { labels }),
            Err(e) => Err(e),
        }
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.labels.join(&LABEL_SEPARATOR.to_string()))
    }
}

/// Tries to convert a slice `&[u8]` into a label [`String`].
///
/// A valid DNS `label` is a string that starts with a letter, ends with a
/// letter or digit, and has as interior characters only letters, digits,
/// and hyphens.
///
/// See [RFC 1034, Section 3.5 - Preferred name syntax](https://datatracker.ietf.org/doc/html/rfc1034#section-3.5)
pub fn parse_label(bytes: &[u8]) -> Result<String, TryFromError> {
    let label = match std::string::String::from_utf8(bytes.to_vec()) {
        Ok(str) => str.to_string(),
        Err(e) => return Err(TryFromError::LabelInvalidEncoding(e)),
    };

    if bytes.len() == 0 {
        return Err(TryFromError::LabelEmpty);
    }

    if bytes.len() > MAX_LABEL_LENGTH {
        return Err(TryFromError::LabelTooLong(label));
    }

    let (first_byte, remaining_bytes) = bytes.split_at(1);
    if remaining_bytes.len() == 0 {
        match first_byte[0].is_ascii_alphabetic() {
            true => return Ok(label),
            false => return Err(TryFromError::LabelInvalidFormat(label)),
        };
    }

    let (middle_bytes, last_byte) = remaining_bytes.split_at(remaining_bytes.len() - 1);

    let first_byte_letter = first_byte[0].is_ascii_alphabetic();
    let last_byte_letter_digit = last_byte.len() == 0 || last_byte[0].is_ascii_alphanumeric();
    let middle_bytes_are_ldh_str = middle_bytes.len() == 0 || bytes_are_ldh_str(middle_bytes);

    match first_byte_letter && middle_bytes_are_ldh_str && last_byte_letter_digit {
        true => Ok(label),
        false => Err(TryFromError::LabelInvalidFormat(label)),
    }
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
    #[case("a".to_string())]
    #[case("a4".to_string())]
    #[case("foo".to_string())]
    #[case("mercedes-benz".to_string())]
    #[case("live-365".to_string())]
    #[case("d111111abcdef8".to_string())]
    #[case("a-label-that-is-exactly-sixty-three-characters-long-as-per-spec".to_string())]
    fn parse_label_succeeds(#[case] input: String) {
        let result = parse_label(input.as_bytes());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), input);
    }

    #[rstest]
    #[case(b"420", "label '420' has invalid format".to_string())]
    #[case(b"4a", "label '4a' has invalid format".to_string())]
    #[case(b"-", "label '-' has invalid format".to_string())]
    #[case(b"a-", "label 'a-' has invalid format".to_string())]
    #[case(b"ab-", "label 'ab-' has invalid format".to_string())]
    #[case(b"-a", "label '-a' has invalid format".to_string())]
    #[case(b"bar-", "label 'bar-' has invalid format".to_string())]
    #[case(b"", "label is empty".to_string())]
    #[case(
        b"a-label-that-exceeds-the-allowed-limit-of-sixty-three-characters",
        "label 'a-label-that-exceeds-the-allowed-limit-of-sixty-three-characters' exceeds the maximum allowed length of 63 characters".to_string()
    )]
    fn parse_label_fails(#[case] input: &[u8], #[case] error_msg: String) {
        let result = parse_label(input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), error_msg);
    }

    #[rstest]
    #[case("a", Domain{ labels: vec!["a".to_string()]})]
    #[case("example", Domain{ labels: vec!["example".to_string()]})]
    #[case("example.com", Domain{ labels: vec!["example".to_string(), "com".to_string()]})]
    #[case("mercedes-benz.de", Domain{ labels: vec!["mercedes-benz".to_string(), "de".to_string()]})]
    #[case("live-365", Domain{ labels: vec!["live-365".to_string()]})]
    #[case("live-365.com", Domain{ labels: vec!["live-365".to_string(), "com".to_string()]})]
    #[case("d111111abcdef8.cloudfront.net", Domain{ labels: vec!["d111111abcdef8".to_string(), "cloudfront".to_string(), "net".to_string()]})]
    fn domain_try_from_string_succeeds(#[case] input: String, #[case] ok: Domain) {
        let result = Domain::try_from(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ok);
    }

    #[rstest]
    #[case(b"a", Domain{ labels: vec!["a".to_string()]})]
    #[case(b"example", Domain{ labels: vec!["example".to_string()]})]
    #[case(b"example.com", Domain{ labels: vec!["example".to_string(), "com".to_string()]})]
    #[case(b"mercedes-benz.de", Domain{ labels: vec!["mercedes-benz".to_string(), "de".to_string()]})]
    #[case(b"live-365", Domain{ labels: vec!["live-365".to_string()]})]
    #[case(b"live-365.com", Domain{ labels: vec!["live-365".to_string(), "com".to_string()]})]
    #[case(b"d111111abcdef8.cloudfront.net", Domain{ labels: vec!["d111111abcdef8".to_string(), "cloudfront".to_string(), "net".to_string()]})]
    fn domain_try_from_byte_slice_succeeds(#[case] input: &[u8], #[case] ok: Domain) {
        let result = Domain::try_from(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ok);
    }

    #[rstest]
    #[case("-.com", "label '-' has invalid format".to_string())]
    #[case("sübway.com", "label 'sübway' has invalid format".to_string())]
    #[case("", "domain is empty".to_string())]
    #[case(
        "a-label-that-exceeds-the-allowed-limit-of-sixty-three-characters.yahoo.com",
        "label 'a-label-that-exceeds-the-allowed-limit-of-sixty-three-characters' exceeds the maximum allowed length of 63 characters".to_string()
    )]
    #[case("cdn..com", "label is empty".to_string())]
    fn domain_try_from_string_fails(#[case] input: String, #[case] error_msg: String) {
        let result = Domain::try_from(input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), error_msg);
    }

    #[rstest]
    #[case("example")]
    #[case("mercedes-benz.de")]
    #[case("live-365")]
    #[case("live-365.com")]
    #[case("d111111abcdef8.cloudfront.net")]
    #[case("a.b.c.d.e.f")]
    fn domain_to_string_valid(#[case] input: String) {
        let result = Domain::try_from(input.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), input);
    }
}
