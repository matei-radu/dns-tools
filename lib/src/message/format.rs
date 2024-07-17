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

use crate::message::error::{OpCodeTryFromError, ZTryFromError};

/// `Message` format used by the DNS protocol.
///
/// For more details, see [RFC 1035, Section 4].
///
/// [RFC 1035, Section 4]: https://datatracker.ietf.org/doc/html/rfc1035#section-4
pub struct Message {
    pub header: Header,
}

/// `Header` section of a DNS `Message`.
///
/// The header section is always present. It includes fields that specify
/// which of the remaining sections are present, and also specify
/// whether the message is a query or a response, a standard query or some
/// other opcode, etc.
///
/// For more details, see [RFC 1035, Section 4.1.1].
///
/// [RFC 1035, Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
pub struct Header {
    pub id: u16,

    pub qr: QR,
    pub opcode: OpCode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub z: Z,
    pub rcode: RCode,

    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[derive(Debug, PartialEq)]
pub enum QR {
    Query = 0,
    Response = 1,
}

impl From<u16> for QR {
    fn from(value: u16) -> Self {
        match value & 0b1_0000_0_0_0_0_000_0000 == 0 {
            true => Self::Query,
            false => Self::Response,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum OpCode {
    Query = 0,
    InverseQuery = 1,
    Status = 2,
}

impl TryFrom<u16> for OpCode {
    type Error = OpCodeTryFromError;

    /// Tries to extract the `OPCODE` from the flags portion of a DNS message
    /// header.
    ///
    /// The flags portion of the DNS message header is the second set of 16
    /// bits, after the 16-bit for the identifier:
    ///
    /// ```text
    ///                                 1  1  1  1  1  1
    ///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                      ID                       |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |QR|   OPCODE  |AA|TC|RD|RA|   Z    |   RCODE   |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// With 4 bits available, `OPCODE` _can_ have 16 possible values, but only
    /// 3 are supported:
    ///
    ///  - `0` a standard query (QUERY)
    ///  - `1` an inverse query (IQUERY)
    ///  - `2` a server status request (STATUS)
    ///
    /// Unsupported values in range `3-15` will result in an
    /// `OpCodeTryFromError`.
    ///
    /// For more details, see [RFC 1035, Section 4.1.1].
    ///
    /// # Example
    /// ```
    /// use dns_lib::message::OpCode;
    ///
    /// let valid_opcode = 0b0_0000_0_0_0_0_000_0000; // 0, QUERY
    /// assert!(OpCode::try_from(valid_opcode).is_ok());
    ///
    /// let invalid_opcode = 0b0_0100_0_0_0_0_000_0000; // 4, RESERVED
    /// assert!(OpCode::try_from(invalid_opcode).is_err());
    /// ```
    ///
    /// [RFC 1035, Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match (value & 0b0_1111_0_0_0_0_000_0000) >> 11 {
            0 => Ok(Self::Query),
            1 => Ok(Self::InverseQuery),
            2 => Ok(Self::Status),
            unsupported => Err(OpCodeTryFromError(unsupported)),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Z {
    AllZeros = 0,
}

impl TryFrom<u16> for Z {
    type Error = ZTryFromError;

    /// Tries to extract the `Z` from the flags portion of a DNS message
    /// header.
    ///
    /// The flags portion of the DNS message header is the second set of 16
    /// bits, after the 16-bit for the identifier:
    ///
    /// ```text
    ///                                 1  1  1  1  1  1
    ///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                      ID                       |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |QR|   OPCODE  |AA|TC|RD|RA|   Z    |   RCODE   |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// All 3 `Z` bits are reserved, so the only acceptable value is `0`.
    /// Any other value will result in an `ZTryFromError`.
    ///
    /// For more details, see [RFC 1035, Section 4.1.1].
    ///
    /// # Example
    /// ```
    /// use dns_lib::message::Z;
    ///
    /// let valid_z_bits = 0b0_0000_0_0_0_0_000_0000; // 0, ok
    /// assert!(Z::try_from(valid_z_bits).is_ok());
    ///
    /// let invalid_z_bits = 0b0_0000_0_0_0_0_100_0000; // 4, reserved
    /// assert!(Z::try_from(invalid_z_bits).is_err());
    /// ```
    ///
    /// [RFC 1035, Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match (value & 0b0_0000_0_0_0_0_111_0000) >> 4 {
            0 => Ok(Self::AllZeros),
            _ => Err(ZTryFromError),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum RCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
    Reserved,
}

impl From<u16> for RCode {
    fn from(value: u16) -> Self {
        match value & 0b0_0000_0_0_0_0_000_1111 {
            0 => Self::NoError,
            1 => Self::FormatError,
            2 => Self::ServerFailure,
            3 => Self::NameError,
            4 => Self::NotImplemented,
            5 => Self::Refused,
            _ => Self::Reserved,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(0b0_0000_0_0_0_0_000_0000, QR::Query)]
    #[case(0b1_0000_0_0_0_0_000_0000, QR::Response)]
    fn qr_from_u16_works_correctly(#[case] input: u16, #[case] expected: QR) {
        let qr = QR::from(input);
        assert_eq!(qr, expected);
    }

    #[rstest]
    #[case(0b0_0000_0_0_0_0_000_0000, OpCode::Query)]
    #[case(0b0_0001_0_0_0_0_000_0000, OpCode::InverseQuery)]
    #[case(0b0_0010_0_0_0_0_000_0000, OpCode::Status)]
    fn op_code_try_from_u16_succeeds(#[case] input: u16, #[case] expected: OpCode) {
        let result = OpCode::try_from(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }

    #[rstest]
    #[case(0b0_0011_0_0_0_0_000_0000, "OPCODE '3' is not supported".to_string())]
    #[case(0b0_1101_0_0_0_0_000_0000, "OPCODE '13' is not supported".to_string())]
    #[case(0b0_1111_0_0_0_0_000_0000, "OPCODE '15' is not supported".to_string())]
    fn op_code_try_from_u16_fails(#[case] input: u16, #[case] error_msg: String) {
        let result = OpCode::try_from(input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), error_msg);
    }

    #[rstest]
    #[case(0b0_0000_0_0_0_0_000_0000)]
    fn z_try_from_u16_succeeds(#[case] input: u16) {
        let result = Z::try_from(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Z::AllZeros);
    }

    #[rstest]
    #[case(0b0_0000_0_0_0_0_001_0000)]
    #[case(0b0_0000_0_0_0_0_100_0000)]
    #[case(0b0_0000_0_0_0_0_111_0000)]
    fn z_try_from_u16_fails(#[case] input: u16) {
        let result = Z::try_from(input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "all Z bits most be zero");
    }

    #[rstest]
    #[case(0b0_0000_0_0_0_0_000_0000, RCode::NoError)]
    #[case(0b0_0000_0_0_0_0_000_0001, RCode::FormatError)]
    #[case(0b0_0000_0_0_0_0_000_0010, RCode::ServerFailure)]
    #[case(0b0_0000_0_0_0_0_000_0011, RCode::NameError)]
    #[case(0b0_0000_0_0_0_0_000_0100, RCode::NotImplemented)]
    #[case(0b0_0000_0_0_0_0_000_0101, RCode::Refused)]
    #[case(0b0_0000_0_0_0_0_000_0111, RCode::Reserved)]
    #[case(0b0_0000_0_0_0_0_000_1010, RCode::Reserved)]
    #[case(0b0_0000_0_0_0_0_000_1111, RCode::Reserved)]
    fn r_code_from_u16_works_correctly(#[case] input: u16, #[case] expected: RCode) {
        let r_code = RCode::from(input);
        assert_eq!(r_code, expected);
    }
}
