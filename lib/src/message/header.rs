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

use crate::message::error::{
    HeaderTryFromError, OpCodeTryFromError, RCodeTryFromError, ZTryFromError,
};

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
#[derive(Debug, PartialEq)]
pub struct Header {
    pub id: u16,

    pub qr: QR,
    pub op_code: OpCode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub z: Z,
    pub r_code: RCode,

    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

impl TryFrom<&[u8]> for Header {
    type Error = HeaderTryFromError;

    /// Tries to convert a slice `&[u8]` into a DNS message `Header`.
    ///
    /// A valid DNS message header requires at least 12 bytes. Trying to convert
    /// a smaller slice will result in an error. Errors will also be triggered
    /// if any header flag is found to use reserved values.
    ///
    /// For more details, see [RFC 1035, Section 4.1.1].
    ///
    /// ```text
    ///                                 1  1  1  1  1  1
    ///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                      ID                       |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |QR|   OPCODE  |AA|TC|RD|RA|   Z    |   RCODE   |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    QDCOUNT                    |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    ANCOUNT                    |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    NSCOUNT                    |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    ARCOUNT                    |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    ///
    /// [RFC 1035, Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 12 {
            return Err(HeaderTryFromError::InsufficientHeaderBytes(value.len()));
        }

        let flags = u16::from_be_bytes([value[2], value[3]]);

        let op_code = OpCode::try_from(flags).map_err(|e| Self::Error::from(e))?;
        let z = Z::try_from(flags).map_err(|e| Self::Error::from(e))?;
        let r_code = RCode::try_from(flags).map_err(|e| Self::Error::from(e))?;

        Ok(Header {
            id: u16::from_be_bytes([value[0], value[1]]),
            qr: QR::from(flags),
            op_code,
            aa: parse_aa_flag(flags),
            tc: parse_tc_flag(flags),
            rd: parse_rd_flag(flags),
            ra: parse_ra_flag(flags),
            z,
            r_code,
            qd_count: u16::from_be_bytes([value[4], value[5]]),
            an_count: u16::from_be_bytes([value[6], value[7]]),
            ns_count: u16::from_be_bytes([value[8], value[9]]),
            ar_count: u16::from_be_bytes([value[10], value[11]]),
        })
    }
}

fn parse_aa_flag(value: u16) -> bool {
    (value & 0b0_0000_1_0_0_0_000_0000) >> 10 == 1
}

fn parse_tc_flag(value: u16) -> bool {
    (value & 0b0_0000_0_1_0_0_000_0000) >> 9 == 1
}

fn parse_rd_flag(value: u16) -> bool {
    (value & 0b0_0000_0_0_1_0_000_0000) >> 8 == 1
}

fn parse_ra_flag(value: u16) -> bool {
    (value & 0b0_0000_0_0_0_1_000_0000) >> 7 == 1
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
    /// Any other value will result in a `ZTryFromError`.
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
}

impl TryFrom<u16> for RCode {
    type Error = RCodeTryFromError;

    /// Tries to extract the `RCODE` from the flags portion of a DNS message
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
    /// With 4 bits available, `RCODE` _can_ have 16 possible values, but only
    /// 6 are supported:
    ///
    ///  - `0` No error condition
    ///  - `1` Format error
    ///  - `2` Server failure
    ///  - `3` Name error
    ///  - `4` Not implemented
    ///  - `5` Refused
    ///
    /// Unsupported values in range `6-15` will result in an
    /// `RCodeTryFromError`.
    ///
    /// For more details, see [RFC 1035, Section 4.1.1].
    ///
    /// # Example
    /// ```
    /// use dns_lib::message::RCode;
    ///
    /// let valid_rcode = 0b0_0000_0_0_0_0_000_0001; // 1, Format error
    /// assert!(RCode::try_from(valid_rcode).is_ok());
    ///
    /// let invalid_rcode = 0b0_0100_0_0_0_0_000_1000; // 8, Reserved
    /// assert!(RCode::try_from(invalid_rcode).is_err());
    /// ```
    ///
    /// [RFC 1035, Section 4.1.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value & 0b0_0000_0_0_0_0_000_1111 {
            0 => Ok(Self::NoError),
            1 => Ok(Self::FormatError),
            2 => Ok(Self::ServerFailure),
            3 => Ok(Self::NameError),
            4 => Ok(Self::NotImplemented),
            5 => Ok(Self::Refused),
            unspported => Err(RCodeTryFromError(unspported)),
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
    #[case(0b0_0011_0_0_0_0_000_0000, OpCodeTryFromError(3))]
    #[case(0b0_1101_0_0_0_0_000_0000, OpCodeTryFromError(13))]
    #[case(0b0_1111_0_0_0_0_000_0000, OpCodeTryFromError(15))]
    fn op_code_try_from_u16_fails(#[case] input: u16, #[case] err: OpCodeTryFromError) {
        let result = OpCode::try_from(input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), err);
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
        assert_eq!(result.unwrap_err(), ZTryFromError);
    }

    #[rstest]
    #[case(0b0_0000_0_0_0_0_000_0000, RCode::NoError)]
    #[case(0b0_0001_0_0_0_0_000_0001, RCode::FormatError)]
    #[case(0b0_0010_0_0_0_0_000_0010, RCode::ServerFailure)]
    #[case(0b0_0000_0_0_0_0_000_0011, RCode::NameError)]
    #[case(0b0_0001_0_0_0_0_000_0100, RCode::NotImplemented)]
    #[case(0b0_0010_0_0_0_0_000_0101, RCode::Refused)]
    fn r_code_try_from_u16_succeeds(#[case] input: u16, #[case] expected: RCode) {
        let result = RCode::try_from(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }

    #[rstest]
    #[case(0b0_0000_0_0_0_0_000_0110, RCodeTryFromError(6))]
    #[case(0b0_0000_0_0_0_0_000_1101, RCodeTryFromError(13))]
    #[case(0b0_0000_0_0_0_0_000_1111, RCodeTryFromError(15))]
    fn r_code_try_from_u16_fails(#[case] input: u16, #[case] err: RCodeTryFromError) {
        let result = RCode::try_from(input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), err);
    }

    #[rstest]
    #[case(
        // ID   , Flags                       , QD  , AN  , NS  , AR
        &[0, 255, 0b0_0000_0_0_0, 0b0_000_0000, 0, 1, 0, 0, 0, 0, 0, 0],
        Header{ id: 255, qr: QR::Query, op_code: OpCode::Query, aa: false, tc: false, rd: false, ra: false, z: Z::AllZeros, r_code: RCode::NoError, qd_count: 1, an_count: 0, ns_count: 0, ar_count: 0 }
    )]
    #[case(
        // ID   , Flags                       , QD  , AN  , NS  , AR        
        &[2, 255, 0b1_0010_0_1_0, 0b0_000_0000, 0, 2, 0, 0, 0, 0, 0, 1],
        Header{ id: 767, qr: QR::Response, op_code: OpCode::Status, aa: false, tc: true, rd: false, ra: false, z: Z::AllZeros, r_code: RCode::NoError, qd_count: 2, an_count: 0, ns_count: 0, ar_count: 1 }
    )]
    #[case(
        // ID , Flags                       , QD  , AN  , NS  , AR
        &[0, 1, 0b1_0001_1_1_1, 0b1_000_0011, 0, 4, 0, 4, 0, 4, 0, 4],
        Header{ id: 1, qr: QR::Response, op_code: OpCode::InverseQuery, aa: true, tc: true, rd: true, ra: true, z: Z::AllZeros, r_code: RCode::NameError, qd_count: 4, an_count: 4, ns_count: 4, ar_count: 4 }
    )]
    fn header_try_from_succeeds(#[case] input: &[u8], #[case] expected: Header) {
        let result = Header::try_from(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }

    #[rstest]
    #[case(&[0x01, 0x02], HeaderTryFromError::InsufficientHeaderBytes(2))]
    #[case(
        // ID   , Flags                       , QD  , AN  , NS  , AR
        &[0, 255, 0b0_0111_0_0_0, 0b0_000_0000, 0, 1, 0, 0, 0, 0, 0, 0],
        OpCodeTryFromError(7).into()
    )]
    #[case(
        // ID   , Flags                       , QD  , AN  , NS  , AR
        &[0, 255, 0b0_0000_0_0_0, 0b0_010_0000, 0, 1, 0, 0, 0, 0, 0, 0],
        ZTryFromError.into()
    )]
    #[case(
        // ID   , Flags                       , QD  , AN  , NS  , AR
        &[0, 255, 0b0_0000_0_0_0, 0b0_000_1100, 0, 1, 0, 0, 0, 0, 0, 0],
        RCodeTryFromError(12).into()
    )]
    fn header_try_from_fails(#[case] input: &[u8], #[case] expected: HeaderTryFromError) {
        let result = Header::try_from(input);
        assert_eq!(result.unwrap_err(), expected);
    }
}
