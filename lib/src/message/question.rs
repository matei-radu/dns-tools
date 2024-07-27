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

use crate::domain::{error, Domain};

#[derive(Debug, PartialEq)]
pub struct Question {
    pub q_name: Domain,
    pub q_type: QType,
    pub q_class: QClass,
}

#[derive(Debug, PartialEq)]
pub struct QuestionParseData {
    pub question: Question,
    pub bytes_read: usize,
}

pub fn parse_question(
    message_bytes: &[u8],
    offset: usize,
) -> Result<QuestionParseData, error::TryFromError> {
    let mut question_pos = offset;
    let mut using_compression = false;
    let mut bytes_read: usize = 0;

    let mut q_name = Domain::new();
    let mut pos = question_pos;
    loop {
        // Are the current and next bytes a pointer?
        if (message_bytes[pos] & 0b11000000) == 0b11000000 {
            if !using_compression {
                bytes_read += 2;
                question_pos = pos + 2;
                using_compression = true;
            }
            let pointer_first_6_bits = (u16::from(message_bytes[pos]) & 0b00111111) << 8;
            let pointer_last_8_bits = u16::from(message_bytes[pos + 1]);
            let pointer = pointer_first_6_bits | pointer_last_8_bits;
            pos = pointer as usize;
            continue;
        }

        let label_length = message_bytes[pos] as usize;

        // zero length indicates end of QNAME portion.
        if label_length == 0 {
            pos += 1;
            if !using_compression {
                bytes_read += 1;
                question_pos = pos;
            }
            break;
        }

        // Go into first byte of the label
        pos += 1;
        if !using_compression {
            bytes_read += 1;
        }
        let label_slice = &message_bytes[pos..pos + label_length];

        // Attempt to parse label, add to domain.
        match q_name.add_label(label_slice) {
            Ok(()) => {
                pos += label_length;
                if !using_compression {
                    bytes_read += label_length;
                }
            }
            Err(e) => return Err(e),
        }
    }

    let q_type_raw =
        u16::from_be_bytes([message_bytes[question_pos], message_bytes[question_pos + 1]]);
    let q_type = QType::new(q_type_raw);

    question_pos += 2;
    bytes_read += 2;
    let q_class_raw =
        u16::from_be_bytes([message_bytes[question_pos], message_bytes[question_pos + 1]]);
    let q_class = QClass::new(q_class_raw);

    bytes_read += 2;

    let question = Question {
        q_name,
        q_type,
        q_class,
    };

    Ok(QuestionParseData {
        question,
        bytes_read,
    })
}

#[derive(Debug)]
pub struct QType {
    pub value: u16,
}

impl QType {
    pub fn new(value: u16) -> Self {
        QType { value }
    }

    pub fn to_known_type(&self) -> Option<KnownQType> {
        match self.value {
            1 => Some(KnownQType::A),
            2 => Some(KnownQType::NS),
            3 => Some(KnownQType::MD),
            4 => Some(KnownQType::MF),
            5 => Some(KnownQType::CNAME),
            6 => Some(KnownQType::SOA),
            7 => Some(KnownQType::MB),
            8 => Some(KnownQType::MG),
            9 => Some(KnownQType::MR),
            10 => Some(KnownQType::NULL),
            11 => Some(KnownQType::WKS),
            12 => Some(KnownQType::PTR),
            13 => Some(KnownQType::HINFO),
            14 => Some(KnownQType::MINFO),
            15 => Some(KnownQType::MX),
            16 => Some(KnownQType::TXT),
            252 => Some(KnownQType::AXFR),
            253 => Some(KnownQType::MAILB),
            254 => Some(KnownQType::MAILA),
            255 => Some(KnownQType::ANY),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u16)]
pub enum KnownQType {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    ANY = 255,
}

impl From<KnownQType> for QType {
    fn from(value: KnownQType) -> Self {
        QType {
            value: value as u16,
        }
    }
}

impl PartialEq<u16> for QType {
    fn eq(&self, other: &u16) -> bool {
        self.value == *other
    }
}

impl PartialEq<QType> for u16 {
    fn eq(&self, other: &QType) -> bool {
        *self == other.value
    }
}

impl PartialEq<KnownQType> for QType {
    fn eq(&self, other: &KnownQType) -> bool {
        self.value == *other as u16
    }
}

impl PartialEq<QType> for KnownQType {
    fn eq(&self, other: &QType) -> bool {
        *self as u16 == other.value
    }
}

impl PartialEq for QType {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

#[derive(Debug)]
pub struct QClass {
    pub value: u16,
}

impl QClass {
    pub fn new(value: u16) -> Self {
        QClass { value }
    }

    pub fn to_known_class(&self) -> Option<KnownQClass> {
        match self.value {
            1 => Some(KnownQClass::IN),
            2 => Some(KnownQClass::CS),
            3 => Some(KnownQClass::CH),
            4 => Some(KnownQClass::HS),
            255 => Some(KnownQClass::ANY),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u16)]
pub enum KnownQClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    ANY = 255,
}

impl From<KnownQClass> for QClass {
    fn from(value: KnownQClass) -> Self {
        QClass {
            value: value as u16,
        }
    }
}

impl PartialEq<u16> for QClass {
    fn eq(&self, other: &u16) -> bool {
        self.value == *other
    }
}

impl PartialEq<QClass> for u16 {
    fn eq(&self, other: &QClass) -> bool {
        *self == other.value
    }
}

impl PartialEq<KnownQClass> for QClass {
    fn eq(&self, other: &KnownQClass) -> bool {
        self.value == *other as u16
    }
}

impl PartialEq<QClass> for KnownQClass {
    fn eq(&self, other: &QClass) -> bool {
        *self as u16 == other.value
    }
}

impl PartialEq for QClass {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(1, KnownQType::A)]
    #[case(5, KnownQType::CNAME)]
    #[case(16, KnownQType::TXT)]
    #[case(15, KnownQType::MX)]
    #[case(255, KnownQType::ANY)]
    fn qtype_new(#[case] input: u16, #[case] expected: KnownQType) {
        let q_type = QType::new(input);
        assert_eq!(q_type.value, input);
        assert_eq!(q_type, expected);
    }

    #[rstest]
    #[case(1, Some(KnownQType::A))]
    #[case(2, Some(KnownQType::NS))]
    #[case(3, Some(KnownQType::MD))]
    #[case(4, Some(KnownQType::MF))]
    #[case(5, Some(KnownQType::CNAME))]
    #[case(6, Some(KnownQType::SOA))]
    #[case(7, Some(KnownQType::MB))]
    #[case(8, Some(KnownQType::MG))]
    #[case(9, Some(KnownQType::MR))]
    #[case(10, Some(KnownQType::NULL))]
    #[case(11, Some(KnownQType::WKS))]
    #[case(12, Some(KnownQType::PTR))]
    #[case(13, Some(KnownQType::HINFO))]
    #[case(14, Some(KnownQType::MINFO))]
    #[case(15, Some(KnownQType::MX))]
    #[case(16, Some(KnownQType::TXT))]
    #[case(252, Some(KnownQType::AXFR))]
    #[case(253, Some(KnownQType::MAILB))]
    #[case(254, Some(KnownQType::MAILA))]
    #[case(255, Some(KnownQType::ANY))]
    #[case(1024, None)]
    fn qtype_to_known_type(#[case] input: u16, #[case] expected: Option<KnownQType>) {
        assert_eq!(QType::new(input).to_known_type(), expected);
    }

    #[rstest]
    #[case(KnownQType::A)]
    #[case(KnownQType::SOA)]
    #[case(KnownQType::AXFR)]
    #[case(KnownQType::NS)]
    #[case(KnownQType::ANY)]
    fn qtype_from_known_qtype(#[case] input: KnownQType) {
        assert_eq!(QType::from(input), input);
    }

    #[rstest]
    #[case(1)]
    #[case(5)]
    #[case(16)]
    #[case(255)]
    #[case(2048)]
    fn qtype_compare_u16(#[case] input: u16) {
        assert_eq!(QType::new(input), input);
        assert_eq!(input, QType::new(input));
    }

    #[rstest]
    #[case(1, KnownQClass::IN)]
    #[case(2, KnownQClass::CS)]
    #[case(4, KnownQClass::HS)]
    #[case(255, KnownQClass::ANY)]
    fn qclass_new(#[case] input: u16, #[case] expected: KnownQClass) {
        let q_class = QClass::new(input);
        assert_eq!(q_class.value, input);
        assert_eq!(q_class, expected);
    }

    #[rstest]
    #[case(1, Some(KnownQClass::IN))]
    #[case(2, Some(KnownQClass::CS))]
    #[case(3, Some(KnownQClass::CH))]
    #[case(4, Some(KnownQClass::HS))]
    #[case(255, Some(KnownQClass::ANY))]
    #[case(1024, None)]
    fn qclass_to_known_type(#[case] input: u16, #[case] expected: Option<KnownQClass>) {
        assert_eq!(QClass::new(input).to_known_class(), expected);
    }

    #[rstest]
    #[case(KnownQClass::IN)]
    #[case(KnownQClass::CS)]
    #[case(KnownQClass::CH)]
    #[case(KnownQClass::HS)]
    #[case(KnownQClass::ANY)]
    fn qclass_from_known_qclass(#[case] input: KnownQClass) {
        assert_eq!(QClass::from(input), input);
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(4)]
    #[case(255)]
    #[case(2048)]
    fn qclass_compare_u16(#[case] input: u16) {
        assert_eq!(QClass::new(input), input);
        assert_eq!(input, QClass::new(input));
    }

    #[rstest]
    #[case(
        // example.com, A, IN, 17 bytes
        &[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1],
        0,
        QuestionParseData{
            question: Question{
                q_name: Domain::try_from("example.com".to_string()).unwrap(),
                q_type: QType::from(KnownQType::A),
                q_class: QClass::from(KnownQClass::IN),
            },
            bytes_read: 17,
        }
    )]
    #[case(
        // example.com, A, IN, 17 bytes, but using offset
        &[0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1],
        3,
        QuestionParseData{
            question: Question{
                q_name: Domain::try_from("example.com".to_string()).unwrap(),
                q_type: QType::from(KnownQType::A),
                q_class: QClass::from(KnownQClass::IN),
            },
            bytes_read: 17,
        }
    )]
    #[case(
        // test.example.com, A, IN, 11 bytes, but using compression for example.com
        &[0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 4, b't', b'e', b's', b't', 0b11000000, 3, 0, 1, 0, 1],
        16,
        QuestionParseData{
            question: Question{
                q_name: Domain::try_from("test.example.com".to_string()).unwrap(),
                q_type: QType::from(KnownQType::A),
                q_class: QClass::from(KnownQClass::IN),
            },
            bytes_read: 11,
        }
    )]
    #[case(
        // test.example.com, A, IN, 11 bytes, but using nested compression for example.com
        &[3, b'c', b'o', b'm', 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0b11000000, 0, 4, b't', b'e', b's', b't', 0b11000000, 5, 0, 1, 0, 1],
        15,
        QuestionParseData{
            question: Question{
                q_name: Domain::try_from("test.example.com".to_string()).unwrap(),
                q_type: QType::from(KnownQType::A),
                q_class: QClass::from(KnownQClass::IN),
            },
            bytes_read: 11,
        }
    )]
    fn parse_question_works(
        #[case] input: &[u8],
        #[case] offset: usize,
        #[case] expected: QuestionParseData,
    ) {
        let result = parse_question(input, offset);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }
}
