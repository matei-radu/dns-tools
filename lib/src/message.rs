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

    pub qr: bool,
    pub opcode: u8, // Actually 4-bit, prefer a custom type here
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub z: u8,     // Acutally 3 bits, prefer a custom type here,
    pub rcode: u8, // Acutally 4 bits, prefer a custom type here,

    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}
