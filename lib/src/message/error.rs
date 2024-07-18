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

use std::error::Error;
use std::fmt;

#[derive(Debug, PartialEq)]
pub struct OpCodeTryFromError(pub u16);

impl fmt::Display for OpCodeTryFromError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "OPCODE '{}' is not supported", self.0)
    }
}

impl Error for OpCodeTryFromError {}

#[derive(Debug, PartialEq)]
pub struct ZTryFromError;

impl fmt::Display for ZTryFromError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "all Z bits most be zero")
    }
}

impl Error for ZTryFromError {}

#[derive(Debug, PartialEq)]
pub struct RCodeTryFromError(pub u16);

impl fmt::Display for RCodeTryFromError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RCODE '{}' is not supported", self.0)
    }
}

impl Error for RCodeTryFromError {}

#[derive(Debug, PartialEq)]
pub enum MalformedFlagsError {
    OpCode(OpCodeTryFromError),
    Z(ZTryFromError),
    RCode(RCodeTryFromError),
}

impl fmt::Display for MalformedFlagsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MalformedFlagsError::OpCode(e) => e.fmt(f),
            MalformedFlagsError::Z(e) => e.fmt(f),
            MalformedFlagsError::RCode(e) => e.fmt(f),
        }
    }
}

impl Error for MalformedFlagsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            MalformedFlagsError::OpCode(e) => Some(e),
            MalformedFlagsError::Z(e) => Some(e),
            MalformedFlagsError::RCode(e) => Some(e),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum HeaderTryFromError {
    InsufficientHeaderBytes(usize),
    MalformedFlags(MalformedFlagsError),
}

impl fmt::Display for HeaderTryFromError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HeaderTryFromError::InsufficientHeaderBytes(len) => {
                write!(f, "insufficient header bytes ({} found, 12 required)", len)
            }
            HeaderTryFromError::MalformedFlags(e) => e.fmt(f),
        }
    }
}

impl Error for HeaderTryFromError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            HeaderTryFromError::MalformedFlags(e) => Some(e),
            _ => None,
        }
    }
}
