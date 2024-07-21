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
pub enum HeaderTryFromError {
    InsufficientHeaderBytes(usize),
    OpCodeTryFromError(OpCodeTryFromError),
    ZTryFromError(ZTryFromError),
    RCodeTryFromError(RCodeTryFromError),
}

impl From<OpCodeTryFromError> for HeaderTryFromError {
    fn from(error: OpCodeTryFromError) -> HeaderTryFromError {
        HeaderTryFromError::OpCodeTryFromError(error)
    }
}

impl From<ZTryFromError> for HeaderTryFromError {
    fn from(error: ZTryFromError) -> HeaderTryFromError {
        HeaderTryFromError::ZTryFromError(error)
    }
}

impl From<RCodeTryFromError> for HeaderTryFromError {
    fn from(error: RCodeTryFromError) -> HeaderTryFromError {
        HeaderTryFromError::RCodeTryFromError(error)
    }
}

impl fmt::Display for HeaderTryFromError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HeaderTryFromError::InsufficientHeaderBytes(len) => {
                write!(f, "insufficient header bytes ({} found, 12 required)", len)
            }
            HeaderTryFromError::OpCodeTryFromError(e) => e.fmt(f),
            HeaderTryFromError::ZTryFromError(e) => e.fmt(f),
            HeaderTryFromError::RCodeTryFromError(e) => e.fmt(f),
        }
    }
}

impl Error for HeaderTryFromError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            HeaderTryFromError::OpCodeTryFromError(e) => Some(e),
            HeaderTryFromError::ZTryFromError(e) => Some(e),
            HeaderTryFromError::RCodeTryFromError(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(HeaderTryFromError::InsufficientHeaderBytes(3), "insufficient header bytes (3 found, 12 required)".to_string())]
    #[case(OpCodeTryFromError(14).into(), "OPCODE '14' is not supported".to_string())]
    #[case(ZTryFromError.into(), "all Z bits most be zero".to_string())]
    #[case(RCodeTryFromError(7).into(), "RCODE '7' is not supported".to_string())]
    fn header_try_from_error_display(#[case] err: HeaderTryFromError, #[case] msg: String) {
        assert_eq!(err.to_string(), msg);
    }
}
