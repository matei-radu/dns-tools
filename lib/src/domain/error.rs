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

use crate::domain;
use std::error::Error;
use std::fmt;
use std::string::FromUtf8Error;

#[derive(Debug, PartialEq)]
pub enum TryFromError {
    DomainEmpty,
    LabelEmpty,
    LabelTooLong(String),
    LabelInvalidEncoding(FromUtf8Error),
    LabelInvalidFormat(String),
}

impl fmt::Display for TryFromError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::DomainEmpty => write!(f, "domain is empty"),
            Self::LabelEmpty => write!(f, "label is empty"),
            Self::LabelTooLong(msg) => write!(
                f,
                "label '{}' exceeds the maximum allowed length of {} characters",
                msg,
                domain::name::MAX_LABEL_LENGTH
            ),
            Self::LabelInvalidFormat(msg) => write!(f, "label '{}' has invalid format", msg),
            Self::LabelInvalidEncoding(err) => {
                write!(f, "label has invalid encoding format: {}", err)
            }
        }
    }
}

impl Error for TryFromError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::LabelInvalidEncoding(err) => Some(err),
            _ => None,
        }
    }
}
