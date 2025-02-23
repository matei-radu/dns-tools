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

use dns_lib::VERSION as LIB_VERSION;

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn fmt_version_info() -> String {
    format!("dns_cli v{}\ndns_lib v{}\n", APP_VERSION, LIB_VERSION)
}
