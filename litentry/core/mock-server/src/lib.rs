// Copyright 2020-2022 Litentry Technologies GmbH.
// This file is part of Litentry.
//
// Litentry is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Litentry is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Litentry.  If not, see <https://www.gnu.org/licenses/>.

#[macro_use]
extern crate lazy_static;

use std::{
	sync::Mutex,
	thread::{spawn, JoinHandle},
};

use codec::Encode;
use httpmock::standalone::start_standalone_server;
use itp_types::AccountId;
use litentry_primitives::{ChallengeCode, Identity};
use sp_core::blake2_256;
use tokio::task::LocalSet;

pub fn standalone_server() {
	let _server = STANDALONE_SERVER.lock().unwrap_or_else(|e| e.into_inner());
}

lazy_static! {
	static ref STANDALONE_SERVER: Mutex<JoinHandle<Result<(), String>>> = Mutex::new(spawn(|| {
		let srv = start_standalone_server(9527, false, None, false, usize::MAX);
		let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
		LocalSet::new().block_on(&runtime, srv)
	}));
}

pub fn mock_tweet_payload(who: &AccountId, identity: &Identity, code: &ChallengeCode) -> Vec<u8> {
	let mut payload = code.encode();
	payload.append(&mut who.encode());
	payload.append(&mut identity.encode());

	blake2_256(payload.as_slice()).to_vec()
}
