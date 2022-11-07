#[macro_use]
extern crate lazy_static;

use std::{
	sync::Mutex,
	thread::{spawn, JoinHandle},
};

use codec::Encode;
use httpmock::{standalone::start_standalone_server, MockServer};
use itp_types::AccountId;
use litentry_primitives::{ChallengeCode, Identity};
use sp_core::blake2_256;
use tokio::task::LocalSet;

// Mock trait
pub trait Mock {
	fn mock(&self, mock_server: &MockServer);
}

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
