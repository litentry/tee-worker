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
use crate::error::{Error, Result};
use lazy_static::lazy_static;
use std::sync::{
	mpsc::{channel, Receiver, Sender},
	Arc,
};

#[cfg(feature = "sgx")]
use std::sync::SgxMutex as Mutex;

use crate::RequestType;
#[cfg(feature = "std")]
use std::sync::Mutex;

pub type XTSender = Sender<RequestType>;

// Global storage of the sender. Should not be accessed directly.
lazy_static! {
	static ref GLOBAL_XT_DAEMON: Arc<Mutex<Option<XTDaemonSender>>> =
		Arc::new(Mutex::new(Default::default()));
}

/// Trait to send an extrinsic request to the extrinsic request daemon.
pub trait SendXTRequest {
	fn send_xt_request(&self, request: RequestType) -> Result<()>;
}

/// Struct to access the `send_xt_request` function.
pub struct XTRequestSender {}
impl XTRequestSender {
	pub fn new() -> Self {
		Self {}
	}
}

impl Default for XTRequestSender {
	fn default() -> Self {
		Self::new()
	}
}

impl SendXTRequest for XTRequestSender {
	fn send_xt_request(&self, request: RequestType) -> Result<()> {
		// Acquire lock on extrinsic sender
		let mutex_guard = GLOBAL_XT_DAEMON.lock().map_err(|_| Error::MutexAccess)?;

		let stf_task_sender = mutex_guard.clone().ok_or(Error::ComponentNotInitialized)?;

		// Release mutex lock, so we don't block the lock longer than necessary.
		drop(mutex_guard);

		// Send the request to the receiver loop.
		stf_task_sender.send(request)
	}
}

/// Initialization of the extrinsic sender. Needs to be called before any sender access.
pub fn init_stf_task_sender_storage() -> Result<Receiver<RequestType>> {
	let (sender, receiver) = channel();
	let mut xt_daemon_storage = GLOBAL_XT_DAEMON.lock().map_err(|_| Error::MutexAccess)?;
	*xt_daemon_storage = Some(XTDaemonSender::new(sender));
	Ok(receiver)
}

/// Wrapping struct around the actual sender. Should not be accessed directly.
#[derive(Clone, Debug)]
struct XTDaemonSender {
	sender: XTSender,
}

impl XTDaemonSender {
	pub fn new(sender: XTSender) -> Self {
		Self { sender }
	}

	fn send(&self, request: RequestType) -> Result<()> {
		self.sender.send(request).map_err(|e| Error::Other(e.into()))?;
		Ok(())
	}
}
