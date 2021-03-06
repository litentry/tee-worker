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
use crate::{
	error::{Error, Result},
	Request,
};
use lazy_static::lazy_static;
use std::sync::{
	mpsc::{channel, Receiver, Sender},
	Arc,
};

#[cfg(feature = "sgx")]
use std::sync::SgxMutex as Mutex;

#[cfg(feature = "std")]
use std::sync::Mutex;

pub type HttpsSender = Sender<Request>;

// Global storage of the sender. Should not be accessed directly.
lazy_static! {
	static ref GLOBAL_HTTPS_DAEMON: Arc<Mutex<Option<HttpsDaemonSender>>> =
		Arc::new(Mutex::new(Default::default()));
}

/// Trait to send an https request to the https client daemon.
pub trait SendHttpsRequest {
	fn send_https_request(&self, request: Request) -> Result<()>;
}

/// Struct to access the `send_https_request` function.
pub struct HttpRequestSender {}
impl HttpRequestSender {
	pub fn new() -> Self {
		Self {}
	}
}

impl Default for HttpRequestSender {
	fn default() -> Self {
		Self::new()
	}
}

impl SendHttpsRequest for HttpRequestSender {
	fn send_https_request(&self, request: Request) -> Result<()> {
		// Acquire lock on https sender
		let mutex_guard = GLOBAL_HTTPS_DAEMON.lock().map_err(|_| Error::MutexAccess)?;

		let daemon_sender = mutex_guard.clone().ok_or(Error::ComponentNotInitialized)?;

		// Release mutex lock, so we don't block the lock longer than necessary.
		drop(mutex_guard);

		// Send the request to the receiver loop.
		daemon_sender.send(request)
	}
}

/// Initialization of the https sender. Needs to be called before any sender access.
pub fn init_https_daemon_sender_storage() -> Result<Receiver<Request>> {
	let (sender, receiver) = channel();
	let mut https_daemon_storage = GLOBAL_HTTPS_DAEMON.lock().map_err(|_| Error::MutexAccess)?;
	*https_daemon_storage = Some(HttpsDaemonSender::new(sender));
	Ok(receiver)
}

/// Wrapping struct around the actual sender. Should not be accessed directly.
#[derive(Clone, Debug)]
struct HttpsDaemonSender {
	sender: HttpsSender,
}

impl HttpsDaemonSender {
	pub fn new(sender: HttpsSender) -> Self {
		Self { sender }
	}

	fn send(&self, request: Request) -> Result<()> {
		self.sender.send(request).map_err(|e| Error::Other(e.into()))?;
		Ok(())
	}
}
