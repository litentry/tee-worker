#[macro_use]
extern crate lazy_static;

use std::{
	sync::Mutex,
	thread::{spawn, JoinHandle},
};

use httpmock::{standalone::start_standalone_server, MockServer};
use tokio::task::LocalSet;

mod discord_litentry;
mod discord_official;
mod twitter_litentry;
mod twitter_official;

use discord_litentry::DiscordLitServer;
use discord_official::DiscordOfficialServer;
use twitter_litentry::TwitterLitServer;
use twitter_official::TwitterOfficialServer;

// Mock trait
pub trait Mock {
	fn mock(&self, mock_server: &MockServer);
}

pub fn standalone_server() {
	let _ = STANDALONE_SERVER.lock().unwrap_or_else(|e| e.into_inner());
}

lazy_static! {
	static ref STANDALONE_SERVER: Mutex<JoinHandle<Result<(), String>>> = Mutex::new(spawn(|| {
		let srv = start_standalone_server(9527, false, None, false, usize::MAX);
		let mut runtime =
			tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
		LocalSet::new().block_on(&mut runtime, srv)
	}));
}

pub struct LitMockServerManager {
	mock_server: MockServer,
	servers: Vec<Box<dyn Mock>>,
}

impl LitMockServerManager {
	pub fn new() -> Self {
		let servers = vec![];
		let mock_server = httpmock::MockServer::connect("localhost:9527");

		LitMockServerManager { mock_server, servers }
	}

	pub fn resigter_server(&mut self, server: Box<dyn Mock>) {
		// unimplemented!();
		self.servers.push(server);
	}

	fn mock(&self) {
		for server in self.servers.iter() {
			server.mock(&self.mock_server);
		}
	}
}

pub fn run() {
	standalone_server();

	// println!("*** Litentry Mock server is starting ...");
	let mut mock_server = LitMockServerManager::new();

	// discord litentry
	let discord_litentry = Box::new(DiscordLitServer::new());
	mock_server.resigter_server(discord_litentry);

	// discord official
	let discord_official = Box::new(DiscordOfficialServer::new());
	mock_server.resigter_server(discord_official);

	// twitter litentry
	let twitter_litentry = Box::new(TwitterLitServer::new());
	mock_server.resigter_server(twitter_litentry);

	// twitter official
	let twitter_official = Box::new(TwitterOfficialServer::new());
	mock_server.resigter_server(twitter_official);

	mock_server.mock();
}
