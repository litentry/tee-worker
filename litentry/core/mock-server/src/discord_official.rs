use crate::Mock;
use httpmock::prelude::*;
use lc_data_providers::discord_official::*;

// define mock api
trait MockDiscordOfficialAPI {
	fn query_message(&self, mock_server: &MockServer);
}

pub struct DiscordOfficialServer {
	// mock_server: MockServer,
}

impl DiscordOfficialServer {
	pub fn new() -> Self {
		DiscordOfficialServer {}
	}
}

impl MockDiscordOfficialAPI for DiscordOfficialServer {
	fn query_message(&self, mock_server: &MockServer) {
		let channel_id = "919848392035794945";
		let message_id = "";

		let user_id = "001";
		let username = "elon";
		let author = DiscordMessageAuthor { id: user_id.into(), username: username.into() };

		let body = DiscordMessage {
			id: message_id.into(),
			channel_id: channel_id.into(),
			content: "Hello, elon.".into(),
			author,
		};

		let path = format! {"/api/channels/{}/messages/{}", channel_id, message_id};
		mock_server.mock(|when, then| {
			when.method(GET).path(path);
			then.status(200).body(serde_json::to_string(&body).unwrap());
		});
	}
}

impl Mock for DiscordOfficialServer {
	fn mock(&self, mock_server: &MockServer) {
		self.query_message(mock_server);
	}
}
