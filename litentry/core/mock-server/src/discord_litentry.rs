use crate::Mock;
use httpmock::prelude::*;
use lc_data_providers::discord_litentry::*;

// define mock api
trait MockDiscordLitentryAPI {
	fn check_join(&self, mock_server: &MockServer);
	fn check_id_hubber(&self, mock_server: &MockServer);
}

pub struct DiscordLitServer {}

impl DiscordLitServer {
	pub fn new() -> Self {
		DiscordLitServer {}
	}
}

impl MockDiscordLitentryAPI for DiscordLitServer {
	fn check_join(&self, mock_server: &MockServer) {
		let body = DiscordResponse {
			data: true,
			message: "success".into(),
			has_errors: false,
			msg_code: 200,
			success: true,
		};

		mock_server.mock(|when, then| {
			when.method(GET)
				.path("/discord/joined")
				.query_param("guildid", "919848390156767232")
				.query_param("handler", "againstwar#4779");

			then.status(200).body(serde_json::to_string(&body).unwrap());
		});
	}

	fn check_id_hubber(&self, mock_server: &MockServer) {
		let body = DiscordResponse {
			data: true,
			message: "success".into(),
			has_errors: false,
			msg_code: 200,
			success: true,
		};

		mock_server.mock(|when, then| {
			when.method(GET)
				.path("/discord/commented/idhubber")
				.query_param("guildid", "919848390156767232")
				.query_param("handler", "ericzhang.eth#0114");

			then.status(200).body(serde_json::to_string(&body).unwrap());
		});
	}
}

impl Mock for DiscordLitServer {
	fn mock(&self, mock_server: &MockServer) {
		self.check_join(mock_server);
		self.check_id_hubber(mock_server);
	}
}
