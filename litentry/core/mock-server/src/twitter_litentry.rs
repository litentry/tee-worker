use crate::Mock;
use httpmock::prelude::*;
use lc_data_providers::Error;

// define mock api
trait MockTwitterLitAPI {
	fn check_follow(&self, mock_server: &MockServer);
}

pub struct TwitterLitServer {}

impl TwitterLitServer {
	pub fn new() -> Self {
		TwitterLitServer {}
	}
}

impl MockTwitterLitAPI for TwitterLitServer {
	fn check_follow(&self, mock_server: &MockServer) {
		let body: Result<bool, Error> = Ok(true);

		let path = "/twitter/followers/verification";
		mock_server.mock(|when, then| {
			when.method(GET)
				.path(path)
				.query_param("handler1", "ericzhangeth")
				.query_param("handler2", "litentry");
			then.status(200).body(serde_json::to_string(&body.unwrap()).unwrap());
		});
	}
}

impl Mock for TwitterLitServer {
	fn mock(&self, mock_server: &MockServer) {
		self.check_follow(mock_server);
	}
}
