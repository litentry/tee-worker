use crate::Mock;
use httpmock::prelude::*;
use lc_data_providers::{twitter_official::*, Error};

// define mock api
trait MockTwitterOfficialAPI {
	fn query_tweet(&self, mock_server: &MockServer);
	fn query_retweet(&self, mock_server: &MockServer);
}

pub struct TwitterOfficialServer {
	// mock_server: MockServer,
}

impl TwitterOfficialServer {
	pub fn new() -> Self {
		TwitterOfficialServer {}
	}
}

impl MockTwitterOfficialAPI for TwitterOfficialServer {
	fn query_tweet(&self, mock_server: &MockServer) {
		let author_id = "ericzhangeth".into();
		let id = "100".into();
		let text = "hello, elon.".into();

		let tweet = Tweet { author_id, id, text };

		let body: Result<Tweet, Error> = Ok(tweet);

		let tweet_id = "";
		let path = format! {"/2/tweets/{}", tweet_id};

		mock_server.mock(|when, then| {
			when.method(GET)
				.path(path)
				.query_param("ids", tweet_id)
				.query_param("expansions", "author_id");
			then.status(200).body(serde_json::to_string(&body.unwrap()).unwrap());
		});
	}

	fn query_retweet(&self, mock_server: &MockServer) {
		let author_id = "ericzhangeth".into();
		let id = "100".into();
		let text = "hello, elon.".into();
		let tweets = vec![Tweet { author_id, id, text }];
		let data = Tweets { data: tweets };
		let body: Result<Tweets, Error> = Ok(data);

		let path = "/2/tweets/search/recent";

		let user = "ericzhangeth";
		let original_tweet_id = "100";
		let query_value = format!("from: {} retweets_of_tweet_id: {}", user, original_tweet_id);

		mock_server.mock(|when, then| {
			when.method(GET)
				.path(path)
				.query_param("query", query_value)
				.query_param("expansions", "author_id");
			then.status(200).body(serde_json::to_string(&body.unwrap()).unwrap());
		});
	}
}

impl Mock for TwitterOfficialServer {
	fn mock(&self, mock_server: &MockServer) {
		self.query_tweet(mock_server);
		self.query_retweet(mock_server);
	}
}
