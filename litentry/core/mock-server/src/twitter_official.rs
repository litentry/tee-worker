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

use httpmock::{Method::GET, MockServer};
use itp_types::AccountId;
use lc_data_providers::twitter_official::*;
use litentry_primitives::{
	ChallengeCode, Identity, IdentityHandle, IdentityString, IdentityWebType, Web2Network,
};

use crate::{mock_tweet_payload, Mock};

pub trait TwitterOfficialAPI {
	fn query_tweet(mock_server: &MockServer);
	fn query_retweet(mock_server: &MockServer);
	fn query_user(mock_server: &MockServer);
}

pub struct TwitterOfficial {}
impl TwitterOfficial {
	pub fn new() -> Self {
		TwitterOfficial {}
	}
}

impl Default for TwitterOfficial {
	fn default() -> Self {
		Self::new()
	}
}

impl TwitterOfficialAPI for TwitterOfficial {
	fn query_tweet(mock_server: &MockServer) {
		let tweet_id = "100";

		let account_id = AccountId::new([0u8; 32]);
		let twitter_identity = Identity {
			web_type: IdentityWebType::Web2(Web2Network::Twitter),
			handle: IdentityHandle::String(
				IdentityString::try_from("litentry".as_bytes().to_vec()).unwrap(),
			),
		};
		let chanllenge_code: ChallengeCode =
			[8, 104, 90, 56, 35, 213, 18, 250, 213, 210, 119, 241, 2, 174, 24, 8];
		let payload = mock_tweet_payload(&account_id, &twitter_identity, &chanllenge_code);

		let tweet = Tweet {
			author_id: "ericzhangeth".into(),
			id: tweet_id.into(),
			text: serde_json::to_string(&payload).unwrap(),
		};

		let path = format! {"/2/tweets/{}", tweet_id};
		mock_server.mock(|when, then| {
			when.method(GET)
				.path(path)
				.query_param("ids", tweet_id)
				.query_param("expansions", "author_id");
			then.status(200).body(serde_json::to_string(&tweet).unwrap());
		});
	}

	fn query_retweet(mock_server: &MockServer) {
		let author_id = "ericzhangeth";
		let id = "100";

		let account_id = AccountId::new([0u8; 32]);
		let twitter_identity = Identity {
			web_type: IdentityWebType::Web2(Web2Network::Twitter),
			handle: IdentityHandle::String(
				IdentityString::try_from("litentry".as_bytes().to_vec()).unwrap(),
			),
		};
		let chanllenge_code: ChallengeCode =
			[8, 104, 90, 56, 35, 213, 18, 250, 213, 210, 119, 241, 2, 174, 24, 8];
		let payload = mock_tweet_payload(&account_id, &twitter_identity, &chanllenge_code);

		let tweets = vec![Tweet {
			author_id: author_id.into(),
			id: id.into(),
			text: serde_json::to_string(&payload).unwrap(),
		}];
		let body = TwitterAPIV2Response { data: Some(tweets), meta: None };

		let path = "/2/tweets/search/recent";

		let user = "ericzhangeth";
		let original_tweet_id = "100";
		let query_value = format!("from: {} retweets_of_tweet_id: {}", user, original_tweet_id);

		mock_server.mock(|when, then| {
			when.method(GET)
				.path(path)
				.query_param("query", query_value)
				.query_param("expansions", "author_id");
			then.status(200).body(serde_json::to_string(&body).unwrap());
		});
	}

	fn query_user(mock_server: &MockServer) {
		let user = "1256908613857226756";

		let twitter_user_data = TwitterUser {
			id: user.into(),
			name: "ericzhang".into(),
			username: "elon".into(),
			public_metrics: TwitterUserPublicMetrics {
				followers_count: 100_u32,
				following_count: 99_u32,
			},
		};

		let body = TwitterAPIV2Response { data: Some(twitter_user_data), meta: None };

		let path = format! {"/2/users/{}", user};

		mock_server.mock(|when, then| {
			when.method(GET).path(path).query_param("user.fields", "public_metrics");
			then.status(200).body(serde_json::to_string(&body).unwrap());
		});
	}
}

impl Mock for TwitterOfficial {
	fn mock(&self, mock_server: &httpmock::MockServer) {
		TwitterOfficial::query_tweet(mock_server);
		TwitterOfficial::query_retweet(mock_server);
		TwitterOfficial::query_user(mock_server);
	}
}
