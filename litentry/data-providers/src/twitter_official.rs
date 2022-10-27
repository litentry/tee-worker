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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{base_url::TWITTER_OFFICIAL, build_client, vec_to_string, Error, HttpError, UserInfo};
use http::header::{AUTHORIZATION, CONNECTION};
use http_req::response::Headers;
use serde::{Deserialize, Serialize};
use std::{
	format,
	string::{String, ToString},
	vec,
	vec::Vec,
};

use itc_rest_client::{
	http_client::{DefaultSend, HttpClient},
	rest_client::RestClient,
	RestGet, RestPath,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct Tweets {
	pub data: Vec<Tweet>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Tweet {
	pub author_id: String,
	pub id: String,
	pub text: String,
}

// #[derive(Serialize, Deserialize, Debug)]
// pub struct TweetExpansions {
// 	pub users: Vec<TweetAuthor>,
// }
//
// #[derive(Serialize, Deserialize, Debug)]
// pub struct TweetAuthor {
// 	pub id: String,
// 	pub name: String,
// 	pub username: String,
// }

impl RestPath<String> for Tweet {
	fn get_path(path: String) -> core::result::Result<String, HttpError> {
		Ok(path)
	}
}

impl RestPath<String> for Tweets {
	fn get_path(path: String) -> core::result::Result<String, HttpError> {
		Ok(path)
	}
}

impl UserInfo for Tweet {
	fn get_user_id(&self) -> Option<String> {
		Some(self.author_id.clone())
	}
}

impl UserInfo for Tweets {
	fn get_user_id(&self) -> Option<String> {
		self.data.get(0).map_or_else(|| None, |v| Some(v.author_id.clone()))
	}
}

pub struct TwitterOfficialClient {
	client: RestClient<HttpClient<DefaultSend>>,
}

/// rate limit: https://developer.twitter.com/en/docs/twitter-api/rate-limits
impl TwitterOfficialClient {
	pub fn new() -> Self {
		let mut headers = Headers::new();
		headers.insert(CONNECTION.as_str(), "close");
		let token = std::env::var("TWITTER_AUTHORIZATION_TOKEN");
		if token.is_ok() {
			headers.insert(AUTHORIZATION.as_str(), token.unwrap().as_str());
		}
		let client = build_client(TWITTER_OFFICIAL, headers);
		TwitterOfficialClient { client }
	}

	/// rate limit: 300/15min(per App) 900/15min(per User)
	pub fn query_tweet(&mut self, tweet_id: Vec<u8>) -> Result<Tweet, Error> {
		let tweet_id = vec_to_string(tweet_id)?;
		let path = format!("/2/tweets/{}", tweet_id);
		let query: Vec<(&str, &str)> =
			vec![("ids", tweet_id.as_str()), ("expansions", "author_id")];
		self.client
			.get_with::<String, Tweet>(path, query.as_slice())
			.map_err(|e| Error::RequestError(format!("{:?}", e)))
	}

	/// rate limit: 450/15min(per App) 180/15min(per User)
	///
	/// Building queries for Search Tweets: https://developer.twitter.com/en/docs/twitter-api/tweets/search/integrate/build-a-query
	pub fn query_retweet(
		&mut self,
		user: Vec<u8>,
		original_tweet_id: Vec<u8>,
	) -> Result<Tweets, Error> {
		let original_tweet_id = vec_to_string(original_tweet_id)?;
		let user = vec_to_string(user)?;
		let query_value = format!("from: {} retweets_of_tweet_id: {}", user, original_tweet_id);
		let query: Vec<(&str, &str)> =
			vec![("query", query_value.as_str()), ("expansions", "author_id")];
		self.client
			.get_with::<String, Tweets>("/2/tweets/search/recent".to_string(), query.as_slice())
			.map_err(|e| Error::RequestError(format!("{:?}", e)))
	}
}
