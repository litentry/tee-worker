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
	default::Default,
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
pub struct TwitterAPIV2Response<T> {
	pub data: Option<T>,
	pub meta: Option<ResponseMeta>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ResponseMeta {
	pub result_count: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Tweet {
	pub author_id: String,
	pub id: String,
	pub text: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TwitterUser {
	pub id: String,
	pub name: String,
	pub username: String,
	pub public_metrics: TwitterUserPublicMetrics,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TwitterUserPublicMetrics {
	pub followers_count: u32,
	pub following_count: u32,
}

impl RestPath<String> for Tweet {
	fn get_path(path: String) -> core::result::Result<String, HttpError> {
		Ok(path)
	}
}

impl<T> RestPath<String> for TwitterAPIV2Response<T> {
	fn get_path(path: String) -> core::result::Result<String, HttpError> {
		Ok(path)
	}
}

impl UserInfo for Tweet {
	fn get_user_id(&self) -> Option<String> {
		Some(self.author_id.clone())
	}
}

pub struct TwitterOfficialClient {
	client: RestClient<HttpClient<DefaultSend>>,
}

impl Default for TwitterOfficialClient {
	fn default() -> Self {
		Self::new()
	}
}

/// rate limit: https://developer.twitter.com/en/docs/twitter-api/rate-limits
impl TwitterOfficialClient {
	pub fn new() -> Self {
		let mut headers = Headers::new();
		headers.insert(CONNECTION.as_str(), "close");
		let token = std::env::var("TWITTER_AUTHORIZATION_TOKEN");
		if let Ok(token) = token {
			headers.insert(AUTHORIZATION.as_str(), token.as_str());
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
	) -> Result<Tweet, Error> {
		let original_tweet_id = vec_to_string(original_tweet_id)?;
		let user = vec_to_string(user)?;
		let query_value = format!("from: {} retweets_of_tweet_id: {}", user, original_tweet_id);
		let query: Vec<(&str, &str)> =
			vec![("query", query_value.as_str()), ("expansions", "author_id")];
		let resp = self
			.client
			.get_with::<String, TwitterAPIV2Response<Vec<Tweet>>>(
				"/2/tweets/search/recent".to_string(),
				query.as_slice(),
			)
			.map_err(|e| Error::RequestError(format!("{:?}", e)))?;
		let tweets = resp.data.ok_or_else(|| Error::RequestError("tweet not found".to_string()))?;
		if !tweets.is_empty() {
			Ok(tweets.get(0).unwrap().clone())
		} else {
			Err(Error::RequestError("tweet not found".to_string()))
		}
	}

	/// rate limit: 300/15min(per App) 900/15min(per User)
	pub fn query_user(&mut self, user: Vec<u8>) -> Result<TwitterUser, Error> {
		let user = vec_to_string(user)?;
		let query = vec![("user.fields", "public_metrics")];
		let resp = self
			.client
			.get_with::<String, TwitterAPIV2Response<TwitterUser>>(
				format!("/2/users/{}", user),
				query.as_slice(),
			)
			.map_err(|e| Error::RequestError(format!("{:?}", e)))?;
		let user = resp.data.ok_or_else(|| Error::RequestError("user not found".to_string()))?;
		Ok(user)
	}
}

#[cfg(test)]
mod tests {
	use crate::twitter_official::TwitterOfficialClient;

	#[test]
	fn query_retweet_work() {
		std::env::set_var("TWITTER_AUTHORIZATION_TOKEN", "Bearer ");
		let mut client = TwitterOfficialClient::new();
		let result = client.query_retweet(
			"2934243054".as_bytes().to_vec(),
			"1584490517391626240".as_bytes().to_vec(),
		);
		println!("query_retweet_work {:?}", result);
		// assert!(result.is_ok(), "error: {:?}", result);
	}

	#[test]
	fn query_user_work() {
		std::env::set_var("TWITTER_AUTHORIZATION_TOKEN", "Bearer ");
		let mut client = TwitterOfficialClient::new();
		let result = client.query_user("1256908613857226756".as_bytes().to_vec());
		println!("query_user_work {:?}", result);
		// assert!(result.is_ok(), "error: {:?}", result);
	}
}
