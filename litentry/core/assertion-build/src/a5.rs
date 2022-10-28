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

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

use crate::Error;
use lc_data_providers::{
	twitter_litentry::TwitterLitentryClient, twitter_official::TwitterOfficialClient,
};
use litentry_primitives::{
	Identity, IdentityHandle, IdentityWebType, ParameterString, Web2Network,
};
use std::{format, string::ToString};

pub fn build(identity: Identity, original_tweet_id: ParameterString) -> Result<(), Error> {
	let litentry_twitter = "litentry".as_bytes().to_vec();

	let _ = match identity.web_type {
		IdentityWebType::Web2(Web2Network::Twitter) => Ok(()),
		_ => Err(Error::AssertionOtherError("Assertion5 only support twitter".to_string())),
	}?;

	let twitter_id = match identity.handle {
		IdentityHandle::String(id) => Ok(id),
		_ => Err(Error::AssertionOtherError(
			"Assertion5 only support IdentityHandle::String type".to_string(),
		)),
	}?;
	let twitter_id = twitter_id.to_vec();

	let mut twitter_litentry = TwitterLitentryClient::new();
	let is_followed = twitter_litentry
		.check_follow(twitter_id.clone(), litentry_twitter)
		.map_err(|e| Error::AssertionOtherError(format!("{:?}", e)))?;

	match is_followed {
		true => {
			let mut twitter_official = TwitterOfficialClient::new();
			let tweets = twitter_official
				.query_retweet(twitter_id, original_tweet_id.to_vec())
				.map_err(|e| Error::AssertionOtherError(format!("{:?}", e)))?;
			if tweets.data.len() > 0 {
				// TODO generate vc;
			} else {
				log::error!("cant not find retweet");
			}
		},
		false => {
			log::error!("account:{:?} don't follow litentry", twitter_id);
		},
	}
	Ok(())
}
