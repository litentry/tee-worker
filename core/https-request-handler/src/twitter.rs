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

use crate::*;

#[derive(Serialize, Deserialize, Debug)]
pub struct TwitterResponse {
	pub data: Vec<Tweet>,
	pub includes: TweetExpansions,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Tweet {
	pub author_id: String,
	pub id: String,
	pub text: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TweetExpansions {
	pub users: Vec<TweetAuthor>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TweetAuthor {
	pub id: String,
	pub name: String,
	pub username: String,
}

impl RestPath<String> for TwitterResponse {
	fn get_path(path: String) -> core::result::Result<String, HttpError> {
		Ok(path)
	}
}

impl UserInfo for TwitterResponse {
	fn get_user_id(&self) -> Option<String> {
		self.data.get(0).map_or_else(|| None, |v| Some(v.author_id.clone()))
	}
}

impl<K: ShieldingCryptoDecrypt> DecryptionVerificationPayload<K> for TwitterResponse {
	fn decrypt_ciphertext(&self, _key: K) -> Result<VerificationPayload, Error> {
		// TODO decrypt
		// if self.data.len() > 0 {
		// 	key.decrypt(self.data.get(0).unwrap().text.as_bytes());
		// }

		// mock data
		let payload = VerificationPayload {
			owner: "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d".to_string(), // alice public key
			code: 1134,
			//identiy json: {"web_type":{"Web2":"Twitter"},"handle":{"String":[108,105,116,101,110,116,114,121]}}
			identity: Identity {
				web_type: IdentityWebType::Web2(Web2Network::Twitter),
				handle: IdentityHandle::String(
					IdentityString::try_from("litentry".as_bytes().to_vec()).unwrap(),
				),
			},
		};
		Ok(payload)
	}
}
