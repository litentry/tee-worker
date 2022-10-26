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

use super::*;

#[derive(Serialize, Deserialize, Debug)]
pub struct DiscordResponse {
	pub id: String, // message_id
	pub channel_id: String,
	pub content: String,
	pub author: DiscordMessageAuthor,
}

impl RestPath<String> for DiscordResponse {
	fn get_path(path: String) -> core::result::Result<String, HttpError> {
		Ok(path)
	}
}

impl UserInfo for DiscordResponse {
	fn get_user_id(&self) -> Option<String> {
		Some(self.author.id.clone())
	}
}

impl<K: ShieldingCryptoDecrypt> DecryptionVerificationPayload<K> for DiscordResponse {
	fn decrypt_ciphertext(&self, _key: K) -> Result<Vec<u8>, Error> {
		let data = &self.content;
		if data.starts_with("0x") {
			let bytes = &data.as_bytes()[b"0x".len()..];
			hex::decode(bytes).map_err(|e| Error::OtherError(format!("Hex error: {:?}", e)))
		} else {
			hex::decode(data.as_bytes())
				.map_err(|e| Error::OtherError(format!("Hex error: {:?}", e)))
		}

		// key.decrypt(self.content.as_bytes())
		// 	.map_err(|e| Error::OtherError(format!("decrypt error: {:?}", e)))

		// mock data -- to be removed
		// let payload = VerificationPayload {
		// 	owner: "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d".to_string(), // alice public key
		// 	code: 1134,
		// 	//identiy json: {"web_type":{"Web2":"Discord"},"handle":{"String":[108,105,116,101,110,116,114,121]}}
		// 	identity: Identity {
		// 		web_type: IdentityWebType::Web2(Web2Network::Discord),
		// 		handle: IdentityHandle::String(
		// 			IdentityString::try_from("litentry".as_bytes().to_vec()).unwrap(),
		// 		),
		// 	},
		// };
		// Ok(payload)
	}
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DiscordMessageAuthor {
	pub id: String, //user_id
	pub username: String,
}
