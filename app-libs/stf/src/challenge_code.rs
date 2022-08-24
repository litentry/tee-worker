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

use rand::Rng;

pub trait ChallengeCodeGenerator {
	fn generate(&mut self) -> String;
}

#[derive(Default)]
pub struct AlphanumericChallengeCode {
	pub len: usize,
}

impl ChallengeCodeGenerator for AlphanumericChallengeCode{
	fn generate(&mut self) -> String {
		if self.len == 0 {
			self.len = 6;
		}
		const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
								abcdefghijklmnopqrstuvwxyz\
								0123456789)(*&^%$#@!~";
		let mut rng = rand::thread_rng();

		let password: String = (0..self.len)
			.map(|_| {
				let idx = rng.gen_range(0..CHARSET.len());
				CHARSET[idx] as char
			})
			.collect();

		password
	}
}

#[test]
fn gen_code(){
	let mut a_code = AlphanumericChallengeCode {
		..Default::default()
	};

	let passwd = a_code.generate();
	assert_eq!(passwd.len(), 6);


	let mut a_code = AlphanumericChallengeCode {
		len: 40
	};

	let passwd = a_code.generate();
	assert_ne!(passwd.len(), 6);
	assert_eq!(passwd.len(), a_code.len);
}
