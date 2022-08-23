/*
	Copyright 2022 Integritee AG and Supercomputing Systems AG

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/

use rand::Rng;

pub trait ChallengeCodeGenerator {
	fn generate(&mut self) -> String;
}

#[derive(Default)]
pub struct NumericChallengeCode {
	pub name: String,
	pub len: u8,
}

impl ChallengeCodeGenerator for NumericChallengeCode{
	fn generate(&mut self) -> String {
		if self.len == 0 {
			self.len = 6;
		}

		let mut rng = rand::thread_rng();
		let first_digit: u8 = rng.gen_range(0..=9) + 48;
		let mut code = vec![first_digit];

		while code.len() < self.len as usize {
			code.push(rng.gen_range(0..=9) + 48);
		}

		String::from_utf8(code).unwrap()
	}
}

#[derive(Default)]
pub struct CharChallengeCode {
	pub name: String,
	pub len: u8,
}

impl ChallengeCodeGenerator for CharChallengeCode{
	fn generate(&mut self) -> String {
		if self.len == 0 {
			self.len = 6;
		}

		let mut rng = rand::thread_rng();
		let first_digit: u8 = rng.gen_range(0..=16) + 65;
		let mut code = vec![first_digit];

		while code.len() < self.len as usize {
			if rng.gen_range(0..=1) == 0 {
				code.push(rng.gen_range(0..=9) + 65);
			} else {
				code.push(rng.gen_range(0..=9) + 48);
			}
		}

		String::from_utf8(code).unwrap()
	}
}

#[test]
fn gen_code(){
	let mut ncode = NumericChallengeCode {
		name: String::from("my numeric challenge code"),
		..Default::default()
	};

	let ncode_str = ncode.generate();
	assert_eq!(ncode_str.len(), 6);

	let mut ccode = CharChallengeCode {
		name: String::from("my character challenge code"),
		len: 10
	};

	let ccode_str = ccode.generate();
	assert_ne!(ccode_str.len(), 6);
	assert_eq!(ccode_str.len(), ccode.len as usize);
}

