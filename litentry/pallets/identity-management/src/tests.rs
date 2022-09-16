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

use crate::{
	identity_context::IdentityContext, mock::*, BlockNumberOf, DidOf, Error, MetadataOf,
	UserShieldingKeyType,
};
use frame_support::{assert_noop, assert_ok};
use litentry_primitives::USER_SHIELDING_KEY_LEN;

#[test]
fn set_user_shielding_key_works() {
	new_test_ext().execute_with(|| {
		let shielding_key: UserShieldingKeyType = [0u8; USER_SHIELDING_KEY_LEN];
		assert_eq!(IMT::user_shielding_keys(2), None);
		assert_ok!(IMT::set_user_shielding_key(Origin::signed(1), 2, shielding_key.clone()));
		assert_eq!(IMT::user_shielding_keys(2), Some(shielding_key.clone()));
		System::assert_last_event(Event::IMT(crate::Event::UserShieldingKeySet {
			who: 2,
			key: shielding_key,
		}));
	});
}

#[test]
fn link_identity_works() {
	new_test_ext().execute_with(|| {
		let did: DidOf<Test> =
			"did:polkadot:web3:substrate:0x1234".as_bytes().to_vec().try_into().unwrap();
		let metadata: MetadataOf<Test> = vec![0u8; 16].try_into().unwrap();
		assert_ok!(IMT::link_identity(
			Origin::signed(1),
			2,
			did.clone(),
			Some(metadata.clone()),
			1
		));
		assert_eq!(
			IMT::id_graphs(2, did).unwrap(),
			IdentityContext {
				metadata: Some(metadata),
				linking_request_block: Some(1),
				verification_request_block: None,
				is_verified: false,
			}
		);
	});
}

#[test]
fn unlink_identity_works() {
	new_test_ext().execute_with(|| {
		let did: DidOf<Test> =
			"did:polkadot:web3:substrate:0x1234".as_bytes().to_vec().try_into().unwrap();
		let metadata: MetadataOf<Test> = vec![0u8; 16].try_into().unwrap();
		assert_noop!(
			IMT::unlink_identity(Origin::signed(1), 2, did.clone()),
			Error::<Test>::IdentityNotExist
		);
		assert_ok!(IMT::link_identity(
			Origin::signed(1),
			2,
			did.clone(),
			Some(metadata.clone()),
			1
		));
		assert_eq!(
			IMT::id_graphs(2, did.clone()).unwrap(),
			IdentityContext {
				metadata: Some(metadata),
				linking_request_block: Some(1),
				verification_request_block: None,
				is_verified: false,
			}
		);
		assert_ok!(IMT::unlink_identity(Origin::signed(1), 2, did.clone()));
		assert_eq!(IMT::id_graphs(2, did), None);
	});
}

#[test]
fn verify_identity_works() {
	new_test_ext().execute_with(|| {
		let did: DidOf<Test> =
			"did:polkadot:web3:substrate:0x1234".as_bytes().to_vec().try_into().unwrap();
		let metadata: MetadataOf<Test> = vec![0u8; 16].try_into().unwrap();
		assert_ok!(IMT::link_identity(
			Origin::signed(1),
			2,
			did.clone(),
			Some(metadata.clone()),
			1
		));
		assert_ok!(IMT::verify_identity(Origin::signed(1), 2, did.clone(), 1));
		assert_eq!(
			IMT::id_graphs(2, did).unwrap(),
			IdentityContext {
				metadata: Some(metadata),
				linking_request_block: Some(1),
				verification_request_block: Some(1),
				is_verified: true,
			}
		);
	});
}

#[test]
fn get_did_and_identity_context_works() {
	new_test_ext().execute_with(|| {
		let did3: DidOf<Test> =
			"did:polkadot:web3:substrate:0x1234".as_bytes().to_vec().try_into().unwrap();
		let metadata3: MetadataOf<Test> = vec![0u8; 16].try_into().unwrap();
		assert_ok!(IMT::link_identity(
			Origin::signed(1),
			2,
			did3.clone(),
			Some(metadata3.clone()),
			3
		));
		assert_ok!(IMT::verify_identity(Origin::signed(1), 2, did3.clone(), 3));

		let did2: DidOf<Test> =
			"did:twitter:web2:_:myTwitterHandle".as_bytes().to_vec().try_into().unwrap();
		let metadata2: MetadataOf<Test> = vec![0u8; 16].try_into().unwrap();
		assert_ok!(IMT::link_identity(
			Origin::signed(1),
			2,
			did2.clone(),
			Some(metadata2.clone()),
			2
		));
		assert_ok!(IMT::verify_identity(Origin::signed(1), 2, did2.clone(), 2));

		let did_contex = IMT::get_did_and_identity_context(&2);
		assert_eq!(did_contex.len(), 2);
	});
}

#[test]
fn verify_identity_fails_when_too_early() {
	new_test_ext().execute_with(|| {
		const LINKNIG_REQUEST_BLOCK: BlockNumberOf<Test> = 2;
		const VERIFICATION_REQUEST_BLOCK: BlockNumberOf<Test> = 1;

		let did: DidOf<Test> =
			"did:polkadot:web3:substrate:0x1234".as_bytes().to_vec().try_into().unwrap();
		let metadata: MetadataOf<Test> = vec![0u8; 16].try_into().unwrap();
		assert_ok!(IMT::link_identity(
			Origin::signed(1),
			2,
			did.clone(),
			Some(metadata.clone()),
			LINKNIG_REQUEST_BLOCK
		));
		assert_noop!(
			IMT::verify_identity(Origin::signed(1), 2, did.clone(), VERIFICATION_REQUEST_BLOCK),
			Error::<Test>::VerificationRequestTooEarly
		);
		assert_eq!(
			IMT::id_graphs(2, did).unwrap(),
			IdentityContext {
				metadata: Some(metadata),
				linking_request_block: Some(LINKNIG_REQUEST_BLOCK),
				verification_request_block: None,
				is_verified: false,
			}
		);
	});
}

#[test]
fn verify_identity_fails_when_too_late() {
	new_test_ext().execute_with(|| {
		const LINKNIG_REQUEST_BLOCK: BlockNumberOf<Test> = 1;
		const VERIFICATION_REQUEST_BLOCK: BlockNumberOf<Test> = 5;

		let did: DidOf<Test> =
			"did:polkadot:web3:substrate:0x1234".as_bytes().to_vec().try_into().unwrap();
		let metadata: MetadataOf<Test> = vec![0u8; 16].try_into().unwrap();
		assert_ok!(IMT::link_identity(
			Origin::signed(1),
			2,
			did.clone(),
			Some(metadata.clone()),
			LINKNIG_REQUEST_BLOCK
		));
		assert_noop!(
			IMT::verify_identity(Origin::signed(1), 2, did.clone(), VERIFICATION_REQUEST_BLOCK),
			Error::<Test>::VerificationRequestTooLate
		);
		assert_eq!(
			IMT::id_graphs(2, did).unwrap(),
			IdentityContext {
				metadata: Some(metadata),
				linking_request_block: Some(LINKNIG_REQUEST_BLOCK),
				verification_request_block: None,
				is_verified: false,
			}
		);
	});
}
