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
	get_layer_two_nonce,
	trusted_command_utils::{get_accountid_from_str, get_identifiers, get_pair_from_str},
	trusted_commands::{
		perform_operation, BlockNumber, EthAddress, EthSignature, LinkedEthereumAddress,
		LinkedSubstrateAddress, LinkingAccountIndex, TrustedArgs, UserShieldingKeyType,
	},
	Cli,
};
use codec::Decode;
use ita_stf::{Index, KeyPair, TrustedCall, TrustedGetter, TrustedOperation};
use litentry_primitives::{ValidationData, DID};
use log::*;
use pallet_sgx_account_linker::{MultiSignature, NetworkType};
use sp_application_crypto::Ss58Codec;
use sp_core::{sr25519 as sr25519_core, Pair};
use sp_runtime::{traits::ConstU32, BoundedVec};
use std::convert::TryFrom;

pub(crate) fn set_user_shielding_key(
	cli: &Cli,
	trusted_args: &TrustedArgs,
	arg_who: &str,
	key_hex: &str,
) {
	warn!("arg_who = {:?}, key = {:?}", arg_who, key_hex);
	let who = get_pair_from_str(trusted_args, arg_who);
	let root = get_pair_from_str(trusted_args, "//Alice");

	warn!("account ss58 is {}", who.public().to_ss58check());

	let (mrenclave, shard) = get_identifiers(trusted_args);
	let nonce = get_layer_two_nonce!(root, cli, trusted_args);
	let mut key = [0u8; 32];
	let _ = hex::decode_to_slice(key_hex, &mut key).expect("decoding key failed");
	let top: TrustedOperation =
		TrustedCall::set_user_shielding_key(root.public().into(), who.public().into(), key)
			.sign(&KeyPair::Sr25519(root), nonce, &mrenclave, &shard)
			.into_trusted_operation(trusted_args.direct);
	let _ = perform_operation(cli, trusted_args, &top);
}

pub(crate) fn shielding_key(cli: &Cli, trusted_args: &TrustedArgs, arg_who: &str) {
	debug!("arg_who = {:?}", arg_who);
	let who = get_pair_from_str(trusted_args, arg_who);
	let top: TrustedOperation = TrustedGetter::shielding_key(who.public().into())
		.sign(&KeyPair::Sr25519(who))
		.into();
	let key = perform_operation(cli, trusted_args, &top)
		.and_then(|v| UserShieldingKeyType::decode(&mut v.as_slice()).ok());
	println!("{}", hex::encode(&key.unwrap()));
}

pub(crate) fn linked_eth_addresses(cli: &Cli, trusted_args: &TrustedArgs, arg_who: &str) {
	debug!("arg_who = {:?}", arg_who);
	let who = get_pair_from_str(trusted_args, arg_who);
	let top: TrustedOperation = TrustedGetter::linked_ethereum_addresses(who.public().into())
		.sign(&KeyPair::Sr25519(who))
		.into();
	let res = perform_operation(cli, trusted_args, &top);
	debug!("received result for linked ethereum addresses");
	let addresses = if let Some(v) = res {
		if let Ok(vd) = LinkedEthereumAddress::decode(&mut v.as_slice()) {
			vd
		} else {
			info!("could not decode value. maybe hasn't been set? {:x?}", v);
			vec![]
		}
	} else {
		vec![]
	};
	println!("{:?}", addresses);
}

pub(crate) fn linked_sub_addresses(cli: &Cli, trusted_args: &TrustedArgs, arg_who: &str) {
	debug!("arg_who = {:?}", arg_who);
	let who = get_pair_from_str(trusted_args, arg_who);
	let top: TrustedOperation = TrustedGetter::linked_substrate_addresses(who.public().into())
		.sign(&KeyPair::Sr25519(who))
		.into();
	let res = perform_operation(cli, trusted_args, &top);
	debug!("received result for linked substrate addresses");
	let addresses = if let Some(v) = res {
		if let Ok(vd) = LinkedSubstrateAddress::decode(&mut v.as_slice()) {
			vd
		} else {
			info!("could not decode value. maybe hasn't been set? {:x?}", v);
			vec![]
		}
	} else {
		vec![]
	};
	println!("{:?}", addresses);
}

pub(crate) fn link_eth(
	cli: &Cli,
	trusted_args: &TrustedArgs,
	arg_who: &str,
	index: &LinkingAccountIndex,
	eth_address: &str,
	expiring_block_number: &BlockNumber,
	signature: &str,
) {
	// get the litentry account
	let account_pair = get_pair_from_str(trusted_args, arg_who);
	let account = get_accountid_from_str(arg_who);

	// get the ethereum address
	let mut eth_address_str = eth_address;

	if eth_address_str.starts_with("0x") {
		eth_address_str = &eth_address_str[2..]
	}

	let decoded_address = hex::decode(eth_address_str).unwrap();
	if decoded_address.len() != 20 {
		error!("ethereum address length is invalid");
		return
	}
	let mut eth_address: EthAddress = [0u8; 20];
	eth_address[0..20].copy_from_slice(&decoded_address[0..20]);

	// get the user signature
	let mut signature_str = signature;

	if signature_str.starts_with("0x") {
		signature_str = &signature_str[2..]
	}

	let decoded_signature = hex::decode(signature_str).unwrap();
	if decoded_signature.len() != 65 {
		error!("signature length is invalid");
		return
	}

	let mut signature: EthSignature = [0u8; 65];
	signature[0..65].copy_from_slice(&decoded_signature[0..65]);

	let (mrenclave, shard) = get_identifiers(trusted_args);
	// get nonce
	let top: TrustedOperation = TrustedGetter::nonce(account_pair.public().into())
		.sign(&KeyPair::Sr25519(account_pair.clone()))
		.into();
	let res = perform_operation(cli, trusted_args, &top);
	let nonce: Index = if let Some(n) = res {
		if let Ok(nonce) = Index::decode(&mut n.as_slice()) {
			nonce
		} else {
			info!("could not decode value. maybe hasn't been set? {:x?}", n);
			0
		}
	} else {
		0
	};
	debug!("got nonce: {:?}", nonce);

	// compose the extrinsic
	let top: TrustedOperation =
		TrustedCall::link_eth(account, *index, eth_address, *expiring_block_number, signature)
			.sign(&KeyPair::Sr25519(account_pair), nonce, &mrenclave, &shard)
			.into_trusted_operation(trusted_args.direct);
	let _ = perform_operation(cli, trusted_args, &top);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn link_sub(
	cli: &Cli,
	trusted_args: &TrustedArgs,
	arg_who: &str,
	index: &LinkingAccountIndex,
	network_type_str: &str,
	linked_account: &str,
	expiring_block_number: &BlockNumber,
	signature: &str,
) {
	// get the litentry account
	let account_pair = get_pair_from_str(trusted_args, arg_who);
	let account = get_accountid_from_str(arg_who);

	let mut linked_account_str = linked_account;

	if linked_account_str.starts_with("0x") {
		linked_account_str = &linked_account_str[2..]
	}

	let decoded_linked_account = hex::decode(linked_account_str).unwrap();
	if decoded_linked_account.len() != 32 {
		error!("substrate address length is invalid");
		return
	}

	let mut linked_account = [0; 32];
	linked_account[0..32].copy_from_slice(&decoded_linked_account[0..32]);

	let network_type: NetworkType;

	// get the network type
	if network_type_str.eq("Kusama") {
		network_type = NetworkType::Kusama;
	} else if network_type_str.eq("Polkadot") {
		network_type = NetworkType::Polkadot;
	} else if network_type_str.starts_with("Kusama") {
		let parachain_id_str = network_type_str.strip_prefix("Kusama").unwrap();
		let parachain_id: u32 = parachain_id_str.parse().unwrap();
		network_type = NetworkType::KusamaParachain(parachain_id);
	} else if network_type_str.starts_with("Polkadot") {
		let parachain_id_str = network_type_str.strip_prefix("Polkadot").unwrap();
		let parachain_id: u32 = parachain_id_str.parse().unwrap();
		network_type = NetworkType::PolkadotParachain(parachain_id);
	} else {
		error!("network type is invalid");
		return
	}

	// get mutli signature
	let multi_signature: MultiSignature;
	let multi_signature_str = signature;

	if multi_signature_str.starts_with("sr") {
		let signature_str = multi_signature_str.strip_prefix("sr").unwrap();
		let decoded_signature = hex::decode(signature_str).unwrap();
		if decoded_signature.len() != 64 {
			error!("signature length is invalid");
			return
		}
		let mut signature = [0u8; 64];
		signature[0..64].copy_from_slice(&decoded_signature[0..64]);

		multi_signature = MultiSignature::Sr25519Signature(signature);
	} else if multi_signature_str.starts_with("ed") {
		let signature_str = multi_signature_str.strip_prefix("ed").unwrap();
		let decoded_signature = hex::decode(signature_str).unwrap();
		if decoded_signature.len() != 64 {
			error!("signature length is invalid");
			return
		}
		let mut signature = [0u8; 64];
		signature[0..64].copy_from_slice(&decoded_signature[0..64]);

		multi_signature = MultiSignature::Ed25519Signature(signature);
	} else if multi_signature_str.starts_with("ecdsa") {
		let signature_str = multi_signature_str.strip_prefix("ecdsa").unwrap();
		let decoded_signature = hex::decode(signature_str).unwrap();
		if decoded_signature.len() != 65 {
			error!("signature length is invalid");
			return
		}
		let mut signature = [0u8; 65];
		signature[0..65].copy_from_slice(&decoded_signature[0..65]);

		multi_signature = MultiSignature::EcdsaSignature(signature);
	} else {
		error!("signature is invalid");
		return
	}

	let (mrenclave, shard) = get_identifiers(trusted_args);
	// get nonce
	let top: TrustedOperation = TrustedGetter::nonce(account_pair.public().into())
		.sign(&KeyPair::Sr25519(account_pair.clone()))
		.into();
	let res = perform_operation(cli, trusted_args, &top);
	let nonce: Index = if let Some(n) = res {
		if let Ok(nonce) = Index::decode(&mut n.as_slice()) {
			nonce
		} else {
			info!("could not decode value. maybe hasn't been set? {:x?}", n);
			0
		}
	} else {
		0
	};
	debug!("got nonce: {:?}", nonce);

	// compose the extrinsic
	let top: TrustedOperation = TrustedCall::link_sub(
		account,
		*index,
		network_type,
		linked_account.into(),
		*expiring_block_number,
		multi_signature,
	)
	.sign(&KeyPair::Sr25519(account_pair), nonce, &mrenclave, &shard)
	.into_trusted_operation(trusted_args.direct);
	let _ = perform_operation(cli, trusted_args, &top);
}

pub(crate) fn query_credit(cli: &Cli, trusted_args: &TrustedArgs, arg_who: &str) {
	// get the litentry account
	let account_pair = get_pair_from_str(trusted_args, arg_who);
	let account = get_accountid_from_str(arg_who);
	let (mrenclave, shard) = get_identifiers(trusted_args);

	let top: TrustedOperation = TrustedGetter::nonce(account_pair.public().into())
		.sign(&KeyPair::Sr25519(account_pair.clone()))
		.into();
	let res = perform_operation(cli, trusted_args, &top);

	let nonce: Index = if let Some(n) = res {
		if let Ok(nonce) = Index::decode(&mut n.as_slice()) {
			nonce
		} else {
			info!("could not decode value. maybe hasn't been set? {:x?}", n);
			0
		}
	} else {
		0
	};
	debug!("got nonce: {:?}", nonce);
	// compose the extrinsic
	let top: TrustedOperation = TrustedCall::query_credit(account)
		.sign(&KeyPair::Sr25519(account_pair), nonce, &mrenclave, &shard)
		.into_trusted_operation(trusted_args.direct);
	let _ = perform_operation(cli, trusted_args, &top);
}

pub fn link_identity(cli: &Cli, trusted_args: &TrustedArgs, arg_who: &str, arg_did: &str) {
	// get the litentry account
	let account_pair = get_pair_from_str(trusted_args, arg_who);
	let account = get_accountid_from_str(arg_who);
	let (mrenclave, shard) = get_identifiers(trusted_args);

	let top: TrustedOperation = TrustedGetter::nonce(account_pair.public().into())
		.sign(&KeyPair::Sr25519(account_pair.clone()))
		.into();
	let res = perform_operation(cli, trusted_args, &top);

	let nonce: Index = if let Some(n) = res {
		if let Ok(nonce) = Index::decode(&mut n.as_slice()) {
			nonce
		} else {
			info!("could not decode value. maybe hasn't been set? {:x?}", n);
			0
		}
	} else {
		0
	};
	debug!("who: {:?} got nonce: {:?}", arg_who, nonce);

	let encode_did: Vec<u8> = arg_did.as_bytes().to_vec();
	let did = BoundedVec::<u8, ConstU32<128>>::try_from(encode_did);
	if did.is_ok() {
		// compose the extrinsic
		let top: TrustedOperation =
			TrustedCall::link_identity(get_accountid_from_str("//Alice"), account, did.unwrap())
				.sign(&KeyPair::Sr25519(account_pair), nonce, &mrenclave, &shard)
				.into_trusted_operation(trusted_args.direct);
		let _ = perform_operation(cli, trusted_args, &top);
	}
}

pub fn set_challenge_code(
	cli: &Cli,
	trusted_args: &TrustedArgs,
	arg_who: &str,
	arg_did: &str,
	code: u32,
) {
	// get the litentry account
	let account_pair = get_pair_from_str(trusted_args, arg_who);
	let account = get_accountid_from_str(arg_who);
	let (mrenclave, shard) = get_identifiers(trusted_args);

	let top: TrustedOperation = TrustedGetter::nonce(account_pair.public().into())
		.sign(&KeyPair::Sr25519(account_pair.clone()))
		.into();
	let res = perform_operation(cli, trusted_args, &top);

	let nonce: Index = if let Some(n) = res {
		if let Ok(nonce) = Index::decode(&mut n.as_slice()) {
			nonce
		} else {
			info!("could not decode value. maybe hasn't been set? {:x?}", n);
			0
		}
	} else {
		0
	};
	debug!("who: {:?} got nonce: {:?}", arg_who, nonce);

	let encode_did: Vec<u8> = arg_did.as_bytes().to_vec();
	let did = BoundedVec::<u8, ConstU32<128>>::try_from(encode_did);
	if did.is_ok() {
		// compose the extrinsic
		let top: TrustedOperation = TrustedCall::set_challenge_code(
			get_accountid_from_str("//Alice"),
			account,
			did.unwrap(),
			code,
		)
		.sign(&KeyPair::Sr25519(account_pair), nonce, &mrenclave, &shard)
		.into_trusted_operation(trusted_args.direct);
		let _ = perform_operation(cli, trusted_args, &top);
	}
}

pub fn prepare_verify_identity(
	cli: &Cli,
	trusted_args: &TrustedArgs,
	arg_who: &str,
	arg_did: &str,
	arg_validation_data: &str,
) {
	// get the litentry account
	let account_pair = get_pair_from_str(trusted_args, arg_who);
	let account = get_accountid_from_str(arg_who);
	let (mrenclave, shard) = get_identifiers(trusted_args);

	let top: TrustedOperation = TrustedGetter::nonce(account_pair.public().into())
		.sign(&KeyPair::Sr25519(account_pair.clone()))
		.into();
	let res = perform_operation(cli, trusted_args, &top);

	let nonce: Index = if let Some(n) = res {
		if let Ok(nonce) = Index::decode(&mut n.as_slice()) {
			nonce
		} else {
			info!("could not decode value. maybe hasn't been set? {:x?}", n);
			0
		}
	} else {
		0
	};
	debug!("who: {:?} got nonce: {:?}", arg_who, nonce);
	let validation_data = serde_json::from_str(arg_validation_data);
	if let Err(e) = validation_data {
		warn!("Deserialize obj error: {:?}", e.to_string());
		return
	}
	let validation_data = validation_data.unwrap();
	// let tweet_id = arg_tweet_id.as_bytes().to_vec();
	let did = DID::try_from(arg_did.as_bytes().to_vec());
	// compose the extrinsic
	if let Ok(did) = did {
		let top: TrustedOperation = TrustedCall::prepare_verify_identity(
			get_accountid_from_str("//Alice"),
			account,
			did,
			validation_data,
		)
		.sign(&KeyPair::Sr25519(account_pair), nonce, &mrenclave, &shard)
		.into_trusted_operation(trusted_args.direct);
		let _ = perform_operation(cli, trusted_args, &top);
	}
}
