/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
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

use crate::{
	attestation,
	ocall::OcallApi,
	rpc,
	sync::tests::{enclave_rw_lock_works, sidechain_rw_lock_works},
	test::{
		cert_tests::*,
		fixtures::initialize_test_state::init_state,
		mocks::{rpc_responder_mock::RpcResponderMock, types::TestStateKeyRepo},
		sidechain_aura_tests, top_pool_tests,
	},
	tls_ra,
};
use codec::{Decode, Encode};
use ita_stf::{
	helpers::{
		account_key_hash, get_parentchain_blockhash, get_parentchain_number,
		get_parentchain_parenthash,
	},
	stf_sgx_tests,
	test_genesis::endowed_account as funded_pair,
	AccountInfo, ShardIdentifier, State, StatePayload, StateTypeDiff, Stf, TrustedCall,
	TrustedCallSigned, TrustedGetter, TrustedOperation,
};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_settings::{
	enclave::MAX_TRUSTED_OPS_EXEC_DURATION,
	node::{PROPOSED_SIDECHAIN_BLOCK, SIDECHAIN_MODULE},
};
use itp_sgx_crypto::{
	ed25519_derivation::DeriveEd25519, mocks::KeyRepositoryMock, Aes, StateCrypto,
};
use itp_stf_executor::{
	enclave_signer_tests as stf_enclave_signer_tests, executor::StfExecutor,
	executor_tests as stf_executor_tests, traits::StateUpdateProposer, BatchExecutionResult,
};
use itp_stf_state_handler::handle_state::HandleState;
use itp_test::mock::{
	handle_state_mock, handle_state_mock::HandleStateMock, metrics_ocall_mock::MetricsOCallMock,
	shielding_crypto_mock::ShieldingCryptoMock,
};
use itp_top_pool::{basic_pool::BasicPool, pool::ExtrinsicHash};
use itp_top_pool_author::{
	api::SidechainApi, author::Author, test_utils::submit_operation_to_top_pool,
	top_filter::AllowAllTopsFilter, traits::AuthorApi,
};
use itp_types::{AccountId, Block, Header, MrEnclave, OpaqueCall};
use its_sidechain::{
	block_composer::{BlockComposer, ComposeBlockAndConfirmation},
	state::{SidechainDB, SidechainState, SidechainSystemExt},
	top_pool_executor::{TopPoolCallOperator, TopPoolOperationHandler},
};
use sgx_externalities::{SgxExternalities, SgxExternalitiesTrait};
use sgx_tunittest::*;
use sgx_types::size_t;
use sidechain_primitives::{
	traits::{
		Block as BlockTrait, BlockData, Header as SidechainHeaderTrait,
		SignedBlock as SignedBlockTrait,
	},
	types::block::SignedBlock,
};
use sp_core::{crypto::Pair, ed25519 as spEd25519, H256};
use sp_runtime::traits::Header as HeaderT;
use std::{string::String, sync::Arc, vec::Vec};

use pallet_sgx_account_linker;

type TestRpcResponder = RpcResponderMock<ExtrinsicHash<SidechainApi<Block>>>;
type TestTopPool = BasicPool<SidechainApi<Block>, Block, TestRpcResponder>;
type TestShieldingKeyRepo = KeyRepositoryMock<ShieldingCryptoMock>;
type TestStfExecutor = StfExecutor<OcallApi, HandleStateMock>;
type TestTopPoolAuthor = Author<
	TestTopPool,
	AllowAllTopsFilter,
	HandleStateMock,
	TestShieldingKeyRepo,
	MetricsOCallMock,
>;
type TestTopPoolOperationHandler =
	TopPoolOperationHandler<Block, SignedBlock, TestTopPoolAuthor, TestStfExecutor>;

#[no_mangle]
pub extern "C" fn test_main_entrance() -> size_t {
	rsgx_unit_tests!(
		attestation::tests::decode_spid_works,
		stf_sgx_tests::enclave_account_initialization_works,
		stf_sgx_tests::shield_funds_increments_signer_account_nonce,
		stf_sgx_tests::test_root_account_exists_after_initialization,
		itp_stf_state_handler::test::sgx_tests::test_write_and_load_state_works,
		itp_stf_state_handler::test::sgx_tests::test_sgx_state_decode_encode_works,
		itp_stf_state_handler::test::sgx_tests::test_encrypt_decrypt_state_type_works,
		itp_stf_state_handler::test::sgx_tests::test_write_access_locks_read_until_finished,
		itp_stf_state_handler::test::sgx_tests::test_ensure_subsequent_state_loads_have_same_hash,
		itp_stf_state_handler::test::sgx_tests::test_state_handler_file_backend_is_initialized,
		itp_stf_state_handler::test::sgx_tests::test_multiple_state_updates_create_snapshots_up_to_cache_size,
		itp_stf_state_handler::test::sgx_tests::test_state_files_from_handler_can_be_loaded_again,
		itp_stf_state_handler::test::sgx_tests::test_file_io_get_state_hash_works,
		itp_stf_state_handler::test::sgx_tests::test_list_state_ids_ignores_files_not_matching_the_pattern,
		test_compose_block_and_confirmation,
		test_submit_trusted_call_to_top_pool,
		test_submit_trusted_getter_to_top_pool,
		test_differentiate_getter_and_call_works,
		test_create_block_and_confirmation_works,
		// needs node to be running.. unit tests?
		// test_ocall_worker_request,
		test_create_state_diff,
		test_executing_call_updates_account_nonce,
		test_call_set_update_parentchain_block,
		test_invalid_nonce_call_is_not_executed,
		test_non_root_shielding_call_is_not_executed,
		test_shielding_call_with_enclave_self_is_executed,
		rpc::worker_api_direct::tests::test_given_io_handler_methods_then_retrieve_all_names_as_string,
		handle_state_mock::tests::initialized_shards_list_is_empty,
		handle_state_mock::tests::shard_exists_after_inserting,
		handle_state_mock::tests::initialize_creates_default_state,
		handle_state_mock::tests::load_mutate_and_write_works,
		handle_state_mock::tests::ensure_subsequent_state_loads_have_same_hash,
		handle_state_mock::tests::ensure_encode_and_encrypt_does_not_affect_state_hash,
		// mra cert tests
		test_verify_mra_cert_should_work,
		test_verify_wrong_cert_is_err,
		test_given_wrong_platform_info_when_verifying_attestation_report_then_return_error,
		// sync tests
		sidechain_rw_lock_works,
		enclave_rw_lock_works,
		// unit tests of stf_executor
		stf_executor_tests::get_stf_state_works,
		stf_executor_tests::upon_false_signature_get_stf_state_errs,
		stf_executor_tests::execute_update_works,
		stf_executor_tests::execute_timed_getters_batch_executes_if_enough_time,
		stf_executor_tests::execute_timed_getters_does_not_execute_more_than_once_if_not_enough_time,
		stf_executor_tests::execute_timed_getters_batch_returns_early_when_no_getter,
		stf_executor_tests::propose_state_update_always_executes_preprocessing_step,
		stf_executor_tests::propose_state_update_executes_only_one_trusted_call_given_not_enough_time,
		stf_executor_tests::propose_state_update_executes_all_calls_given_enough_time,
		stf_enclave_signer_tests::enclave_signer_signatures_are_valid,
		stf_enclave_signer_tests::derive_key_is_deterministic,
		// sidechain integration tests
		sidechain_aura_tests::produce_sidechain_block_and_import_it,
		top_pool_tests::process_indirect_call_in_top_pool,
		top_pool_tests::submit_shielding_call_to_top_pool,
		// tls_ra unit tests
		tls_ra::seal_handler::test::seal_shielding_key_works,
		tls_ra::seal_handler::test::seal_shielding_key_fails_for_invalid_key,
		tls_ra::seal_handler::test::unseal_seal_shielding_key_works,
		tls_ra::seal_handler::test::seal_state_key_works,
		tls_ra::seal_handler::test::seal_state_key_fails_for_invalid_key,
		tls_ra::seal_handler::test::unseal_seal_state_key_works,
		tls_ra::seal_handler::test::seal_state_works,
		tls_ra::seal_handler::test::seal_state_fails_for_invalid_state,
		tls_ra::seal_handler::test::unseal_seal_state_works,
		tls_ra::tests::test_tls_ra_server_client_networking,

		// these unit test (?) need an ipfs node running..
		// ipfs::test_creates_ipfs_content_struct_works,
		// ipfs::test_verification_ok_for_correct_content,
		// ipfs::test_verification_fails_for_incorrect_content,
		// test_ocall_read_write_ipfs,

		// litentry
		test_call_link_eth,
		test_call_link_sub_sr25519,
		test_call_link_sub_ed25519,
		test_call_link_sub_ecdsa,
	)
}

fn test_compose_block_and_confirmation() {
	// given
	let (_, _, shard, _, _, state_handler) = test_setup();
	let block_composer = BlockComposer::<Block, SignedBlock, _, _>::new(
		test_account(),
		Arc::new(TestStateKeyRepo::new(state_key())),
	);

	let signed_top_hashes: Vec<H256> = vec![[94; 32].into(), [1; 32].into()].to_vec();

	let (lock, state) = state_handler.load_for_mutation(&shard).unwrap();
	let mut db = SidechainDB::<SignedBlock, _>::new(state.clone());
	db.set_block_number(&1);
	let state_hash_before_execution = db.state_hash();
	state_handler.write_after_mutation(db.ext.clone(), lock, &shard).unwrap();

	// when
	let (opaque_call, signed_block) = block_composer
		.compose_block_and_confirmation(
			&latest_parentchain_header(),
			signed_top_hashes,
			shard,
			state_hash_before_execution,
			db.ext,
		)
		.unwrap();

	// then
	let expected_call = OpaqueCall::from_tuple(&(
		[SIDECHAIN_MODULE, PROPOSED_SIDECHAIN_BLOCK],
		shard,
		&signed_block.block().header(),
	));

	assert!(signed_block.verify_signature());
	assert_eq!(signed_block.block().header().block_number(), 1);
	assert!(opaque_call.encode().starts_with(&expected_call.encode()));
}

fn test_submit_trusted_call_to_top_pool() {
	// given
	let (top_pool_author, _, shard, mrenclave, shielding_key, _) = test_setup();

	let sender = funded_pair();

	let signed_call =
		TrustedCall::balance_set_balance(sender.public().into(), sender.public().into(), 42, 42)
			.sign(&sender.into(), 0, &mrenclave, &shard);
	let trusted_operation = direct_top(signed_call);

	// when
	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&trusted_operation,
		&shielding_key,
		shard,
	)
	.unwrap();

	let (calls, _) = top_pool_author.get_pending_tops_separated(shard).unwrap();

	// then
	assert_eq!(calls[0], trusted_operation);
}

fn test_submit_trusted_getter_to_top_pool() {
	// given
	let (top_pool_author, _, shard, _, shielding_key, _) = test_setup();

	let sender = funded_pair();

	let signed_getter = TrustedGetter::free_balance(sender.public().into()).sign(&sender.into());

	// when
	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&signed_getter.clone().into(),
		&shielding_key,
		shard,
	)
	.unwrap();

	let (_, getters) = top_pool_author.get_pending_tops_separated(shard).unwrap();

	// then
	assert_eq!(getters[0], signed_getter);
}

fn test_differentiate_getter_and_call_works() {
	// given
	let (top_pool_author, _, shard, mrenclave, shielding_key, _) = test_setup();

	// create accounts
	let sender = funded_pair();

	let signed_getter =
		TrustedGetter::free_balance(sender.public().into()).sign(&sender.clone().into());

	let signed_call =
		TrustedCall::balance_set_balance(sender.public().into(), sender.public().into(), 42, 42)
			.sign(&sender.clone().into(), 0, &mrenclave, &shard);
	let trusted_operation = direct_top(signed_call);

	// when
	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&signed_getter.clone().into(),
		&shielding_key,
		shard,
	)
	.unwrap();
	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&trusted_operation,
		&shielding_key,
		shard,
	)
	.unwrap();

	let (calls, getters) = top_pool_author.get_pending_tops_separated(shard).unwrap();

	// then
	assert_eq!(calls[0], trusted_operation);
	assert_eq!(getters[0], signed_getter);
}

fn test_create_block_and_confirmation_works() {
	// given
	let (top_pool_author, _, shard, mrenclave, shielding_key, state_handler) = test_setup();
	let stf_executor = Arc::new(StfExecutor::new(Arc::new(OcallApi), state_handler.clone()));
	let top_pool_operation_handler = TopPoolOperationHandler::<Block, SignedBlock, _, _>::new(
		top_pool_author.clone(),
		stf_executor.clone(),
	);
	let block_composer = BlockComposer::<Block, SignedBlock, _, _>::new(
		test_account(),
		Arc::new(TestStateKeyRepo::new(state_key())),
	);

	let sender = funded_pair();
	let receiver = unfunded_public();

	let signed_call = TrustedCall::balance_transfer(sender.public().into(), receiver.into(), 1000)
		.sign(&sender.into(), 0, &mrenclave, &shard);
	let trusted_operation = direct_top(signed_call);

	let top_hash = submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&trusted_operation,
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let execution_result =
		execute_trusted_calls(&shard, stf_executor.as_ref(), &top_pool_operation_handler);

	let executed_operation_hashes =
		execution_result.get_executed_operation_hashes().iter().copied().collect();

	let (opaque_call, signed_block) = block_composer
		.compose_block_and_confirmation(
			&latest_parentchain_header(),
			executed_operation_hashes,
			shard,
			execution_result.state_hash_before_execution,
			execution_result.state_after_execution,
		)
		.unwrap();

	// then
	let expected_call = OpaqueCall::from_tuple(&(
		[SIDECHAIN_MODULE, PROPOSED_SIDECHAIN_BLOCK],
		shard,
		&signed_block.block().header(),
	));

	assert!(signed_block.verify_signature());
	assert_eq!(signed_block.block().header().block_number(), 1);
	assert_eq!(signed_block.block().block_data().signed_top_hashes()[0], top_hash);
	assert!(opaque_call.encode().starts_with(&expected_call.encode()));
}

fn test_create_state_diff() {
	// given
	let (top_pool_author, _, shard, mrenclave, shielding_key, state_handler) = test_setup();
	let stf_executor = Arc::new(StfExecutor::new(Arc::new(OcallApi), state_handler.clone()));
	let top_pool_operation_handler = TopPoolOperationHandler::<Block, SignedBlock, _, _>::new(
		top_pool_author.clone(),
		stf_executor.clone(),
	);
	let block_composer = BlockComposer::<Block, SignedBlock, _, _>::new(
		test_account(),
		Arc::new(TestStateKeyRepo::new(state_key())),
	);

	let sender = funded_pair();
	let receiver = unfunded_public();

	let signed_call = TrustedCall::balance_transfer(sender.public().into(), receiver.into(), 1000)
		.sign(&sender.clone().into(), 0, &mrenclave, &shard);
	let trusted_operation = direct_top(signed_call);

	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&trusted_operation,
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let execution_result =
		execute_trusted_calls(&shard, stf_executor.as_ref(), &top_pool_operation_handler);

	let executed_operation_hashes =
		execution_result.get_executed_operation_hashes().iter().copied().collect();

	let (_, signed_block) = block_composer
		.compose_block_and_confirmation(
			&latest_parentchain_header(),
			executed_operation_hashes,
			shard,
			execution_result.state_hash_before_execution,
			execution_result.state_after_execution,
		)
		.unwrap();

	let encrypted_state_diff = encrypted_state_diff_from_encrypted(
		signed_block.block().block_data().encrypted_state_diff(),
	);
	let state_diff = encrypted_state_diff.state_update();

	// then
	let sender_acc_info: AccountInfo =
		get_from_state_diff(&state_diff, &account_key_hash(&sender.public().into()));

	let receiver_acc_info: AccountInfo =
		get_from_state_diff(&state_diff, &account_key_hash(&receiver.into()));

	// state diff should consist of the following updates:
	// (last_hash, sidechain block_number, sender_funds, receiver_funds)
	assert_eq!(state_diff.len(), 4);
	assert_eq!(receiver_acc_info.data.free, 1000);
	assert_eq!(sender_acc_info.data.free, 1000);
}

fn test_executing_call_updates_account_nonce() {
	// given
	let (top_pool_author, _, shard, mrenclave, shielding_key, state_handler) = test_setup();
	let stf_executor = Arc::new(StfExecutor::new(Arc::new(OcallApi), state_handler.clone()));
	let top_pool_operation_handler = TopPoolOperationHandler::<Block, SignedBlock, _, _>::new(
		top_pool_author.clone(),
		stf_executor.clone(),
	);

	let sender = funded_pair();
	let receiver = unfunded_public();

	let trusted_operation =
		TrustedCall::balance_transfer(sender.public().into(), receiver.into(), 1000)
			.sign(&sender.clone().into(), 0, &mrenclave, &shard)
			.into_trusted_operation(false);

	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&trusted_operation,
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let mut execution_result =
		execute_trusted_calls(&shard, stf_executor.as_ref(), &top_pool_operation_handler);

	let nonce =
		Stf::account_nonce(&mut execution_result.state_after_execution, &sender.public().into());
	assert_eq!(nonce, 1);
}

fn test_call_set_update_parentchain_block() {
	let (_, _, shard, _, _, state_handler) = test_setup();
	let mut state = state_handler.load(&shard).unwrap();

	let block_number = 3;
	let parent_hash = H256::from([1; 32]);

	let header: Header = HeaderT::new(
		block_number,
		Default::default(),
		Default::default(),
		parent_hash,
		Default::default(),
	);

	Stf::update_parentchain_block(&mut state, header.clone()).unwrap();

	assert_eq!(header.hash(), state.execute_with(|| get_parentchain_blockhash().unwrap()));
	assert_eq!(parent_hash, state.execute_with(|| get_parentchain_parenthash().unwrap()));
	assert_eq!(block_number, state.execute_with(|| get_parentchain_number().unwrap()));
}

fn test_invalid_nonce_call_is_not_executed() {
	// given
	let (top_pool_author, _, shard, mrenclave, shielding_key, state_handler) = test_setup();
	let stf_executor = Arc::new(StfExecutor::new(Arc::new(OcallApi), state_handler.clone()));
	let top_pool_operation_handler = TopPoolOperationHandler::<Block, SignedBlock, _, _>::new(
		top_pool_author.clone(),
		stf_executor.clone(),
	);

	// create accounts
	let sender = funded_pair();
	let receiver = unfunded_public();

	let trusted_operation =
		TrustedCall::balance_transfer(sender.public().into(), receiver.into(), 1000)
			.sign(&sender.clone().into(), 10, &mrenclave, &shard)
			.into_trusted_operation(true);

	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&trusted_operation,
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let executed_batch =
		execute_trusted_calls(&shard, stf_executor.as_ref(), &top_pool_operation_handler);

	// then
	assert!(!executed_batch.executed_operations[0].is_success());
}

fn test_non_root_shielding_call_is_not_executed() {
	// given
	let (top_pool_author, _state, shard, mrenclave, shielding_key, state_handler) = test_setup();
	let stf_executor = Arc::new(StfExecutor::new(Arc::new(OcallApi), state_handler.clone()));
	let top_pool_operation_handler = TopPoolOperationHandler::<Block, SignedBlock, _, _>::new(
		top_pool_author.clone(),
		stf_executor.clone(),
	);

	let sender = funded_pair();
	let sender_acc: AccountId = sender.public().into();

	let signed_call = TrustedCall::balance_shield(sender_acc.clone(), sender_acc.clone(), 1000)
		.sign(&sender.into(), 0, &mrenclave, &shard);

	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&direct_top(signed_call),
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let executed_batch =
		execute_trusted_calls(&shard, stf_executor.as_ref(), &top_pool_operation_handler);

	// then
	assert!(!executed_batch.executed_operations[0].is_success());
}

fn test_shielding_call_with_enclave_self_is_executed() {
	let (top_pool_author, _state, shard, mrenclave, shielding_key, state_handler) = test_setup();
	let stf_executor = Arc::new(StfExecutor::new(Arc::new(OcallApi), state_handler.clone()));
	let top_pool_operation_handler = TopPoolOperationHandler::<Block, SignedBlock, _, _>::new(
		top_pool_author.clone(),
		stf_executor.clone(),
	);

	let sender = funded_pair();
	let sender_account: AccountId = sender.public().into();
	let enclave_call_signer = enclave_call_signer(&shielding_key);

	let signed_call = TrustedCall::balance_shield(
		enclave_call_signer.public().into(),
		sender_account.clone(),
		1000,
	)
	.sign(&enclave_call_signer.into(), 0, &mrenclave, &shard);
	let trusted_operation = TrustedOperation::indirect_call(signed_call);

	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&trusted_operation,
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let executed_batch =
		execute_trusted_calls(&shard, stf_executor.as_ref(), &top_pool_operation_handler);

	// then
	assert_eq!(1, executed_batch.executed_operations.len());
	assert!(executed_batch.executed_operations[0].is_success());
}

fn execute_trusted_calls(
	shard: &ShardIdentifier,
	stf_executor: &TestStfExecutor,
	top_pool_executor: &TestTopPoolOperationHandler,
) -> BatchExecutionResult<State> {
	let top_pool_calls = top_pool_executor.get_trusted_calls(&shard).unwrap();
	let execution_result = stf_executor
		.propose_state_update(
			&top_pool_calls,
			&latest_parentchain_header(),
			&shard,
			MAX_TRUSTED_OPS_EXEC_DURATION,
			|s| {
				let mut sidechain_db = SidechainDB::<SignedBlock, SgxExternalities>::new(s);
				sidechain_db
					.set_block_number(&sidechain_db.get_block_number().map_or(1, |n| n + 1));
				sidechain_db.ext
			},
		)
		.unwrap();
	execution_result
}

// litentry test link eth
fn test_call_link_eth() {
	// init test environment
	let (_, mut state, shard, mrenclave, _, _) = test_setup();
	// update parent chain header
	let block_number = 10;
	let parent_hash = H256::from([1; 32]);

	let header: Header = HeaderT::new(
		block_number,
		Default::default(),
		Default::default(),
		parent_hash,
		Default::default(),
	);

	Stf::update_parentchain_block(&mut state, header.clone()).unwrap();

	// link eth arguments
	let sender = funded_pair();

	let link_acc: AccountId32 = AccountId32::from([
		0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c, 0x61, 0x14, 0x1a, 0xbd, 0x04, 0xa9, 0x9f,
		0xd6, 0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3, 0x9a, 0x56, 0x84, 0xe7, 0xa5, 0x6d,
		0xa2, 0x7d,
	]);
	let index = 0;
	let eth_address: [u8; 20] =
		[77, 136, 220, 93, 82, 138, 51, 228, 184, 190, 87, 158, 148, 118, 113, 95, 96, 6, 5, 130];
	let block_number = 10000;
	let signature: [u8; 65] = [
		49, 132, 0, 240, 249, 189, 21, 240, 216, 132, 40, 112, 181, 16, 233, 150, 223, 252, 148,
		75, 119, 17, 29, 237, 3, 164, 37, 92, 102, 232, 45, 66, 113, 50, 231, 101, 213, 230, 187,
		33, 186, 4, 109, 187, 152, 226, 139, 178, 140, 178, 190, 190, 12, 138, 206, 210, 197, 71,
		172, 166, 10, 85, 72, 146, 28,
	];
	let signed_call =
		TrustedCall::link_eth(link_acc.clone(), index, eth_address, block_number, signature).sign(
			&sender.clone().into(),
			0,
			&mrenclave,
			&shard,
		);

	// when
	let mut dummy_vec = vec![];
	Stf::execute(&mut state, signed_call, &mut dummy_vec).unwrap();

	// let mut updated_state = state_handler.load_initialized(&shard).unwrap();

	// then
	// FIXME: That's not yet working.. needs some more investigation
	// let signed_getter = crate::Getter::trusted(
	// 	TrustedGetter::linked_ethereum_addresses(link_acc).sign(&sender.clone().into()),
	// );
	// let encoded_eth_address = Stf::get_state(&mut updated_state, signed_getter).unwrap();
	// assert_eq!(encoded_eth_address, vec![eth_address].encode());

	// check the result via comparing nonce
	// let nonce = Stf::account_nonce(&mut updated_state, &sender.public().into());
	// assert_eq!(nonce, 1);
}

fn test_call_link_sub_sr25519() {
	// init test environment
	let (_, mut state, shard, mrenclave, _, _) = test_setup();
	// update parent chain header
	let block_number = 10;
	let parent_hash = H256::from([1; 32]);

	let header: Header = HeaderT::new(
		block_number,
		Default::default(),
		Default::default(),
		parent_hash,
		Default::default(),
	);

	Stf::update_parentchain_block(&mut state, header.clone()).unwrap();

	// link eth arguments
	let sender = funded_pair();

	let link_acc: AccountId32 = AccountId32::from([
		0xd4, 0x35, 0x93, 0xc7, 0x15, 0xfd, 0xd3, 0x1c, 0x61, 0x14, 0x1a, 0xbd, 0x04, 0xa9, 0x9f,
		0xd6, 0x82, 0x2c, 0x85, 0x58, 0x85, 0x4c, 0xcd, 0xe3, 0x9a, 0x56, 0x84, 0xe7, 0xa5, 0x6d,
		0xa2, 0x7d,
	]);
	let index = 0;

	let network_type = pallet_sgx_account_linker::NetworkType::Kusama;

	let block_number = 10000;

	let signature: [u8; 64] = [
		222, 199, 221, 119, 241, 81, 156, 222, 87, 197, 34, 148, 246, 98, 178, 197, 1, 100, 76, 7,
		186, 157, 27, 175, 120, 122, 177, 136, 200, 162, 250, 87, 105, 145, 155, 114, 127, 199,
		192, 0, 254, 87, 133, 220, 75, 39, 248, 175, 169, 223, 195, 19, 116, 248, 78, 150, 205, 31,
		7, 222, 39, 8, 200, 140,
	];

	let multi_signature = pallet_sgx_account_linker::MultiSignature::Sr25519Signature(signature);

	let signed_call = TrustedCall::link_sub(
		link_acc.clone(),
		index,
		network_type,
		link_acc.clone(),
		block_number,
		multi_signature,
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	let mut dummy_vec = vec![];
	Stf::execute(&mut state, signed_call, &mut dummy_vec).unwrap();
}

fn test_call_link_sub_ed25519() {
	// init test environment
	let (_, mut state, shard, mrenclave, _, _) = test_setup();
	// update parent chain header
	let block_number = 10;
	let parent_hash = H256::from([1; 32]);

	let header: Header = HeaderT::new(
		block_number,
		Default::default(),
		Default::default(),
		parent_hash,
		Default::default(),
	);

	Stf::update_parentchain_block(&mut state, header.clone()).unwrap();

	// link eth arguments
	let sender = funded_pair();

	// account id of Alice 0x88dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee
	let link_acc: AccountId32 = AccountId32::from([
		136, 220, 52, 23, 213, 5, 142, 196, 180, 80, 62, 12, 18, 234, 26, 10, 137, 190, 32, 15,
		233, 137, 34, 66, 61, 67, 52, 1, 79, 166, 176, 238,
	]);
	let index = 0;

	let network_type = pallet_sgx_account_linker::NetworkType::Kusama;

	let block_number = 10000;

	let signature: [u8; 64] = [
		58, 226, 34, 84, 182, 42, 7, 168, 0, 196, 66, 184, 230, 130, 152, 152, 151, 105, 30, 246,
		64, 210, 148, 46, 90, 215, 198, 18, 20, 3, 38, 245, 44, 230, 24, 138, 65, 31, 197, 215,
		129, 165, 251, 132, 87, 33, 251, 199, 79, 227, 102, 55, 175, 180, 104, 166, 124, 54, 201,
		241, 44, 233, 249, 14,
	];

	let multi_signature = pallet_sgx_account_linker::MultiSignature::Ed25519Signature(signature);

	let signed_call = TrustedCall::link_sub(
		link_acc.clone(),
		index,
		network_type,
		link_acc.clone(),
		block_number,
		multi_signature,
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	let mut dummy_vec = vec![];
	Stf::execute(&mut state, signed_call, &mut dummy_vec).unwrap();
}

fn test_call_link_sub_ecdsa() {
	// init test environment
	let (_, mut state, shard, mrenclave, _, _) = test_setup();
	// update parent chain header
	let block_number = 10;
	let parent_hash = H256::from([1; 32]);

	let header: Header = HeaderT::new(
		block_number,
		Default::default(),
		Default::default(),
		parent_hash,
		Default::default(),
	);

	Stf::update_parentchain_block(&mut state, header.clone()).unwrap();

	// link eth arguments
	let sender = funded_pair();

	// account id of Alice 0x01e552298e47454041ea31273b4b630c64c104e4514aa3643490b8aaca9cf8ed
	let link_acc: AccountId32 = AccountId32::from([
		1, 229, 82, 41, 142, 71, 69, 64, 65, 234, 49, 39, 59, 75, 99, 12, 100, 193, 4, 228, 81, 74,
		163, 100, 52, 144, 184, 170, 202, 156, 248, 237,
	]);

	let index = 0;

	let network_type = pallet_sgx_account_linker::NetworkType::KusamaParachain(1);

	let block_number = 10000;

	let signature: [u8; 65] = [
		5, 24, 201, 38, 61, 125, 93, 167, 213, 109, 202, 205, 113, 155, 62, 172, 208, 148, 242,
		198, 171, 6, 4, 187, 36, 38, 216, 123, 118, 107, 254, 115, 125, 219, 81, 167, 154, 117, 1,
		184, 144, 4, 248, 144, 177, 8, 44, 93, 153, 204, 137, 1, 21, 92, 63, 245, 244, 36, 141, 73,
		118, 200, 228, 167, 1,
	];

	let multi_signature = pallet_sgx_account_linker::MultiSignature::EcdsaSignature(signature);

	let signed_call = TrustedCall::link_sub(
		link_acc.clone(),
		index,
		network_type,
		link_acc.clone(),
		block_number,
		multi_signature,
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	let mut dummy_vec = vec![];
	Stf::execute(&mut state, signed_call, &mut dummy_vec).unwrap();
}

// helper functions
pub fn test_top_pool() -> TestTopPool {
	let chain_api = Arc::new(SidechainApi::<Block>::new());
	let top_pool =
		BasicPool::create(Default::default(), chain_api, Arc::new(TestRpcResponder::new()));

	top_pool
}

/// Decrypt `encrypted` and decode it into `StatePayload`
pub fn encrypted_state_diff_from_encrypted(encrypted: &[u8]) -> StatePayload {
	let mut encrypted_payload: Vec<u8> = encrypted.to_vec();
	let state_key = state_key();
	state_key.decrypt(&mut encrypted_payload).unwrap();
	StatePayload::decode(&mut encrypted_payload.as_slice()).unwrap()
}

pub fn state_key() -> Aes {
	Aes::default()
}

/// Returns all the things that are commonly used in tests and runs
/// `ensure_no_empty_shard_directory_exists`
pub fn test_setup() -> (
	Arc<TestTopPoolAuthor>,
	State,
	ShardIdentifier,
	MrEnclave,
	ShieldingCryptoMock,
	Arc<HandleStateMock>,
) {
	let shielding_key = ShieldingCryptoMock::default();
	let shielding_key_repo = Arc::new(KeyRepositoryMock::new(shielding_key.clone()));

	let state_handler = Arc::new(HandleStateMock::default());
	let (state, shard) =
		init_state(state_handler.as_ref(), enclave_call_signer(&shielding_key).public().into());
	let top_pool = test_top_pool();
	let mrenclave = OcallApi.get_mrenclave_of_self().unwrap().m;

	(
		Arc::new(TestTopPoolAuthor::new(
			Arc::new(top_pool),
			AllowAllTopsFilter,
			state_handler.clone(),
			shielding_key_repo,
			Arc::new(MetricsOCallMock {}),
		)),
		state,
		shard,
		mrenclave,
		shielding_key,
		state_handler,
	)
}

/// Some random account that has no funds in the `Stf`'s `test_genesis` config.
pub fn unfunded_public() -> spEd25519::Public {
	spEd25519::Public::from_raw(*b"asdfasdfadsfasdfasfasdadfadfasdf")
}

pub fn test_account() -> spEd25519::Pair {
	spEd25519::Pair::from_seed(b"42315678901234567890123456789012")
}

pub fn enclave_call_signer<Source: DeriveEd25519>(key_source: &Source) -> spEd25519::Pair {
	key_source.derive_ed25519().unwrap()
}

/// transforms `call` into `TrustedOperation::direct(call)`
pub fn direct_top(call: TrustedCallSigned) -> TrustedOperation {
	call.into_trusted_operation(true)
}

/// Just some random onchain header
pub fn latest_parentchain_header() -> Header {
	Header::new(1, Default::default(), Default::default(), [69; 32].into(), Default::default())
}

/// Reads the value at `key_hash` from `state_diff` and decodes it into `D`
pub fn get_from_state_diff<D: Decode>(state_diff: &StateTypeDiff, key_hash: &[u8]) -> D {
	// fixme: what's up here with the wrapping??
	state_diff
		.get(key_hash)
		.unwrap()
		.as_ref()
		.map(|d| Decode::decode(&mut d.as_slice()))
		.unwrap()
		.unwrap()
}
