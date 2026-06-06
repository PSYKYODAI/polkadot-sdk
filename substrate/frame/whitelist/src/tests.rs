// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Tests for Whitelist Pallet

use crate::mock::*;
use codec::Encode;
use frame::{
	deps::{
		frame_support::traits::Authorize,
		sp_runtime::{
			generic::UncheckedExtrinsic as GenUncheckedExtrinsic,
			testing::UintAuthorityId,
			traits::{Applyable, Checkable},
		},
	},
	testing_prelude::*,
	traits::{QueryPreimage, StorePreimage},
};

#[test]
fn test_whitelist_call_and_remove() {
	new_test_ext().execute_with(|| {
		let call = RuntimeCall::System(frame_system::Call::remark { remark: vec![] });
		let encoded_call = call.encode();
		let call_hash = <Test as frame_system::Config>::Hashing::hash(&encoded_call[..]);

		assert_noop!(
			Whitelist::remove_whitelisted_call(RuntimeOrigin::root(), call_hash),
			crate::Error::<Test>::CallIsNotWhitelisted,
		);

		assert_noop!(
			Whitelist::whitelist_call(RuntimeOrigin::signed(1), call_hash),
			DispatchError::BadOrigin,
		);

		assert_ok!(Whitelist::whitelist_call(RuntimeOrigin::root(), call_hash));

		assert!(Preimage::is_requested(&call_hash));

		assert_noop!(
			Whitelist::whitelist_call(RuntimeOrigin::root(), call_hash),
			crate::Error::<Test>::CallAlreadyWhitelisted,
		);

		assert_noop!(
			Whitelist::remove_whitelisted_call(RuntimeOrigin::signed(1), call_hash),
			DispatchError::BadOrigin,
		);

		assert_ok!(Whitelist::remove_whitelisted_call(RuntimeOrigin::root(), call_hash));

		assert!(!Preimage::is_requested(&call_hash));

		assert_noop!(
			Whitelist::remove_whitelisted_call(RuntimeOrigin::root(), call_hash),
			crate::Error::<Test>::CallIsNotWhitelisted,
		);
	});
}

#[test]
fn test_whitelist_call_and_execute() {
	new_test_ext().execute_with(|| {
		let call = RuntimeCall::System(frame_system::Call::remark_with_event { remark: vec![1] });
		let call_weight = call.get_dispatch_info().call_weight;
		let encoded_call = call.encode();
		let call_encoded_len = encoded_call.len() as u32;
		let call_hash = <Test as frame_system::Config>::Hashing::hash(&encoded_call[..]);

		assert_noop!(
			Whitelist::dispatch_whitelisted_call(
				RuntimeOrigin::root(),
				call_hash,
				call_encoded_len,
				call_weight
			),
			crate::Error::<Test>::CallIsNotWhitelisted,
		);

		assert_ok!(Whitelist::whitelist_call(RuntimeOrigin::root(), call_hash));

		assert_noop!(
			Whitelist::dispatch_whitelisted_call(
				RuntimeOrigin::signed(1),
				call_hash,
				call_encoded_len,
				call_weight
			),
			DispatchError::BadOrigin,
		);

		assert_noop!(
			Whitelist::dispatch_whitelisted_call(
				RuntimeOrigin::root(),
				call_hash,
				call_encoded_len,
				call_weight
			),
			crate::Error::<Test>::UnavailablePreImage,
		);

		assert_ok!(Preimage::note(encoded_call.into()));

		assert!(Preimage::is_requested(&call_hash));

		assert_noop!(
			Whitelist::dispatch_whitelisted_call(
				RuntimeOrigin::root(),
				call_hash,
				call_encoded_len,
				call_weight - Weight::from_parts(1, 0)
			),
			crate::Error::<Test>::InvalidCallWeightWitness,
		);

		assert_ok!(Whitelist::dispatch_whitelisted_call(
			RuntimeOrigin::root(),
			call_hash,
			call_encoded_len,
			call_weight
		));

		assert!(!Preimage::is_requested(&call_hash));

		assert_noop!(
			Whitelist::dispatch_whitelisted_call(
				RuntimeOrigin::root(),
				call_hash,
				call_encoded_len,
				call_weight
			),
			crate::Error::<Test>::CallIsNotWhitelisted,
		);
	});
}

#[test]
fn test_whitelist_call_and_execute_failing_call() {
	new_test_ext().execute_with(|| {
		let call = RuntimeCall::Whitelist(crate::Call::dispatch_whitelisted_call {
			call_hash: Default::default(),
			call_encoded_len: Default::default(),
			call_weight_witness: Weight::zero(),
		});
		let call_weight = call.get_dispatch_info().call_weight;
		let encoded_call = call.encode();
		let call_encoded_len = encoded_call.len() as u32;
		let call_hash = <Test as frame_system::Config>::Hashing::hash(&encoded_call[..]);

		assert_ok!(Whitelist::whitelist_call(RuntimeOrigin::root(), call_hash));
		assert_ok!(Preimage::note(encoded_call.into()));
		assert!(Preimage::is_requested(&call_hash));
		assert_ok!(Whitelist::dispatch_whitelisted_call(
			RuntimeOrigin::root(),
			call_hash,
			call_encoded_len,
			call_weight
		));
		assert!(!Preimage::is_requested(&call_hash));
	});
}

#[test]
fn test_whitelist_call_and_execute_without_note_preimage() {
	new_test_ext().execute_with(|| {
		let call = Box::new(RuntimeCall::System(frame_system::Call::remark_with_event {
			remark: vec![1],
		}));
		let call_hash = <Test as frame_system::Config>::Hashing::hash_of(&call);

		assert_ok!(Whitelist::whitelist_call(RuntimeOrigin::root(), call_hash));
		assert!(Preimage::is_requested(&call_hash));

		assert_ok!(Whitelist::dispatch_whitelisted_call_with_preimage(
			RuntimeOrigin::root(),
			call.clone()
		));

		assert!(!Preimage::is_requested(&call_hash));

		assert_noop!(
			Whitelist::dispatch_whitelisted_call_with_preimage(RuntimeOrigin::root(), call),
			crate::Error::<Test>::CallIsNotWhitelisted,
		);
	});
}

#[test]
fn test_whitelist_call_and_execute_decode_consumes_all() {
	new_test_ext().execute_with(|| {
		let call = RuntimeCall::System(frame_system::Call::remark_with_event { remark: vec![1] });
		let call_weight = call.get_dispatch_info().call_weight;
		let mut call = call.encode();
		// Appending something does not make the encoded call invalid.
		// This tests that the decode function consumes all data.
		call.extend(call.clone());
		let call_encoded_len = call.len() as u32;

		let call_hash = <Test as frame_system::Config>::Hashing::hash(&call[..]);

		assert_ok!(Preimage::note(call.into()));
		assert_ok!(Whitelist::whitelist_call(RuntimeOrigin::root(), call_hash));

		assert_noop!(
			Whitelist::dispatch_whitelisted_call(
				RuntimeOrigin::root(),
				call_hash,
				call_encoded_len,
				call_weight
			),
			crate::Error::<Test>::UndecodableCall,
		);
	});
}

// ---------------------------------------------------------------------------
// Tests for the permissionless authorized dispatch path (RFC #12224)
// ---------------------------------------------------------------------------

#[test]
fn authorize_callback_rejected_when_feature_disabled() {
	// With EnableAuthorizedDispatch = false (Test config), the authorize callback
	// must reject unsigned submissions regardless of whether the call is whitelisted.
	new_test_ext().execute_with(|| {
		let inner = RuntimeCall::System(frame_system::Call::remark { remark: vec![1] });
		let call_hash = <Test as frame_system::Config>::Hashing::hash_of(&inner);

		assert_ok!(Whitelist::whitelist_call(RuntimeOrigin::root(), call_hash));

		// `dispatch_whitelisted_call_with_preimage` has an authorize callback; with the
		// feature disabled it must return None-equivalent (Err from the callback).
		let outer =
			RuntimeCall::Whitelist(crate::Call::dispatch_whitelisted_call_with_preimage {
				call: Box::new(inner),
			});

		// `authorize` returns Some(Err(...)) because the callback runs but rejects.
		let auth = outer.authorize(TransactionSource::External);
		assert!(
			matches!(auth, Some(Err(_))),
			"Expected Some(Err) when feature is disabled, got {:?}",
			auth
		);
	});
}

#[test]
fn authorize_callback_rejected_when_hash_not_whitelisted() {
	// With EnableAuthorizedDispatch = true but the call hash absent from WhitelistedCall,
	// the authorize callback must still reject.
	permissionless::new_test_ext().execute_with(|| {
		use permissionless::*;

		let inner = RuntimeCall::System(frame_system::Call::remark { remark: vec![42] });

		let outer =
			RuntimeCall::Whitelist(crate::Call::dispatch_whitelisted_call_with_preimage {
				call: Box::new(inner),
			});

		let auth = outer.authorize(TransactionSource::External);
		assert!(
			matches!(auth, Some(Err(_))),
			"Expected Some(Err) when hash is not whitelisted, got {:?}",
			auth
		);
	});
}

#[test]
fn authorize_callback_admits_when_hash_whitelisted() {
	// With EnableAuthorizedDispatch = true and the call hash present in WhitelistedCall,
	// the authorize callback must admit the transaction.
	permissionless::new_test_ext().execute_with(|| {
		use permissionless::*;

		let inner = RuntimeCall::System(frame_system::Call::remark { remark: vec![1] });
		let call_hash = <TestPermissionless as frame_system::Config>::Hashing::hash_of(&inner);

		assert_ok!(Whitelist::whitelist_call(RuntimeOrigin::root(), call_hash));

		let outer =
			RuntimeCall::Whitelist(crate::Call::dispatch_whitelisted_call_with_preimage {
				call: Box::new(inner),
			});

		let auth = outer.authorize(TransactionSource::External);
		assert!(
			matches!(auth, Some(Ok(_))),
			"Expected Some(Ok) when hash is whitelisted and feature enabled, got {:?}",
			auth
		);
	});
}

#[test]
fn authorize_callback_for_dispatch_whitelisted_call_rejected_when_disabled() {
	// Same check for `dispatch_whitelisted_call` (preimage-based variant).
	new_test_ext().execute_with(|| {
		let call_hash = <Test as frame_system::Config>::Hashing::hash_of(&vec![1u8]);
		assert_ok!(Whitelist::whitelist_call(RuntimeOrigin::root(), call_hash));

		let outer = RuntimeCall::Whitelist(crate::Call::dispatch_whitelisted_call {
			call_hash,
			call_encoded_len: 1,
			call_weight_witness: Weight::zero(),
		});

		let auth = outer.authorize(TransactionSource::External);
		assert!(
			matches!(auth, Some(Err(_))),
			"Expected Some(Err) when feature disabled, got {:?}",
			auth
		);
	});
}

#[test]
fn authorize_callback_for_dispatch_whitelisted_call_admits_when_whitelisted() {
	// `dispatch_whitelisted_call` authorize callback admits when the feature is on
	// and the hash is in WhitelistedCall.
	permissionless::new_test_ext().execute_with(|| {
		use permissionless::*;

		let call_hash = <TestPermissionless as frame_system::Config>::Hashing::hash_of(&vec![1u8]);
		assert_ok!(Whitelist::whitelist_call(RuntimeOrigin::root(), call_hash));

		let outer = RuntimeCall::Whitelist(crate::Call::dispatch_whitelisted_call {
			call_hash,
			call_encoded_len: 1,
			call_weight_witness: Weight::zero(),
		});

		let auth = outer.authorize(TransactionSource::External);
		assert!(
			matches!(auth, Some(Ok(_))),
			"Expected Some(Ok) when hash whitelisted and feature enabled, got {:?}",
			auth
		);
	});
}

#[test]
fn permissionless_dispatch_with_authorized_origin_succeeds() {
	// End-to-end: whitelist a call, then dispatch it with the `Authorized` system origin
	// (the origin that `AuthorizeCall` produces after a successful `authorize` callback).
	// With DispatchWhitelistedOrigin = EnsureAuthorized, the dispatch body accepts it.
	permissionless::new_test_ext().execute_with(|| {
		use permissionless::*;

		let inner = Box::new(RuntimeCall::System(frame_system::Call::remark { remark: vec![1] }));
		let call_hash =
			<TestPermissionless as frame_system::Config>::Hashing::hash_of(&inner);

		assert_ok!(Whitelist::whitelist_call(RuntimeOrigin::root(), call_hash));

		// The Authorized origin is what AuthorizeCall injects for a successful unsigned tx.
		let authorized_origin =
			frame_system::RawOrigin::<u64>::Authorized.into();

		assert_ok!(Whitelist::dispatch_whitelisted_call_with_preimage(
			authorized_origin,
			inner,
		));

		// Hash removed from whitelist after successful dispatch.
		assert!(!crate::WhitelistedCall::<TestPermissionless>::contains_key(call_hash));
	});
}

#[test]
fn signed_dispatch_still_rejected_when_permissionless_enabled() {
	// Enabling permissionless dispatch must not weaken the `DispatchWhitelistedOrigin`
	// check for an arbitrary signed origin that is NOT the whitelisted dispatcher.
	// With DispatchWhitelistedOrigin = EnsureAuthorized, only Authorized origin passes;
	// a regular signed origin is still rejected.
	permissionless::new_test_ext().execute_with(|| {
		use permissionless::*;

		let inner = Box::new(RuntimeCall::System(frame_system::Call::remark { remark: vec![1] }));
		let call_hash =
			<TestPermissionless as frame_system::Config>::Hashing::hash_of(&inner);

		assert_ok!(Whitelist::whitelist_call(RuntimeOrigin::root(), call_hash));

		assert_noop!(
			Whitelist::dispatch_whitelisted_call_with_preimage(
				RuntimeOrigin::signed(1),
				inner,
			),
			DispatchError::BadOrigin,
		);
	});
}

// ---------------------------------------------------------------------------
// NoopPreimages tests
// ---------------------------------------------------------------------------

#[test]
fn noop_preimages_makes_dispatch_whitelisted_call_unusable() {
	// With NoopPreimages, fetch always returns Unavailable, so
	// dispatch_whitelisted_call (preimage-based) must fail.
	permissionless::new_test_ext().execute_with(|| {
		use permissionless::*;

		let call = RuntimeCall::System(frame_system::Call::remark { remark: vec![1] });
		let call_weight = call.get_dispatch_info().call_weight;
		let encoded = call.encode();
		let call_encoded_len = encoded.len() as u32;
		let call_hash =
			<TestPermissionless as frame_system::Config>::Hashing::hash(&encoded[..]);

		assert_ok!(Whitelist::whitelist_call(RuntimeOrigin::root(), call_hash));

		// dispatch_whitelisted_call requires a stored preimage — NoopPreimages never
		// has one, so it must return UnavailablePreImage.
		assert_noop!(
			Whitelist::dispatch_whitelisted_call(
				frame_system::RawOrigin::<u64>::Authorized.into(),
				call_hash,
				call_encoded_len,
				call_weight,
			),
			crate::Error::<TestPermissionless>::UnavailablePreImage,
		);
	});
}

#[test]
fn noop_preimages_dispatch_whitelisted_call_with_preimage_still_works() {
	// With NoopPreimages, dispatch_whitelisted_call_with_preimage (inline payload)
	// must still succeed — it never touches preimage storage.
	permissionless::new_test_ext().execute_with(|| {
		use permissionless::*;

		let inner =
			Box::new(RuntimeCall::System(frame_system::Call::remark { remark: vec![1] }));
		let call_hash =
			<TestPermissionless as frame_system::Config>::Hashing::hash_of(&inner);

		assert_ok!(Whitelist::whitelist_call(RuntimeOrigin::root(), call_hash));

		assert_ok!(Whitelist::dispatch_whitelisted_call_with_preimage(
			frame_system::RawOrigin::<u64>::Authorized.into(),
			inner,
		));

		assert!(
			!crate::WhitelistedCall::<TestPermissionless>::contains_key(call_hash),
			"entry must be cleared after successful dispatch"
		);
	});
}

// ---------------------------------------------------------------------------
// Full unsigned transaction pipeline tests (the path that actually happens on-chain)
// ---------------------------------------------------------------------------
// These tests exercise the complete flow:
//   unsigned tx → AuthorizeCall validates → None origin → Authorized origin → EnsureAuthorized
// This corresponds to the RC side of the cross-chain flow described in RFC #12224:
//   AH sends whitelist_call(hash) via XCM → anyone submits the full call as unsigned tx on RC.

type TxExt = frame_system::AuthorizeCall<permissionless::TestPermissionless>;
type PipelineExtrinsic =
	GenUncheckedExtrinsic<u64, permissionless::RuntimeCall, UintAuthorityId, TxExt>;

#[test]
fn unsigned_tx_pipeline_admits_and_dispatches_whitelisted_call() {
	// Full end-to-end: general (unsigned) extrinsic with AuthorizeCall extension is
	// validated and dispatched once the call hash is in WhitelistedCall.
	permissionless::new_test_ext().execute_with(|| {
		use permissionless::*;

		let inner =
			Box::new(RuntimeCall::System(frame_system::Call::remark { remark: vec![1] }));
		let call_hash =
			<TestPermissionless as frame_system::Config>::Hashing::hash_of(&inner);

		// Simulate what AH sends as a small XCM Transact on the RC.
		assert_ok!(Whitelist::whitelist_call(RuntimeOrigin::root(), call_hash));

		let outer = RuntimeCall::Whitelist(
			crate::Call::dispatch_whitelisted_call_with_preimage { call: inner },
		);

		let tx = PipelineExtrinsic::new_transaction(outer, TxExt::new());
		let info = tx.get_dispatch_info();
		let len = tx.using_encoded(|e| e.len());

		let checked =
			Checkable::check(tx, &frame_system::ChainContext::<TestPermissionless>::default())
				.expect("general transaction is always checkable");

		// Pool admission: AuthorizeCall calls our callback, which admits the tx.
		checked
			.validate::<TestPermissionless>(TransactionSource::External, &info, len)
			.expect("whitelisted call must be admitted by the authorize callback");

		// Full dispatch: AuthorizeCall converts None → Authorized; EnsureAuthorized accepts it.
		let result = checked
			.apply::<TestPermissionless>(&info, len)
			.expect("tx must apply without a validity error");

		assert!(result.is_ok(), "inner call dispatch must succeed");
		assert!(
			!crate::WhitelistedCall::<TestPermissionless>::contains_key(call_hash),
			"whitelist entry must be removed after successful dispatch",
		);
	});
}

#[test]
fn unsigned_tx_pipeline_rejected_when_hash_not_whitelisted() {
	// General (unsigned) extrinsic is rejected at the pool level when the call hash
	// is absent from WhitelistedCall — the authorize callback must return Err.
	permissionless::new_test_ext().execute_with(|| {
		use permissionless::*;

		// Intentionally do NOT call whitelist_call — hash is absent.
		let inner =
			Box::new(RuntimeCall::System(frame_system::Call::remark { remark: vec![99] }));

		let outer = RuntimeCall::Whitelist(
			crate::Call::dispatch_whitelisted_call_with_preimage { call: inner },
		);

		let tx = PipelineExtrinsic::new_transaction(outer, TxExt::new());
		let info = tx.get_dispatch_info();
		let len = tx.using_encoded(|e| e.len());

		let checked =
			Checkable::check(tx, &frame_system::ChainContext::<TestPermissionless>::default())
				.expect("general transaction is always checkable");

		assert!(
			checked
				.validate::<TestPermissionless>(TransactionSource::External, &info, len)
				.is_err(),
			"tx must be rejected at pool level when hash is not whitelisted",
		);
	});
}
