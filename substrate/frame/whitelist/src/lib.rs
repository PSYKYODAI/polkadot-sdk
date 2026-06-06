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

//! # Whitelist Pallet
//!
//! - [`Config`]
//! - [`Call`]
//!
//! ## Overview
//!
//! Allow some configurable origin: [`Config::WhitelistOrigin`] to whitelist some hash of a call,
//! and allow another configurable origin: [`Config::DispatchWhitelistedOrigin`] to dispatch them
//! with the root origin.
//!
//! In the meantime the call corresponding to the hash must have been submitted to the pre-image
//! handler [`pallet::Config::Preimages`].

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;
pub use weights::WeightInfo;

extern crate alloc;

use alloc::{borrow::Cow, boxed::Box};
use codec::{DecodeLimit, Encode, FullCodec};
use frame::{
	prelude::*,
	traits::{QueryPreimage, StorePreimage},
};
use scale_info::TypeInfo;

pub use pallet::*;

/// A no-op implementation of [`QueryPreimage`] and [`StorePreimage`] for runtimes that
/// have no on-chain preimage storage (e.g. the relay chain post-AHM, which has no
/// `pallet-balances` and therefore cannot host `pallet-preimage`).
///
/// Behaviour:
/// - `fetch` always returns `Err(DispatchError::Unavailable)`, so
///   [`Pallet::dispatch_whitelisted_call`] (which relies on stored preimages) is
///   effectively disabled — any call to it returns [`Error::UnavailablePreImage`].
/// - `request`, `unrequest`, and `note` are all no-ops, so `whitelist_call` and
///   `remove_whitelisted_call` remain fully functional.
/// - Only [`Pallet::dispatch_whitelisted_call_with_preimage`] is operational: the
///   caller supplies the full call inline and it is hash-checked on the spot.
///
/// Recommended relay-chain wiring (RFC #12224):
/// ```ignore
/// impl pallet_whitelist::Config for Runtime {
///     type Preimages              = pallet_whitelist::NoopPreimages<Self::Hashing>;
///     type DispatchWhitelistedOrigin = frame_system::EnsureAuthorized<Self::AccountId>;
///     type EnableAuthorizedDispatch  = ConstBool<true>;
///     // ...
/// }
/// ```
pub struct NoopPreimages<H>(core::marker::PhantomData<H>);

impl<H: frame::deps::sp_runtime::traits::Hash> QueryPreimage for NoopPreimages<H> {
	type H = H;

	fn len(_hash: &H::Output) -> Option<u32> {
		None
	}

	fn fetch(_hash: &H::Output, _len: Option<u32>) -> frame::deps::frame_support::traits::FetchResult {
		Err(DispatchError::Unavailable)
	}

	fn is_requested(_hash: &H::Output) -> bool {
		false
	}

	fn request(_hash: &H::Output) {}

	fn unrequest(_hash: &H::Output) {}
}

impl<H: frame::deps::sp_runtime::traits::Hash> StorePreimage for NoopPreimages<H> {
	/// No preimage can ever be stored; callers that depend on `note` must use
	/// `dispatch_whitelisted_call_with_preimage` with an inline payload instead.
	const MAX_LENGTH: usize = 0;

	fn note(_bytes: Cow<[u8]>) -> Result<H::Output, DispatchError> {
		Err(DispatchError::Exhausted)
	}
}

#[frame::pallet]
pub mod pallet {
	use super::*;

	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// The overarching event type.
		#[allow(deprecated)]
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// The overarching call type.
		type RuntimeCall: IsType<<Self as frame_system::Config>::RuntimeCall>
			+ Dispatchable<RuntimeOrigin = Self::RuntimeOrigin, PostInfo = PostDispatchInfo>
			+ GetDispatchInfo
			+ FullCodec
			+ TypeInfo
			+ From<frame_system::Call<Self>>
			+ Parameter;

		/// Required origin for whitelisting a call.
		type WhitelistOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Required origin for dispatching whitelisted call with root origin.
		type DispatchWhitelistedOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// The handler of pre-images.
		type Preimages: QueryPreimage<H = Self::Hashing> + StorePreimage;

		/// When `true`, both `dispatch_whitelisted_call` and
		/// `dispatch_whitelisted_call_with_preimage` can be submitted as unsigned, fee-free
		/// transactions by anyone once the corresponding call hash is present in
		/// [`WhitelistedCall`]. The `#[pallet::authorize]` callback enforces this at
		/// transaction-pool admission, so oversized or bogus payloads are rejected before
		/// any on-chain work is done.
		///
		/// Set `DispatchWhitelistedOrigin` to `frame_system::EnsureAuthorized` on runtimes
		/// that enable this path; leave it as `ConstBool<false>` to preserve the existing
		/// privileged-only behavior.
		type EnableAuthorizedDispatch: Get<bool>;

		/// The weight information for this pallet.
		type WeightInfo: WeightInfo;
	}

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		CallWhitelisted { call_hash: T::Hash },
		WhitelistedCallRemoved { call_hash: T::Hash },
		WhitelistedCallDispatched { call_hash: T::Hash, result: DispatchResultWithPostInfo },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The preimage of the call hash could not be loaded.
		UnavailablePreImage,
		/// The call could not be decoded.
		UndecodableCall,
		/// The weight of the decoded call was higher than the witness.
		InvalidCallWeightWitness,
		/// The call was not whitelisted.
		CallIsNotWhitelisted,
		/// The call was already whitelisted; No-Op.
		CallAlreadyWhitelisted,
	}

	#[pallet::storage]
	pub type WhitelistedCall<T: Config> = StorageMap<_, Twox64Concat, T::Hash, (), OptionQuery>;

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::whitelist_call())]
		pub fn whitelist_call(origin: OriginFor<T>, call_hash: T::Hash) -> DispatchResult {
			T::WhitelistOrigin::ensure_origin(origin)?;

			ensure!(
				!WhitelistedCall::<T>::contains_key(call_hash),
				Error::<T>::CallAlreadyWhitelisted,
			);

			WhitelistedCall::<T>::insert(call_hash, ());
			T::Preimages::request(&call_hash);

			Self::deposit_event(Event::<T>::CallWhitelisted { call_hash });

			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::remove_whitelisted_call())]
		pub fn remove_whitelisted_call(origin: OriginFor<T>, call_hash: T::Hash) -> DispatchResult {
			T::WhitelistOrigin::ensure_origin(origin)?;

			WhitelistedCall::<T>::take(call_hash).ok_or(Error::<T>::CallIsNotWhitelisted)?;

			T::Preimages::unrequest(&call_hash);

			Self::deposit_event(Event::<T>::WhitelistedCallRemoved { call_hash });

			Ok(())
		}

		#[pallet::call_index(2)]
		#[pallet::weight(
			T::WeightInfo::dispatch_whitelisted_call(*call_encoded_len)
				.saturating_add(*call_weight_witness)
		)]
		#[pallet::authorize(Self::authorize_dispatch_whitelisted_call)]
		#[pallet::weight_of_authorize(T::WeightInfo::authorize_dispatch_whitelisted_call())]
		pub fn dispatch_whitelisted_call(
			origin: OriginFor<T>,
			call_hash: T::Hash,
			call_encoded_len: u32,
			call_weight_witness: Weight,
		) -> DispatchResultWithPostInfo {
			T::DispatchWhitelistedOrigin::ensure_origin(origin)?;

			ensure!(
				WhitelistedCall::<T>::contains_key(call_hash),
				Error::<T>::CallIsNotWhitelisted,
			);

			let call = T::Preimages::fetch(&call_hash, Some(call_encoded_len))
				.map_err(|_| Error::<T>::UnavailablePreImage)?;

			let call = <T as Config>::RuntimeCall::decode_all_with_depth_limit(
				frame::deps::frame_support::MAX_EXTRINSIC_DEPTH,
				&mut &call[..],
			)
			.map_err(|_| Error::<T>::UndecodableCall)?;

			ensure!(
				call.get_dispatch_info().call_weight.all_lte(call_weight_witness),
				Error::<T>::InvalidCallWeightWitness
			);

			let actual_weight = Self::clean_and_dispatch(call_hash, call).map(|w| {
				w.saturating_add(T::WeightInfo::dispatch_whitelisted_call(call_encoded_len))
			});

			Ok(actual_weight.into())
		}

		#[pallet::call_index(3)]
		#[pallet::weight({
			let call_weight = call.get_dispatch_info().call_weight;
			let call_len = call.encoded_size() as u32;

			T::WeightInfo::dispatch_whitelisted_call_with_preimage(call_len)
				.saturating_add(call_weight)
		})]
		#[pallet::authorize(Self::authorize_dispatch_whitelisted_call_with_preimage)]
		#[pallet::weight_of_authorize(T::WeightInfo::authorize_dispatch_whitelisted_call_with_preimage())]
		pub fn dispatch_whitelisted_call_with_preimage(
			origin: OriginFor<T>,
			call: Box<<T as Config>::RuntimeCall>,
		) -> DispatchResultWithPostInfo {
			T::DispatchWhitelistedOrigin::ensure_origin(origin)?;

			let call_hash = T::Hashing::hash_of(&call).into();

			ensure!(
				WhitelistedCall::<T>::contains_key(call_hash),
				Error::<T>::CallIsNotWhitelisted,
			);

			let call_len = call.encoded_size() as u32;
			let actual_weight = Self::clean_and_dispatch(call_hash, *call).map(|w| {
				w.saturating_add(T::WeightInfo::dispatch_whitelisted_call_with_preimage(call_len))
			});

			Ok(actual_weight.into())
		}
	}
}

impl<T: Config> Pallet<T> {
	/// Pool-level authorization callback for [`Pallet::dispatch_whitelisted_call`].
	///
	/// Admits an unsigned submission if and only if:
	/// 1. `T::EnableAuthorizedDispatch` is `true`, and
	/// 2. the `call_hash` is already present in [`WhitelistedCall`].
	///
	/// Returning `Err` here drops the transaction before it touches block inclusion,
	/// so no on-chain work is wasted on invalid or bogus submissions.
	fn authorize_dispatch_whitelisted_call(
		_source: TransactionSource,
		call_hash: &T::Hash,
		_call_encoded_len: &u32,
		_call_weight_witness: &Weight,
	) -> TransactionValidityWithRefund {
		if !T::EnableAuthorizedDispatch::get() {
			return Err(TransactionValidityError::Invalid(InvalidTransaction::Call));
		}
		if !WhitelistedCall::<T>::contains_key(call_hash) {
			return Err(TransactionValidityError::Invalid(InvalidTransaction::Call));
		}
		Ok((
			ValidTransaction {
				provides: vec![call_hash.encode()],
				..Default::default()
			},
			Weight::zero(),
		))
	}

	/// Pool-level authorization callback for
	/// [`Pallet::dispatch_whitelisted_call_with_preimage`].
	///
	/// Admits an unsigned submission if and only if:
	/// 1. `T::EnableAuthorizedDispatch` is `true`, and
	/// 2. `hash(call)` is already present in [`WhitelistedCall`].
	///
	/// The hash is computed from the inline call payload so that oversized or
	/// tampered payloads are caught here, at pool admission, rather than on-chain.
	fn authorize_dispatch_whitelisted_call_with_preimage(
		_source: TransactionSource,
		call: &Box<<T as Config>::RuntimeCall>,
	) -> TransactionValidityWithRefund {
		if !T::EnableAuthorizedDispatch::get() {
			return Err(TransactionValidityError::Invalid(InvalidTransaction::Call));
		}
		let call_hash = T::Hashing::hash_of(call);
		if !WhitelistedCall::<T>::contains_key(call_hash) {
			return Err(TransactionValidityError::Invalid(InvalidTransaction::Call));
		}
		Ok((
			ValidTransaction {
				provides: vec![call_hash.encode()],
				..Default::default()
			},
			Weight::zero(),
		))
	}

	/// Clean whitelisting/preimage and dispatch call.
	///
	/// Return the call actual weight of the dispatched call if there is some.
	fn clean_and_dispatch(call_hash: T::Hash, call: <T as Config>::RuntimeCall) -> Option<Weight> {
		WhitelistedCall::<T>::remove(call_hash);

		T::Preimages::unrequest(&call_hash);

		let result = call.dispatch(frame_system::Origin::<T>::Root.into());

		let call_actual_weight = match result {
			Ok(call_post_info) => call_post_info.actual_weight,
			Err(call_err) => call_err.post_info.actual_weight,
		};

		Self::deposit_event(Event::<T>::WhitelistedCallDispatched { call_hash, result });

		call_actual_weight
	}
}
