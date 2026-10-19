//------------------------------------------------------------------------------
/**
 * @file signed_index_refresh.cpp
 * @brief 固定currentの検証と既存原子storeをlock外通信で接続します。
 * @version 01.00.00
 * @date 2026/10/16
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます。
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください。
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/16  HTTP/暗号/schema/storeと明示cacheを接続。
 * </pre>
 */
//------------------------------------------------------------------------------
#include "platform/signed_index_refresh.h"
#include <algorithm>
#include <new>
#include <winhttp.h>

namespace drivercrate {
namespace {
/** @brief 既知取得recordの元attestationを現在UTCへ再照合します。
 * @param[in] receipt 不変の全schema検査結果です。
 * @param[in] now 現在の信頼UTCです。
 * @return 既知attestationが全て有効ならtrueです。UNKNOWNを既知化しません。
 */
[[nodiscard]] bool attestationsCurrent( const IndexRecordsSchemaReceipt				&receipt,
									   const std::optional<std::chrono::sys_seconds> now) noexcept
{
	// 時刻不明を既知の鮮度へ推測しません。
	if( !now) {
		return false ;
	}

	// 全recordを確認し、先頭一件だけで後続を許可しません。
	for( const auto &record : receipt.records()) {
		// UNKNOWN/v1は取得能力を作らず、既知の元期限だけを拒否します。
		if( record.acquisitionDescriptor &&
		   record.acquisitionDescriptor->state == IndexDescriptorState::KNOWN) {
			const auto &attestation =
				record.acquisitionDescriptor->attestation ;	// 元の個別期限です。
			// 確認前と期限以上を同じ有効値へ丸めません。
			if( !attestation || *now < attestation->checkedAtUtc ||
			   *now >= attestation->validUntilUtc) {
				return false ;
			}
		}
	}

	return true ;
}
/** @brief 実storeのstatusとsnapshot有無を非機密値へ要約します。
 * @param[in] result 所有する実store結果です。外へ能力を渡しません。
 * @param[in] now 使用時の信頼UTCです。
 * @return 元commit事実と現在有効なsnapshot観測だけです。
 */
[[nodiscard]] IndexRefreshStoreObservation observe(
	IndexStoreResult result, std::optional<std::chrono::sys_seconds> now) noexcept
{
	return {result.status,
			result.commit,
			result.error,
			result.manifestStatus,
			result.persistedGeneration,
			result.status == IndexStoreStatus::SNAPSHOT_READY && result.snapshot.has_value() &&
				attestationsCurrent( result.snapshot->schemaReceipt(), now)} ;
}
/** @brief 明示した一時的通信拒否だけをcache再認証の候補にします。
 * @param[in] error 元のHTTPまたはWinHTTP診断です。
 * @param[in] status 実観測HTTP statusです。
 * @return 暗号/世代/保護/route拒否を含まない場合だけtrueです。
 */
[[nodiscard]] bool transient( const NativeError error, const std::uint32_t status) noexcept
{
	// HTTP拒否は匿名404と有限な一時応答だけを許可します。
	if( status == 404U || status == 408U || status == 429U || status == 500U || status == 502U ||
	   status == 503U || status == 504U) {
		return true ;
	}

	return error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_WINHTTP_TIMEOUT)) ||
		   error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_WINHTTP_CANNOT_CONNECT)) ||
		   error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_WINHTTP_CONNECTION_ERROR)) ||
		   error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_WINHTTP_NAME_NOT_RESOLVED)) ;
}
}

/** @see SignedIndexHttpControl宣言側の契約を正本とします。 */
NativeError SignedIndexHttpControl::checkpoint() noexcept
{
	// 最初の停止理由を後続timeoutや例外で上書きしません。
	if( stopped != 0) {
		return stopped ;
	}

	try {
		// 取消しを期限と別の元診断で保持します。
		if( cancellation && cancellation()) {
			stopped = HRESULT_FROM_WIN32( ERROR_CANCELLED) ;
		}
		// 欠損時計からnative時計へfallbackしません。
		else if( !monotonicNow) {
			stopped = E_INVALIDARG ;
		}
		// 一度決めた90秒期限を延長しません。
		else if( monotonicNow() >= deadline) {
			stopped = HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
		}
	} catch( ...) {
		stopped = E_UNEXPECTED ;
	}

	return stopped ;
}
/** @see SignedIndexHttpControl宣言側の契約を正本とします。 */
int SignedIndexHttpControl::timeoutMilliseconds( const int maximum) noexcept
{
	// APIへ渡す0は無限になるため、停止か不正上限を先に拒否します。
	if( checkpoint() != 0 || maximum <= 0) {
		return 0 ;
	}

	try {
		const auto remaining =
			std::chrono::duration_cast<std::chrono::milliseconds>( deadline - monotonicNow())
				.count() ;	// 同じ単調期限です。
		// 正の残millisecondがないAPIは開始しません。
		if( remaining <= 0) {
			stopped = HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
			return 0 ;
		}

		return static_cast<int>( std::min<std::int64_t>( remaining, maximum)) ;
	} catch( ...) {
		stopped = E_UNEXPECTED ;
		return 0 ;
	}
}

/** @see Access宣言側の契約を正本とします。 */
IndexRefreshSummary signed_index_refresh_detail::Access::execute(
	OfficialHttpClient &client, const Services &services,
	const HttpCancellationCallback &cancellation) noexcept
{
	IndexRefreshSummary	   result ;		// 能力を含まない全段階の元診断です。
	SignedIndexHttpControl control ;	// この呼出しだけの固定90秒です。
	try {
		// 欠損依存を製品HTTPや保護storeへ補完しません。
		if( !services.utcNow || !services.monotonicNow || !services.commit || !services.reload) {
			result.error = E_INVALIDARG ;
			return result ;
		}

		control.cancellation = cancellation ;
		control.monotonicNow = services.monotonicNow ;
		control.deadline	 = services.monotonicNow() + std::chrono::seconds{90} ;
		const auto finish	 = [&]() {
			   result.sends			= control.sends ;
			   result.receivedBytes = control.receivedBytes ;
			   // 停止は成功/cacheより優先し、既commitの事実は独立に残します。
			   if( control.checkpoint() != 0) {
				   result.error					 = control.stopped ;
				   result.usedAuthenticatedCache = false ;
				   result.status =
					   control.stopped == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))
						   ? IndexRefreshStatus::CANCELLED
						   : (control.stopped ==
									  static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT))
								  ? IndexRefreshStatus::TIMED_OUT
								  : IndexRefreshStatus::INTERNAL_FAILURE) ;
			   }

			   return result ;
		} ; // 成功や失敗を返す直前の共通停止です。
		// UTC不明では通信・cache・保存を開始しません。
		if( !services.utcNow()) {
			result.status = IndexRefreshStatus::TIME_UNAVAILABLE ;
			return finish() ;
		}

		// 送信前取消しはstoreを変更しません。
		if( control.checkpoint() != 0) {
			return finish() ;
		}

		std::vector<std::byte> envelope ;	// 原currentだけの有限所有byteです。
		std::vector<std::byte> gzip ;		// 署名された元gzipだけです。
		auto				   error	   = client.getSignedIndexCurrent( control, envelope,
																		  result.httpStatus) ;	// 固定用途の共通HTTPです。
		const auto			   httpFailure = [&]( const NativeError failure) {
			result.status	 = IndexRefreshStatus::HTTP_FAILED ;
			result.error	 = failure ;
			result.httpError = failure ;
			// 一時通信失敗だけを現在UTCの全cache再認証へ渡します。
			if( control.checkpoint() == 0 && transient( failure, result.httpStatus)) {
				result.cache = services.reload( services.utcNow()) ;
				// 署名済みの現在有効snapshot観測だけを明示cache利用にします。
				if( result.cache->status == IndexStoreStatus::SNAPSHOT_READY &&
				   result.cache->usableSnapshot) {
					result.status = IndexRefreshStatus::AUTHENTICATED_CACHE ;
					result.usedAuthenticatedCache = true ;
				}
			}

			return finish() ;
		} ; // 元失敗を消さないcache分岐です。
		// 部分currentやHTTP拒否を署名成功へ渡しません。
		if( error != 0) {
			return httpFailure( error) ;
		}

		const std::string_view raw{reinterpret_cast<const char *>( envelope.data()),
								   // 原byteを借用する暗号境界です。
								   envelope.size()} ;
		auto				   manifest = services.fixtureTrust.empty()
											  ? authenticateSignedIndexManifest( raw, services.utcNow(), std::nullopt)
											  : signed_index_detail::authenticateWithTrustKeys(
									raw, services.utcNow(), std::nullopt,
									services.fixtureTrust) ;	// 内部fixtureだけのRAM trustです。
		// 未認証のgeneration/URL/鍵をauthorityにしません。
		if( !manifest.manifest) {
			result.status		  = IndexRefreshStatus::MANIFEST_REJECTED ;
			result.error		  = manifest.error ;
			result.manifestStatus = manifest.status ;
			return finish() ;
		}

		result.attemptedGeneration = manifest.manifest->data().generation ;
		// 認証段階間の停止をasset送信より先に確認します。
		if( control.checkpoint() != 0) {
			return finish() ;
		}

		error = client.getSignedIndexAsset( *manifest.manifest, control, gzip, result.httpStatus) ;
		// Assetの通信失敗も同じ有限cache規則だけを使用します。
		if( error != 0) {
			return httpFailure( error) ;
		}

		auto asset = authenticateIndexAssetBytes( *manifest.manifest, gzip,
												 // 実hash/GZip検査です。
												 services.utcNow()) ;
		// 原gzipの拒否をcacheで隠しません。
		if( !asset.receipt) {
			result.status	   = IndexRefreshStatus::ASSET_REJECTED ;
			result.error	   = asset.error ;
			result.assetStatus = asset.status ;
			return finish() ;
		}

		// 大きなcodec段階間でも同じ停止を確認します。
		if( control.checkpoint() != 0) {
			return finish() ;
		}

		auto records =
			// 実record/schema検査です。
			readSignedIndexRecords( *asset.receipt, services.utcNow()) ;
		// Schemaと元個別期限の拒否を有効取得recordへ昇格しません。
		if( !records.receipt || !attestationsCurrent( *records.receipt, services.utcNow())) {
			result.status		 = IndexRefreshStatus::RECORDS_REJECTED ;
			result.error		 = records.error ;
			result.recordsStatus = records.receipt ? IndexRecordsStatus::EXPIRED : records.status ;
			return finish() ;
		}

		// 通信終了後かつcommit直前の停止でのみ保存を開始しません。
		if( control.checkpoint() != 0) {
			return finish() ;
		}

		result.store = services.commit( *records.receipt, raw, gzip, services.utcNow()) ;
		result.status =
			result.store.status == IndexStoreStatus::SNAPSHOT_READY && result.store.usableSnapshot
				? IndexRefreshStatus::REFRESHED
				: IndexRefreshStatus::STORE_FAILED ;
		result.error		  = result.store.error ;
		result.manifestStatus = result.store.manifestStatus ;
		return finish() ;
	} catch( const std::bad_alloc &) {
		result.error = E_OUTOFMEMORY ;
	} catch( ...) {
		result.error = E_UNEXPECTED ;
	}

	result.status		 = IndexRefreshStatus::INTERNAL_FAILURE ;
	result.sends		 = control.sends ;
	result.receivedBytes = control.receivedBytes ;
	return result ;
}
/** @see Access宣言側の契約を正本とします。 */
IndexRefreshSummary signed_index_refresh_detail::Access::forTest(
	const Services &services, const HttpCancellationCallback &cancellation) noexcept
{
	// Fixtureのtransport欠損は製品native clientへfallbackしません。
	if( !services.transport) {
		IndexRefreshSummary result ;	// 欠損依存だけの拒否summaryです。
		result.error = E_INVALIDARG ;
		return result ;
	}

	OfficialHttpClient client( *services.transport) ;	// 完全fake表だけの非cache clientです。
	return execute( client, services, cancellation) ;
}
/** @see refreshFixedSignedIndex宣言側の契約を正本とします。 */
IndexRefreshSummary refreshFixedSignedIndex( const HttpCancellationCallback &cancellation) noexcept
{
	try {
		signed_index_refresh_detail::Services services ;	// 製品固定の依存だけです。
		services.utcNow = []() {
			return std::optional<std::chrono::sys_seconds>{
				std::chrono::floor<std::chrono::seconds>( std::chrono::system_clock::now())} ;
		} ;
		services.monotonicNow = []() { return std::chrono::steady_clock::now() ; } ;
		services.commit		  = []( const IndexRecordsSchemaReceipt &receipt,
							   const std::string_view envelope, const std::span<const std::byte> gzip,
							   const std::optional<std::chrono::sys_seconds> now) {
			  auto opened =
				  // HTTP終了後だけ固定rootを開きます。
				  SignedIndexStore::openFixedProtectedStore() ;
			  // 固定rootの拒否を別root/genesisへ回避しません。
			  if( !opened.store) {
				  IndexRefreshStoreObservation result ;	// 固定rootを開けなかった元診断です。
				  result.status = IndexStoreStatus::IO_FAILURE ;
				  result.error	= opened.error ;
				  return result ;
			  }

			  return observe( opened.store->commit( receipt, envelope, gzip, now), now) ;
		} ;
		services.reload = []( const std::optional<std::chrono::sys_seconds> now) {
			return observe( SignedIndexStore::reloadFixedExisting( now), now) ;
		} ;
		OfficialHttpClient client( false) ;	// 通常metadata cacheとsource ledgerを使用しません。
		return signed_index_refresh_detail::Access::execute( client, services, cancellation) ;
	} catch( ...) {
		IndexRefreshSummary result ;	// 境界例外を保持する拒否summaryです。
		result.error = E_UNEXPECTED ;
		return result ;
	}
}
} // namespace drivercrate
