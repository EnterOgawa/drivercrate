//------------------------------------------------------------------------------
/**
 * @file official_delegated_http_request.cpp
 * @brief Record限定grantから一回のGETだけを作る秘密requestを実装します。
 * @version 01.04.00
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  GET限定の秘密request所有型を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  固定payload redirect照合用viewを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  各HTTP hop開始前の期限再検証を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  取得予算でgrant上限を狭める準備引数を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  署名索引の共通取得境界と既存経路の区別を追加。
 * </pre>
 *
 * @note 例外をworker境界へ漏らさず、放棄時もgrantを失敗終端してURLを消去します。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#include "platform/official_delegated_http_request.h"

#include <Windows.h>

#include <utility>

namespace drivercrate {
namespace {

constexpr NativeError ABANDONED_REQUEST =
	// RAII放棄をgrantへ保持する診断値。
	static_cast<NativeError>( E_ABORT) ;
constexpr NativeError INVALID_REQUEST =
	// Request状態またはURL所有の不整合。
	static_cast<NativeError>( E_UNEXPECTED) ;

} // namespace

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_http_request.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
OfficialDelegatedGetRequest::~OfficialDelegatedGetRequest() noexcept
{
	abandon() ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_http_request.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
OfficialDelegatedGetRequest::OfficialDelegatedGetRequest(
	OfficialDelegatedGetRequest &&other) noexcept
{
	moveFrom( other) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_http_request.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
OfficialDelegatedGetRequest &OfficialDelegatedGetRequest::operator=(
	OfficialDelegatedGetRequest &&other) noexcept
{
	// 自己moveで所有URLとgrant終端責務を失わない。
	if( this != &other) {
		abandon() ;
		moveFrom( other) ;
	}

	return *this ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_http_request.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError OfficialDelegatedGetRequest::prepare( RecordScopedDownloadGrant &grant,
												 const ScanSessionId		scanSessionId,
												 const std::uint64_t		grantId,
												 const std::uint64_t		nowUtcSeconds,
												 const std::uint64_t		maximumBytes) noexcept
{
	// 同じrequest objectへ二つのgrantを結合しない。
	if( state_ != OfficialDelegatedGetState::EMPTY || grant_ != nullptr || !targetUrl_.empty() ||
	   maximumBytes == 0U || maximumBytes > grant.metadata().maximumBytes) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const NativeError claimError =
		// Grantの一回開始結果。
		grant.claim( scanSessionId, grantId, nowUtcSeconds) ;
	// Grantが拒否したrequestはURLを取得せずその診断を返す。
	if( claimError != 0) {
		return claimError ;
	}

	SecretOfficialUrl claimedUrl =
		// HTTP requestが単独所有する秘密URL。
		grant.takeTargetUrlForHttp() ;
	// Claim後にURL所有権を得られない不整合はgrantも失敗へ閉じる。
	if( claimedUrl.empty()) {
		static_cast<void>(
			grant.finishAcquisition( OfficialDownloadGrantState::FAILED, INVALID_REQUEST)) ;
		return INVALID_REQUEST ;
	}

	grant_		  = &grant ;
	targetUrl_	  = std::move( claimedUrl) ;
	state_		  = OfficialDelegatedGetState::READY ;
	maximumBytes_ = maximumBytes ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_http_request.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError OfficialDelegatedGetRequest::beginGet( std::wstring_view &exactTarget) noexcept
{
	exactTarget = {} ;
	// 未準備、既開始、所有権不整合のrequestをGETに使わない。
	if( state_ != OfficialDelegatedGetState::READY || grant_ == nullptr || targetUrl_.empty() ||
	   maximumBytes_ == 0U) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	state_		= OfficialDelegatedGetState::STARTED ;
	exactTarget = targetUrl_.view() ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_http_request.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError OfficialDelegatedGetRequest::finish( const OfficialDownloadGrantState outcome,
												const NativeError				 error) noexcept
{
	// 終端済みまたはgrantに結合されないrequestを成功として閉じない。
	if( (state_ != OfficialDelegatedGetState::READY &&
		state_ != OfficialDelegatedGetState::STARTED) ||
	   grant_ == nullptr) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	// GET開始前のrequestを取得成功として確定しない。
	if( outcome == OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION &&
	   state_ != OfficialDelegatedGetState::STARTED) {
		return static_cast<NativeError>( E_INVALIDARG) ;
	}

	// Grant側の終端状態と診断整合を確定した結果。
	const NativeError finishError = grant_->finishAcquisition( outcome, error) ;
	// Grantが終端値を拒否した場合はrequestを維持し、正しい終端を必須にする。
	if( finishError != 0) {
		return finishError ;
	}

	targetUrl_.clear() ;
	grant_		  = nullptr ;
	maximumBytes_ = 0U ;
	state_		  = OfficialDelegatedGetState::CONSUMED ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_http_request.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
OfficialDelegatedGetState OfficialDelegatedGetRequest::state() const noexcept
{
	return state_ ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_http_request.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
std::uint64_t OfficialDelegatedGetRequest::maximumBytes() const noexcept
{
	return state_ == OfficialDelegatedGetState::READY ||
				   state_ == OfficialDelegatedGetState::STARTED
			   ? maximumBytes_
			   : 0U ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_http_request.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
std::wstring_view OfficialDelegatedGetRequest::providerId() const noexcept
{
	const bool active = state_ == OfficialDelegatedGetState::READY ||
						// Policy照合可能な状態。
						state_ == OfficialDelegatedGetState::STARTED ;
	return active && grant_ != nullptr ? std::wstring_view{grant_->metadata().providerId}
									   : std::wstring_view{} ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_http_request.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
std::wstring_view OfficialDelegatedGetRequest::payloadResourceId() const noexcept
{
	const bool active = state_ == OfficialDelegatedGetState::READY ||
						// Policy照合可能な状態。
						state_ == OfficialDelegatedGetState::STARTED ;
	return active && grant_ != nullptr ? grant_->payloadView().resourceId : std::wstring_view{} ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_http_request.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
NativeError OfficialDelegatedGetRequest::validateStartDeadline(
	const std::uint64_t nowUtcSeconds) const noexcept
{
	// GET開始後かつgrant終端前だけをredirectを含むhop開始へ使用する。
	if( state_ != OfficialDelegatedGetState::STARTED || grant_ == nullptr) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	return grant_->validateRequestStartDeadline( nowUtcSeconds) ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_http_request.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
bool OfficialDelegatedGetRequest::canReresolveExpiringTarget() const noexcept
{
	const bool active = state_ == OfficialDelegatedGetState::READY ||
						// HTTP開始後も終端前なら判定できる。
						state_ == OfficialDelegatedGetState::STARTED ;
	return active && grant_ != nullptr && grant_->metadata().externalExpiryPresent &&
		   grant_->metadata().reresolutionCount == 0U ;
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_http_request.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
OfficialDownloadGrantOrigin OfficialDelegatedGetRequest::origin() const noexcept
{
	return grant_ == nullptr ? OfficialDownloadGrantOrigin::LIVE_OFFICIAL_NETWORK
							 : grant_->metadata().origin ;
}

/** @see OfficialDelegatedGetRequest 宣言側の契約を正本とする。 */
NativeError OfficialDelegatedGetRequest::validateSignedIndexHop(
	const std::wstring_view target, const std::uint32_t hop,
	const bool finalResponse) const noexcept
{
	return grant_ == nullptr ? E_ACCESSDENIED
							 : grant_->validateSignedIndexHop( target, hop, finalResponse) ;
}

/** @see OfficialDelegatedGetRequest 宣言側の契約を正本とする。 */
std::wstring_view OfficialDelegatedGetRequest::expectedContentType() const noexcept
{
	return grant_ == nullptr ? std::wstring_view{} : grant_->payloadView().expectedContentType ;
}

/** @see OfficialDelegatedGetRequest 宣言側の契約を正本とする。 */
void OfficialDelegatedGetRequest::abandon() noexcept
{
	// 終端前のgrantをrequest破棄後にACQUIRINGへ残さない。
	if( grant_ != nullptr && (state_ == OfficialDelegatedGetState::READY ||
							 state_ == OfficialDelegatedGetState::STARTED)) {
		static_cast<void>(
			grant_->finishAcquisition( OfficialDownloadGrantState::FAILED, ABANDONED_REQUEST)) ;
	}

	targetUrl_.clear() ;
	grant_		  = nullptr ;
	maximumBytes_ = 0U ;
	// 既に使用したrequest objectは再準備できない。
	if( state_ != OfficialDelegatedGetState::EMPTY) {
		state_ = OfficialDelegatedGetState::CONSUMED ;
	}
}

//------------------------------------------------------------------------------
/**
 * @see src/platform/official_delegated_http_request.h 宣言側の契約を正本とします。
 */
//------------------------------------------------------------------------------
void OfficialDelegatedGetRequest::moveFrom( OfficialDelegatedGetRequest &other) noexcept
{
	grant_		  = std::exchange( other.grant_, nullptr) ;
	targetUrl_	  = std::move( other.targetUrl_) ;
	state_		  = std::exchange( other.state_, OfficialDelegatedGetState::EMPTY) ;
	maximumBytes_ = std::exchange( other.maximumBytes_, 0U) ;
}

} // namespace drivercrate
