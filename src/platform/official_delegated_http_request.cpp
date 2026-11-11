//------------------------------------------------------------------------------
/**
 * @file official_delegated_http_request.cpp
 * @brief Record限定grantから一回のGETだけを作る秘密requestを実装します。
 * @version 01.05.01
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
 * Ver.01.05.00 Shunji Ogawa  2026/11/03  匿名CDNの同record二要求と有限予約を接続。
 * Ver.01.05.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
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
 * @brief 未終端requestを失敗とし、秘密URLを消去します。
 */
//------------------------------------------------------------------------------
OfficialDelegatedGetRequest::~OfficialDelegatedGetRequest() noexcept
{
	abandon() ;
}

//------------------------------------------------------------------------------
/**
 * @brief Requestとgrantへの終端責務を移動します。
 * @param[in,out] other 空状態へ戻る移動元。
 */
//------------------------------------------------------------------------------
OfficialDelegatedGetRequest::OfficialDelegatedGetRequest(
	OfficialDelegatedGetRequest &&other) noexcept
{
	moveFrom( other) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現在のrequestを安全に中止し、別requestの所有権を移動します。
 * @param[in,out] other 空状態へ戻る移動元。自己代入も許可します。
 * @return このobjectへの参照。
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
 * @brief SessionとID・30秒余裕をgrantで検証し、秘密URL所有権を引き取ります。
 * @param[in,out] grant 成功時に`ACQUIRING`となり、request終了まで生存するgrant。
 * @param[in] scanSessionId 現在のworker scan session ID。
 * @param[in] grantId 操作が指定したopaque grant ID。
 * @param[in] nowUtcSeconds 最初のrequest開始直前UTC秒。
 * @param[in] maximumBytes Session予算と公開sizeで狭めた0ではない受信上限。
 * @return 準備成功時は0、再使用・stale・期限切れ・所有権不整合はHRESULT bit pattern。
 * @pre 本requestは`EMPTY`です。
 * @post 成功時は`READY`です。
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
 * @brief 所有中のexact targetを一回のHTTP GET開始境界へ貸し出します。
 * @param[out] exactTarget 成功時にだけrequest所有の完全URLを参照するview。
 * @return 最初の開始成功時は0、未準備・再使用・空URLはHRESULT bit pattern。
 * @post 成功時は`STARTED`です。
 * @warning ViewをHTTP parserと`WinHttpOpenRequest`呼出しより長く保持しないでください。
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
 * @brief Grantの取得結果を確定し、requestの秘密URLを消去します。
 * @param[in] outcome `RecordScopedDownloadGrant::finishAcquisition`が許可する終端結果。
 * @param[in] error 成功は0、それ以外は0ではない診断値。
 * @return Grantの終端成功時は0、不正状態・結果・診断値はHRESULT bit pattern。
 * @post 成功時は`CONSUMED`でURLを保持しません。
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
 * @brief URLを公開せず現在のrequest状態を返します。
 * @return Worker内requestの現在状態。
 */
//------------------------------------------------------------------------------
OfficialDelegatedGetState OfficialDelegatedGetRequest::state() const noexcept
{
	return state_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief Grantが許可した有限受信上限を返します。
 * @return `READY`または`STARTED`の上限byte数。それ以外は0。
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
 * @brief 固定payload policy照合に使うProvider stable IDを返します。
 * @return `READY`または`STARTED`のProvider ID。それ以外は空view。
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
 * @brief 固定payload policy照合に使うresource IDを返します。
 * @return `READY`または`STARTED`のpayload resource ID。それ以外は空view。
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
 * @brief 現在のGET hopを開始できる期限余裕があるか検証します。
 * @param[in] nowUtcSeconds Hop開始直前のUTC秒。
 * @return 30秒以上の余裕があれば0、状態不整合・時計異常・期限不足はHRESULT bit pattern。
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
 * @brief 索引以外の認識済み外部expiryを持つ初回grantか返します。
 * @return 索引以外で外部expiryがあり、root再解決回数が0の有効requestならtrue。
 * @note 本値だけでは再解決を実行せず、期限または最初の401／403を別途要求します。
 */
//------------------------------------------------------------------------------
bool OfficialDelegatedGetRequest::canReresolveExpiringTarget() const noexcept
{
	const bool active = state_ == OfficialDelegatedGetState::READY ||
						// HTTP開始後も終端前なら判定できる。
						state_ == OfficialDelegatedGetState::STARTED ;
	return active && grant_ != nullptr &&
		   grant_->metadata().origin !=
			   OfficialDownloadGrantOrigin::SIGNED_INDEX_COLLECTOR_ATTESTATION &&
		   grant_->metadata().externalExpiryPresent && grant_->metadata().reresolutionCount == 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現requestのgrant由来を非機密分類で返します。
 * @return 結合済みgrant由来。空requestでは従来分類です。
 */
//------------------------------------------------------------------------------
OfficialDownloadGrantOrigin OfficialDelegatedGetRequest::origin() const noexcept
{
	return grant_ == nullptr ? OfficialDownloadGrantOrigin::LIVE_OFFICIAL_NETWORK
							 : grant_->metadata().origin ;
}

//------------------------------------------------------------------------------
/**
 * @brief 索引grant自身の封印exact routeを再照合します。
 * @param[in] target 現hopの完全URL。
 * @param[in] hop 0起点hop位置。
 * @param[in] finalResponse 最終200 responseの確認指定。
 * @return 生存封印・exact順一致時0。それ以外は拒否HRESULT。
 */
//------------------------------------------------------------------------------
NativeError OfficialDelegatedGetRequest::validateSignedIndexHop(
	const std::wstring_view target, const std::uint32_t hop,
	const bool finalResponse) const noexcept
{
	return grant_ == nullptr ? E_ACCESSDENIED
							 : grant_->validateSignedIndexHop( target, hop, finalResponse) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Grantが固定した期待content typeを借用します。
 * @return 結合grantの期待形式。空requestは空です。
 */
//------------------------------------------------------------------------------
std::wstring_view OfficialDelegatedGetRequest::expectedContentType() const noexcept
{
	return grant_ == nullptr ? std::wstring_view{} : grant_->payloadView().expectedContentType ;
}

//------------------------------------------------------------------------------
/**
 * @brief 未終端grantを失敗へ進め、request所有値を消去します。
 */
//------------------------------------------------------------------------------
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
 * @brief 秘密URL・grant終端責務と非機密状態を移動します。
 * @param[in,out] other 空に戻る移動元。
 */
//------------------------------------------------------------------------------
void OfficialDelegatedGetRequest::moveFrom( OfficialDelegatedGetRequest &other) noexcept
{
	auxiliary_	  = std::exchange( other.auxiliary_, {}) ;
	grant_		  = std::exchange( other.grant_, nullptr) ;
	targetUrl_	  = std::move( other.targetUrl_) ;
	state_		  = std::exchange( other.state_, OfficialDelegatedGetState::EMPTY) ;
	maximumBytes_ = std::exchange( other.maximumBytes_, 0U) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同recordの未解決公開文脈だけを借用する。
 * @return 同STARTED requestで元planが有効ならその値。なければnull。
 */
//------------------------------------------------------------------------------
const OfficialAnonymousCdnPlan *OfficialDelegatedGetRequest::anonymousCdnPlan() const noexcept
{
	return state_ == OfficialDelegatedGetState::STARTED && grant_ ? grant_->anonymousCdnPlan()
																  : nullptr ;
}
//------------------------------------------------------------------------------
/**
 * @brief 新responseを元request/grantへ一度だけ結合する。
 * @param[in,out] resolution 成功時に秘密URL所有権を引き取る同response。
 * @param[in] now 現workerのUTC秒。
 * @return 元record/route/expiry結合成功0、元HRESULT。
 */
//------------------------------------------------------------------------------
NativeError OfficialDelegatedGetRequest::acceptAnonymousCdnResolution(
	OfficialAnonymousCdnResolution &resolution, const std::uint64_t now)
{
	// 公開DTOや再使用requestから秘密routeを差し替えない。
	if( state_ != OfficialDelegatedGetState::STARTED || !grant_) {
		return E_ACCESSDENIED ;
	}

	const auto error = grant_->sealAnonymousCdnResolution(
		// 元sealの診断。
		targetUrl_.view(), resolution.target, resolution.expiresUtcSeconds, now) ;
	// 全結合が揃った秘密URLだけを同requestへ移す。
	if( error == 0) {
		targetUrl_ = std::move( resolution.target) ;
	}

	return error ;
}

} // namespace drivercrate
