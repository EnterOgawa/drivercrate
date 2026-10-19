//------------------------------------------------------------------------------
/**
 * @file local_collector_http_client.cpp
 * @brief 永続許可の照合後だけ有限公式GETへ接続します。
 * @version 01.02.00
 * @date 2026/09/28
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  有限DNS・共通HTTP制御接続を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/28  正常200だけのmove-only本文とmode照合を追加。
 * Ver.01.01.01 Shunji Ogawa  2026/09/28  元200 pin以前の条件付きGETと304成功を拒否。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  不変job入口・本文消費と同一control所有を追加。
 * </pre>
 *
 * @note 台帳・公式parser・導入処理は実行しません。
 * @see docs/adr/0218-collector-controlled-http-lifetime.md
 */
//------------------------------------------------------------------------------
#include "platform/local_collector_http_client.h"
#include "platform/local_collector_legacy.h"
#include "core/official_source_policy.h"
#include <utility>

namespace drivercrate {
/** @see local_collector_http_client.h */
CollectorMetadataBody::CollectorMetadataBody( std::wstring &&text, std::wstring &&bodySha256,
											 const std::uint64_t			   headerUtcMillis,
											 const std::uint64_t			   validatedUtcMillis,
											 const CollectorRecoveryDispatch  &binding,
											 const CollectorProjectedJobInput &job,
											 const std::shared_ptr<CollectorHttpControl> &control)
	: text_( std::move( text)), bodySha256_( std::move( bodySha256)), headerUtcMillis_( headerUtcMillis),
	  validatedUtcMillis_( validatedUtcMillis), binding_( binding), scopeSha256_( job.scopeSha256),
	  providerId_( job.providerId), policyId_( job.policyId), control_( control), valid_( true)
{
}

/** @see local_collector_http_client.h */
CollectorMetadataBody::CollectorMetadataBody( CollectorMetadataBody &&other) noexcept
	: text_( std::move( other.text_)), bodySha256_( std::move( other.bodySha256_)),
	  headerUtcMillis_( other.headerUtcMillis_), validatedUtcMillis_( other.validatedUtcMillis_),
	  binding_( std::move( other.binding_)), scopeSha256_( std::move( other.scopeSha256_)),
	  providerId_( std::move( other.providerId_)), policyId_( std::move( other.policyId_)),
	  control_( std::move( other.control_)), valid_( std::exchange( other.valid_, false))
{
	other.text_.clear() ;
	other.bodySha256_.clear() ;
}

/** @see local_collector_http_client.h */
CollectorMetadataBody &CollectorMetadataBody::operator=( CollectorMetadataBody &&other) noexcept
{
	// 自身への移動でも本文を複製しない。
	if( this == &other) {
		return *this ;
	}

	text_				= std::move( other.text_) ;
	bodySha256_			= std::move( other.bodySha256_) ;
	headerUtcMillis_	= other.headerUtcMillis_ ;
	validatedUtcMillis_ = other.validatedUtcMillis_ ;
	binding_			= std::move( other.binding_) ;
	scopeSha256_		= std::move( other.scopeSha256_) ;
	providerId_			= std::move( other.providerId_) ;
	policyId_			= std::move( other.policyId_) ;
	control_			= std::move( other.control_) ;
	valid_				= std::exchange( other.valid_, false) ;
	other.text_.clear() ;
	other.bodySha256_.clear() ;
	return *this ;
}

/** @see local_collector_http_client.h */
bool CollectorMetadataBody::consumeForProjection(
	const CollectorPreparedProjectedCampaign &campaign, const std::size_t jobIndex,
	std::shared_ptr<CollectorHttpControl> &control) noexcept
{
	control.reset() ;
	// 不成立でも同じ本文の別jobへの再提示を許さない。
	if( !std::exchange( valid_, false)) {
		return false ;
	}

	const auto *job = campaign.job( jobIndex) ;	// 元入力から作られた一つの共有job。
	// 元GETとcontrolの全binding、正常200の原観測を再照合する。
	if( job == nullptr || control_ == nullptr ||
	   binding_.mode != CollectorRecoveryDispatch::Mode::PROJECTED ||
	   binding_.generationKey != campaign.generationKey() || binding_.jobIndex != jobIndex ||
	   binding_.jobKey != job->value().jobKey || binding_.requestKey != job->value().requestKey ||
	   binding_.cacheBinding != job->value().cacheBinding ||
	   binding_.scopeSha256 != job->value().scopeSha256 ||
	   scopeSha256_ != job->value().scopeSha256 || providerId_ != job->value().providerId ||
	   policyId_ != job->value().policyId ||
	   !sameCollectorRecoveryDispatch( binding_, control_->binding())) {
		return false ;
	}

	const auto observed = control_->snapshot() ;	// GET後・finish前の元観測。
	// 空本文・解放前・別header・終了済み制御から射影へ進まない。
	if( text_.empty() || bodySha256_.size() != 64U || validatedUtcMillis_ < headerUtcMillis_ ||
	   observed.cause != CollectorIoCause::NONE || observed.sealed || !observed.nativeReleased ||
	   observed.sends != 1U || observed.headerUtcMillis != headerUtcMillis_) {
		return false ;
	}

	control = std::move( control_) ;
	return true ;
}

/** @see local_collector_http_client.h */
LocalCollectorHttpClient::LocalCollectorHttpClient() : client_( false), dns_( nativeCollectorDnsApi())
{
}
/** @see local_collector_http_client.h */
LocalCollectorHttpClient::LocalCollectorHttpClient( OfficialHttpTransport   transport,
												   OfficialCollectorDnsApi dnsApi)
	: client_( transport), dns_( dnsApi)
{
	// 既存tableのnative既定値をfixtureの欠損へ補完させない。
	dependenciesValid_ =
		transport.open && transport.open != WinHttpOpen && transport.connect &&
		transport.connect != WinHttpConnect && transport.openRequest &&
		transport.openRequest != WinHttpOpenRequest && transport.setTimeouts &&
		transport.setTimeouts != WinHttpSetTimeouts && transport.setOption &&
		transport.setOption != WinHttpSetOption && transport.addHeaders &&
		transport.addHeaders != WinHttpAddRequestHeaders && transport.sendRequest &&
		transport.sendRequest != WinHttpSendRequest && transport.receiveResponse &&
		transport.receiveResponse != WinHttpReceiveResponse && transport.queryHeaders &&
		transport.queryHeaders != WinHttpQueryHeaders && transport.queryAvailable &&
		transport.queryAvailable != WinHttpQueryDataAvailable && transport.readData &&
		transport.readData != WinHttpReadData && transport.closeHandle &&
		transport.closeHandle != WinHttpCloseHandle && dns_.startup && dns_.startup != WSAStartup &&
		dns_.resolve && dns_.resolve != GetAddrInfoExW && dns_.freeResult &&
		dns_.freeResult != FreeAddrInfoExW && dns_.cleanup && dns_.cleanup != WSACleanup &&
		dns_.lastError && dns_.lastError != WSAGetLastError ;
}
/** @see local_collector_http_client.h */
NativeError LocalCollectorHttpClient::get( const LocalCollectorTarget	  &target,
										  const CollectorRecoveryDispatch &binding,
										  CollectorHttpPermit &permit, std::wstring_view entityTag,
										  std::wstring							&text,
										  CollectorControlledHttpObservation	&observation,
										  std::shared_ptr<CollectorHttpControl> &control)
{
	return getCore( target, binding, permit, entityTag, CollectorRecoveryDispatch::Mode::CONTROLLED,
				   text, observation, control) ;
}

/** @see local_collector_http_client.h */
NativeError LocalCollectorHttpClient::getMetadataBody(
	const CollectorPreparedProjectedCampaign &campaign, const std::size_t jobIndex,
	const CollectorRecoveryDispatch &binding, CollectorHttpPermit &permit,
	const std::wstring_view entityTag, std::optional<CollectorMetadataBody> &body,
	CollectorControlledHttpObservation &observation, std::shared_ptr<CollectorHttpControl> &control)
{
	const auto *job = campaign.job( jobIndex) ;	// 元canonicalから一回だけ準備したjob。
	// 別世代・別index・空jobは元permitをclaimせず拒否する。
	if( job == nullptr || binding.mode != CollectorRecoveryDispatch::Mode::PROJECTED ||
	   binding.generationKey != campaign.generationKey() || binding.jobIndex != jobIndex) {
		used_ = true ;
		body.reset() ;
		observation = {} ;
		control.reset() ;
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	return getMetadataBody( job->value(), binding, permit, entityTag, body, observation, control) ;
}

/** @see local_collector_http_client.h */
NativeError LocalCollectorHttpClient::getMetadataBody(
	const CollectorProjectedJobInput &job, const CollectorRecoveryDispatch &binding,
	CollectorHttpPermit &permit, const std::wstring_view entityTag,
	std::optional<CollectorMetadataBody> &body, CollectorControlledHttpObservation &observation,
	std::shared_ptr<CollectorHttpControl> &control)
{
	body.reset() ;
	observation = {} ;
	control.reset() ;
	// 元予約と公開requestの全結合が欠ける場合は一回clientを消費し、送信しない。
	if( binding.mode != CollectorRecoveryDispatch::Mode::PROJECTED ||
	   binding.jobIndex != job.jobIndex || binding.jobKey != job.jobKey ||
	   binding.requestKey != job.requestKey || binding.cacheBinding != job.cacheBinding ||
	   binding.scopeSha256 != job.scopeSha256 || binding.source.sourceId != job.source.sourceId ||
	   binding.source.resourceId != job.source.resourceId ||
	   binding.source.rateLimitGroup != job.source.rateLimitGroup ||
	   binding.source.parserRevision != job.source.parserRevision ||
	   binding.source.maximumResponseBytes != job.source.maximumResponseBytes ||
	   job.scopeSha256.size() != 64U || job.providerId.empty() || job.policyId.empty() ||
	   !entityTag.empty()) {
		used_ = true ;
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	try {
		LocalCollectorRequest request ;	// 元公式requestを別sourceから差替えさせない。
		// Providerに登録済みの固定公式policyだけを解決する。
		const auto			 *policy = officialSourcePolicyForProvider( job.providerId) ;
		// 元公開requestと組み込みpolicyの対応をGETより先に検査する。
		if( !makeLocalCollectorRequest( job.requestTarget, request) ||
		   request.provider != job.providerId || request.requestKey != binding.requestKey ||
		   policy == nullptr || policy->id != job.policyId) {
			used_ = true ;
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		std::wstring text ;	// 同じGETが返した200本文だけを一時所有する。
		// 元permitをclaimして有限GETを一度だけ実行する。
		const auto	 error =
			getCore( job.requestTarget, binding, permit, entityTag,
					CollectorRecoveryDispatch::Mode::PROJECTED, text, observation, control) ;
		// 通信拒否・取消し・期限後に200本文を作らない。
		if( error != 0U) {
			return error ;
		}

		// 元200のpinがない304は200検証を通過させない。
		const auto snapshot = control->snapshot() ;	// 元GETのheaders・解放・送信数。
		// Decode・raw hash・native解放後の正常200だけを所有本文にする。
		if( observation.status != 200U || text.empty() || observation.bodySha256.size() != 64U ||
		   !snapshot.headerUtcMillis || !snapshot.nativeReleased || snapshot.sends != 1U ||
		   control->begin( CollectorIoStage::PARSE, 60000U) == 0U) {
			control->fail(
				CollectorIoCause::PARSER,
				{CollectorIoErrorDomain::PARSER, ERROR_INVALID_DATA, CollectorIoStage::PARSE},
				false) ;
			return collectorControlError( *control) ;
		}

		const auto verified = control->lastClockSample() ;	// PARSE直前に実採取したUTC。
		// headerより前の検証時刻を成功に丸めない。
		if( !verified || verified->utcMillis < *snapshot.headerUtcMillis) {
			control->fail(
				CollectorIoCause::CLOCK,
				{CollectorIoErrorDomain::WIN32_ERROR, ERROR_INVALID_DATA, CollectorIoStage::PARSE},
				false) ;
			return collectorControlError( *control) ;
		}

		std::wstring bodyHash = observation.bodySha256 ;	// HTTP観測は元hashのまま維持する。
		body.emplace( CollectorMetadataBody( std::move( text), std::move( bodyHash),
										   *snapshot.headerUtcMillis, verified->utcMillis, binding,
										   job, control)) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		used_ = true ;
		body.reset() ;
		// 同一controlに元OOMを記録し、再取得しない。
		if( control) {
			control->fail( CollectorIoCause::PARSER,
						  {CollectorIoErrorDomain::HRESULT_ERROR,
						   static_cast<std::uint32_t>( E_OUTOFMEMORY), CollectorIoStage::PARSE},
						  false) ;
			return collectorControlError( *control) ;
		}

		return static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		used_ = true ;
		body.reset() ;
		// OOM以外の例外をOOMと誤報せず固定診断へ落とす。
		if( control) {
			control->fail( CollectorIoCause::PARSER,
						  {CollectorIoErrorDomain::HRESULT_ERROR,
						   static_cast<std::uint32_t>( E_FAIL), CollectorIoStage::PARSE},
						  false) ;
			return collectorControlError( *control) ;
		}

		return static_cast<NativeError>( E_FAIL) ;
	}
}

/** @see local_collector_http_client.h */
NativeError LocalCollectorHttpClient::getCore(
	const LocalCollectorTarget &target, const CollectorRecoveryDispatch &binding,
	CollectorHttpPermit &permit, const std::wstring_view entityTag,
	const CollectorRecoveryDispatch::Mode mode, std::wstring &text,
	CollectorControlledHttpObservation &observation, std::shared_ptr<CollectorHttpControl> &control)
{
	text.clear() ;
	observation = {} ;
	control.reset() ;
	// Clientを別permitへ使い回さない。
	if( std::exchange( used_, true) || binding.mode != mode) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	control = permit.claim( this, binding) ;
	// 空・別結合・二重消費のpermitで通信しない。
	if( !control) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	try {
		LocalCollectorRequest request ;	// 共通生成したメモリ内URLと恒久identity。
		// Source／resource／固定header／requestを予約へ再結合する。
		if( !dependenciesValid_ || !makeLocalCollectorRequest( target, request) ||
		   request.source != binding.source.sourceId ||
		   request.resource != binding.source.resourceId ||
		   request.group != binding.source.rateLimitGroup ||
		   request.requestKey != binding.requestKey ||
		   request.accept !=
			   L"application/json, application/xml, text/xml, application/octet-stream, */*" ||
		   binding.source.maximumResponseBytes == 0U ||
		   binding.source.maximumResponseBytes > 8U * 1024U * 1024U) {
			control->fail(
				CollectorIoCause::SETUP,
				{CollectorIoErrorDomain::PARSER, ERROR_INVALID_PARAMETER, CollectorIoStage::SETUP},
				false) ;
			return collectorControlError( *control) ;
		}

		// Sessionを作る前も元予約の時計で停止を確認する。
		if( control->begin( CollectorIoStage::SETUP, 60000U) == 0U) {
			return collectorControlError( *control) ;
		}

		const auto sessionError =
			// 許可済みsource限定。
			client_.beginSourceSession( 1U, request.provider) ;
		// Policy拒否をURL直指定で迂回しない。
		if( sessionError != 0U) {
			control->fail( CollectorIoCause::SETUP,
						  {CollectorIoErrorDomain::HRESULT_ERROR,
						   static_cast<std::uint32_t>( sessionError), CollectorIoStage::SETUP},
						  false) ;
			return collectorControlError( *control) ;
		}

		return client_.getControlledCollectorMetadataForSource(
			request.url, request.resource, binding.source.maximumResponseBytes, entityTag, *control,
			dns_, text, observation) ;
	} catch( ...) {
		control->fail( CollectorIoCause::SETUP,
					  {CollectorIoErrorDomain::HRESULT_ERROR, static_cast<std::uint32_t>( E_FAIL),
					   CollectorIoStage::SETUP},
					  false) ;
		return collectorControlError( *control) ;
	}
}
} // namespace drivercrate
