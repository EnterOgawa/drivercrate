//------------------------------------------------------------------------------
/**
 * @file collector_inspection_acquisition.cpp
 * @brief 台帳起点の実HTML確認と一回payload取得の共通接続。
 * @version 01.00.00
 * @date 2026/10/06
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  外部定義の静的導線と共通生存取得を接続。
 * </pre>
 *
 * @note 同期収集worker専用。公開bool・研究hashで公式取得根拠を復元しない。
 * @see docs/adr/0280-collector-scoped-inspection-acquisition.md
 */
//------------------------------------------------------------------------------
#include "platform/collector_inspection_acquisition.h"
#include "core/official_source_policy.h"
#include "platform/official_static_record_parser.h"
#include <algorithm>
#include <array>
#include <utility>

namespace drivercrate {
namespace {
/** @brief URLとhrefの有限な未解釈文字を確認する。
 * @param[in] value 台帳のURLまたはhref。
 * @param[in] maximum 文字数上限。
 * @return 空・制御・認証query・entity・fragment等がない場合true。
 */
bool plainInspectionValue( std::wstring_view value, std::size_t maximum)
{
	return !value.empty() && value.size() <= maximum &&
		   value.find_first_of( L"?#@<>&\"'\\") == std::wstring_view::npos &&
		   value.find( L"..") == std::wstring_view::npos &&
		   std::ranges::none_of(
			   value, []( wchar_t character) { return character <= L' ' || character == L'\x7f' ; }) ;
}

/** @brief Exact hostだけの小文字ASCII集合を確認する。
 * @param[in] host 台帳host。
 * @return Suffix・大文字・制御・IP literalを含まないDNS形の場合true。
 */
bool exactInspectionHost( std::wstring_view host)
{
	return host.size() <= 253U && host.find( L'.') != std::wstring_view::npos &&
		   !host.starts_with( L'.') && !host.ends_with( L'.') &&
		   std::ranges::all_of( host, []( wchar_t character) {
			   return (character >= L'a' && character <= L'z') ||
					  (character >= L'0' && character <= L'9') || character == L'-' ||
					  character == L'.' ;
		   }) ;
}

/** @brief 定義hrefを起点URLから有限な文字列規則で解決する。
 * @param[in] source 事前文字検査済みの定義。
 * @return 絶対href、root相対、page相対だけの解決値。
 * @note Dot segment・query・entity・scheme相対の補完は行わない。
 */
std::wstring resolvedInspectionHref( const CollectorInspectionSource &source)
{
	// 明示絶対HTTPSを別schemeへ補完しない。
	if( source.href.starts_with( L"https://")) {
		return source.href ;
	}

	// Root相対は同じ起点originだけへ解決する。
	if( source.href.starts_with( L"/")) {
		return L"https://" + source.rootHost + source.href ;
	}

	return source.rootUrl.substr( 0U, source.rootUrl.rfind( L'/') + 1U) + source.href ;
}
/** @brief 対象href markerが別属性の引用符内でないことを確認する。
 * @param[in] tag 引用符終端を確認した原anchor開始tag。
 * @param[in] marker 空白とhrefの正確な属性token。
 * @return 引用符外の一意属性だけならtrue。
 */
bool inspectionMarkerIsAttribute( std::wstring_view tag, std::wstring_view marker)
{
	wchar_t		quote{} ;	// 0は属性値外。
	std::size_t matches{} ;	// 属性値内の偽markerを数えない。
	// 有限tag全体を走査し、属性tokenの文脈を確認する。
	for( std::size_t index = 0U; index < tag.size(); ++index) {
		// Markerが属性値の外にある時だけ有効とする。
		if( quote == 0U && tag.substr( index).starts_with( marker)) {
			++matches ;
		}

		// 同じ引用符だけが属性値を閉じる。
		if( quote != 0U && tag[index] == quote) {
			quote = 0U ;
		}
		// 別引用符の開始は属性値外だけで認める。
		else if( quote == 0U && (tag[index] == L'"' || tag[index] == L'\'')) {
			quote = tag[index] ;
		}
	}

	return quote == 0U && matches == 1U ;
}
} // namespace

/** @see collector_inspection_acquisition.h */
bool validateCollectorInspectionSource( const CollectorInspectionSource &source)
{
	const std::array<std::wstring_view, 1U> rootHosts{source.rootHost} ;		// Exact起点host。
	const std::array<std::wstring_view, 1U> payloadHosts{source.payloadHost} ;	// Record限定委譲先。
	return exactInspectionHost( source.rootHost) && exactInspectionHost( source.payloadHost) &&
		   plainInspectionValue( source.rootUrl, 8192U) &&
		   plainInspectionValue( source.payloadUrl, 8192U) &&
		   plainInspectionValue( source.href, 480U) && !source.href.starts_with( L"//") &&
		   source.rootUrl.starts_with( L"https://" + source.rootHost + L"/") &&
		   source.payloadUrl.starts_with( L"https://" + source.payloadHost + L"/") &&
		   validateOfficialHttpsUrl( source.rootUrl, rootHosts) == 0 &&
		   validateOfficialHttpsUrl( source.payloadUrl, payloadHosts) == 0 &&
		   resolvedInspectionHref( source) == source.payloadUrl ;
}

/** @see collector_inspection_acquisition.h */
bool verifyCollectorInspectionLink( std::wstring_view html, const CollectorInspectionSource &source)
{
	// 台帳の不正形・過大／NUL本文を走査前に拒否する。
	if( !validateCollectorInspectionSource( source) || html.empty() ||
	   html.size() > 2U * 1024U * 1024U || html.find( L'\0') != std::wstring_view::npos) {
		return false ;
	}

	std::wstring lower( html) ;	// TagのASCII caseだけを走査用に統一する。
	// 原属性値はhtmlから読み、大小文字を勝手に変換しない。
	for( auto &character : lower) {
		// Tag比較用のASCII大文字だけを小文字へ揃える。
		if( character >= L'A' && character <= L'Z') {
			character = static_cast<wchar_t>( character - L'A' + L'a') ;
		}
	}

	const std::wstring marker = L" href=\"" + source.href + L"\"" ;	// 対象の原属性。
	std::size_t		   offset{} ;									// 最後に処理したtag末尾。最大8192tagで終了する。
	std::size_t		   tagCount{} ;									// Commentを含む有限走査数。
	std::size_t		   matches{} ;									// 二件以上なら曖昧として拒否する。
	// 全開始tagを走査し、対象anchorの一意性を確認する。
	while( (offset = lower.find( L'<', offset)) != std::wstring::npos) {
		// 過大tag集合を一部分だけ検査して成功にしない。
		if( ++tagCount > 8192U) {
			return false ;
		}

		// Comment内markupを配布根拠にしない。
		if( lower.compare( offset, 4U, L"<!--") == 0) {
			const auto end = lower.find( L"-->", offset + 4U) ;	// Commentの有限終端。
			// 未終端comment以降を有効HTMLとみなさない。
			if( end == std::wstring::npos) {
				return false ;
			}

			offset = end + 3U ;
			continue ;
		}

		std::size_t end = offset + 1U ;	// 引用符内の偽tagを読み飛ばす有限走査。
		wchar_t		quote{} ;			// 0は属性値外、単／二重引用符を独立に扱う。
		// 最大4096文字で引用符外のtag終端まで進める。
		for( ; end < lower.size() && end - offset <= 4096U; ++end) {
			const wchar_t character = lower[end] ;	// 現在tagの文字。
			// 同じ引用符だけが属性値を閉じる。
			if( quote != 0U && character == quote) {
				quote = 0U ;
			}
			// 別引用符の開始を属性値外だけで認める。
			else if( quote == 0U && (character == L'\"' || character == L'\'')) {
				quote = character ;
			}
			// 引用符外の終端だけをtag末尾とする。
			else if( quote == 0U && character == L'>') {
				break ;
			}
		}

		// 未終端・過大tagは別parserへfallbackしない。
		if( end >= lower.size() || end - offset > 4096U) {
			return false ;
		}

		const auto	 tag = std::wstring_view( lower).substr( offset, end - offset + 1U) ;	// Tagだけ。
		std::wstring suppressed ;															// 非実行・非表示要素の開始だけで設定する。
		// Script等の開始tagは大小文字以外を推測補正しない。
		for( const auto name : {L"script", L"style", L"template", L"noscript", L"textarea",
							   L"iframe", L"xmp", L"title", L"plaintext"}) {
			const std::wstring prefix = L"<" + std::wstring( name) ;	// 要素境界を確認するprefix。
			// 別名要素を同じ非表示要素と誤認しない。
			if( tag.starts_with( prefix) && tag.size() > prefix.size() &&
			   std::wstring_view( L">/ \t\n\r\f").find( tag[prefix.size()]) !=
				   std::wstring_view::npos) {
				suppressed = name ;
				break ;
			}
		}

		// 非表示内容内の偽anchorや引用符をtag走査へ戻さない。
		if( !suppressed.empty()) {
			const auto close = lower.find( L"</" + suppressed + L">", end + 1U) ;	// 有限close。
			// 未終端またはnested templateを独自に推測しない。
			if( close == std::wstring::npos ||
			   (suppressed == L"template" && lower.find( L"<template", end + 1U) < close)) {
				return false ;
			}

			offset = close + suppressed.size() + 3U ;
			continue ;
		}

		// 有効anchorだけを属性parserへ渡す。終了tag・他要素は根拠にしない。
		if( suppressed.empty() && (tag.starts_with( L"<a ") || tag.starts_with( L"<a\n"))) {
			std::wstring href ;													// 同じtagの原属性値。
			const auto	 original = html.substr( offset, end - offset + 1U) ;	// Case未変更の原tag。
			// 同じ原hrefの一意属性だけを配布根拠にする。
			if( tag.find( L"href") != std::wstring_view::npos &&
			   tag.find( L"href", tag.find( L"href") + 4U) == std::wstring_view::npos &&
			   inspectionMarkerIsAttribute( original, marker) &&
			   extractUniqueOfficialHtmlAttribute( original, marker, L"href", 480U, href) &&
			   href == source.href && ++matches > 1U) {
				return false ;
			}
		}

		offset = end + 1U ;
	}

	return matches == 1U ;
}

/** @see collector_inspection_acquisition.h */
CollectorInspectionAcquisition::CollectorInspectionAcquisition() : http_( false)
{
}
/** @see collector_inspection_acquisition.h */
CollectorInspectionAcquisition::CollectorInspectionAcquisition( OfficialHttpTransport transport)
	: http_( std::move( transport))
{
}

/** @see collector_inspection_acquisition.h */
NativeError CollectorInspectionAcquisition::acquire( ScanSessionId					 scanSessionId,
													const CollectorInspectionSource &source,
													OfficialAcquisitionSession		&session,
													OfficialDownloadWorkspace		&workspace,
													IOfficialNetworkCostReader		&costReader,
													const HttpCancellationCallback	&cancellation,
													OfficialAcquisitionResult		&result)
{
	result			  = {} ;
	const bool reused = std::exchange( used_, true) ;	// 初回拒否も一回scopeを消費する。
	// 再試行・別session・任意URL形は実起点GET前に止める。
	if( reused || scanSessionId == 0U || scanSessionId != session.scanSessionId_ ||
	   !validateCollectorInspectionSource( source)) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = E_INVALIDARG ;
		return result.error ;
	}

	scanSessionId_			= scanSessionId ;
	source_					= source ;
	result.networkCostError = costReader.read( result.networkCost) ;
	// 起点本文にも制限付き・不明回線の自動同意を適用しない。
	if( result.networkCostError != 0 ||
	   result.networkCost != OfficialNetworkCostKind::UNRESTRICTED) {
		result.state = OfficialAcquisitionState::AWAITING_NETWORK_CONSENT ;
		result.error = E_ACCESSDENIED ;
		return result.error ;
	}

	std::wstring html ;		// 同scopeの実起点本文。結果JSONへ出さない。
	std::wstring finalUrl ;	// 実最終responseの相対href base。永続化しない。
	// 同じ起点の元HTTP診断を保ち、parser拒否と分離する。
	auto error = http_.getCollectorInspectionPage( source_.rootUrl, source_.rootHost, cancellation,
												  html, finalUrl) ;
	auto resolvedSource	   = source_ ;	// 台帳を変更せず、実最終URLでだけhrefを再解決する。
	resolvedSource.rootUrl = finalUrl ;
	// 起点取得に成功しても、対象linkが有効anchorでなければ取得しない。
	if( error == 0 && !verifyCollectorInspectionLink( html, resolvedSource)) {
		error = HRESULT_FROM_WIN32( ERROR_NOT_FOUND) ;
	}

	// 元HTTP／parser失敗をpackage不適合に変換しない。
	if( error != 0) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = error ;
		return error ;
	}

	rootVerified_ = true ;
	const OfficialAcquisitionRequest request{
		.url			   = source_.payloadUrl,
		.providerId		   = COLLECTOR_INSPECTION_PROVIDER_ID,
		.resourceId		   = OFFICIAL_PAYLOAD_RESOURCE_ID,
		.workspaceFileName = L"inspection.zip",
		.maximumFileBytes = COLLECTOR_INSPECTION_MAXIMUM_BYTES} ;	// 外部成功flag・hashは使用しない。
	return session.acquireCore(
		request, workspace, *this, costReader, []( std::uint64_t, std::uint64_t) {}, cancellation,
		result, this) ;
}

/** @see collector_inspection_acquisition.h */
bool CollectorInspectionAcquisition::matches(
	ScanSessionId scanSessionId, const OfficialAcquisitionRequest &request) const noexcept
{
	return used_ && rootVerified_ && !payloadAttempted_ && scanSessionId == scanSessionId_ &&
		   request.url == source_.payloadUrl &&
		   request.providerId == COLLECTOR_INSPECTION_PROVIDER_ID &&
		   request.resourceId == OFFICIAL_PAYLOAD_RESOURCE_ID &&
		   request.workspaceFileName == L"inspection.zip" &&
		   request.maximumFileBytes == COLLECTOR_INSPECTION_MAXIMUM_BYTES &&
		   !request.publishedSize && request.publishedSha256.empty() &&
		   request.publishedSha512.empty() && !request.restrictedNetworkApproved &&
		   request.delegatedGrant == nullptr && request.delegatedGrantId == 0U &&
		   !request.delegatedUtcNow ;
}

/** @see collector_inspection_acquisition.h */
NativeError CollectorInspectionAcquisition::download(
	std::wstring_view url, std::wstring_view resourceId, std::uint64_t maximumBytes,
	HANDLE outputFile, const HttpDownloadProgressCallback &progressCallback,
	const HttpCancellationCallback &cancellationCallback)
{
	// 同じ実起点からの唯一payload以外は送信しない。
	if( !rootVerified_ || payloadAttempted_ || url != source_.payloadUrl ||
	   resourceId != OFFICIAL_PAYLOAD_RESOURCE_ID || maximumBytes == 0U ||
	   maximumBytes > COLLECTOR_INSPECTION_MAXIMUM_BYTES) {
		return E_ACCESSDENIED ;
	}

	payloadAttempted_ = true ;
	const std::array<std::wstring_view, 1U> hosts{source_.payloadHost} ;	// 当該recordだけの委譲先。
	std::vector<std::uint32_t>				origins ;						// 同一origin内二redirectまで。
	const auto error = http_.downloadToFile( url, hosts, 2U, maximumBytes, outputFile,
											progressCallback, cancellationCallback, origins,
											true) ;	// 共通公開宛先・credential拒否GET。
	payloadVerified_ = error == 0 && !origins.empty() ;
	return error ;
}

/** @see collector_inspection_acquisition.h */
NativeError CollectorInspectionAcquisition::downloadDelegated(
	OfficialDelegatedGetRequest &, HANDLE, const HttpDownloadProgressCallback &,
	const HttpCancellationCallback &, OfficialPublicDestinationEvidence &destinationEvidence)
{
	destinationEvidence = {} ;
	return E_ACCESSDENIED ;
}

/** @see collector_inspection_acquisition.h */
bool CollectorInspectionAcquisition::hasSourceEvidence( ScanSessionId	 scanSessionId,
													   std::wstring_view providerId,
													   std::wstring_view resourceId) const noexcept
{
	return sourceVerified() && scanSessionId == scanSessionId_ &&
		   providerId == COLLECTOR_INSPECTION_PROVIDER_ID &&
		   resourceId == OFFICIAL_PAYLOAD_RESOURCE_ID ;
}

/** @see collector_inspection_acquisition.h */
bool CollectorInspectionAcquisition::sourceVerified() const noexcept
{
	return used_ && rootVerified_ && payloadAttempted_ && payloadVerified_ ;
}
} // namespace drivercrate
