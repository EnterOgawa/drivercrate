//------------------------------------------------------------------------------
/**
 * @file collector_inspection_acquisition.cpp
 * @brief 台帳起点の実HTML確認と一回payload取得の共通接続。
 * @version 01.03.00
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
 * Ver.01.01.00 Shunji Ogawa  2026/10/23  同原page観測と明示予算・公開hash・確認本文固定を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/23  実完全PAGEの同run有限共有とjob別再確認を追加。
 * Ver.01.02.01 Shunji Ogawa  2026/10/23  重複照会中の停止を未取得へ読み替えない保持条件へ修正。
 * Ver.01.03.00 Shunji Ogawa  2026/10/25  原byteと原SHAを維持した限定末尾診断コメント比較を追加。
 * </pre>
 *
 * @note 同期収集worker専用。公開bool・研究hashで公式取得根拠を復元しない。
 * @see docs/adr/0280-collector-scoped-inspection-acquisition.md
 */
//------------------------------------------------------------------------------
#include "platform/collector_inspection_acquisition.h"
#include "core/official_source_policy.h"
#include "platform/official_static_record_parser.h"
#include "platform/official_file_verifier.h"
#include <algorithm>
#include <array>
#include <utility>

namespace drivercrate {

/** @brief 私有scopeだけが作る全bindingと一方向の失効状態です。 */
struct CollectorRunPageLifetime {
	/// 元parentの固定run識別子です。
	std::wstring										   runId ;
	/// 将来callerが検証して固定する元native leaseです。
	std::uint64_t										   parentLease{} ;
	/// 将来callerが監督する元child identityです。
	std::uint64_t										   childProcess{} ;
	/// 元runの全固定入力hashを順序付きで保持します。
	std::vector<std::wstring>							   inputHashes ;
	/// 元runの固定plan hashです。
	std::wstring										   planHash ;
	/// 延長しない単調期限です。
	std::chrono::steady_clock::time_point				   deadline ;
	/// 停止したchild等の親照会です。
	HttpCancellationCallback							   cancellation ;
	/// 空は実時計、非空は専用fixture時計です。
	std::function<std::chrono::steady_clock::time_point()> now ;
	/// 最後の確認単調時刻です。時計後退を拒否します。
	std::chrono::steady_clock::time_point				   lastNow{} ;
	/// 一度falseになれば再開しない元scopeの生存です。
	bool												   active{} ;
} ;

/** @see collector_inspection_acquisition.h */
CollectorRunPageProof::CollectorRunPageProof(
	const std::shared_ptr<CollectorRunPageLifetime> &lifetime,
	const CollectorInspectionSource &source, std::vector<std::byte> raw, std::wstring html,
	CollectorInspectionPageObservation observation, CollectorHttpTransferObservation transfer)
	: lifetime_( lifetime), rootUrl_( source.rootUrl), rootHost_( source.rootHost),
	  raw_( std::move( raw)), html_( std::move( html)), observation_( std::move( observation)),
	  transfer_( std::move( transfer))
{
}

/** @see collector_inspection_acquisition.h */
CollectorRunPageScope::CollectorRunPageScope(
	std::wstring runId, std::uint64_t parentLease, std::uint64_t childProcess,
	std::vector<std::wstring> inputHashes, std::wstring planHash,
	std::chrono::steady_clock::time_point deadline, HttpCancellationCallback cancellation,
	std::function<std::chrono::steady_clock::time_point()> now)
	: lifetime_( std::make_shared<CollectorRunPageLifetime>())
{
	// 全結合値を同じ私有lifetimeへ一度だけ所有させます。
	lifetime_->runId		= std::move( runId) ;
	lifetime_->parentLease	= parentLease ;
	lifetime_->childProcess = childProcess ;
	lifetime_->inputHashes	= std::move( inputHashes) ;
	lifetime_->planHash		= std::move( planHash) ;
	lifetime_->deadline		= deadline ;
	lifetime_->cancellation = std::move( cancellation) ;
	lifetime_->now			= std::move( now) ;
	// Hash群の要素は順序付きで固定し、欠損した入力を暗黙補完しません。
	const auto hashValid = []( std::wstring_view hash) {
		return hash.size() == 64U &&
			   hash.find_first_not_of( L"0123456789abcdef") == std::wstring_view::npos ;
	} ;
	lifetime_->active = !lifetime_->runId.empty() && lifetime_->runId.size() <= 128U &&
						parentLease != 0U && childProcess != 0U &&
						!lifetime_->inputHashes.empty() && lifetime_->inputHashes.size() <= 32U &&
						hashValid( lifetime_->planHash) &&
						std::ranges::all_of( lifetime_->inputHashes, hashValid) ;
}

/** @see collector_inspection_acquisition.h */
CollectorRunPageScope::~CollectorRunPageScope()
{
	finish() ;
}

/** @see collector_inspection_acquisition.h */
void CollectorRunPageScope::finish() noexcept
{
	lifetime_->active = false ;
	pages_.clear() ;
	rawBytes_ = 0U ;
}

/** @see collector_inspection_acquisition.h */
bool CollectorRunPageScope::checkpoint() noexcept
{
	try {
		const auto now = lifetime_->now ? lifetime_->now()
										: std::chrono::steady_clock::now() ;	// 元単調時計です。
		// 終了・期限・子停止・時計後退はいずれも同runの全借用を失効します。
		if( !lifetime_->active || now < lifetime_->lastNow || now >= lifetime_->deadline ||
		   (lifetime_->cancellation && lifetime_->cancellation())) {
			finish() ;
			return false ;
		}

		lifetime_->lastNow = now ;
		return true ;
	} catch( ...) {
		// 取消し/時計の障害を生存証明へ変えません。
		finish() ;
		return false ;
	}
}

/** @see collector_inspection_acquisition.h */
std::shared_ptr<const CollectorRunPageProof> CollectorRunPageScope::find(
	const CollectorInspectionSource &source) noexcept
{
	// 停止後に保存済み本文から新しい権限を作りません。
	if( !checkpoint()) {
		return {} ;
	}

	// 同じrunの有限集合からexact起点だけを検索します。
	for( const auto &page : pages_) {
		// Payloadの一致や別jobの成功はcache keyへ使いません。
		if( page->rootUrl_ == source.rootUrl && page->rootHost_ == source.rootHost) {
			return page ;
		}
	}

	return {} ;
}

/** @see collector_inspection_acquisition.h */
bool CollectorRunPageScope::accepts( const CollectorRunPageProof		&proof,
									const CollectorInspectionSource &source) noexcept
{
	return checkpoint() && proof.lifetime_.lock() == lifetime_ &&
		   proof.rootUrl_ == source.rootUrl && proof.rootHost_ == source.rootHost &&
		   proof.transfer_.completion() == CollectorHttpTransferCompletion::COMPLETE &&
		   std::ranges::any_of( pages_, [&proof]( const auto &page) { return page.get() == &proof ; }) ;
}

/** @see collector_inspection_acquisition.h */
std::shared_ptr<const CollectorRunPageProof> CollectorRunPageScope::retain(
	const CollectorInspectionSource &source, std::vector<std::byte> raw, std::wstring html,
	CollectorInspectionPageObservation observation, CollectorHttpTransferObservation transfer)
{
	constexpr std::uint64_t MAX_RAW_BYTES = 32ULL * 1024ULL * 1024ULL ;	// 同runの保有限度です。
	// 同実HTTP完全終端と有限容量だけを保持し、過大集合を一部だけ保存しません。
	if( !checkpoint() || pages_.size() >= 32U || raw.empty() || raw.size() > 2U * 1024U * 1024U ||
	   raw.size() > MAX_RAW_BYTES - rawBytes_ || html.empty() || observation.httpStatus != 200U ||
	   observation.bodyBytes != raw.size() || observation.bodySha256.size() != 64U ||
	   transfer.stage() != CollectorHttpTransferStage::PAGE ||
	   transfer.completion() != CollectorHttpTransferCompletion::COMPLETE ||
	   transfer.bodyBytesRead() != raw.size() ||
	   std::ranges::any_of( pages_, [&source]( const auto &page) {
		   return page->rootUrl_ == source.rootUrl && page->rootHost_ == source.rootHost ;
	   })) {
		return {} ;
	}

	const auto proof = std::make_shared<const CollectorRunPageProof>(
		CollectorRunPageProof( lifetime_, source, std::move( raw), std::move( html),
							  // 同run不変所有です。
							  std::move( observation), std::move( transfer))) ;
	pages_.push_back( proof) ;
	rawBytes_ += proof->raw_.size() ;
	return proof ;
}

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

namespace {
/** @brief 同じ有限HTML走査で一意anchorまたは実末尾終了tagを確認します。
 * @param[in] html 原文字順を維持した本文です。
 * @param[in] href 空でない場合は対象anchor、空の場合は末尾終了tagを検査します。
 * @return 完全な有限走査と当該条件が成立する場合trueです。
 * @note Comment・属性文字列・非表示要素内の偽tagを根拠にしません。
 */
bool inspectCollectorHtml( std::wstring_view html, std::wstring_view href)
{
	// 台帳の不正形・過大／NUL本文を走査前に拒否する。
	if( html.empty() || html.size() > 2U * 1024U * 1024U ||
	   html.find( L'\0') != std::wstring_view::npos) {
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

	const std::wstring marker = L" href=\"" + std::wstring( href) + L"\"" ;	// 対象の原属性。
	std::size_t		   offset{} ;											// 最後に処理したtag末尾。最大8192tagで終了する。
	std::size_t		   tagCount{} ;											// Commentを含む有限走査数。
	std::size_t		   matches{} ;											// 二件以上なら曖昧として拒否する。
	bool			   terminal{} ;											// 実tagとして確認した固定末尾だけでtrueです。
	// 全開始tagを走査し、対象anchorまたは末尾位置を確認します。
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
		for( const auto name :
			{L"script", L"style", L"template", L"noscript", L"textarea", L"iframe", L"xmp",
			 L"title", L"plaintext", L"noembed", L"noframes", L"svg", L"math"}) {
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
			if( close == std::wstring::npos || (href.empty() && suppressed == L"plaintext") ||
			   ((suppressed == L"template" || suppressed == L"svg" || suppressed == L"math") &&
				lower.find( L"<" + suppressed, end + 1U) < close)) {
				return false ;
			}

			offset = close + suppressed.size() + 3U ;
			continue ;
		}

		// 元HTML終端と同じ位置の実body終了tagだけを比較境界にします。
		if( href.empty() && html.ends_with( L"</body>\n</html>") && offset + 15U == html.size() &&
		   tag == L"</body>") {
			terminal = true ;
		}

		// 直前bodyと連続する実html終了tagを必要とします。
		if( href.empty() && offset + 7U == html.size() && tag == L"</html>") {
			return terminal ;
		}

		// 有効anchorだけを属性parserへ渡す。終了tag・他要素は根拠にしない。
		if( !href.empty() && suppressed.empty() &&
		   (tag.starts_with( L"<a ") || tag.starts_with( L"<a\n"))) {
			std::wstring actualHref ;											// 同じtagの原属性値です。
			const auto	 original = html.substr( offset, end - offset + 1U) ;	// Case未変更の原tag。
			// 同じ原hrefの一意属性だけを配布根拠にする。
			if( tag.find( L"href") != std::wstring_view::npos &&
			   tag.find( L"href", tag.find( L"href") + 4U) == std::wstring_view::npos &&
			   inspectionMarkerIsAttribute( original, marker) &&
			   extractUniqueOfficialHtmlAttribute( original, marker, L"href", 480U, actualHref) &&
			   actualHref == href && ++matches > 1U) {
				return false ;
			}
		}

		offset = end + 1U ;
	}

	return !href.empty() && matches == 1U ;
}
} // namespace

/** @see collector_inspection_acquisition.h */
bool verifyCollectorInspectionLink( std::wstring_view html, const CollectorInspectionSource &source)
{
	return validateCollectorInspectionSource( source) && inspectCollectorHtml( html, source.href) ;
}

/** @see collector_inspection_acquisition.h */
NativeError computeCollectorPageContentSha256( const std::string_view raw, std::wstring &sha256)
{
	sha256.clear() ;
	// 原PAGEの有限容量を越える入力から比較値を発行しません。
	if( raw.empty() || raw.size() > 2U * 1024U * 1024U) {
		return E_INVALIDARG ;
	}

	constexpr std::string_view MARKER =
		"<!-- WP Fastest Cache file was created in " ;	// 唯一の除外候補です。
	const auto start   = raw.find( MARKER) ;			// 一件以外は全rawを比較します。
	auto	   content = raw ;							// 不明な形式では元byte全体を保持します。
	// EOF直結・一件・固定桁の既知診断だけを詳しく確認します。
	if( start != std::string_view::npos && raw.find( MARKER, start + 1U) == std::string_view::npos &&
	   raw.size() - start == MARKER.size() + 50U) {
		const auto value  = raw.substr( start + MARKER.size()) ;	// 固定50byteの診断値です。
		bool	   digits = true ;									// 秒数の可変部はASCII数字14桁だけです。
		// 全14桁を確認し、指数表記や任意文字列を除去しません。
		for( std::size_t index = 2U; index < 16U; ++index) {
			digits = digits && value[index] >= '0' && value[index] <= '9' ;
		}

		const auto stamp = value.substr( 29U, 17U) ;	// 実観測とは独立した診断日時です。
		// 日時の数字を全て確認し、書式不明は全rawへ戻します。
		for( const auto index : {0U, 1U, 3U, 4U, 6U, 7U, 9U, 10U, 12U, 13U, 15U, 16U}) {
			digits = digits && stamp[index] >= '0' && stamp[index] <= '9' ;
		}

		// 生成日時は書式だけを検査し、実観測時刻や期限へ使用しません。
		if( digits && value.starts_with( "0.") && value.substr( 16U, 13U) == " seconds, on " &&
		   value.ends_with( " -->") && stamp[2U] == '-' && stamp[5U] == '-' && stamp[8U] == ' ' &&
		   stamp[11U] == ':' && stamp[14U] == ':') {
			const auto number = [stamp]( const std::size_t at) {
				return static_cast<unsigned>( (stamp[at] - '0') * 10 + stamp[at + 1U] - '0') ;
			} ; // 検証済み二桁だけを読む短期借用です。
			const std::chrono::year_month_day date{
				std::chrono::year{2000 + static_cast<int>( number( 6U))},
				std::chrono::month{number( 3U)},
				std::chrono::day{number( 0U)}} ;	// 診断書式だけの検査です。
			std::wstring prefix ;					// ASCII tag走査用だけのbyte対応文字列です。
			prefix.reserve( start) ;
			// 再encodeせず、ASCII tagの位置を原byteへ対応させます。
			for( const unsigned char character : raw.substr( 0U, start)) {
				prefix.push_back( static_cast<wchar_t>( character)) ;
			}

			// 実HTML終端の外側にある既知書式だけを比較digestから除外します。
			if( date.ok() && number( 9U) < 24U && number( 12U) < 60U && number( 15U) < 60U &&
			   inspectCollectorHtml( prefix, {})) {
				content = raw.substr( 0U, start) ;
			}
		}
	}

	return computeCollectorMetadataSha256( content, sha256) ;
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
NativeError CollectorInspectionAcquisition::acquire(
	ScanSessionId scanSessionId, const CollectorInspectionSource &source,
	OfficialAcquisitionSession &session, OfficialDownloadWorkspace &workspace,
	IOfficialNetworkCostReader &costReader, const HttpCancellationCallback &cancellation,
	OfficialAcquisitionResult &result, const std::uint64_t maximumBytes,
	const std::wstring_view publishedSha256, const std::wstring_view expectedPageContentSha256)
{
	return acquireCore( scanSessionId, source, session, workspace, costReader, cancellation, result,
					   maximumBytes, publishedSha256, expectedPageContentSha256, nullptr, nullptr) ;
}

/** @see collector_inspection_acquisition.h */
NativeError CollectorInspectionAcquisition::acquireWithRunPage(
	ScanSessionId scanSessionId, const CollectorInspectionSource &source,
	OfficialAcquisitionSession &session, OfficialDownloadWorkspace &workspace,
	IOfficialNetworkCostReader &costReader, const HttpCancellationCallback &cancellation,
	OfficialAcquisitionResult &result, std::uint64_t maximumBytes,
	std::wstring_view publishedSha256, std::wstring_view expectedPageContentSha256,
	CollectorRunPageScope &scope, const CollectorRunPageProof *proof)
{
	// 元parentの生存照会を全HTTP hopと本文の取消しへ接続します。
	const auto stop = [&scope, &cancellation]() {
		return !scope.checkpoint() || (cancellation && cancellation()) ;
	} ;
	return acquireCore( scanSessionId, source, session, workspace, costReader, stop, result,
					   maximumBytes, publishedSha256, expectedPageContentSha256, &scope, proof) ;
}

/** @see collector_inspection_acquisition.h */
NativeError CollectorInspectionAcquisition::acquireCore(
	ScanSessionId scanSessionId, const CollectorInspectionSource &source,
	OfficialAcquisitionSession &session, OfficialDownloadWorkspace &workspace,
	IOfficialNetworkCostReader &costReader, const HttpCancellationCallback &cancellation,
	OfficialAcquisitionResult &result, std::uint64_t maximumBytes,
	std::wstring_view publishedSha256, std::wstring_view expectedPageContentSha256,
	CollectorRunPageScope *scope, const CollectorRunPageProof *proof)
{
	result			  = {} ;
	const bool reused = std::exchange( used_, true) ;	// 初回拒否も一回scopeを消費する。
	// 再試行・別session・任意URL形は実起点GET前に止める。
	if( reused || scanSessionId == 0U || scanSessionId != session.scanSessionId_ ||
	   !validateCollectorInspectionSource( source) || maximumBytes == 0U ||
	   maximumBytes > COLLECTOR_INSPECTION_MAXIMUM_BYTES ||
	   (scope == nullptr && proof != nullptr) || (scope != nullptr && !scope->checkpoint()) ||
	   (!publishedSha256.empty() &&
		(publishedSha256.size() != 64U ||
		 publishedSha256.find_first_not_of( L"0123456789abcdef") != std::wstring_view::npos)) ||
	   (!expectedPageContentSha256.empty() &&
		(expectedPageContentSha256.size() != 64U ||
		 expectedPageContentSha256.find_first_not_of( L"0123456789abcdef") !=
			 std::wstring_view::npos))) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = E_INVALIDARG ;
		return result.error ;
	}

	scanSessionId_	 = scanSessionId ;
	source_			 = source ;
	maximumBytes_	 = maximumBytes ;
	publishedSha256_ = publishedSha256 ;
	// 親が既存proofを渡さなかった場合も同PAGEを二度取得しません。
	if( scope != nullptr && proof == nullptr && scope->find( source_)) {
		result.state = OfficialAcquisitionState::REJECTED ;
		result.error = E_ACCESSDENIED ;
		return result.error ;
	}

	result.networkCostError = costReader.read( result.networkCost) ;
	// 起点本文にも制限付き・不明回線の自動同意を適用しない。
	if( result.networkCostError != 0 ||
	   result.networkCost != OfficialNetworkCostKind::UNRESTRICTED) {
		result.state = OfficialAcquisitionState::AWAITING_NETWORK_CONSENT ;
		result.error = E_ACCESSDENIED ;
		return result.error ;
	}

	std::wstring html ;				// 同scopeの実起点本文。結果JSONへ出さない。
	std::wstring finalUrl ;			// 実最終responseの相対href base。永続化しない。
	std::wstring contentSha256 ;	// 同HTTPの原SHAとは別の比較値です。
	NativeError	 error{} ;			// 元HTTPと借用拒否を後段parserから分離します。
	// 借用証拠の期限・元run・全bindingを再確認し、無効時は新GETへfallbackしません。
	if( proof != nullptr) {
		// 別scope/終了済み証拠ではpayloadも起点も送信しません。
		if( !scope->accepts( *proof, source_)) {
			result.state = OfficialAcquisitionState::REJECTED ;
			result.error = E_ACCESSDENIED ;
			return result.error ;
		}

		html			 = proof->html_ ;
		pageObservation_ = proof->observation_ ;
		pageTransfer_	 = proof->transfer_ ;
		finalUrl		 = proof->observation_.finalUrl ;
		pageReusedInRun_ = true ;
		// 同じ生存proofの原byteから毎jobの比較値を再確認します。
		error = computeCollectorPageContentSha256(
			{reinterpret_cast<const char *>( proof->raw_.data()), proof->raw_.size()},
			contentSha256) ;
	} else {
		std::vector<std::byte> raw ;	// 同HTTP比較と私有runが原本文を所有します。
		error =
			http_.getCollectorInspectionPage( source_.rootUrl, source_.rootHost, cancellation, html,
											 finalUrl, &pageObservation_, &pageTransfer_, &raw) ;
		std::shared_ptr<const CollectorRunPageProof>
			retained ;	// 比較失敗でも元完全PAGEをscopeへ残します。
		// PAGE自体が完全なら、後続anchor/hash/CAT失敗と独立して他jobへ保持します。
		if( error == 0 && scope != nullptr) {
			retained =
				scope->retain( source_, std::move( raw), html, pageObservation_, pageTransfer_) ;
			// 保持拒否を比較成功として扱いません。
			if( !retained) {
				error = E_ACCESSDENIED ;
			}
		}

		// 同HTTPのbyteを文字aliasで借用し、再encodeせず比較します。
		if( error == 0) {
			const auto &actual = retained ? retained->raw_ : raw ;	// 同じ完全PAGEの所有領域です。
			error			   = computeCollectorPageContentSha256(
				 {reinterpret_cast<const char *>( actual.data()), actual.size()}, contentSha256) ;
		}
	}

	auto resolvedSource	   = source_ ;	// 台帳を変更せず、実最終URLでだけhrefを再解決する。
	resolvedSource.rootUrl = finalUrl ;
	// 旧本文への手動確認を変更後pageへ移し替えません。
	if( error == 0 && !expectedPageContentSha256.empty() &&
	   contentSha256 != expectedPageContentSha256) {
		error = HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH) ;
	}

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
		.maximumFileBytes  = maximumBytes_,
		.publishedSha256   = publishedSha256_} ;	// 公開hashは共通実byte検証でだけ使用する。
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
		   request.maximumFileBytes == maximumBytes_ && !request.publishedSize &&
		   request.publishedSha256 == publishedSha256_ && request.publishedSha512.empty() &&
		   !request.restrictedNetworkApproved && request.delegatedGrant == nullptr &&
		   request.delegatedGrantId == 0U && !request.delegatedUtcNow ;
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
	   maximumBytes > maximumBytes_) {
		return E_ACCESSDENIED ;
	}

	payloadAttempted_ = true ;
	const std::array<std::wstring_view, 1U> hosts{source_.payloadHost} ;	// 当該recordだけの委譲先。
	std::vector<std::uint32_t>				origins ;						// 同一origin内二redirectまで。
	const auto error = http_.downloadToFile( url, hosts, 2U, maximumBytes, outputFile,
											progressCallback, cancellationCallback, origins, true,
											&payloadTransfer_) ;	// 同じ実保存観測です。
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

/** @see collector_inspection_acquisition.h */
const CollectorInspectionPageObservation &CollectorInspectionAcquisition::pageObservation()
	const noexcept
{
	return pageObservation_ ;
}

/** @see collector_inspection_acquisition.h */
const CollectorHttpTransferObservation &CollectorInspectionAcquisition::pageTransfer()
	const noexcept
{
	return pageTransfer_ ;
}
/** @see collector_inspection_acquisition.h */
const CollectorHttpTransferObservation &CollectorInspectionAcquisition::payloadTransfer()
	const noexcept
{
	return payloadTransfer_ ;
}
/** @see collector_inspection_acquisition.h */
bool CollectorInspectionAcquisition::pageReusedInRun() const noexcept
{
	return pageReusedInRun_ ;
}
} // namespace drivercrate
