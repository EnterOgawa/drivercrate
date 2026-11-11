//------------------------------------------------------------------------------
/**
 * @file signed_index_acquisition_adapter.cpp
 * @brief 同snapshotの取得能力とtaskを封印し、既存grantと検査入力へ接続します。
 * @version 01.16.00
 * @date 2026/10/24
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  署名snapshotと同grant・共通取得の有限接続を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  完全hash/sizeと取得policy一致だけを有限な共有taskへ結合。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.04.00 Shunji Ogawa  2026/10/13  Local公開pinの独立revision1能力を接続。
 * Ver.01.05.00 Shunji Ogawa  2026/10/14  共通HTML許諾の原文書・全文・revision照合をRAM取得へ接続。
 * Ver.01.06.00 Shunji Ogawa  2026/10/14  元不足を保持したnative証拠付き一deviceの準備を接続。
 * Ver.01.06.01 Shunji Ogawa  2026/10/16  製品revision1取得認可をmanifest trustと独立に接続。
 * Ver.01.07.00 Shunji Ogawa  2026/10/24  同payloadの全原関係とunique device数を分離しclaimで再照合。
 * Ver.01.08.00 Shunji Ogawa  2026/10/27  元tuple/cohortと個別証拠を標準INF準備で再検証。
 * Ver.01.09.00 Shunji Ogawa  2026/11/03  共通公式packageの手動索引と選択内容検査を接続。
 * Ver.01.10.00 Shunji Ogawa  2026/11/03  原payloadの同一policy比較を開発用集合観測と共用。
 * Ver.01.11.00 Shunji Ogawa  2026/11/03  有界large archiveと共有内容保持・標準serviceを接続。
 * Ver.01.12.00 Shunji Ogawa  2026/11/03  署名原範囲の非実行resource内容を接続。
 * Ver.01.13.00 Shunji Ogawa  2026/11/03  匿名CDNの同record二要求と有限予約を接続。
 * Ver.01.14.00 Shunji Ogawa  2026/11/05  独立静的規約の原文書・公式リンクと既存同意を共通接続。
 * Ver.01.15.00 Shunji Ogawa  2026/11/07  全体容量・所有stateと有限進行の契約へ整合。
 * Ver.01.16.00 Shunji Ogawa  2026/11/10  対象限定の完了更新と未処理所有・本体再検証を接続。
 * </pre>
 *
 * @note 同workerの直列処理です。監視PCの申告と端末実byteを分け、live根拠を合成しません。
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#include "core/index_capacity_limits.h"
#include "platform/signed_index_acquisition_adapter.h"
#include "platform/signed_index_acquisition_adapter_internal.h"
#include "core/provider_registry.h"
#include "platform/official_http_client.h"
#include "platform/official_html_terms.h"
#include "platform/official_file_verifier.h"
#include "platform/official_prepared_acquisition.h"
#include "local_index_acceptance.h"
#include "platform/index_distribution_trust.h"
#include <span>
#include <algorithm>
#include <array>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>
#include <windows.h>
#include <winhttp.h>

namespace drivercrate {
namespace {
// 全メーカー共通の取得resource。URLや製品名から組み立てません。
constexpr std::wstring_view					INDEX_PAYLOAD_RESOURCE = L"index-static-zip" ;
// 署名認証から推論せず、normal/localの独立取得集合を排他的に選択します。
constexpr std::span<const std::string_view> PRODUCT_ACQUISITION_KEYS =
	local_index_profile::ENABLED
		? std::span<const std::string_view>{local_index_profile::ACQUISITION_KEYS}
		: std::span<const std::string_view>{index_distribution_trust::ACQUISITION_KEYS} ;

/** @brief Strict codecが検査した原UTF-8公開textを欠損なくWindows表示へ変換します。
 * @param[in] text 元recordの変更していない有限UTF-8 textです。
 * @return 正確なUTF-16 textです。不正byteは例外でfail-closedにします。
 */
[[nodiscard]] std::wstring indexUtf8Text( const std::string_view text)
{
	// 未指定の任意属性だけは空のまま保持します。
	if( text.empty()) {
		return {} ;
	}

	const auto length = static_cast<int>( text.size()) ;	// Strict codecの有限上限内です。
	// 終端または元集合の有限必要数です。成功数を推測しません。
	const auto count =
		MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, nullptr, 0) ;
	// 不正UTF-8を代替文字へ補完しません。
	if( count <= 0) {
		throw std::runtime_error( "invalid index UTF-8 text") ;
	}

	std::wstring result( static_cast<std::size_t>( count), L'\0') ;	// 正確なUTF-16長です。
	// 同原byteを正確な受信長で変換します。
	if( MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, result.data(),
						   count) != count) {
		throw std::runtime_error( "index UTF-8 conversion failed") ;
	}

	return result ;
}

/** @brief Schema検査済みASCII HTTPS URLからexact小文字hostを取り出します。
 * @param[in] value 元sourceまたはtextDocumentの未変更URLです。
 * @param[out] host 成功時だけ443/HTTPSのexact DNS hostです。失敗時は空です。
 * @return 共通Windows URL parserの成功時trueです。通信や公式性認定は行いません。
 */
[[nodiscard]] bool exactHttpsHost( const std::string_view value, std::wstring &host)
{
	host.clear() ;
	const std::wstring url{value.begin(), value.end()} ;	// strict codec済み原ASCIIを借用変換します。
	URL_COMPONENTS	   parts{} ;							// 同期parserが返す借用componentです。
	parts.dwStructSize	   = sizeof( parts) ;
	parts.dwHostNameLength = static_cast<DWORD>( -1) ;
	// 別scheme/portを同originへ正規化しません。
	if( !WinHttpCrackUrl( url.c_str(), static_cast<DWORD>( url.size()), 0U, &parts) ||
	   parts.nScheme != INTERNET_SCHEME_HTTPS || parts.nPort != INTERNET_DEFAULT_HTTPS_PORT ||
	   !parts.lpszHostName || parts.dwHostNameLength == 0U) {
		return false ;
	}

	host.assign( parts.lpszHostName, parts.dwHostNameLength) ;
	// DNS名のASCII caseだけを共通origin比較へ揃え、元URL自体は変更しません。
	for( auto &character : host) {
		// 大文字ASCIIのDNS文字だけを小文字へ変換します。
		if( character >= L'A' && character <= L'Z') {
			character = static_cast<wchar_t>( character + (L'a' - L'A')) ;
		}
	}

	return true ;
}

/** @brief 原SHA-256を小文字hexへ表現します。暗号検証は複製しません。
 * @param[in] digest 認証済み原digest。
 * @return 小文字64桁。
 */
[[nodiscard]] std::wstring hexDigest( const IndexManifestSha256 &digest)
{
	constexpr std::wstring_view HEX = L"0123456789abcdef" ;	// 固定hex表。
	std::wstring				value ;						// 認証済みdigestの表示ではない内部照合値。
	value.reserve( 64U) ;
	// 原32byteを二桁へ表現し、全byteで終了します。
	for( const auto byte : digest) {
		value.push_back( HEX[byte >> 4U]) ;
		value.push_back( HEX[byte & 15U]) ;
	}

	return value ;
}

/** @brief 固定信頼UTC秒を既存時刻型へ変換します。
 * @param[in] seconds 正のUTC秒。
 * @return 範囲内だけ時刻。0またはsigned秒範囲外はnullopt。
 */
[[nodiscard]] std::optional<std::chrono::sys_seconds> utcFromSeconds(
	const std::uint64_t seconds) noexcept
{
	// 時計なしや符号範囲超過を丸めて有効時刻にしません。
	if( seconds == 0U ||
	   seconds > static_cast<std::uint64_t>( std::numeric_limits<std::int64_t>::max())) {
		return std::nullopt ;
	}

	return std::chrono::sys_seconds{std::chrono::seconds{static_cast<std::int64_t>( seconds)}} ;
}

/** @brief 完全内容根拠と取得policyが一致したrecordだけを共有対象とします。
 * @param[in] left 個別validateRecord済みの元record。
 * @param[in] right 個別validateRecord済みの元record。
 * @return 完全hash/正のsize/全取得条件一致時だけtrueです。名称や版を使用しません。
 * @param[in] sameTimeWindow 共有taskはtrue、独立期限検証後の同owned byte比較だけfalseです。
	 */
[[nodiscard]] bool sameSharedPayloadEvidence( const IndexDistributionRecord &left,
											 const IndexDistributionRecord &right,
											 const bool sameTimeWindow = true) noexcept
{
	const auto &firstEvidence  = left.packageEvidence ;		// 発行側の認証された完全内容根拠。
	const auto &secondEvidence = right.packageEvidence ;	// 別原recordの独立根拠。
	// 不足hash/sizeや異なる方式・対象条件から共有identityを推測しません。
	if( !firstEvidence.size.value || !secondEvidence.size.value || *firstEvidence.size.value == 0U ||
	   firstEvidence.size.value != secondEvidence.size.value ||
	   (!firstEvidence.publishedHash.sha256 && !firstEvidence.calculatedHash.sha256) ||
	   left.targetOs.value != right.targetOs.value ||
	   left.architecture.value != right.architecture.value ||
	   left.driverKind.value != right.driverKind.value ||
	   left.acquisition.value != right.acquisition.value || !left.acquisitionDescriptor ||
	   !right.acquisitionDescriptor) {
		return false ;
	}

	const auto sameHashEvidence = []( const IndexHashEvidence &first,
									 const IndexHashEvidence &second) {
		return first.sha256 == second.sha256 && first.evidenceUrl == second.evidenceUrl &&
			   first.evidenceSha256 == second.evidenceSha256 && first.reason == second.reason ;
	} ; // 出典と未知理由も同じ元申告へ結合し、hashの由来を変更しません。
	const auto &first  = *left.acquisitionDescriptor ;	// 個別検証済みZIP/同意不要/条件なし。
	const auto &second = *right.acquisitionDescriptor ;	// Policyの和集合を作りません。
	// 全policy値を比較し、後続sliceの未確認条件を共有成功に補完しません。
	if( !sameHashEvidence( firstEvidence.publishedHash, secondEvidence.publishedHash) ||
	   !sameHashEvidence( firstEvidence.calculatedHash, secondEvidence.calculatedHash) ||
	   firstEvidence.size.reason != secondEvidence.size.reason || first.state != second.state ||
	   first.reason != second.reason || first.payloadUrl != second.payloadUrl ||
	   first.fileName != second.fileName || first.format != second.format ||
	   first.expectedContentType != second.expectedContentType ||
	   first.maximumBytes != second.maximumBytes || first.schemaVersion != second.schemaVersion ||
	   first.resourceContent != second.resourceContent ||
	   first.anonymousCdn != second.anonymousCdn ||
	   first.publisher.value != second.publisher.value ||
	   first.publisher.reason != second.publisher.reason ||
	   first.terms.state != second.terms.state || first.terms.reason != second.terms.reason ||
	   first.terms.evidenceUrl != second.terms.evidenceUrl ||
	   first.terms.evidenceSha256 != second.terms.evidenceSha256 ||
	   first.terms.revisionKind != second.terms.revisionKind ||
	   first.terms.revision != second.terms.revision ||
	   first.terms.textDocument.has_value() != second.terms.textDocument.has_value() ||
	   left.sourceId != right.sourceId || first.prerequisites.state != second.prerequisites.state ||
	   first.prerequisites.reason != second.prerequisites.reason ||
	   first.prerequisites.items.size() != second.prerequisites.items.size() ||
	   !first.attestation || !second.attestation || first.route.size() != second.route.size()) {
		return false ;
	}

	// 全文の固定取得先と全原byte根拠を省略して共有しません。
	if( first.terms.textDocument &&
	   (first.terms.textDocument->url != second.terms.textDocument->url ||
		first.terms.textDocument->sha256 != second.terms.textDocument->sha256 ||
		first.terms.textDocument->sizeBytes != second.terms.textDocument->sizeBytes ||
		first.terms.textDocument->contentType != second.terms.textDocument->contentType)) {
		return false ;
	}

	// 同じ原pageでも別の抽出範囲・全文・リンク根拠を一つの同意へ共有しません。
	if( first.terms.textDocument) {
		const auto &a = first.terms.textDocument->htmlExtraction ;	// 一つ目の原抽出宣言です。
		const auto &b = second.terms.textDocument->htmlExtraction ;	// 二つ目の原抽出宣言です。
		// plain/HTMLの違いも取得policyの違いです。
		if( a.has_value() != b.has_value()) {
			return false ;
		}

		// HTMLの全fieldを原値で比較し、新profileの根拠byte数も省略しません。
		if( a) {
			const auto sameSelector = []( const IndexHtmlTermsSelector &x,
										 const IndexHtmlTermsSelector &y) {
				return x.tag == y.tag && x.attribute == y.attribute && x.value == y.value ;
			} ; // 同期借用した原selectorだけの値比較です。
			// 同じ全文・同じ元リンクだけを共有可能とします。
			if( a->profile != b->profile || !sameSelector( a->selector, b->selector) ||
			   !sameSelector( a->containerSelector, b->containerSelector) ||
			   !sameSelector( a->linkSelector, b->linkSelector) ||
			   a->payloadAttribute != b->payloadAttribute ||
			   a->documentSha256 != b->documentSha256 ||
			   a->documentSizeBytes != b->documentSizeBytes || a->textSha256 != b->textSha256 ||
			   a->textSizeBytes != b->textSizeBytes ||
			   a->bindingEvidenceUrl != b->bindingEvidenceUrl ||
			   a->bindingEvidenceSha256 != b->bindingEvidenceSha256 ||
			   a->bindingEvidenceSizeBytes != b->bindingEvidenceSizeBytes) {
				return false ;
			}
		}
	}

	// 元条件は全field完全一致へ結び、別recordの確認権限を和集合へ広げません。
	if( !std::ranges::equal( first.prerequisites.items, second.prerequisites.items,
						   []( const auto &leftItem, const auto &rightItem) {
							   return leftItem.kind == rightItem.kind &&
									  leftItem.description == rightItem.description &&
									  leftItem.evidenceUrl == rightItem.evidenceUrl &&
									  leftItem.evidenceSha256 == rightItem.evidenceSha256 ;
						   })) {
		return false ;
	}

	const auto &firstAuthority	= *first.attestation ;	// 元公式確認主体と個別期限。
	const auto &secondAuthority = *second.attestation ;	// 観測時刻を共有で更新しません。
	return firstAuthority.policyRevision == secondAuthority.policyRevision &&
		   (!sameTimeWindow || (firstAuthority.checkedAtUtc == secondAuthority.checkedAtUtc &&
								firstAuthority.validUntilUtc == secondAuthority.validUntilUtc)) &&
		   firstAuthority.authorityMethod == secondAuthority.authorityMethod &&
		   firstAuthority.authorityEvidenceUrl == secondAuthority.authorityEvidenceUrl &&
		   firstAuthority.authorityEvidenceSha256 == secondAuthority.authorityEvidenceSha256 &&
		   std::ranges::equal(
			   first.route, second.route, []( const auto &firstHop, const auto &secondHop) {
				   return firstHop.url == secondHop.url && firstHop.kind == secondHop.kind &&
						  firstHop.evidenceUrl == secondHop.evidenceUrl &&
						  firstHop.evidenceSha256 == secondHop.evidenceSha256 ;
			   }) ;
}
} // namespace

/** @see signed_index_acquisition_adapter.h */
bool matchesSharedIndexPayloadEvidence( const IndexDistributionRecord &left,
									   const IndexDistributionRecord &right) noexcept
{
	return sameSharedPayloadEvidence( left, right) ;
}

/** @see SignedIndexAcquisitionAdapter 宣言側の契約を正本とする。 */
NativeError SignedIndexAcquisitionAdapter::begin(
	std::shared_ptr<const SignedIndexRecordLookup> lookup, const IndexLookupContext current,
	const IndexTargetOs targetOs, const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	return beginImpl( std::move( lookup), current, targetOs, nowUtc, AuthorityProfile::PRODUCT) ;
}

/** @see SignedIndexAcquisitionAdapter 宣言側の契約を正本とする。 */
NativeError SignedIndexAcquisitionAdapter::beginImpl(
	std::shared_ptr<const SignedIndexRecordLookup> lookup, const IndexLookupContext current,
	const IndexTargetOs targetOs, const std::optional<std::chrono::sys_seconds> nowUtc,
	const AuthorityProfile profile) noexcept
{
	invalidate() ;
	// 不足・stale・未知OSを新しいissuerへ補完しません。
	if( !lookup || current.operationId == 0U || current.scanSessionId == 0U ||
	   current.inventoryGeneration == 0U || !nowUtc ||
	   (targetOs != IndexTargetOs::WINDOWS_10 && targetOs != IndexTargetOs::WINDOWS_11 &&
		targetOs != IndexTargetOs::WINDOWS_SERVER)) {
		return E_INVALIDARG ;
	}

	const auto &snapshot   = lookup->snapshot() ;						// 非公開構築の原保存snapshot。
	const auto &receipt	   = snapshot.schemaReceipt() ;					// 現readerで再認証したreceipt。
	const auto &manifest   = receipt.assetBytes().manifest().data() ;	// 認証された鍵と世代・時刻。
	const bool	authorized = profile == AuthorityProfile::INTERNAL_RAM_FIXTURE
								 ? manifest.keyId == "fixture-main"
								 : std::find( PRODUCT_ACQUISITION_KEYS.begin(),
											 PRODUCT_ACQUISITION_KEYS.end(), manifest.keyId) !=
									   // Manifest認証と独立した固定取得能力。
									   PRODUCT_ACQUISITION_KEYS.end() ;
	// 取得能力のないmanifest鍵や不完全原byteを権限へ昇格しません。
	if( !authorized || snapshot.originalEnvelope().empty() || snapshot.originalGzip().empty() ||
	   receipt.schemaPolicyVersion() != INDEX_RECORD_READER_POLICY_VERSION ||
	   snapshot.storePolicyVersion() != INDEX_STORE_POLICY_VERSION) {
		return E_ACCESSDENIED ;
	}

	// 現在の期限検査を保存時の成功へ置換しません。
	if( *nowUtc < manifest.publishedAtUtc || *nowUtc >= manifest.expiresAtUtc) {
		return HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
	}

	try {
		issuer_			 = std::make_shared<const std::byte>( std::byte{}) ;
		acquisitionOpen_ = std::make_shared<bool>( true) ;
		lookup_			 = std::move( lookup) ;
		context_		 = current ;
		targetOs_		 = targetOs ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		// issuer発行の不明障害を成功へ変更しません。
		return E_UNEXPECTED ;
	}
}

/** @see SignedIndexAcquisitionAdapter 宣言側の契約を正本とする。 */
void SignedIndexAcquisitionAdapter::invalidate() noexcept
{
	terms_.clear() ;
	issuer_.reset() ;
	acquisitionOpen_.reset() ;
	lookup_.reset() ;
	bindings_.clear() ;
	context_	 = {} ;
	nextGrantId_ = 1U ;
}

/** @see SignedIndexAcquisitionAdapter 宣言側の契約を正本とします。 */
void SignedIndexAcquisitionAdapter::closeAcquisitionForInstall() noexcept
{
	// 同じissuerの消費済み成功根拠を保持し、新しい取得だけを不可逆に閉鎖します。
	if( acquisitionOpen_) {
		*acquisitionOpen_ = false ;
	}
}

/** @see SignedIndexAcquisitionAdapter 宣言側の契約を正本とする。 */
NativeError SignedIndexAcquisitionAdapter::validateRecord(
	const std::size_t relationIndex, const IndexLookupContext current,
	const std::optional<std::chrono::sys_seconds> nowUtc, std::string &reason) const
{
	reason.clear() ;
	// 失効・context不一致・時計なしは元snapshot共有寿命にかかわらず拒否します。
	if( !issuer_ || !lookup_ || current != context_ || !nowUtc ||
	   relationIndex >= lookup_->relations().size()) {
		reason = "expired lease, stale context, unavailable time or relation" ;
		return E_ACCESSDENIED ;
	}

	const auto &relation = lookup_->relations()[relationIndex] ;	// 私有構築lookupの原関係。
	const auto &receipt	 = lookup_->snapshot().schemaReceipt() ;	// 原indexとrecordの完全不変結合。
	const auto &manifest = receipt.assetBytes().manifest().data() ;	// 元manifest期限。
	const bool	completeSingle = relation.state == IndexRecordMatchState::MATCHED &&
								relation.reason == IndexRecordMatchReason::UNIQUE_RELATION &&
								// 元完全関係です。
								relation.error == 0U ;
	const bool verifiedPartial =
		relation.state == IndexRecordMatchState::VERIFIED_PARTIAL &&
		relation.reason == IndexRecordMatchReason::VERIFIED_POSITIVE_PARTIAL &&
		relation.positiveProof ;	// 後段で元record tupleとleaseを再確認します。
	const bool verifiedDevice =
		relation.state == IndexRecordMatchState::VERIFIED_DEVICE &&
		relation.reason == IndexRecordMatchReason::VERIFIED_DEVICE_PROJECTION &&
		relation.deviceProof ;	// 元cohortと対象一件を後段で完全再確認します。
	// 全体不足だけで権限を作らず、完全関係か私有証拠付き一deviceを要求します。
	if( relation.context != current || (!completeSingle && !verifiedPartial && !verifiedDevice) ||
	   !relation.deviceIdentity ||
	   (!verifiedDevice && (relation.relatedDevices.size() != 1U ||
							relation.relatedDevices.front() != *relation.deviceIdentity)) ||
	   (verifiedDevice &&
		(relation.relatedDevices.empty() || relation.relatedDevices.size() > 32U)) ||
	   relation.recordIndex >= receipt.records().size()) {
		reason = "same-scan unique relation unavailable" ;
		return E_ACCESSDENIED ;
	}

	const auto &record = receipt.records()[relation.recordIndex] ;	// 元record原byteとhash。
	// Record位置だけの一致で別source／record／公開IDへ結びません。
	if( record.recordSha256 != relation.recordSha256 || record.sourceId != relation.sourceId ||
	   record.recordId != relation.recordId || !relation.publicIdIndex ||
	   *relation.publicIdIndex >= record.publishedIdentityEvidence.pnpIds.size()) {
		reason = "exact record and source binding mismatch" ;
		return E_ACCESSDENIED ;
	}

	// 部分positiveの元公開tuple・同owner・lease・全opaqueが変われば取得権限を失効します。
	if( verifiedPartial &&
	   !relation.positiveProof->matches(
		   current, record.publishedIdentityEvidence.pnpIds[*relation.publicIdIndex].kind,
		   record.publishedIdentityEvidence.pnpIds[*relation.publicIdIndex].value,
		   record.publishedIdentityEvidence.classGuid, GetCurrentThreadId(),
		   relation.relatedDevices, relation.error)) {
		reason = "same-scan native positive proof unavailable" ;
		return E_ACCESSDENIED ;
	}

	// 個別投影も原公開tuple/元completed/error/全cohortと対象一件から切り離しません。
	if( verifiedDevice &&
	   !relation.deviceProof->matches(
		   current, record.publishedIdentityEvidence.pnpIds[*relation.publicIdIndex].kind,
		   record.publishedIdentityEvidence.pnpIds[*relation.publicIdIndex].value,
		   record.publishedIdentityEvidence.classGuid, GetCurrentThreadId(),
		   relation.relatedDevices, relation.error, relation.resolutionCompleted,
		   *relation.deviceIdentity)) {
		reason = "same-scan authenticated individual observation unavailable" ;
		return E_ACCESSDENIED ;
	}

	// Manifest個別期限を超える原recordは再確認待ちへ保持します。
	if( *nowUtc < manifest.publishedAtUtc || *nowUtc >= manifest.expiresAtUtc) {
		reason = "manifest time window unavailable" ;
		return HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
	}

	// 部分positiveの確認device集合だけでinstallerの全作用範囲を承認しません。
	if( (verifiedPartial || verifiedDevice) &&
	   (!record.acquisition.value ||
		*record.acquisition.value != IndexAcquisitionKind::STANDARD_INF_ARCHIVE)) {
		reason = "partial native positive supports only standard INF inspection" ;
		return E_NOTIMPL ;
	}

	// 元申告の未知条件をdescriptor形式から補完しません。
	if( !record.targetOs.value || !record.architecture.value || !record.driverKind.value ||
	   !record.acquisition.value) {
		reason = "unknown target OS: " + record.targetOs.reason +
				 "; architecture: " + record.architecture.reason +
				 "; driver kind: " + record.driverKind.reason +
				 "; acquisition: " + record.acquisition.reason ;
		return E_NOTIMPL ;
	}

	// 既知の別OS・対象外種別・別方式を静的ZIP方式へ変更しません。
	if( *record.targetOs.value != targetOs_ ||
	   *record.architecture.value != IndexArchitecture::X64 ||
	   *record.driverKind.value != IndexDriverKind::NORMAL_DRIVER ||
	   (*record.acquisition.value != IndexAcquisitionKind::STANDARD_INF_ARCHIVE &&
		*record.acquisition.value != IndexAcquisitionKind::OFFICIAL_INSTALLER)) {
		reason = "target conditions do not support the initial standard driver slice" ;
		return E_NOTIMPL ;
	}

	// v1やUNKNOWN取得情報は原理由とともに保留します。
	if( !record.acquisitionDescriptor ||
	   record.acquisitionDescriptor->state != IndexDescriptorState::KNOWN) {
		reason = record.acquisitionDescriptor ? record.acquisitionDescriptor->reason
											  : record.acquisitionDescriptorUnavailableReason ;
		return E_NOTIMPL ;
	}

	const auto &descriptor = *record.acquisitionDescriptor ;	// Schema認証済み元取得申告。
	// このsliceで未接続の規約・具体的条件・形式は成功へ補完しません。
	const bool	standard =
		*record.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE ;	// 元方式です。
	// 形式と方式の接続不足や未知規約を同意不要へ補完しません。
	if( (standard && descriptor.format != IndexPayloadFormat::ZIP &&
		descriptor.format != IndexPayloadFormat::CABINET &&
		descriptor.format != IndexPayloadFormat::SEVEN_ZIP_SFX &&
		descriptor.format != IndexPayloadFormat::PE_RESOURCE_CONTAINER) ||
	   (!standard && descriptor.format != IndexPayloadFormat::WINDOWS_EXE &&
		descriptor.format != IndexPayloadFormat::WINDOWS_MSI) ||
	   descriptor.terms.state == IndexTermsState::UNKNOWN ||
	   descriptor.prerequisites.state != IndexDescriptorState::KNOWN || !descriptor.attestation) {
		reason = "format, terms or concrete prerequisites remain unresolved" ;
		return E_NOTIMPL ;
	}

	bool installerScope{} ;	// 公式の選択driver限定手順を認証recordが明示した場合だけtrueです。
	const std::string expectedOs = targetOs_ == IndexTargetOs::WINDOWS_10 ? "WINDOWS_10"
								   : targetOs_ == IndexTargetOs::WINDOWS_11
									   ? "WINDOWS_11"
									   : "WINDOWS_SERVER" ;	// workerの元観測です。
	// 最大16の具体的条件だけを検査し、同pageの別NVM記載から条件を追加しません。
	for( const auto &condition : descriptor.prerequisites.items) {
		// 分離不能firmwareを普通driverの導入へ含めません。
		if( condition.kind == IndexPrerequisiteKind::INSEPARABLE_FIRMWARE) {
			reason = "inseparable firmware is excluded: " + condition.description ;
			return E_NOTIMPL ;
		}

		// 既知の元worker OS観測以外を文字列同意で確認済みにしません。
		if( condition.kind == IndexPrerequisiteKind::LOCAL_CHECK &&
		   condition.description != "DriverCrate:target-os=" + expectedOs) {
			reason = "local prerequisite unconfirmed: " + condition.description ;
			return E_NOTIMPL ;
		}

		installerScope |=
			condition.kind == IndexPrerequisiteKind::USER_CONFIRMATION &&
			condition.description == "DriverCrate:installer-scope=selected-driver-only" ;
	}

	// 任意installerの作用範囲や期待publisherを推測して起動候補へ変更しません。
	if( !standard && (!installerScope || !descriptor.publisher.value ||
					 (!record.packageEvidence.publishedHash.sha256 &&
					  !record.packageEvidence.calculatedHash.sha256))) {
		reason = "installer driver-only scope, complete hash or expected publisher unavailable" ;
		return E_NOTIMPL ;
	}

	const auto &attestation = *descriptor.attestation ;	// 固定issuerが責任を持つ原確認申告。
	// Policy版と観測個別期限は署名manifestの生存とは独立に検査します。
	if( attestation.policyRevision != 1U || *nowUtc < attestation.checkedAtUtc ||
	   *nowUtc >= attestation.validUntilUtc) {
		reason = "acquisition attestation policy or time window unavailable" ;
		return HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
	}

	return 0 ;
}

/** @see SignedIndexAcquisitionAdapter 宣言側の契約を正本とします。 */
NativeError SignedIndexAcquisitionAdapter::readTermsText(
	const std::size_t relationIndex, const IndexLookupContext current,
	const std::optional<std::chrono::sys_seconds> nowUtc, OfficialHttpClient &client,
	const HttpCancellationCallback &cancellation)
{
	std::string reason ;	// 元recordの不成立理由です。全文をlogへ出しません。
	const auto	validation =
		// 全原条件です。
		validateRecord( relationIndex, current, nowUtc, reason) ;
	// 失効やUNKNOWNから本文取得権限を生成しません。
	if( validation != 0U || !acquisitionOpen_ || !*acquisitionOpen_) {
		return validation != 0U ? validation : static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const auto &receipt = lookup_->snapshot().schemaReceipt() ;	// 元署名wireの正本です。
	const auto &record =
		// 元関係です。
		receipt.records()[lookup_->relations()[relationIndex].recordIndex] ;
	const auto &terms			  = record.acquisitionDescriptor->terms ;	// 原固定documentです。
	const auto	sameRecordBinding = std::ranges::find_if( bindings_, [&]( const auto &binding) {
		 return lookup_->relations()[binding.relationIndex].recordIndex ==
					lookup_->relations()[relationIndex].recordIndex &&
				std::ranges::find( binding.relationIndices, relationIndex) !=
					binding.relationIndices.end() ;
	 }) ; // 同原recordの取得済み全文を持つ同じ共有bindingだけです。
	// 同recordの個別投影で規約を二重取得せず、元全member/lease/期限を使用時に再確認します。
	if( sameRecordBinding != bindings_.end()) {
		return validateBinding( *sameRecordBinding, current, nowUtc, reason) ;
	}

	// 同意不要では本文を取得せず、既取得の同原関係は再送しません。
	if( terms.state == IndexTermsState::CONFIRMED_NO_CONSENT ||
	   std::ranges::any_of( terms_, [relationIndex]( const auto &value) {
		   return value.relationIndex == relationIndex ;
	   })) {
		return 0U ;
	}

	// 本文未確定を空の同意へ補完せず、RAM集合上限を保持します。
	if( !terms.textDocument || terms_.size() >= 256U) {
		return E_NOTIMPL ;
	}

	const auto	 source = std::ranges::find_if( receipt.sources(), [&record]( const auto &value) {
		  return value.sourceId == record.sourceId ;
	  }) ;					 // 原sourceです。
	std::wstring sourceHost ;	// 公式起点の元hostです。
	std::wstring textHost ;		// 本文の同origin hostです。
	const bool	 staticSection = terms.textDocument->htmlExtraction &&
							   terms.textDocument->htmlExtraction->profile ==
								   "STATIC_HTML_SECTION_V1" ;	// 明示した独立規約だけです。
	// 旧契約の同origin条件を維持し、独立profileだけ実公式リンクを後段で確認します。
	if( source == receipt.sources().end() || !exactHttpsHost( source->officialOrigin, sourceHost) ||
	   !exactHttpsHost( terms.textDocument->url, textHost) ||
	   (!staticSection && sourceHost != textHost) ||
	   terms.textDocument->url.find( '?') != std::string::npos) {
		return E_NOTIMPL ;
	}

	// 独立規約は署名sourceの公式配布pageと実anchorにだけ由来させ、任意originへfallbackしません。
	if( staticSection) {
		const auto	&binding = *terms.textDocument->htmlExtraction ;	// 認証済みの原リンク根拠です。
		std::wstring bindingHost ;										// 同source originからだけ取得します。
		// 元source/原hashへの結合を使用時にも要求します。
		if( binding.bindingEvidenceUrl != source->distributionPage ||
		   !source->officialEvidence.evidenceSha256 ||
		   binding.bindingEvidenceSha256 != *source->officialEvidence.evidenceSha256 ||
		   !exactHttpsHost( binding.bindingEvidenceUrl, bindingHost) || bindingHost != sourceHost) {
			return E_ACCESSDENIED ;
		}

		std::string	 linkRaw ;	// URLや本文を通常logへ渡しません。
		std::wstring linkHtml ;	// 周辺HTMLのnonceは同意対象ではありません。
		// 使用時の公式配布pageを同originで有限取得します。
		const auto	 linkError = client.getSignedIndexTermsDocument(
			  indexUtf8Text( binding.bindingEvidenceUrl), bindingHost,
			  binding.bindingEvidenceSizeBytes, true, cancellation, linkRaw, linkHtml, true) ;
		// 周辺byteの同一性ではなく、同じ規約URLへの実anchorを要求します。
		if( linkError != 0U || !hasStaticHtmlDocumentLink( linkHtml, terms.textDocument->url)) {
			return linkError != 0U ? linkError : static_cast<NativeError>( E_ACCESSDENIED) ;
		}
	}

	std::string	 raw ;	// 全原byteをhash確認までRAMへだけ所有します。
	std::wstring text ;	// 変形しない元全文です。
	const bool	 html =
		// Plainと明示HTMLを区別します。
		terms.textDocument->htmlExtraction.has_value() ;
	auto error = client.getSignedIndexTermsDocument(
		std::wstring{terms.textDocument->url.begin(), terms.textDocument->url.end()}, textHost,
		terms.textDocument->sizeBytes, html, cancellation, raw, text,
		staticSection) ;	// 共通の有限GETです。
	std::wstring digest ;	// 実全文の完全SHA-256です。
	// 本文未取得の状態でhash成功値を作りません。
	if( error == 0U && !html) {
		error = computeBytesSha256( raw, digest) ;
	}

	// HTMLの原page provenanceと使用時の原選択文書/全文を明示別契約で照合します。
	if( error == 0U && html) {
		std::wstring extracted ;	// 全原文書/全文照合が終わるまで公開しない値です。
		error = verifyStaticHtmlTerms( text, *terms.textDocument->htmlExtraction,
									  record.acquisitionDescriptor->payloadUrl,
									  indexUtf8Text( terms.revision), extracted) ;
		// 部分抽出を正常snapshotへ残しません。
		if( error == 0U) {
			text = std::move( extracted) ;
		}
	}

	// 原全文/長さ/hash/表示上限が成立しない対象を同意可能へ変えません。
	if( error != 0U || (!html && digest != hexDigest( terms.textDocument->sha256)) ||
	   !validPreparationEulaText( text)) {
		return error != 0U ? error : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC)) ;
	}

	std::size_t retained{} ;	// 同scanの全文code unit累計です。
	// 全既取得本文だけを合計し、plan全文上限を超えません。
	for( const auto &value : terms_) {
		retained += value.text.size() ;
	}

	// 大量の別規約をplan上限を越えてRAMへ保持しません。
	if( text.size() > MAXIMUM_PREPARATION_PLAN_EULA_CHARACTERS - retained) {
		return HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE) ;
	}

	std::wstring revision = indexUtf8Text( terms.revision) ;	// 原公開revisionを文字化けさせません。
	// 算出方式だけは既存の全文revision共通処理を使用します。
	if( terms.revisionKind == IndexTermsRevisionKind::COMPUTED_UTF8_SHA256) {
		error = makeComputedEulaRevision( text, revision) ;
	}

	// 再検証不成立やrevision失敗をRAM正常snapshotへ追加しません。
	if( error != 0U || validateRecord( relationIndex, current, nowUtc, reason) != 0U) {
		return error != 0U ? error : static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	terms_.push_back( {relationIndex, std::move( text), std::move( revision)}) ;
	return 0U ;
}

/** @see SignedIndexAcquisitionAdapter 宣言側の契約を正本とする。 */
NativeError SignedIndexAcquisitionAdapter::describe(
	const std::size_t relationIndex, const IndexLookupContext current,
	const std::optional<std::chrono::sys_seconds> nowUtc, const OfficialPreparationLimits &limits,
	SignedIndexPreparationDescription &description)
{
	description = {} ;
	// 導入開始後に取得計画や未使用権限を増やさず、元成功根拠だけを残します。
	if( !acquisitionOpen_ || !*acquisitionOpen_) {
		return E_ACCESSDENIED ;
	}

	const NativeError error =
		// 全元binding再確認。
		validateRecord( relationIndex, current, nowUtc, description.reason) ;
	// 不足理由のあるrecordから取得対象を生成しません。
	if( error != 0) {
		return error ;
	}

	const auto existing =
		std::find_if( bindings_.begin(), bindings_.end(), [&]( const auto &binding) {
			return std::ranges::find( binding.relationIndices, relationIndex) !=
				   binding.relationIndices.end() ;
		}) ; // 同原関係が既に含まれる共有取得bindingだけ。
	// 別予算や失効したmemberから旧承認targetを再使用しません。
	if( existing != bindings_.end()) {
		const auto groupError =
			// 全member再確認。
			validateBinding( *existing, current, nowUtc, description.reason) ;
		// 記述済み共有targetの全条件が不変な場合だけ同じ対象を返します。
		if( groupError != 0U || existing->limits != limits) {
			return groupError != 0U ? groupError : static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		description.target = existing->target ;
		return 0U ;
	}

	const auto &record =
		lookup_->snapshot()
			.schemaReceipt()
			.records()[lookup_->relations()[relationIndex].recordIndex] ;	// 一意元record。
	const auto		   &descriptor = *record.acquisitionDescriptor ;		// 元静的ZIP条件。
	const std::uint64_t maximum =
		std::min( {descriptor.maximumBytes, limits.maximumFileBytes, limits.maximumProviderBytes,
				  limits.maximumSessionBytes}) ;	// 同じ有限予算の最小枠。
	// 容量不明は有限取得できるが、既知容量超過を架空sizeで補完しません。
	if( maximum == 0U ||
	   (record.packageEvidence.size.value && *record.packageEvidence.size.value > maximum) ||
	   limits.maximumProviderFiles == 0U || limits.maximumSessionFiles == 0U) {
		description.reason = "known size exceeds the finite acquisition capacity" ;
		return HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE) ;
	}

	OfficialPreparationTarget target ;	// URL非保持の計画snapshot。
	target.identity		   = L"index-acquisition-" + std::to_wstring( relationIndex) ;
	target.providerId	   = SIGNED_INDEX_PROVIDER_ID ;
	target.resourceId	   = INDEX_PAYLOAD_RESOURCE ;
	target.releaseIdentity = hexDigest( record.recordSha256) ;
	target.parserRevision  = 1U ;
	target.maximumBytes	   = maximum ;
	target.deviceCount	   = 1U ;
	target.terms		   = OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
	const auto &receipt	   = lookup_->snapshot().schemaReceipt() ;	// 同sourceの正本です。
	const auto	source	   = std::ranges::find_if( receipt.sources(), [&record]( const auto &value) {
		 return value.sourceId == record.sourceId ;
	 }) ; // 元公式主体です。
	// 規約出典のないrecordから共通Providerだけの同意を作りません。
	if( source == receipt.sources().end()) {
		return E_ACCESSDENIED ;
	}

	target.eulaSourceSubject =
		std::wstring{source->sourceId.begin(), source->sourceId.end()} + L" (" +
		std::wstring{source->officialOrigin.begin(), source->officialOrigin.end()} + L")" ;
	// 原規約全文の実取得が完了した対象だけを同意可能な計画へ渡します。
	if( descriptor.terms.state == IndexTermsState::ACCEPTANCE_REQUIRED) {
		const auto text = std::ranges::find_if( terms_, [relationIndex]( const auto &value) {
			return value.relationIndex == relationIndex ;
		}) ; // RAMの同原全文です。
		// 未取得全文を空の同意不要へ変更しません。
		if( text == terms_.end()) {
			description.reason = "exact terms text has not been acquired" ;
			return E_NOTIMPL ;
		}

		target.terms		   = OfficialPreparationTerms::ACCEPTANCE_REQUIRED ;
		target.eulaText		   = text->text ;
		target.eulaRevision	   = text->revision ;
		target.sharedEulaToken = bindings_.size() + 1U ;
		// 同subject/revision/全文だけへ短命tokenを共有し、他出典の同意を流用しません。
		for( const auto &binding : bindings_) {
			// 出典と全文が完全一致する先行groupだけを再利用します。
			if( binding.target.terms == target.terms &&
			   binding.target.eulaSourceSubject == target.eulaSourceSubject &&
			   binding.target.eulaRevision == target.eulaRevision &&
			   binding.target.eulaText == target.eulaText) {
				target.sharedEulaToken = binding.target.sharedEulaToken ;
				break ;
			}
		}
	}

	// 全具体的user条件をEULAとは独立した完全targetへ結びます。
	for( const auto &condition : descriptor.prerequisites.items) {
		// 機械確認済みOS条件を利用者への包括確認へ変換しません。
		if( condition.kind == IndexPrerequisiteKind::USER_CONFIRMATION) {
			target.requiresPrerequisiteConfirmation = true ;
			target.prerequisiteText += indexUtf8Text( condition.description) + L"\r\n" ;
		}
	}

	std::vector<std::size_t> members{relationIndex} ;	// 原lookupの既存有限枠内で全関係を保持します。
	std::vector<std::wstring> devices{
		*lookup_->relations()[relationIndex].deviceIdentity} ;	// 最大32のunique deviceです。
	// 同deviceの別recordも元位置で保持し、完全内容と全policyを個別に照合します。
	for( std::size_t index = 0U;
		index < lookup_->relations().size() && members.size() < index_capacity::RETAINED_RELATIONS;
		++index) {
		const auto &relation = lookup_->relations()[index] ;	// 外部DTOではない元私有relation。
		std::string rejectedReason ;							// 保留理由を共有合格へ変換しません。
		// 既記述関係と未検証関係を共有targetへ加えません。
		if( index == relationIndex || validateRecord( index, current, nowUtc, rejectedReason) != 0U ||
		   std::ranges::any_of( bindings_, [&]( const auto &binding) {
			   return std::ranges::find( binding.relationIndices, index) !=
					  binding.relationIndices.end() ;
		   })) {
			continue ;
		}

		const bool newDevice = std::ranges::find( devices, *relation.deviceIdentity) ==
							   // 重複数ではありません。
							   devices.end() ;
		// 32device上限へ達しても、既存deviceの別原recordは保持できます。
		if( newDevice && devices.size() >= 32U) {
			continue ;
		}

		const auto &other = lookup_->snapshot()
								.schemaReceipt()
								.records()[relation.recordIndex] ;	// 同snapshotの原record。
		// 同URLや版だけで共有せず、UNKNOWN outerを別recordの実byteで補完しません。
		if( matchesSharedIndexPayloadEvidence( record, other)) {
			members.push_back( index) ;
			// unique deviceだけをUIの作用対象件数へ計上します。
			if( newDevice) {
				devices.push_back( *relation.deviceIdentity) ;
			}
		}
	}

	target.deviceCount = static_cast<std::uint32_t>( devices.size()) ;
	// 一issuerの有限記述枠をscan対象全体の上限へ拡大しません。
	if( bindings_.size() >= 256U) {
		description.reason = "finite preparation binding capacity exceeded" ;
		return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	bindings_.push_back( {relationIndex, target, limits, std::nullopt, 0U, std::move( members)}) ;

	description.target = std::move( target) ;
	return 0 ;
}

/** @see SignedIndexAcquisitionAdapter宣言側の契約を正本とします。 */
NativeError SignedIndexAcquisitionAdapter::validateBinding(
	const PreparedBinding &binding, const IndexLookupContext current,
	const std::optional<std::chrono::sys_seconds> nowUtc, std::string &reason) const
{
	// 関係数とdevice数を混同せず、既存lookup枠と32device枠を独立に検査します。
	if( !lookup_ || binding.relationIndices.empty() ||
	   lookup_->relations().size() > index_capacity::RETAINED_RELATIONS ||
	   binding.relationIndices.size() > index_capacity::RETAINED_RELATIONS ||
	   binding.relationIndices.front() != binding.relationIndex ||
	   binding.target.deviceCount == 0U || binding.target.deviceCount > 32U) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const auto firstError = validateRecord( binding.relationIndex, current, nowUtc,
										   reason) ;	// 位置を使用する前の独立検証。
	// 代表の位置や原tupleが不正なら、他関係で補完しません。
	if( firstError != 0U) {
		return firstError ;
	}

	const auto &records = lookup_->snapshot().schemaReceipt().records() ;	// 同原snapshotです。
	const auto &representative =
		records[lookup_->relations()[binding.relationIndex].recordIndex] ;	// 検証済み代表原record。
	std::vector<bool> seen( lookup_->relations().size(), false) ;			// 原lookup枠を超えない重複検査。
	std::vector<std::wstring> devices ;										// Unique deviceを別に再計数します。
	// 各原関係を元context/hash/期限へ再照合し、代表recordだけで権限を省略しません。
	for( const auto index : binding.relationIndices) {
		// 同じ元位置の二重権限や範囲外位置を拒否します。
		if( index >= seen.size() || seen[index]) {
			reason = "duplicate or unavailable original relation" ;
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		seen[index]		 = true ;
		const auto error = validateRecord( index, current, nowUtc, reason) ;	// 元recordの独立検証。
		// 最初の個別拒否は共有成功へ上書きしません。
		if( error != 0U) {
			return error ;
		}

		const auto &relation = lookup_->relations()[index] ;	// 元record/source/hash再照合済みです。
		// 一部のpolicy一致から全groupの取得権限を生成しません。
		if( index != binding.relationIndex &&
		   !matchesSharedIndexPayloadEvidence( representative, records[relation.recordIndex])) {
			reason = "shared payload evidence or policy mismatch" ;
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		// 同deviceの複数INF/版を複数deviceへ数えません。
		if( std::ranges::find( devices, *relation.deviceIdentity) == devices.end()) {
			devices.push_back( *relation.deviceIdentity) ;
		}

		// Claim時にも作用device数を増やす改変を拒否します。
		if( devices.size() > 32U) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}
	}

	// Targetの公開件数も全原関係から再計数した値へ完全一致させます。
	if( devices.size() != binding.target.deviceCount) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	return 0U ;
}

/** @see SignedIndexAcquisitionAdapter 宣言側の契約を正本とする。 */
NativeError SignedIndexAcquisitionAdapter::claimApprovedRecord(
	OfficialPreparationSession &preparation, const OfficialPreparationTask &task,
	const IndexLookupContext current, const std::uint64_t nowUtcSeconds,
	RecordScopedDownloadGrant &grant)
{
	return grant.issueSignedIndex( *this, preparation, task, current, nowUtcSeconds) ;
}

/** @see RecordScopedDownloadGrant 宣言側の契約を正本とする。 */
NativeError RecordScopedDownloadGrant::issueSignedIndex( SignedIndexAcquisitionAdapter &adapter,
														OfficialPreparationSession	  &preparation,
														const OfficialPreparationTask &task,
														const IndexLookupContext	   current,
														const std::uint64_t nowUtcSeconds)
{
	const auto binding =
		std::find_if( adapter.bindings_.begin(), adapter.bindings_.end(),
					 [&task]( const SignedIndexAcquisitionAdapter::PreparedBinding &entry) {
						 return entry.target == task.target ;
					 }) ; // 私有記述へ完全一致。
	// Tokenだけの自己申告、再発行、stale、別sessionやgrant再使用を拒否します。
	if( !adapter.acquisitionOpen_ || !*adapter.acquisitionOpen_ ||
	   metadata_.state != OfficialDownloadGrantState::NOT_REQUESTED ||
	   !preparation.ownsActiveTask( task) || binding == adapter.bindings_.end() ||
	   binding->claimedTask || task.scanSessionId != current.scanSessionId ||
	   adapter.nextGrantId_ == 0U) {
		return E_ACCESSDENIED ;
	}

	std::string		  reason ;	// 再確認不能の理由をworker内だけに保持します。
	const NativeError error =
		adapter.validateBinding( *binding, current, utcFromSeconds( nowUtcSeconds),
								reason) ;	// 共有する全原recordの最終再照合。
	// 不足・個別失効からgrantを発行しません。
	if( error != 0) {
		return error ;
	}

	const auto &lookup = *adapter.lookup_ ;	// 不変の元関係と保存snapshot。
	const auto &record =
		lookup.snapshot()
			.schemaReceipt()
			.records()[lookup.relations()[binding->relationIndex].recordIndex] ;	// 元record。
	const auto &descriptor = *record.acquisitionDescriptor ;						// 型認証済みexact route。
	const auto &manifest =
		// 元manifest。
		lookup.snapshot().schemaReceipt().assetBytes().manifest().data() ;
	// 15分を加算できないUTCを丸めません。
	if( nowUtcSeconds > std::numeric_limits<std::uint64_t>::max() - 900U) {
		return E_INVALIDARG ;
	}

	const auto expires = std::min(
		{nowUtcSeconds + 900U,
		 static_cast<std::uint64_t>( manifest.expiresAtUtc.time_since_epoch().count()),
		 static_cast<std::uint64_t>( descriptor.attestation->validUntilUtc.time_since_epoch()
										.count())}) ;	// 三期限の最小値。
	// 開始余裕30秒を持たない取得は発行前に拒否します。
	if( expires <= nowUtcSeconds || expires - nowUtcSeconds < 30U) {
		return HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
	}

	RecordScopedDownloadGrant pending ;	// 全copy成功後だけ公開する同じgrant型。
	pending.metadata_.origin = OfficialDownloadGrantOrigin::SIGNED_INDEX_COLLECTOR_ATTESTATION ;
	pending.signedIndexResolverPending_ = descriptor.anonymousCdn.has_value() ;
	pending.metadata_.scanSessionId		= task.scanSessionId ;
	pending.metadata_.grantId			= adapter.nextGrantId_ ;
	pending.metadata_.recordEvidenceId	= binding->relationIndex + 1U ;
	pending.metadata_.providerId		= SIGNED_INDEX_PROVIDER_ID ;
	pending.metadata_.policyId			= L"signed-index-attestation-v1" ;
	pending.metadata_.rootResourceId	= L"authenticated-index-record" ;
	// 原32byteを既存record fingerprint容器へ表現し、live fingerprintの由来を合成しません。
	std::transform( record.recordSha256.begin(), record.recordSha256.end(),
				   pending.metadata_.recordFingerprint.bytes.begin(),
				   []( const std::uint8_t byte) { return static_cast<std::byte>( byte) ; }) ;
	pending.metadata_.state				= OfficialDownloadGrantState::GRANT_ISSUED ;
	pending.metadata_.issuedUtcSeconds	= nowUtcSeconds ;
	pending.metadata_.expiresUtcSeconds = expires ;
	pending.metadata_.maximumBytes		= task.target.maximumBytes ;
	pending.resourceId_					= INDEX_PAYLOAD_RESOURCE ;
	pending.kind_			 = *record.acquisition.value == IndexAcquisitionKind::OFFICIAL_INSTALLER
								   ? OfficialDistributionPayloadKind::OFFICIAL_INSTALLER
								   : OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE ;
	pending.fileDisplayName_ = indexUtf8Text( descriptor.fileName) ;
	pending.expectedContentType_ =
		std::wstring{descriptor.expectedContentType.begin(), descriptor.expectedContentType.end()} ;
	// メーカー公表hashだけを公開hashへ渡し、監視PC計算hashは後段の独立照合へ残します。
	if( record.packageEvidence.publishedHash.sha256) {
		pending.publishedSha256_ = hexDigest( *record.packageEvidence.publishedHash.sha256) ;
	}

	// 期待publisherは元申告だけを保持し、索引発行者を代入しません。
	if( descriptor.publisher.value) {
		pending.publisher_ = indexUtf8Text( *descriptor.publisher.value) ;
	}

	pending.targetUrl_ =
		SecretOfficialUrl{std::wstring{descriptor.payloadUrl.begin(), descriptor.payloadUrl.end()}} ;
	// Codecで公式導線・一方向CDN・有限回数を検査済みのexact順を全hop封印します。
	for( const auto &hop : descriptor.route) {
		pending.signedIndexRoute_.emplace_back( std::wstring{hop.url.begin(), hop.url.end()}) ;
	}

	pending.signedIndexIssuer_			= adapter.issuer_ ;
	pending.signedIndexAcquisitionOpen_ = adapter.acquisitionOpen_ ;
	pending.signedIndexLookup_			= adapter.lookup_ ;
	pending.signedIndexRelationIndex_	= binding->relationIndex ;
	binding->claimedTask				= task ;
	// 全所有値の準備後に実preparation自身で一回発行を確定します。
	if( !preparation.claimIndexAcquisition( task)) {
		binding->claimedTask.reset() ;
		return E_ACCESSDENIED ;
	}

	binding->grantId = adapter.nextGrantId_ ;
	*this			 = std::move( pending) ;
	++adapter.nextGrantId_ ;
	return 0 ;
}

/** @see RecordScopedDownloadGrant 宣言側の契約を正本とする。 */
NativeError RecordScopedDownloadGrant::validateSignedIndexAuthority(
	const ScanSessionId scanSessionId) const noexcept
{
	// 弱issuerと非公開lookupの同一関係が残る場合だけ索引分岐を許可します。
	if( metadata_.origin != OfficialDownloadGrantOrigin::SIGNED_INDEX_COLLECTOR_ATTESTATION ||
	   signedIndexIssuer_.expired() || !signedIndexLookup_ ||
	   signedIndexRelationIndex_ >= signedIndexLookup_->relations().size()) {
		return E_ACCESSDENIED ;
	}

	const auto acquisitionOpen = signedIndexAcquisitionOpen_.lock() ;	// 元workerの閉鎖状態。
	// 閉鎖後の新claim・各HTTP hopを拒否し、既消費成功根拠の読取りだけを許します。
	if( !acquisitionOpen ||
	   (!*acquisitionOpen &&
		(metadata_.state != OfficialDownloadGrantState::CONSUMED ||
		 metadata_.outcome != OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION))) {
		return E_ACCESSDENIED ;
	}

	const auto &relation =
		// 不変の封印関係。
		signedIndexLookup_->relations()[signedIndexRelationIndex_] ;
	return metadata_.scanSessionId == scanSessionId &&
				   relation.context.scanSessionId == scanSessionId
			   ? 0
			   : E_ACCESSDENIED ;
}

/** @see RecordScopedDownloadGrant 宣言側の契約を正本とする。 */
NativeError RecordScopedDownloadGrant::validateSignedIndexHop(
	const std::wstring_view exactTarget, const std::uint32_t hop,
	const bool finalResponse) const noexcept
{
	return validateSignedIndexAuthority( metadata_.scanSessionId) == 0 &&
				   metadata_.state == OfficialDownloadGrantState::ACQUIRING &&
				   !signedIndexResolverPending_ && hop < signedIndexRoute_.size() &&
				   signedIndexRoute_[hop].view() == exactTarget &&
				   (!finalResponse || hop + 1U == signedIndexRoute_.size())
			   ? 0
			   : E_ACCESSDENIED ;
}

/** @see official_download_grant.h */
const OfficialAnonymousCdnPlan *RecordScopedDownloadGrant::anonymousCdnPlan() const noexcept
{
	// 元lookup/issuer/同用途がなければresolverを起動しない。
	if( !signedIndexResolverPending_ || validateSignedIndexAuthority( metadata_.scanSessionId) != 0 ||
	   (metadata_.state != OfficialDownloadGrantState::GRANT_ISSUED &&
		metadata_.state != OfficialDownloadGrantState::ACQUIRING) ||
	   kind_ != OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE) {
		return nullptr ;
	}

	const auto &record = signedIndexLookup_->snapshot()
							 .schemaReceipt()
							 .records()[signedIndexLookup_->relations()[signedIndexRelationIndex_]
											.recordIndex] ;	// 私有元record。
	return record.acquisitionDescriptor && record.acquisitionDescriptor->anonymousCdn
			   ? &*record.acquisitionDescriptor->anonymousCdn
			   : nullptr ;
}
/** @see official_download_grant.h */
bool RecordScopedDownloadGrant::requiresAnonymousCdnResolution() const noexcept
{
	return anonymousCdnPlan() != nullptr ;
}
/** @see official_download_grant.h */
NativeError RecordScopedDownloadGrant::sealAnonymousCdnResolution( const std::wstring_view canonical,
																  const SecretOfficialUrl &resolved,
																  const std::uint64_t	   expires,
																  const std::uint64_t	   now)
{
	const auto *plan = anonymousCdnPlan() ;	// 元署名recordだけの公開文脈。
	// 同じclaim中の元canonical/path/modelと新response以外を封印しない。
	if( !plan || metadata_.state != OfficialDownloadGrantState::ACQUIRING ||
	   canonical != asusAnonymousCdnCanonicalUrl( *plan) ||
	   !matchesAsusAnonymousCdnTarget( *plan, resolved.view(), expires)) {
		return E_ACCESSDENIED ;
	}

	const auto deadline = validateRequestStartDeadline( now) ;	// 元grantの時計/期限。
	// 期限切れを新responseの未来値で救済しない。
	if( deadline != 0) {
		return deadline ;
	}

	const auto effective =
		// 元権限と実外部期限の最小値。
		std::min( expires, metadata_.expiresUtcSeconds) ;
	// 30秒の開始余裕は元期限にも外部期限にも要求する。
	if( effective <= now || effective - now < 30U) {
		return HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
	}

	std::vector<SecretOfficialUrl> route ;	// 全準備後だけ旧public routeから切り替える。
	route.emplace_back( std::wstring( resolved.view())) ;
	signedIndexRoute_				= std::move( route) ;
	metadata_.expiresUtcSeconds		= effective ;
	metadata_.externalExpiryPresent = true ;
	signedIndexResolverPending_		= false ;
	return 0 ;
}

/** @see SignedIndexAcquisitionAdapter 宣言側の契約を正本とする。 */
NativeError SignedIndexAcquisitionAdapter::bindInspectionInput(
	const OfficialPreparationTask &task, const IndexLookupContext current,
	const std::uint64_t nowUtcSeconds, const OfficialAcquisitionSession &session,
	const OfficialDownloadWorkspace &workspace, const OfficialAcquiredFileEvidence &evidence,
	IndexedDriverArchiveHint &hint, DriverArchiveInput &input) const
{
	hint  = {} ;
	input = {} ;
	const auto binding =
		std::find_if( bindings_.begin(), bindings_.end(), [&task]( const PreparedBinding &entry) {
			return entry.claimedTask && *entry.claimedTask == task ;
		}) ; // 実claim元token。
	// 別taskから元取得sealを再bindしません。
	if( binding == bindings_.end()) {
		return E_ACCESSDENIED ;
	}

	std::string		  reason ;	// 同recordの期限・元binding不足理由。
	const NativeError recordError =
		validateBinding( *binding, current, utcFromSeconds( nowUtcSeconds),
						reason) ;	// seal後も全原recordと個別期限を再確認。
	// 失効原recordや元file再検証失敗を公開成功結果で補完しません。
	if( recordError != 0) {
		return recordError ;
	}

	const NativeError sealError =
		// 同issuer・保護fileと原byteの共通検証。
		session.verifyAcquiredFile( evidence, workspace) ;
	// 公開DTOや実byte改変から内容入力を生成しません。
	if( sealError != 0) {
		return sealError ;
	}

	const auto &receipt = lookup_->snapshot().schemaReceipt() ;	// 元index／recordの不変hash。
	const auto &record =
		// 元record。
		receipt.records()[lookup_->relations()[binding->relationIndex].recordIndex] ;
	const auto &observed = evidence.observation() ;	// 私有issuerが発行した実取得結果。
	// Grantの由来・opaque record・実hashとsizeを別々に照合します。
	if( evidence.signedIndexIssuer_.lock() != issuer_ ||
	   observed.downloadGrantId != binding->grantId ||
	   observed.recordOrigin != OfficialDownloadGrantOrigin::SIGNED_INDEX_COLLECTOR_ATTESTATION ||
	   observed.scanSessionId != task.scanSessionId ||
	   observed.providerId != SIGNED_INDEX_PROVIDER_ID ||
	   observed.resourceId != INDEX_PAYLOAD_RESOURCE || !observed.delegatedRecord ||
	   observed.recordEvidenceId != binding->relationIndex + 1U ||
	   hexDigest( record.recordSha256) != hexDigest( [&evidence]() {
		   IndexManifestSha256 value{} ;	// 既存fingerprint容器の原byte表現。
		   std::transform( evidence.recordFingerprint().bytes.begin(),
						  evidence.recordFingerprint().bytes.end(), value.begin(),
						  []( const std::byte byte) { return std::to_integer<std::uint8_t>( byte) ; }) ;
		   return value ;
	   }()) ||
	   (record.packageEvidence.size.value &&
		observed.byteCount != *record.packageEvidence.size.value) ||
	   (record.packageEvidence.calculatedHash.sha256 &&
		observed.sha256 != hexDigest( *record.packageEvidence.calculatedHash.sha256))) {
		return HRESULT_FROM_WIN32( ERROR_CRC) ;
	}

	hint = {hexDigest( receipt.indexSha256()), hexDigest( record.recordSha256), observed.sha256,
			observed.byteCount} ;
	// 認証済み元recordの閉じたcontent計画だけを渡します。
	if( record.acquisitionDescriptor->resourceContent) {
		hint.resourceContent = std::make_shared<const OfficialResourceContentPlan>(
			*record.acquisitionDescriptor->resourceContent) ;
	}

	// 元の共有選択集合だけから一意INFを固定し、別の内包INFへ対象を広げません。
	for( const auto relationIndex : binding->relationIndices) {
		const auto &selectedRecord =
			receipt
				.records()[lookup_->relations()[relationIndex].recordIndex] ;	// 元認証recordです。
		const auto &identity =
			selectedRecord.publishedIdentityEvidence ;	// 同recordの元selectorです。
		// 標準INFで公開selectorを持つrecordだけを通常内容検査へ結合します。
		if( selectedRecord.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE &&
		   identity.state == IndexEvidenceState::PUBLISHED &&
		   identity.kind == IndexIdentityEvidenceKind::INF) {
			IndexedDriverInfSelector selector{indexUtf8Text( identity.nestedArchiveIdentity),
											  // 原Unicode値です。
											  indexUtf8Text( identity.infIdentity)} ;
			std::ranges::replace( selector.nestedArchive, L'/', L'\\') ;
			std::ranges::replace( selector.infIdentity, L'/', L'\\') ;
			// 元同一memberをdevice数やModels節数で重複検査しません。
			if( std::ranges::find( hint.selectedInfs, selector) == hint.selectedInfs.end()) {
				hint.selectedInfs.push_back( std::move( selector)) ;
			}
		}
	}

	input = {observed.scanSessionId, observed.inspectionPath, observed.byteCount, observed.sha256,
			 hint.resourceContent} ;
	return 0 ;
}

/** @see signed_index_acquisition_adapter.h 宣言側の契約を正本とします。 */
bool SignedIndexAcquisitionAdapter::matchesRetainedBody(
	const OfficialPreparationTask &task, const OfficialPreparationTask &sourceTask) const
{
	// 元owner以外やlocalからの連鎖参照を作りません。
	if( !lookup_ || !issuer_ || task.scanSessionId != context_.scanSessionId ||
	   sourceTask.scanSessionId != context_.scanSessionId) {
		return false ;
	}

	const auto target =
		// 新原targetです。
		std::ranges::find( bindings_, task.target, &PreparedBinding::target) ;
	const auto source = std::ranges::find( bindings_, sourceTask.target,
										  &PreparedBinding::target) ;	// 原所有targetです。
	// 原TRANSFERの実claimが存在し、新しいtargetは別recordです。
	if( target == bindings_.end() || source == bindings_.end() || target == source ||
	   !source->claimedTask || *source->claimedTask != sourceTask ||
	   source->localInspectionClaimed || source->grantId == 0U) {
		return false ;
	}

	const auto &records = lookup_->snapshot().schemaReceipt().records() ;	// 原署名recordです。
	const auto &left =
		records[lookup_->relations()[target->relationIndex].recordIndex] ;	// 新対象です。
	const auto &right =
		records[lookup_->relations()[source->relationIndex].recordIndex] ;	// 原ownerです。
	return left.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE &&
		   right.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE &&
		   sameSharedPayloadEvidence( left, right, false) ;
}

/** @see signed_index_acquisition_adapter.h 宣言側の契約を正本とします。 */
NativeError SignedIndexAcquisitionAdapter::bindRetainedInspectionInput(
	const OfficialPreparationTask &task, const OfficialPreparationTask &sourceTask,
	const IndexLookupContext current, const std::uint64_t nowUtcSeconds,
	const OfficialAcquisitionSession &session, const OfficialDownloadWorkspace &workspace,
	const OfficialAcquiredFileEvidence	  &evidence,
	const OfficialLocalInspectionEvidence &localInspection, IndexedDriverArchiveHint &hint,
	DriverArchiveInput &input) const
{
	hint  = {} ;
	input = {} ;
	const auto target =
		// 原Bです。
		std::ranges::find( bindings_, task.target, &PreparedBinding::target) ;
	const auto source =
		// 原Aです。
		std::ranges::find( bindings_, sourceTask.target, &PreparedBinding::target) ;
	// 過去TRANSFER証拠は現在の読取許可にせず、新LOCALの実claimを必須にします。
	if( !localInspection.matches( task) || !matchesRetainedBody( task, sourceTask) ||
	   target == bindings_.end() || source == bindings_.end() || !target->claimedTask ||
	   *target->claimedTask != task || !target->localInspectionClaimed || target->grantId != 0U) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	std::string reason ;	// 原metadataの独立再検証結果です。
	auto		error =
		// 原A期限です。
		validateBinding( *source, current, utcFromSeconds( nowUtcSeconds), reason) ;
	// 時刻窓が異なっても原Bの実時刻・全relationを独立検証します。
	if( error == 0U) {
		error = validateBinding( *target, current, utcFromSeconds( nowUtcSeconds), reason) ;
	}

	// 元issuer/ledger/seal/workspace/全file byteを新LOCAL scopeの下で再検証します。
	if( error == 0U) {
		error = bindInspectionInput( sourceTask, current, nowUtcSeconds, session, workspace,
									evidence, hint, input) ;
	}

	// 不一致を同hash/pathだけで補完しません。
	if( error != 0U) {
		hint  = {} ;
		input = {} ;
		return error ;
	}

	const auto &receipt = lookup_->snapshot().schemaReceipt() ;	// 原署名snapshotです。
	const auto &record =
		// 原Bです。
		receipt.records()[lookup_->relations()[target->relationIndex].recordIndex] ;
	hint.recordSha256 = hexDigest( record.recordSha256) ;
	hint.selectedInfs.clear() ;
	// 新Bの元relationだけを実INF検査へ渡します。Aの検査結果は複写しません。
	for( const auto relationIndex : target->relationIndices) {
		const auto &selected =
			receipt
				.records()[lookup_->relations()[relationIndex].recordIndex] ;	// Bの原selectorです。
		const auto &identity = selected.publishedIdentityEvidence ;				// 認証済みINF名です。
		// 元INFの公開selector以外を再利用対象へ広げません。
		if( identity.state == IndexEvidenceState::PUBLISHED &&
		   identity.kind == IndexIdentityEvidenceKind::INF) {
			IndexedDriverInfSelector selector{indexUtf8Text( identity.nestedArchiveIdentity),
											  // 元Unicode値です。
											  indexUtf8Text( identity.infIdentity)} ;
			std::ranges::replace( selector.nestedArchive, L'/', L'\\') ;
			std::ranges::replace( selector.infIdentity, L'/', L'\\') ;
			// 同一memberを重複検査しません。
			if( std::ranges::find( hint.selectedInfs, selector) == hint.selectedInfs.end()) {
				hint.selectedInfs.push_back( std::move( selector)) ;
			}
		}
	}

	return 0U ;
}

namespace signed_index_acquisition_detail {
/** @see Access 宣言側の契約を正本とする。 */
NativeError Access::beginFixture( SignedIndexAcquisitionAdapter				   &adapter,
								 std::shared_ptr<const SignedIndexRecordLookup> lookup,
								 const IndexLookupContext current, const IndexTargetOs targetOs,
								 const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	return adapter.beginImpl( std::move( lookup), current, targetOs, nowUtc,
							 SignedIndexAcquisitionAdapter::AuthorityProfile::INTERNAL_RAM_FIXTURE) ;
}
} // namespace signed_index_acquisition_detail
} // namespace drivercrate
