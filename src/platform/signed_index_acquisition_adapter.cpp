//------------------------------------------------------------------------------
/**
 * @file signed_index_acquisition_adapter.cpp
 * @brief 同snapshotの取得能力とtaskを封印し、既存grantと検査入力へ接続します
 * @version 01.41.00
 * @date 2026/10/24
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  同署名索引候補の所有・表示・指定導入境界を接続
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  完全hash/sizeと取得policy一致だけを有限な共有taskへ結合
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続
 * Ver.01.04.00 Shunji Ogawa  2026/10/13  Local公開pinの独立revision1能力を接続
 * Ver.01.05.00 Shunji Ogawa  2026/10/14  共通HTML許諾の原文書・全文・revision照合をRAM取得へ接続
 * Ver.01.06.00 Shunji Ogawa  2026/10/14  元不足を保持したnative証拠付き一deviceの準備を接続
 * Ver.01.06.01 Shunji Ogawa  2026/10/16  製品revision1取得認可をmanifest trustと独立に接続
 * Ver.01.07.00 Shunji Ogawa  2026/10/24  同payloadの全原関係とunique device数を分離しclaimで再照合
 * Ver.01.08.00 Shunji Ogawa  2026/10/27  元tuple/cohortと個別証拠を標準INF準備で再検証
 * Ver.01.09.00 Shunji Ogawa  2026/11/03  共通公式packageの手動索引と選択内容検査を接続
 * Ver.01.10.00 Shunji Ogawa  2026/11/03  原payloadの同一policy比較を開発用集合観測と共用
 * Ver.01.11.00 Shunji Ogawa  2026/11/03  有界large archiveと共有内容保持・標準serviceを接続
 * Ver.01.12.00 Shunji Ogawa  2026/11/03  署名原範囲の非実行resource内容を接続
 * Ver.01.13.00 Shunji Ogawa  2026/11/03  匿名CDNの同record二要求と有限予約を接続
 * Ver.01.14.00 Shunji Ogawa  2026/11/05  独立静的規約の原文書・公式リンクと既存同意を共通接続
 * Ver.01.15.00 Shunji Ogawa  2026/11/07  全体容量・所有stateと有限進行の契約へ整合
 * Ver.01.16.00 Shunji Ogawa  2026/11/10  対象限定の完了更新と未処理所有・本体再検証を接続
 * Ver.01.16.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.16.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.16.03 Shunji Ogawa  2026/11/12  外側tupleの取得予約と開始拒否の原理由を接続
 * Ver.01.17.00 Shunji Ogawa  2026/11/18  P3同scan fullhost観測と取得直前拒否を接続
 * Ver.01.18.00 Shunji Ogawa  2026/11/18  Server標準INFの二入力fenceを全原binding検証後に解除
 * Ver.01.19.00 Shunji Ogawa  2026/11/19  正規client最低buildを項目判定と両入力の同host再観測へ接続
 * Ver.01.20.00 Shunji Ogawa  2026/11/19  固定baseと条件内GUIDの正規判定を共通scopeだけから受理
 * Ver.01.21.00 Shunji Ogawa  2026/11/19  取得・監査で元native列挙の失効を早期拒否
 * Ver.01.22.00 Shunji Ogawa  2026/11/20  Catalog対象とHardwareIds限定の証拠を候補の取得前に照合
 * Ver.01.23.00 Shunji Ogawa  2026/11/20  元領域の証拠と全選択期限を規約・取得・再利用に結合
 * Ver.01.24.00 Shunji Ogawa  2026/11/20  機種観測の再確認接続前は取得権限を保留
 * Ver.01.25.00 Shunji Ogawa  2026/11/20  規約取得・本体送信・保持fileで同じ型番を再確認
 * Ver.01.26.00 Shunji Ogawa  2026/11/20  取得検査の型番観測と所有バイトの再照合を分離
 * Ver.01.27.00 Shunji Ogawa  2026/11/20  機器別ファームウェアの承認接続前は取得権限を保留
 * Ver.01.28.00 Shunji Ogawa  2026/11/20  同一端末での必須群競合を取得前に区別
 * Ver.01.29.00 Shunji Ogawa  2026/11/20  機器別の本人確認を通常計画へ結合
 * Ver.01.30.00 Shunji Ogawa  2026/11/20  取得の権限と送信前に承認済み端末の現在群を再確認
 * Ver.01.31.00 Shunji Ogawa  2026/11/22  専用Modelsの原証拠と同スキャンのホストを取得に結合
 * Ver.01.32.00 Shunji Ogawa  2026/11/22  導入の全選択確認で元封印とホスト観測を明示分離
 * Ver.01.33.00 Shunji Ogawa  2026/11/22  未接続の私有規約を取得と同意から保留
 * Ver.01.34.00 Shunji Ogawa  2026/11/22  ZIP規約の署名済み文書を初回表示と明示同意後に照合
 * Ver.01.35.00 Shunji Ogawa  2026/11/22  利用者の必須条件確認を元デバイス一台へ結合
 * Ver.01.36.00 Shunji Ogawa  2026/11/22  公式ベンダー配布の元機器と現在HardwareIdsを取得前に再照合
 * Ver.01.37.00 Shunji Ogawa  2026/11/23  署名索引のWiX配布で元アンカーと一回の指定転送先を封印
 * Ver.01.38.00 Shunji Ogawa  2026/11/23  WiXの検査専用取得を元機器と実公式アンカーへ結合
 * Ver.01.39.00 Shunji Ogawa  2026/11/23  同じWiX取得票の照合と端末の再観測を分ける
 * Ver.01.39.01 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * Ver.01.39.02 Shunji Ogawa  2026/11/27  複数機器の部分一致集約と個別取得準備の所有検査を分離
 * Ver.01.40.00 Shunji Ogawa  2026/11/27  同じ署名元ページと同意を確認してAMD取得許可へ結合
 * Ver.01.41.00 Shunji Ogawa  2026/11/27  二段の公式規約を表示と承認後の取得許可へ結合
 * </pre>
 *
 * @note 同workerの直列処理です。監視PCの申告と端末実byteを分け、live根拠を合成しません
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#include "core/index_capacity_limits.h"
#include "platform/signed_index_acquisition_adapter.h"
#include "platform/signed_index_acquisition_adapter_internal.h"
#include "platform/signed_index_codec_internal.h"
#include "core/provider_registry.h"
#include "core/official_source_policy.h"
#include "platform/driver_store_provider.h"
#include "platform/official_download_workspace.h"
#include "platform/official_http_client.h"
#include "platform/official_html_terms.h"
#include "platform/official_file_verifier.h"
#include "platform/official_prepared_acquisition.h"
#include "local_index_acceptance.h"
#include "platform/server_index_scope.h"
#include "platform/client_min_build_scope.h"
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
//------------------------------------------------------------------------------
/**
 * @brief 元認証recordの外側tupleを有限転送上限へ結びます
 * @param[in] record 再検証済みの元署名recordです。内包memberのsizeを使いません
 * @param[in] limits 元scanから変更しない予約上限です
 * @return 原cap内の既知外側hash/sizeがそろえばexact size、不明なら原cap、不正/超過は0です
 * @note 転送だけの値であり、展開/内容検査の上限を変更しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint64_t effectiveIndexPayloadMaximum(
	const IndexDistributionRecord &record, const OfficialPreparationLimits &limits) noexcept
{
	const auto &descriptor = *record.acquisitionDescriptor ;	// 呼出元で元recordを再検証済みです
	const auto	maximum =
		std::min( {descriptor.maximumBytes, limits.maximumFileBytes, limits.maximumProviderBytes,
				  limits.maximumSessionBytes}) ;			// 原capの最小値です
	const auto size = record.packageEvidence.size.value ;	// 外側package tupleだけです
	// 既知sizeの0/超過を、未知の保守上限へ置換しません
	if( size && (*size == 0U || *size > maximum)) {
		return 0U ;
	}

	const bool hashKnown = record.packageEvidence.calculatedHash.sha256.has_value() ||
						   // 同じ外側byteの元hashです
						   record.packageEvidence.publishedHash.sha256.has_value() ;
	return size && hashKnown ? *size : maximum ;
}

// 全メーカー共通の取得resource。URLや製品名から組み立てません
constexpr std::wstring_view					INDEX_PAYLOAD_RESOURCE = L"index-static-zip" ;
// 署名認証から推論せず、normal/localの独立取得集合を排他的に選択します
constexpr std::span<const std::string_view> PRODUCT_ACQUISITION_KEYS =
	local_index_profile::ENABLED
		? std::span<const std::string_view>{local_index_profile::ACQUISITION_KEYS}
		: std::span<const std::string_view>{index_distribution_trust::ACQUISITION_KEYS} ;

//------------------------------------------------------------------------------
/**
 * @brief Strict codecが検査した原UTF-8公開textを欠損なくWindows表示へ変換します
 * @param[in] text 元recordの変更していない有限UTF-8 textです
 * @return 正確なUTF-16 textです。不正byteは例外でfail-closedにします
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring indexUtf8Text( const std::string_view text)
{
	// 未指定の任意属性だけは空のまま保持します
	if( text.empty()) {
		return {} ;
	}

	const auto length = static_cast<int>( text.size()) ;	// Strict codecの有限上限内です
	// 終端または元集合の有限必要数です。成功数を推測しません
	const auto count =
		MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, nullptr, 0) ;
	// 不正UTF-8を代替文字へ補完しません
	if( count <= 0) {
		throw std::runtime_error( "invalid index UTF-8 text") ;
	}

	std::wstring result( static_cast<std::size_t>( count), L'\0') ;	// 正確なUTF-16長です
	// 同原byteを正確な受信長で変換します
	if( MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), length, result.data(),
						   count) != count) {
		throw std::runtime_error( "index UTF-8 conversion failed") ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元スキャンの一意な群を同じ端末と必須バージョンに結びます
 * @param[in] record 元署名とHardwareIdsの適用範囲を検査した配布行です
 * @param[in] relation 同じ配布行と端末の元関係です
 * @return 同じ端末と群が一意に成立した場合の本人確認条件です
 * @note 端末の生IDを返さず、承認や実取得権限を発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<OfficialPlatformFirmwareCondition> firmwarePreparationCondition(
	const IndexDistributionRecord &record, const IndexRecordRelation &relation)
{
	// 機器別条件又は元端末の証拠がなければ同意対象を作りません
	if( record.platformFirmwareGroups.empty() || !relation.deviceIdentity || !relation.deviceProof) {
		return {} ;
	}

	const auto match = relation.deviceProof->platformFirmwareMatch(
		record, relation.context, GetCurrentThreadId(),
		*relation.deviceIdentity) ;	// 同じ所有者の元観測です
	// 別群や証拠不足の状態を必須バージョンだけで補完しません
	if( match.state != IndexPlatformFirmwareMatchState::UNIQUE || !match.groupIndex ||
	   *match.groupIndex >= record.platformFirmwareGroups.size()) {
		return {} ;
	}

	return OfficialPlatformFirmwareCondition{
		*relation.deviceIdentity, *match.groupIndex,
		indexUtf8Text( record.platformFirmwareGroups[*match.groupIndex].versionLabel)} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Schema検査済みASCII HTTPS URLからexact小文字hostを取り出します
 * @param[in] value 元sourceまたはtextDocumentの未変更URLです
 * @param[out] host 成功時だけ443/HTTPSのexact DNS hostです。失敗時は空です
 * @return 共通Windows URL parserの成功時trueです。通信や公式性認定は行いません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool exactHttpsHost( const std::string_view value, std::wstring &host)
{
	host.clear() ;
	const std::wstring url{value.begin(), value.end()} ;	// strict codec済み原ASCIIを借用変換します
	URL_COMPONENTS	   parts{} ;							// 同期parserが返す借用componentです
	parts.dwStructSize	   = sizeof( parts) ;
	parts.dwHostNameLength = static_cast<DWORD>( -1) ;
	// 別scheme/portを同originへ正規化しません
	if( !WinHttpCrackUrl( url.c_str(), static_cast<DWORD>( url.size()), 0U, &parts) ||
	   parts.nScheme != INTERNET_SCHEME_HTTPS || parts.nPort != INTERNET_DEFAULT_HTTPS_PORT ||
	   !parts.lpszHostName || parts.dwHostNameLength == 0U) {
		return false ;
	}

	host.assign( parts.lpszHostName, parts.dwHostNameLength) ;
	// DNS名のASCII caseだけを共通origin比較へ揃え、元URL自体は変更しません
	for( auto &character : host) {
		// 大文字ASCIIのDNS文字だけを小文字へ変換します
		if( character >= L'A' && character <= L'Z') {
			character = static_cast<wchar_t>( character + (L'a' - L'A')) ;
		}
	}

	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原SHA-256を小文字hexへ表現します。暗号検証は複製しません
 * @param[in] digest 認証済み原digest
 * @return 小文字64桁
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring hexDigest( const IndexManifestSha256 &digest)
{
	constexpr std::wstring_view HEX = L"0123456789abcdef" ;	// 固定hex表
	std::wstring				value ;						// 認証済みdigestの表示ではない内部照合値
	value.reserve( 64U) ;
	// 原32byteを二桁へ表現し、全byteで終了します
	for( const auto byte : digest) {
		value.push_back( HEX[byte >> 4U]) ;
		value.push_back( HEX[byte & 15U]) ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定信頼UTC秒を既存時刻型へ変換します
 * @param[in] seconds 正のUTC秒
 * @return 範囲内だけ時刻。0またはsigned秒範囲外はnullopt
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::chrono::sys_seconds> utcFromSeconds(
	const std::uint64_t seconds) noexcept
{
	// 時計なしや符号範囲超過を丸めて有効時刻にしません
	if( seconds == 0U ||
	   seconds > static_cast<std::uint64_t>( std::numeric_limits<std::int64_t>::max())) {
		return std::nullopt ;
	}

	return std::chrono::sys_seconds{std::chrono::seconds{static_cast<std::int64_t>( seconds)}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 完全内容根拠と取得policyが一致したrecordだけを共有対象とします
 * @param[in] left 個別validateRecord済みの元record
 * @param[in] right 個別validateRecord済みの元record
 * @param[in] sameTimeWindow 共有taskはtrue、独立期限検証後の同owned byte比較だけfalseです
 * @return 完全hash/正のsize/全取得条件一致時だけtrueです。名称や版を使用しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool sameSharedPayloadEvidence( const IndexDistributionRecord &left,
											 const IndexDistributionRecord &right,
											 const bool sameTimeWindow = true) noexcept
{
	// 専用Modelsの取得許可は同じ領域の同一原レコードと証拠だけで共有します
	if( sameTimeWindow && (left.recordSchemaVersion == 6U || right.recordSchemaVersion == 6U) &&
	   (left.recordSchemaVersion != right.recordSchemaVersion || !left.scopedModelsEvidence ||
		left.scopedModelsEvidence != right.scopedModelsEvidence ||
		!left.scopedModelsEvidenceSha256 ||
		left.scopedModelsEvidenceSha256 != right.scopedModelsEvidenceSha256 ||
		left.recordId != right.recordId || left.recordSha256 != right.recordSha256 ||
		left.originalBytes != right.originalBytes)) {
		return false ;
	}

	// ベンダー配布の完全ID付き承認と取得物は同じ原レコード内だけで共有します
	if( (left.archiveHardwareScope || right.archiveHardwareScope) &&
	   (!left.archiveHardwareScope || !right.archiveHardwareScope ||
		left.recordSha256 != right.recordSha256 || left.originalBytes != right.originalBytes)) {
		return false ;
	}

	// WiXの原アンカーと埋込み規約を別の署名レコードの取得へ流用しません
	if( (left.wixContentEvidence || right.wixContentEvidence) &&
	   (!left.wixContentEvidence || !right.wixContentEvidence ||
		left.recordSha256 != right.recordSha256 || left.originalBytes != right.originalBytes)) {
		return false ;
	}

	const auto &firstEvidence  = left.packageEvidence ;			// 発行側の認証された完全内容根拠
	const auto &secondEvidence = right.packageEvidence ;		// 別原recordの独立根拠
	const auto &firstMachine   = left.platformDeviceScope ;		// 共有と再利用に適用する機種条件です
	const auto &secondMachine  = right.platformDeviceScope ;	// 別の元関係の条件です
	// 機種別行の保留が別条件の行へ波及しないscopeでだけ配布物を共有します
	if( firstMachine.has_value() != secondMachine.has_value() ||
	   (firstMachine &&
		(firstMachine->machineVendor != secondMachine->machineVendor ||
		 !std::ranges::is_permutation( firstMachine->machineTypes, secondMachine->machineTypes)))) {
		return false ;
	}

	// 不足hash/sizeや異なる方式・対象条件から共有identityを推測しません
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
	} ; // 出典と未知理由も同じ元申告へ結合し、hashの由来を変更しません
	const auto &first  = *left.acquisitionDescriptor ;	// 個別検証済みZIP/同意不要/条件なし
	const auto &second = *right.acquisitionDescriptor ;	// Policyの和集合を作りません
	// 全policy値を比較し、後続sliceの未確認条件を共有成功に補完しません
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
	   first.terms.archiveNotice != second.terms.archiveNotice ||
	   first.terms.textDocument.has_value() != second.terms.textDocument.has_value() ||
	   left.sourceId != right.sourceId || first.prerequisites.state != second.prerequisites.state ||
	   first.prerequisites.reason != second.prerequisites.reason ||
	   first.prerequisites.items.size() != second.prerequisites.items.size() ||
	   !first.attestation || !second.attestation || first.route.size() != second.route.size()) {
		return false ;
	}

	// 全文の固定取得先と全原byte根拠を省略して共有しません
	if( first.terms.textDocument &&
	   (first.terms.textDocument->url != second.terms.textDocument->url ||
		first.terms.textDocument->sha256 != second.terms.textDocument->sha256 ||
		first.terms.textDocument->sizeBytes != second.terms.textDocument->sizeBytes ||
		first.terms.textDocument->contentType != second.terms.textDocument->contentType)) {
		return false ;
	}

	// 同じ原pageでも別の抽出範囲・全文・リンク根拠を一つの同意へ共有しません
	if( first.terms.textDocument) {
		const auto &a = first.terms.textDocument->htmlExtraction ;	// 一つ目の原抽出宣言です
		const auto &b = second.terms.textDocument->htmlExtraction ;	// 二つ目の原抽出宣言です
		// plain/HTMLの違いも取得policyの違いです
		if( a.has_value() != b.has_value()) {
			return false ;
		}

		// HTMLの全fieldを原値で比較し、新profileの根拠byte数も省略しません
		if( a) {
			const auto sameSelector = []( const IndexHtmlTermsSelector &x,
										 const IndexHtmlTermsSelector &y) {
				return x.tag == y.tag && x.attribute == y.attribute && x.value == y.value ;
			} ; // 同期借用した原selectorだけの値比較です
			// 同じ全文・同じ元リンクだけを共有可能とします
			if( a->profile != b->profile || !sameSelector( a->selector, b->selector) ||
			   !sameSelector( a->containerSelector, b->containerSelector) ||
			   !sameSelector( a->linkSelector, b->linkSelector) ||
			   a->payloadAttribute != b->payloadAttribute ||
			   a->documentSha256 != b->documentSha256 ||
			   a->documentSizeBytes != b->documentSizeBytes || a->textSha256 != b->textSha256 ||
			   a->textSizeBytes != b->textSizeBytes ||
			   a->bindingEvidenceUrl != b->bindingEvidenceUrl ||
			   a->bindingEvidenceSha256 != b->bindingEvidenceSha256 ||
			   a->bindingEvidenceSizeBytes != b->bindingEvidenceSizeBytes ||
			   a->bindingDirectoryUrl != b->bindingDirectoryUrl ||
			   a->bindingDirectorySha256 != b->bindingDirectorySha256 ||
			   a->bindingDirectorySizeBytes != b->bindingDirectorySizeBytes) {
				return false ;
			}
		}
	}

	// 元条件は全field完全一致へ結び、別recordの確認権限を和集合へ広げません
	if( !std::ranges::equal( first.prerequisites.items, second.prerequisites.items,
						   []( const auto &leftItem, const auto &rightItem) {
							   return leftItem.kind == rightItem.kind &&
									  leftItem.description == rightItem.description &&
									  leftItem.evidenceUrl == rightItem.evidenceUrl &&
									  leftItem.evidenceSha256 == rightItem.evidenceSha256 ;
						   })) {
		return false ;
	}

	const auto &firstAuthority	= *first.attestation ;	// 元公式確認主体と個別期限
	const auto &secondAuthority = *second.attestation ;	// 観測時刻を共有で更新しません
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

//------------------------------------------------------------------------------
/**
 * @brief 通常adapterと同じ完全payload/取得policyの値比較を行います
 * @param[in] left 個別codec検査済みの原recordです
 * @param[in] right 別の個別codec検査済み原recordです
 * @return 全内容根拠と取得条件が一致する場合だけtrueです
 * @note 認証型、共有claim、通信許可、端末適用性や導入能力を発行しません
 */
//------------------------------------------------------------------------------
bool matchesSharedIndexPayloadEvidence( const IndexDistributionRecord &left,
									   const IndexDistributionRecord &right) noexcept
{
	return sameSharedPayloadEvidence( left, right) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保存snapshotを含む同worker lookupへ固定policyで結合します
 * @param[in] lookup 非公開構築の不変lookup。Null・不足を拒否します
 * @param[in] current 同workerのoperation・scan・inventory
 * @param[in] targetOs 現workerが確認したOS分類。端末適合の合格ではありません
 * @param[in] nowUtc 信頼UTC。確認不能を拒否します
 * @return 開始0。未配備の製品policy・stale・期限・不足は拒否HRESULT
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::begin(
	std::shared_ptr<const SignedIndexRecordLookup> lookup, const IndexLookupContext current,
	const IndexTargetOs targetOs, const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	return beginImpl( std::move( lookup), current, targetOs, nowUtc, AuthorityProfile::PRODUCT) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 内部固定profileを使って同じ開始検査を行います
 * @param[in] lookup 保存済み元lookup
 * @param[in] current 現context
 * @param[in] targetOs 既知OS分類
 * @param[in] nowUtc 信頼UTC
 * @param[in] profile 外部設定ではない内部固定policy区分
 * @param[in] hostAware 元fullhostとの結合を伴う内部開始だけtrueです
 * @return 全開始検査成功0、それ以外は拒否HRESULT
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::beginImpl(
	std::shared_ptr<const SignedIndexRecordLookup> lookup, const IndexLookupContext current,
	const IndexTargetOs targetOs, const std::optional<std::chrono::sys_seconds> nowUtc,
	const AuthorityProfile profile, const bool hostAware) noexcept
{
	// 既host拒否contextはlegacy再beginでも復活させません
	if( hostRejectionStorageFailed_) {
		return E_OUTOFMEMORY ;
	}

	const auto rejection = hostDecision( current) ;	// 完全contextの原拒否です
	// 元初回成功は再開始禁止の根拠に使いません
	if( rejection && rejection->state != IndexHostGateState::ALLOW_UNVERIFIED) {
		return rejection->error ;
	}

	// 不足・stale・未知OSを新しいissuerへ補完しません
	if( !lookup || current.operationId == 0U || current.scanSessionId == 0U ||
	   current.inventoryGeneration == 0U || !nowUtc ||
	   (targetOs != IndexTargetOs::WINDOWS_10 && targetOs != IndexTargetOs::WINDOWS_11 &&
		targetOs != IndexTargetOs::WINDOWS_SERVER)) {
		return E_INVALIDARG ;
	}

	// 既に置き換わった元列挙から新しい取得権限を作りません
	if( !lookup->hasLiveNativeOwner( current)) {
		return E_ACCESSDENIED ;
	}

	// enum-only Serverへfullhostを補完しません
	if( targetOs == IndexTargetOs::WINDOWS_SERVER && !hostAware) {
		return E_NOTIMPL ;
	}

	const auto &snapshot   = lookup->snapshot() ;						// 非公開構築の原保存snapshot
	const auto &receipt	   = snapshot.schemaReceipt() ;					// 現readerで再認証したreceipt
	const auto &manifest   = receipt.assetBytes().manifest().data() ;	// 認証された鍵と世代・時刻
	const bool	authorized = profile == AuthorityProfile::INTERNAL_RAM_FIXTURE
								 ? manifest.keyId == "fixture-main"
								 : std::find( PRODUCT_ACQUISITION_KEYS.begin(),
											 PRODUCT_ACQUISITION_KEYS.end(), manifest.keyId) !=
									   // Manifest認証と独立した固定取得能力
									   PRODUCT_ACQUISITION_KEYS.end() ;
	// 取得能力のないmanifest鍵や不完全原byteを権限へ昇格しません
	if( !authorized || snapshot.originalEnvelope().empty() || snapshot.originalGzip().empty() ||
	   receipt.schemaPolicyVersion() != INDEX_RECORD_READER_POLICY_VERSION ||
	   snapshot.storePolicyVersion() != INDEX_STORE_POLICY_VERSION) {
		return E_ACCESSDENIED ;
	}

	// 現在の期限検査を保存時の成功へ置換しません
	if( *nowUtc < manifest.publishedAtUtc || *nowUtc >= manifest.expiresAtUtc) {
		return HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
	}

	try {
		SignedIndexAcquisitionAdapter pending ;	// 不正な別入力で現contextを上書きしません
		pending.issuer_			 = std::make_shared<const std::byte>( std::byte{}) ;
		pending.acquisitionOpen_ = std::make_shared<bool>( true) ;
		pending.lookup_			 = std::move( lookup) ;
		pending.context_		 = current ;
		pending.targetOs_		 = targetOs ;
		// 選択可能な原関係はhost callbackより前に所有/hash/leaseへ照合します
		if( hostAware || host_) {
			// 元全関係を個別照合し、既知条件の不足を成功へ補完しません
			for( std::size_t index = 0U; index < pending.lookup_->relations().size(); ++index) {
				const auto &relation =
					// 元contextは全行で保持します
					pending.lookup_->relations()[index] ;
				// 別context混入を正常batchへ変換しません
				if( relation.context != current) {
					return E_ACCESSDENIED ;
				}

				// 複数機器の部分一致集約は未判定として保持し、対象を持つ個別の証拠を次の行で検査します
				if( relation.state == IndexRecordMatchState::VERIFIED_PARTIAL &&
				   relation.reason == IndexRecordMatchReason::VERIFIED_POSITIVE_PARTIAL &&
				   relation.positiveProof && !relation.deviceIdentity &&
				   relation.relatedDevices.size() > 1U) {
					continue ;
				}

				// 未解決行は後段の個別HOLDへ残します
				if( relation.state == IndexRecordMatchState::MATCHED ||
				   relation.state == IndexRecordMatchState::VERIFIED_PARTIAL ||
				   relation.state == IndexRecordMatchState::VERIFIED_DEVICE) {
					std::string reason ;	// 元binding失敗をhost失敗へ書き換えません
					const auto	error =
						pending.validateRecord( index, current, nowUtc, reason,
											   RecordValidation::OWNERSHIP) ;	// 純粋な元所有検査です
					// 不正lookupでは現issuer/初回観測を消費しません
					if( error != 0) {
						return error ;
					}
				}
			}
		}

		invalidate() ;
		issuer_			 = std::move( pending.issuer_) ;
		acquisitionOpen_ = std::move( pending.acquisitionOpen_) ;
		lookup_			 = std::move( pending.lookup_) ;
		context_		 = current ;
		targetOs_		 = targetOs ;
		return 0 ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		// issuer発行の不明障害を成功へ変更しません
		return E_UNEXPECTED ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 私有issuerと未開始計画を失効します。原snapshotを修復・削除しません
 */
//------------------------------------------------------------------------------
void SignedIndexAcquisitionAdapter::invalidate() noexcept
{
	host_.reset() ;
	hostObserver_			 = {} ;
	platformMachineObserver_ = {} ;
	platformDeviceStore_	 = nullptr ;
	initialHostDecision_	 = {} ;
	terms_.clear() ;
	issuer_.reset() ;
	acquisitionOpen_.reset() ;
	lookup_.reset() ;
	bindings_.clear() ;
	context_	 = {} ;
	nextGrantId_ = 1U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 新しい取得だけを閉鎖し、消費済み成功grantの同期限内再検証を保持します
 */
//------------------------------------------------------------------------------
void SignedIndexAcquisitionAdapter::closeAcquisitionForInstall() noexcept
{
	// 同じissuerの消費済み成功根拠を保持し、新しい取得だけを不可逆に閉鎖します
	if( acquisitionOpen_) {
		*acquisitionOpen_ = false ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元tuple・descriptor・期限・通常driver条件を再照合します
 * @param[in] relationIndex 元関係位置
 * @param[in] current 現context
 * @param[in] nowUtc 信頼UTC
 * @param[out] reason 失敗時の具体的理由。成功時は空
 * @param[in] purpose 元所有、確認計画、実取得の別です。計画は本体の取得権限を発行しません
 * @return 全条件成立0、それ以外は拒否または保留HRESULT
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::validateRecord(
	const std::size_t relationIndex, const IndexLookupContext current,
	const std::optional<std::chrono::sys_seconds> nowUtc, std::string &reason,
	const RecordValidation purpose) const
{
	reason.clear() ;
	// 失効・context不一致・時計なしは元snapshot共有寿命にかかわらず拒否します
	if( !issuer_ || !lookup_ || current != context_ || !nowUtc ||
	   relationIndex >= lookup_->relations().size() || !lookup_->hasLiveNativeOwner( current)) {
		reason = "expired lease, stale context, unavailable time or relation" ;
		return E_ACCESSDENIED ;
	}

	const auto &relation = lookup_->relations()[relationIndex] ;	// 私有構築lookupの原関係
	const auto &snapshot = lookup_->snapshot() ;					// 同scanの原indexを所有します
	const auto	records	 = snapshot.consumerRecords() ;				// 本文と追加欄の元recordです
	const auto &manifest =
		// 元manifest期限です
		snapshot.schemaReceipt().assetBytes().manifest().data() ;
	const bool completeSingle = relation.state == IndexRecordMatchState::MATCHED &&
								relation.reason == IndexRecordMatchReason::UNIQUE_RELATION &&
								// 元完全関係です
								relation.error == 0U ;
	const bool verifiedPartial =
		relation.state == IndexRecordMatchState::VERIFIED_PARTIAL &&
		relation.reason == IndexRecordMatchReason::VERIFIED_POSITIVE_PARTIAL &&
		relation.positiveProof ;	// 後段で元record tupleとleaseを再確認します
	const bool verifiedDevice =
		relation.state == IndexRecordMatchState::VERIFIED_DEVICE &&
		relation.reason == IndexRecordMatchReason::VERIFIED_DEVICE_PROJECTION &&
		relation.deviceProof ;	// 元cohortと対象一件を後段で完全再確認します
	// 全体不足だけで権限を作らず、完全関係か私有証拠付き一deviceを要求します
	if( relation.context != current || (!completeSingle && !verifiedPartial && !verifiedDevice) ||
	   !relation.deviceIdentity ||
	   (!verifiedDevice && (relation.relatedDevices.size() != 1U ||
							relation.relatedDevices.front() != *relation.deviceIdentity)) ||
	   (verifiedDevice &&
		(relation.relatedDevices.empty() || relation.relatedDevices.size() > 32U)) ||
	   relation.recordIndex >= records.size()) {
		reason = "same-scan unique relation unavailable" ;
		return E_ACCESSDENIED ;
	}

	const auto &record = records[relation.recordIndex] ;	// 元record原byteとhash
	// Record位置だけの一致で別source／record／公開IDへ結びません
	if( record.recordSha256 != relation.recordSha256 || record.sourceId != relation.sourceId ||
	   record.recordId != relation.recordId || !relation.publicIdIndex ||
	   !isIndexLookupIdEligible( record, *relation.publicIdIndex)) {
		reason = "exact record and source binding mismatch" ;
		return E_ACCESSDENIED ;
	}

	const bool	scopedModels = record.recordSchemaVersion == 6U ;		// 専用欄の原レコードです
	const auto &proof		 = record.scopedModelsEvidence ;			// 同認証レコードが所有する元証拠です
	const bool	wix			 = record.wixContentEvidence.has_value() ;	// 私有WiXの元証拠です
	// 同じ認証済みの追加領域、用途と完全HardwareIdsの個別証拠だけを使います
	if( (record.recordSchemaVersion == 8U) != wix ||
	   (wix && (relation.recordIndex < records.base.size() || !relation.deviceProof ||
				relation.positiveProof))) {
		reason = "WIX_ORIGINAL_RECORD_OR_EXACT_DEVICE_PROOF_REQUIRED" ;
		return E_ACCESSDENIED ;
	}

	// 元レコードの証拠参照、認証済み証拠と公式対象を一組として扱います
	if( scopedModels &&
	   (relation.recordIndex < records.base.size() || !record.catalogHardwareScope || !proof ||
		!proof->models.platform || record.scopedModelsEvidenceSha256 != proof->evidenceSha256)) {
		reason = "SCOPED_MODELS_ORIGINAL_EVIDENCE_REQUIRED" ;
		return E_ACCESSDENIED ;
	}

	// 部分positiveの元公開tuple・同owner・lease・全opaqueが変われば取得権限を失効します
	if( verifiedPartial &&
	   !relation.positiveProof->matches(
		   current, record.publishedIdentityEvidence.pnpIds[*relation.publicIdIndex].kind,
		   record.publishedIdentityEvidence.pnpIds[*relation.publicIdIndex].value,
		   record.publishedIdentityEvidence.classGuid, GetCurrentThreadId(),
		   relation.relatedDevices, relation.error)) {
		reason = "same-scan native positive proof unavailable" ;
		return E_ACCESSDENIED ;
	}

	// 個別投影も原公開tuple/元completed/error/全cohortと対象一件から切り離しません
	const bool hardwareOnly = requiresExactIndexHardwareMatch( record) ;	// 元配布の完全ID条件です
	// 公式配布対象は一意結果でも同スキャンのHardwareIds限定証拠を確かめます
	if( (verifiedDevice || hardwareOnly) &&
	   (!relation.deviceProof ||
		!relation.deviceProof->matches(
			current, record.publishedIdentityEvidence.pnpIds[*relation.publicIdIndex].kind,
			record.publishedIdentityEvidence.pnpIds[*relation.publicIdIndex].value,
			record.publishedIdentityEvidence.classGuid, GetCurrentThreadId(),
			relation.relatedDevices, relation.error, relation.resolutionCompleted,
			*relation.deviceIdentity, hardwareOnly))) {
		reason = "same-scan authenticated individual observation unavailable" ;
		return E_ACCESSDENIED ;
	}

	// Manifest個別期限を超える原recordは再確認待ちへ保持します
	if( *nowUtc < manifest.publishedAtUtc || *nowUtc >= manifest.expiresAtUtc) {
		reason = "manifest time window unavailable" ;
		return HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
	}

	// 開始時の所有照合はhost/方式の権限を発行しません
	if( purpose == RecordValidation::OWNERSHIP) {
		return 0 ;
	}

	// 元領域の期限切れは当該行の取得だけを拒否します
	if( *nowUtc >= snapshot.consumerRecordRegion( relation.recordIndex).expiresAtUtc) {
		reason = "original index record region expired" ;
		return HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
	}

	// HardwareIds限定の証拠から同一端末の必須群を判定します
	if( !record.platformFirmwareGroups.empty()) {
		const auto match = relation.deviceProof->platformFirmwareMatch(
			record, current, GetCurrentThreadId(),
			*relation.deviceIdentity) ;	// 元候補と同じ端末です
		// 確認に進める条件と、端末条件の証拠が成立しない場合を区別します
		switch( match.state) {
			case IndexPlatformFirmwareMatchState::AMBIGUOUS:
				// 別々の必須群が同じ端末に該当します
				reason = "PLATFORM_FIRMWARE_GROUP_AMBIGUOUS" ;
				return E_ACCESSDENIED ;
			case IndexPlatformFirmwareMatchState::NO_MATCH:
				// 完全な観測に署名済み対象がありません
				reason = "PLATFORM_FIRMWARE_GROUP_NO_MATCH" ;
				return E_ACCESSDENIED ;
			case IndexPlatformFirmwareMatchState::UNIQUE:
				// 一意の条件は確認に表示できます。本体取得には再観測の接続を求めます
				if( purpose != RecordValidation::PREPARATION && !platformDeviceStore_) {
					reason = "PLATFORM_FIRMWARE_REOBSERVATION_UNAVAILABLE" ;
					return E_NOTIMPL ;
				}

				break ;

			case IndexPlatformFirmwareMatchState::UNAVAILABLE:
				// 同じ端末の観測を確認できないため保留します
			default:
				reason = "PLATFORM_FIRMWARE_GROUP_UNAVAILABLE" ;
				return E_ACCESSDENIED ;
		}
	}

	// 元型番と同じスキャンに結び、明示された再観測を確かめます
	if( record.platformDeviceScope &&
	   (!platformMachineObserver_ || !snapshot.platformMachine( current))) {
		reason = "platform machine acquisition revalidation unavailable" ;
		return E_ACCESSDENIED ;
	}

	const auto hostRejection = hostDecision( current) ;	// 元host拒否は後続正常で消えません
	// private host失敗のラッチを別recordやlegacyから回避しません
	if( hostRejection && hostRejection->state != IndexHostGateState::ALLOW_UNVERIFIED) {
		reason = hostRejection->state == IndexHostGateState::STALE
					 ? "HOST_STALE_NEW_SCAN_REQUIRED"
					 : "HOST_UNKNOWN_OR_UNSUPPORTED_NEW_SCAN_REQUIRED" ;
		return hostRejection->error ;
	}

	// 部分positiveの確認device集合だけでinstallerの全作用範囲を承認しません
	if( (verifiedPartial || verifiedDevice) &&
	   (!record.acquisition.value ||
		*record.acquisition.value != IndexAcquisitionKind::STANDARD_INF_ARCHIVE)) {
		reason = "partial native positive supports only standard INF inspection" ;
		return E_NOTIMPL ;
	}

	// 元申告の未知条件をdescriptor形式から補完しません
	if( !record.targetOs.value || !record.architecture.value || !record.driverKind.value ||
	   !record.acquisition.value) {
		reason = "unknown target OS: " + record.targetOs.reason +
				 "; architecture: " + record.architecture.reason +
				 "; driver kind: " + record.driverKind.reason +
				 "; acquisition: " + record.acquisition.reason ;
		return E_NOTIMPL ;
	}

	// 既知の別OS・対象外種別・別方式を静的ZIP方式へ変更しません
	if( host_ && *record.targetOs.value != targetOs_) {
		reason = "HOST_INCOMPATIBLE" ;
		return E_ACCESSDENIED ;
	}

	// 元全関係を個別照合し、既知条件の不足を成功へ補完しません
	if( *record.targetOs.value != targetOs_ ||
	   *record.architecture.value != IndexArchitecture::X64 ||
	   *record.driverKind.value != IndexDriverKind::NORMAL_DRIVER ||
	   (*record.acquisition.value != IndexAcquisitionKind::STANDARD_INF_ARCHIVE &&
		*record.acquisition.value != IndexAcquisitionKind::OFFICIAL_INSTALLER)) {
		reason = "target conditions do not support the initial standard driver slice" ;
		return E_NOTIMPL ;
	}

	// v1やUNKNOWN取得情報は原理由とともに保留します
	if( !record.acquisitionDescriptor ||
	   record.acquisitionDescriptor->state != IndexDescriptorState::KNOWN) {
		reason = record.acquisitionDescriptor ? record.acquisitionDescriptor->reason
											  : record.acquisitionDescriptorUnavailableReason ;
		return E_NOTIMPL ;
	}

	const auto &descriptor = *record.acquisitionDescriptor ;	// Schema認証済み元取得申告
	const bool	server =
		*record.targetOs.value == IndexTargetOs::WINDOWS_SERVER ;	// acquisition kindで区別します
	// WiXの埋込み規約を出す前の取得は、対応する実クライアントと同じ一台に限ります
	if( wix) {
		// enumだけの開始や再観測依存の欠落で検査対象を作りません
		if( !host_ || host_->context != current || !hostObserver_ || !platformDeviceStore_) {
			reason = "WIX_FULL_HOST_AND_DEVICE_REOBSERVATION_REQUIRED" ;
			return E_NOTIMPL ;
		}

		const auto decision = matchWixIndexHost( record, host_->observation) ;	// 原端末の対象OSです
		// 実観測と元のWindows client x64が一致する場合だけ進みます
		if( decision.state != IndexHostGateState::ALLOW_UNVERIFIED) {
			reason = "WIX_HOST_INCOMPATIBLE_OR_UNSUPPORTED" ;
			return decision.error ;
		}
	}

	// 元形式、埋込み規約と作用範囲を検査専用の一台へ限定します
	if( wix != (descriptor.format == IndexPayloadFormat::WIX_BURN_V3) ||
	   (wix && (record.acquisition.value != IndexAcquisitionKind::STANDARD_INF_ARCHIVE ||
				descriptor.terms.state != IndexTermsState::ACCEPTANCE_REQUIRED ||
				descriptor.terms.revisionKind != IndexTermsRevisionKind::WIX_RTF_SHA256 ||
				descriptor.terms.textDocument || descriptor.terms.archiveNotice ||
				!record.platformFirmwareGroups.empty()))) {
		reason = "WIX_STANDARD_ARCHIVE_AND_EMBEDDED_TERMS_REQUIRED" ;
		return E_NOTIMPL ;
	}

	// 専用欄の元CABを標準INFとして取得し、同スキャンの完全観測を要求します
	if( scopedModels) {
		// 専用Modelsは元CABの検査に対応する取得形式だけを認めます
		if( descriptor.format != IndexPayloadFormat::CABINET || descriptor.resourceContent ||
		   record.acquisition.value != IndexAcquisitionKind::STANDARD_INF_ARCHIVE) {
			reason = "SCOPED_MODELS_STANDARD_CAB_REQUIRED" ;
			return E_NOTIMPL ;
		}

		// enum-onlyの開始や再観測依存の欠落から許可を発行しません
		if( !host_ || host_->context != current || !hostObserver_) {
			reason = "SCOPED_MODELS_FULLHOST_REQUIRED" ;
			return E_NOTIMPL ;
		}

		const auto decision = classifyIndexHost( host_->observation) ;	// 元観測の判定です
		// 同じスキャンで元配布のOS条件を満たせない場合は取得を許可しません
		if( decision.state != IndexHostGateState::ALLOW_UNVERIFIED) {
			reason = "SCOPED_MODELS_HOST_UNKNOWN_OR_UNSUPPORTED" ;
			return decision.error ;
		}

		const auto &platform = *proof->models.platform ;	// 索引が固定したWindowsの観測点です
		const auto &observed = *host_->observation.value ;	// 同スキャンで成立した実観測です
		// 元suiteは明示観測用の値です。実suiteは後続の同ホスト確認に保持します
		if( observed.majorVersion != platform.majorVersion ||
		   observed.minorVersion != platform.minorVersion ||
		   observed.nativeArchitecture != platform.processorArchitecture ||
		   observed.productType != platform.productType ||
		   observed.buildNumber < platform.buildNumber) {
			reason = "SCOPED_MODELS_HOST_INCOMPATIBLE" ;
			return E_ACCESSDENIED ;
		}
	}

	// EXE/SFX容器のstandard INFとinstallerのkindを混同しません
	if( server && *record.acquisition.value != IndexAcquisitionKind::STANDARD_INF_ARCHIVE) {
		reason = "SERVER_UNSUPPORTED_METHOD" ;
		return E_NOTIMPL ;
	}

	// 新Server三条件は同PUBLISHED/INF根拠と原hostへ結びます
	if( server) {
		const auto scope = readServerIndexScope( record.publishedIdentityEvidence,
												descriptor.prerequisites) ;	// 元署名rawの三条件です
		// legacy enumや欠落条件から取得権限を作りません
		if( !host_ || !scope) {
			reason = "SERVER_SCOPE_OR_FULLHOST_REQUIRED" ;
			return E_NOTIMPL ;
		}

		const auto decision =
			// actual suite等値は要求しません
			matchServerIndexHost( *scope, host_->observation) ;
		// 他release/productのpolicyへfallbackしません
		if( decision.state != IndexHostGateState::ALLOW_UNVERIFIED) {
			reason = "SERVER_HOST_INCOMPATIBLE_OR_UNSUPPORTED" ;
			return decision.error ;
		}
	}

	const auto clientScope = readClientMinimumBuildScope( record) ;	// 同認証recordの元条件だけです
	// reserved不正/未採用floorは当該recordだけ拒否し、host失敗ラッチを作りません
	if( clientScope.state == ClientMinBuildState::INVALID ||
	   clientScope.state == ClientMinBuildState::UNSUPPORTED) {
		reason = "CLIENT_MIN_BUILD_SCOPE_INVALID_OR_UNSUPPORTED" ;
		return E_NOTIMPL ;
	}

	// 正規client条件はlegacy enumで代用せず、同scan所有の原fullhostへ結びます
	if( clientScope.state == ClientMinBuildState::VALID) {
		// 原観測の欠落は成功へ補完せず、他record/indexを失効させません
		if( !host_) {
			reason = "CLIENT_MIN_BUILD_FULLHOST_REQUIRED" ;
			return E_NOTIMPL ;
		}

		const auto decision =
			// 元六field/原codeです
			matchClientMinimumBuildHost( clientScope, host_->observation) ;
		// 低build/別productのrecord不適合をglobal host失敗へ読み替えません
		if( decision.state != IndexHostGateState::ALLOW_UNVERIFIED) {
			reason = "CLIENT_MIN_BUILD_HOST_INCOMPATIBLE_OR_UNSUPPORTED" ;
			return decision.error ;
		}
	}

	// このsliceで未接続の規約・具体的条件・形式は成功へ補完しません
	const bool standard =
		*record.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE ;	// 元方式です
	// 形式と方式の接続不足や未知規約を同意不要へ補完しません
	if( (standard && descriptor.format != IndexPayloadFormat::ZIP &&
		descriptor.format != IndexPayloadFormat::CABINET &&
		descriptor.format != IndexPayloadFormat::SEVEN_ZIP_SFX &&
		descriptor.format != IndexPayloadFormat::PE_RESOURCE_CONTAINER && !wix) ||
	   (!standard && descriptor.format != IndexPayloadFormat::WINDOWS_EXE &&
		descriptor.format != IndexPayloadFormat::WINDOWS_MSI) ||
	   descriptor.terms.state == IndexTermsState::UNKNOWN ||
	   descriptor.prerequisites.state != IndexDescriptorState::KNOWN || !descriptor.attestation) {
		reason = "format, terms or concrete prerequisites remain unresolved" ;
		return E_NOTIMPL ;
	}

	bool installerScope{} ;	// 公式の選択driver限定手順を認証recordが明示した場合だけtrueです
	const std::string expectedOs = targetOs_ == IndexTargetOs::WINDOWS_10 ? "WINDOWS_10"
								   : targetOs_ == IndexTargetOs::WINDOWS_11
									   ? "WINDOWS_11"
									   : "WINDOWS_SERVER" ;	// workerの元観測です
	// 最大16の具体的条件だけを検査し、同pageの別NVM記載から条件を追加しません
	for( const auto &condition : descriptor.prerequisites.items) {
		// 分離不能firmwareを普通driverの導入へ含めません
		if( condition.kind == IndexPrerequisiteKind::INSEPARABLE_FIRMWARE) {
			reason = "inseparable firmware is excluded: " + condition.description ;
			return E_NOTIMPL ;
		}

		// 検査専用の承認へ利用者の条件確認を合成しません
		if( wix && condition.kind == IndexPrerequisiteKind::USER_CONFIRMATION) {
			reason = "WIX_PREREQUISITE_CONFIRMATION_NOT_AVAILABLE" ;
			return E_NOTIMPL ;
		}

		// 既知の元worker OS観測以外を文字列同意で確認済みにしません
		if( condition.kind == IndexPrerequisiteKind::LOCAL_CHECK && !server &&
		   condition.description != "DriverCrate:target-os=" + expectedOs &&
		   clientScope.state != ClientMinBuildState::VALID) {
			reason = "local prerequisite unconfirmed: " + condition.description ;
			return E_NOTIMPL ;
		}

		installerScope |=
			condition.kind == IndexPrerequisiteKind::USER_CONFIRMATION &&
			condition.description == "DriverCrate:installer-scope=selected-driver-only" ;
	}

	// 任意installerの作用範囲や期待publisherを推測して起動候補へ変更しません
	if( !standard && (!installerScope || !descriptor.publisher.value ||
					 (!record.packageEvidence.publishedHash.sha256 &&
					  !record.packageEvidence.calculatedHash.sha256))) {
		reason = "installer driver-only scope, complete hash or expected publisher unavailable" ;
		return E_NOTIMPL ;
	}

	const auto &attestation = *descriptor.attestation ;	// 固定issuerが責任を持つ原確認申告
	// Policy版と観測個別期限は署名manifestの生存とは独立に検査します
	if( attestation.policyRevision != 1U || *nowUtc < attestation.checkedAtUtc ||
	   *nowUtc >= attestation.validUntilUtc) {
		reason = "acquisition attestation policy or time window unavailable" ;
		return HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
	}

	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元認証規約を有限共通GETで取得し、全文と出典をRAMの記述へ固定します
 * @param[in] relationIndex 私有lookupの原関係位置です
 * @param[in] current 元scanの全contextです
 * @param[in] utc 信頼UTCの取得処理です。送信前と受信後の期限を再照合します
 * @param[in,out] client 同workerの完全共通HTTP依存です。公開URLは受理しません
 * @param[in] cancellation 同scanの協調停止です
 * @return 全原byte/全文成立0、未対応/変更/失効は元HRESULTです
 * @note 同意を発行せず、未取得本文を空の同意不要へ変更しません
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::readTermsText(
	const std::size_t relationIndex, const IndexLookupContext current,
	const std::function<std::optional<std::chrono::sys_seconds>()> &utc, OfficialHttpClient &client,
	const HttpCancellationCallback &cancellation)
{
	return readTermsTextImpl( relationIndex, current, utc, client, cancellation, false) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ元配布と規約を有限GETで照合して、初回表示または取得前の再確認に使います
 * @param[in] relationIndex 私有lookupの原関係位置です
 * @param[in] current 同じスキャンの全contextです
 * @param[in] utc 送信前と受信後に期限を検査する信頼時計です
 * @param[in,out] client 固定公式URLだけを取得する共通HTTPです
 * @param[in] cancellation 実行中の停止条件です
 * @param[in] recheck trueはZIP規約の取得前で、保存済み本文と改訂を変更しません
 * @return 同じ文書の照合成功0か元HRESULTです
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::readTermsTextImpl(
	const std::size_t relationIndex, const IndexLookupContext current,
	const std::function<std::optional<std::chrono::sys_seconds>()> &utc, OfficialHttpClient &client,
	const HttpCancellationCallback &cancellation, const bool recheck)
{
	const auto	nowUtc = utc ? utc() : std::nullopt ;	// 規約送信前の信頼UTCです
	std::string reason ;								// 元recordの不成立理由です。全文をlogへ出しません
	const auto	purpose = recheck
							  ? RecordValidation::ACQUISITION
							  : RecordValidation::PREPARATION ;	// 再確認では本体の原条件も要求します
	const auto	validation =
		// 全原条件です
		validateRecord( relationIndex, current, nowUtc, reason, purpose) ;
	// 失効やUNKNOWNから本文取得権限を生成しません
	if( validation != 0U || !acquisitionOpen_ || !*acquisitionOpen_) {
		return validation != 0U ? validation : static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const auto &snapshot = lookup_->snapshot() ;	// 元署名wireの正本です
	const auto	recordIndex =
		// 選択した元recordの位置です
		lookup_->relations()[relationIndex].recordIndex ;
	const auto &record = snapshot.consumerRecords()[recordIndex] ;		// 元規約を持つ行です
	const auto	region = snapshot.consumerRecordRegion( recordIndex) ;	// 同じ元領域の取得元です
	const auto &terms  = record.acquisitionDescriptor->terms ;			// 原固定documentです
	// WiXの規約は元配布物を検査して確定するため、通常規約の表示・再確認では扱いません
	if( record.wixContentEvidence) {
		return E_NOTIMPL ;
	}

	const auto displayed = std::ranges::find(
		terms_, recordIndex, &TermsSnapshot::recordIndex) ;	// 初回表示に結んだ元本文です
	// 同意のない別レコードや空の表示から取得前の再確認を始めません
	if( recheck && (!requiresApprovedTermsRecheck( terms) || displayed == terms_.end())) {
		return E_ACCESSDENIED ;
	}

	const auto sameRecordBinding = std::ranges::find_if( bindings_, [&]( const auto &binding) {
		return lookup_->relations()[binding.relationIndex].recordIndex ==
				   lookup_->relations()[relationIndex].recordIndex &&
			   std::ranges::find( binding.relationIndices, relationIndex) !=
				   binding.relationIndices.end() ;
	}) ; // 同原recordの取得済み全文を持つ同じ共有bindingだけです
	// 同recordの個別投影で規約を二重取得せず、元全member/lease/期限を使用時に再確認します
	if( !recheck && sameRecordBinding != bindings_.end()) {
		return validateBinding( *sameRecordBinding, current, nowUtc, reason,
							   RecordValidation::PREPARATION) ;
	}

	// 同意不要では本文を取得せず、既取得の同原関係は再送しません
	if( !recheck &&
	   (terms.state == IndexTermsState::CONFIRMED_NO_CONSENT || displayed != terms_.end())) {
		return 0U ;
	}

	// 本文未確定を空の同意へ補完せず、RAM集合上限を保持します
	if( !terms.textDocument || (!recheck && terms_.size() >= 256U)) {
		return E_NOTIMPL ;
	}

	const auto	 source = std::ranges::find_if( region.sources, [&record]( const auto &value) {
		  return value.sourceId == record.sourceId ;
	  }) ;														  // 原sourceです
	std::wstring sourceHost ;										// 公式起点の元hostです
	std::wstring textHost ;											// 本文の同origin hostです
	const auto	&extraction = terms.textDocument->htmlExtraction ;	// 認証済みの元抽出宣言
	const bool	 linked =
		extraction && extraction->profile == LINKED_STATIC_TERMS_PROFILE ;	// 二段リンク用
	const bool staticSection =
		linked ||
		(extraction && extraction->profile == "STATIC_HTML_SECTION_V1") ;	// 独立規約の固定二形式
	// 旧契約の同origin条件を維持し、独立profileだけ実公式リンクを後段で確認します
	if( source == region.sources.end() || !exactHttpsHost( source->officialOrigin, sourceHost) ||
	   !exactHttpsHost( terms.textDocument->url, textHost) ||
	   ((!staticSection || linked) && sourceHost != textHost) ||
	   terms.textDocument->url.find( '?') != std::string::npos) {
		return E_NOTIMPL ;
	}

	auto	   lastChecked	   = *nowUtc ;	// 各GET前後で増加を確認する信頼UTC
	const auto confirmNextPage = [&]() -> NativeError {
		const auto next = utc() ;	// 次のGET前の信頼UTC
		const auto status =
			// 同じ署名元の原期限
			validateRecord( relationIndex, current, next, reason, purpose) ;
		// 元期限と同じ操作の時系列を満たす場合だけ次の取得へ進める
		if( status != 0U || !next || *next < lastChecked) {
			return status != 0U ? status
								: static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_TIMEOUT)) ;
		}

		lastChecked = *next ;
		return 0U ;
	} ; // worker内の元選択と最後のUTCだけを同期中に借用

	// 独立規約は署名sourceの公式配布pageと実anchorにだけ由来させ、任意originへfallbackしません
	if( staticSection) {
		const auto	&binding = *terms.textDocument->htmlExtraction ;	// 認証済みの原リンク根拠です
		std::wstring bindingHost ;										// 同source originからだけ取得します
		// 元source/原hashへの結合を使用時にも要求します
		if( binding.bindingEvidenceUrl != source->distributionPage ||
		   !source->officialEvidence.evidenceSha256 ||
		   binding.bindingEvidenceSha256 != *source->officialEvidence.evidenceSha256 ||
		   !exactHttpsHost( binding.bindingEvidenceUrl, bindingHost) || bindingHost != sourceHost) {
			return E_ACCESSDENIED ;
		}

		std::string	 linkRaw ;								// URLや本文を通常logへ渡しません
		std::wstring linkHtml ;								// 周辺HTMLのnonceは同意対象ではありません
		auto		 hostError = reobserveHost( current) ;	// 実GET直前だけ同原hostを確認します
		// 型番付きの元行だけ同じ端末を再確認します
		if( hostError == 0U) {
			hostError = reobservePlatformMachine( record, current) ;
		}

		// HTTP失敗ではhost状態を再初期化しません
		if( hostError != 0) {
			return hostError ;
		}

		// 使用時の公式配布pageを同originで有限取得します
		const auto linkError = client.getSignedIndexTermsDocument(
			indexUtf8Text( binding.bindingEvidenceUrl), bindingHost,
			binding.bindingEvidenceSizeBytes, true, cancellation, linkRaw, linkHtml, true) ;
		const auto &payloadUrl =
			record.acquisitionDescriptor->payloadUrl ;	// 同じ署名レコードの配布本体
		const auto &linkedUrl = (terms.archiveNotice || linked)
									? payloadUrl
									: terms.textDocument->url ;	// 公式ページで直接確認する元リンク
		// 公式配布ページが取得できない場合や、リンクが消えた場合は同意を発行しません
		if( linkError != 0U || !hasStaticHtmlDocumentLink( linkHtml, linkedUrl)) {
			return linkError != 0U ? linkError : static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		// 署名レコードで指定した同一HTTPS起点の一覧だけを一度調べる
		if( linked) {
			const auto	&directory = binding.bindingDirectoryUrl ;	// 同一配布の明示中間一覧
			std::wstring directoryHost ;							// 一覧送信の固定HTTPSホスト
			// 別origin、または公式製品ページに無い一覧を参照しない
			if( !exactHttpsHost( directory, directoryHost) || directoryHost != sourceHost ||
			   !hasSameOriginStaticHtmlDocumentLink( linkHtml, binding.bindingEvidenceUrl,
													directory)) {
				return E_ACCESSDENIED ;
			}

			auto status = confirmNextPage() ;	// 一覧送信直前の同じ元期限
			// 元回線と端末を一つの許可から二段目に流用しない
			if( status == 0U) {
				status = reobserveHost( current) ;
			}

			// 型番条件も元レコードに結び直す
			if( status == 0U) {
				status = reobservePlatformMachine( record, current) ;
			}

			// 一覧の本文は正式な送信前検査が成立した場合だけ取得する
			if( status == 0U) {
				status = client.getSignedIndexTermsDocument( indexUtf8Text( directory), directoryHost,
															binding.bindingDirectorySizeBytes, true,
															cancellation, linkRaw, linkHtml, true) ;
			}

			// 一覧が署名レコードの同じ全文を指さない場合は連鎖をここで終える
			if( status != 0U ||
			   !hasSameOriginStaticHtmlDocumentLink( linkHtml, directory, terms.textDocument->url)) {
				return status != 0U ? status : static_cast<NativeError>( E_ACCESSDENIED) ;
			}
		}
	}

	// 配布ページまたは一覧を読み終えた時点で元配布の期限を再検証する
	if( requiresApprovedTermsRecheck( terms)) {
		const auto status = confirmNextPage() ;	// 全文を送信する直前の確認
		// 失効・時刻逆行では既取得の導線から本文送信を認めない
		if( status != 0U) {
			return status ;
		}
	}

	std::string	 raw ;	// 全原byteをhash確認までRAMへだけ所有します
	std::wstring text ;	// 変形しない元全文です
	const bool	 html =
		// Plainと明示HTMLを区別します
		terms.textDocument->htmlExtraction.has_value() ;
	auto hostError = reobserveHost( current) ;	// 本文実GETへ渡す最後の観測です
	// 固定文書の送信直前にも元型番を確認します
	if( hostError == 0U) {
		hostError = reobservePlatformMachine( record, current) ;
	}

	// 欠落/変化は本文取得許可を発行しません
	if( hostError != 0) {
		return hostError ;
	}

	auto error = client.getSignedIndexTermsDocument(
		std::wstring{terms.textDocument->url.begin(), terms.textDocument->url.end()}, textHost,
		terms.textDocument->sizeBytes, html, cancellation, raw, text,
		staticSection) ;	// 共通の有限GETです
	std::wstring digest ;	// 実全文の完全SHA-256です
	// 本文未取得の状態でhash成功値を作りません
	if( error == 0U && (!html || terms.archiveNotice)) {
		error =
			html ? computeCollectorMetadataSha256( raw, digest) : computeBytesSha256( raw, digest) ;
	}

	// HTMLの原page provenanceと使用時の原選択文書/全文を明示別契約で照合します
	if( error == 0U && html) {
		std::wstring extracted ;	// 全原文書/全文照合が終わるまで公開しない値です
		error = verifyStaticHtmlTerms( text, *terms.textDocument->htmlExtraction,
									  record.acquisitionDescriptor->payloadUrl,
									  indexUtf8Text( terms.revision), extracted) ;
		// 部分抽出を正常snapshotへ残しません
		if( error == 0U) {
			text = std::move( extracted) ;
		}
	}

	// 原全文/長さ/hash/表示上限が成立しない対象を同意可能へ変えません
	if( error != 0U ||
	   ((!html || terms.archiveNotice) && digest != hexDigest( terms.textDocument->sha256)) ||
	   (terms.archiveNotice && raw.size() != terms.textDocument->sizeBytes) ||
	   !validPreparationEulaText( text)) {
		return error != 0U ? error : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CRC)) ;
	}

	std::size_t retained{} ;	// 同scanの全文code unit累計です
	// 全既取得本文だけを合計し、plan全文上限を超えません
	for( const auto &value : terms_) {
		retained += value.text.size() ;
	}

	// 大量の別規約をplan上限を越えてRAMへ保持しません
	if( !recheck && text.size() > MAXIMUM_PREPARATION_PLAN_EULA_CHARACTERS - retained) {
		return HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE) ;
	}

	std::wstring revision = indexUtf8Text( terms.revision) ;	// 原公開revisionを文字化けさせません
	// 算出方式だけは既存の全文revision共通処理を使用します
	if( terms.revisionKind == IndexTermsRevisionKind::COMPUTED_UTF8_SHA256) {
		error = makeComputedEulaRevision( text, revision) ;
	}

	// Revision失敗をRAM正常snapshotへ追加しません
	if( error != 0U) {
		return error ;
	}

	const auto completedAt = utc() ;	// 受信・検査後に再確認した信頼UTCです
	// 受信時刻が不明又は送信時刻より前なら規約を公開しません
	if( !completedAt || *completedAt < lastChecked) {
		return HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
	}

	error = validateRecord( relationIndex, current, completedAt, reason, purpose) ;
	// 検証済み本文を別の機種条件や古い観測へ公開しません
	if( error == 0U) {
		error = reobservePlatformMachine( record, current) ;
	}

	// 受信後に元領域や元候補が失効した場合も規約を公開しません
	if( error != 0U) {
		return error ;
	}

	// 再確認で取得した本文を、元承認対象の本文と改訂へ完全一致させます
	if( recheck) {
		return displayed->text == text && displayed->revision == revision
				   ? 0U
				   : static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	terms_.push_back( {recordIndex, std::move( text), std::move( revision)}) ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 承認済み操作で再確認が必要な規約の形式を判定する
 * @param[in] terms 同じ署名記述子の元規約
 * @return ZIP内の明示規約または二段リンク用の場合true
 */
//------------------------------------------------------------------------------
bool SignedIndexAcquisitionAdapter::requiresApprovedTermsRecheck(
	const IndexAcquisitionTerms &terms) noexcept
{
	return terms.archiveNotice ||
		   (terms.textDocument && terms.textDocument->htmlExtraction &&
			terms.textDocument->htmlExtraction->profile == LINKED_STATIC_TERMS_PROFILE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 端末の承認済みtask用に公式導線と元規約を再取得して、同じ操作だけへ照合を結びます
 * @param[in,out] preparation 実active taskの所有者です。承認やclaim自体は変更しません
 * @param[in] task 利用者の同意を消費した元taskです
 * @param[in] current 現スキャンの全contextです
 * @param[in] utc 送信前と受信後に検査する信頼時刻です
 * @param[in,out] client 同一レコードの有限HTTPS取得です
 * @param[in] cancellation 停止又は回線の失効を確認します
 * @return 元承認と再取得した規約の照合成立0、変更や不成立は元HRESULTです
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::recheckApprovedTerms(
	OfficialPreparationSession &preparation, const OfficialPreparationTask &task,
	const IndexLookupContext										current,
	const std::function<std::optional<std::chrono::sys_seconds>()> &utc, OfficialHttpClient &client,
	const HttpCancellationCallback &cancellation)
{
	// 元taskの取得対象が保持中の承認済み結合と一致する位置
	const auto binding = std::ranges::find( bindings_, task.target, &PreparedBinding::target) ;
	// 旧taskや未同意入力から、再取得を開始したり既存証拠を変更したりしません
	if( !preparation.ownsActiveTask( task) || binding == bindings_.end() || binding->claimedTask ||
	   task.operationId == 0U || task.planId == 0U || task.scanSessionId != current.scanSessionId ||
	   task.target.terms != OfficialPreparationTerms::ACCEPTANCE_REQUIRED || !utc) {
		return E_ACCESSDENIED ;
	}

	binding->recheckedTermsOperation = 0U ;
	binding->recheckedTermsPlan		 = 0U ;
	std::string reason ;			// 認証済み原関係の固定診断です
	const auto	initial = utc() ;	// 再取得開始前の信頼時刻です
	const auto	validation =
		// 共有する全関係を先に検査します
		validateBinding( *binding, current, initial, reason) ;
	// 期限切れや矛盾した全関係には規約を取得しません
	if( validation != 0U) {
		return validation ;
	}

	const auto recordIndex =
		// 原規約を保持する位置です
		lookup_->relations()[binding->relationIndex].recordIndex ;
	const auto &record =
		// 同じ元配布レコードです
		lookup_->snapshot().consumerRecords()[recordIndex] ;
	const auto displayed = std::ranges::find(
		terms_, recordIndex, &TermsSnapshot::recordIndex) ;	// 画面に結んだ固定文書です
	// 画面の本文・改訂を別規約の同意へ流用しません
	if( !requiresApprovedTermsRecheck( record.acquisitionDescriptor->terms) ||
	   displayed == terms_.end() || displayed->text != task.target.eulaText ||
	   displayed->revision != task.target.eulaRevision) {
		return E_ACCESSDENIED ;
	}

	auto error =
		// 取得前の対象を再照合します
		reobservePreparedDevice( record, task.target, current) ;
	// 同じ端末・対象のままの場合だけ公式文書を再取得します
	if( error == 0U) {
		error = readTermsTextImpl( binding->relationIndex, current, utc, client, cancellation, true) ;
	}

	// 再取得の失敗をキャッシュ済みの元同意で救済しません
	if( error != 0U) {
		return error ;
	}

	const auto completed = utc() ;	// 受信後に全共有期限を再確認します
	// 時刻又は承認状態が変わった場合は同じ操作の証拠を発行しません
	if( !completed || !initial || *completed < *initial || !preparation.ownsActiveTask( task)) {
		return E_ACCESSDENIED ;
	}

	error = validateBinding( *binding, current, completed, reason) ;
	// 同じ操作と計画にだけ規約照合を結び、別操作では再利用しません
	if( error == 0U) {
		binding->recheckedTermsOperation = task.operationId ;
		binding->recheckedTermsPlan		 = task.planId ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 承認済みのWiX検査taskへ現在の公式ページと元アンカーの照合を結びます
 * @param[in] preparation 実active taskを所有するsessionです
 * @param[in] task 一台だけに結合した検査専用の承認済みtaskです
 * @param[in] current 元スキャンの全contextです
 * @param[in] utc 送信前、送信中、受信後に原期限と時計逆行を検査する信頼時計です
 * @param[in,out] client 同じ元公式ページを有限HTTPSで取得する共通HTTPです
 * @param[in] cancellation 回線、共有待機又は取消しによる停止を確認します
 * @return 同じ公式ページの実アンカーを確認した場合0です。拒否時はHRESULTです
 * @note 原観測ハッシュを変更せず、規約同意や導入許可を発行しません
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::verifyWixInspectionPage(
	OfficialPreparationSession &preparation, const OfficialPreparationTask &task,
	const IndexLookupContext										current,
	const std::function<std::optional<std::chrono::sys_seconds>()> &utc, OfficialHttpClient &client,
	const HttpCancellationCallback &cancellation)
{
	const auto binding = std::ranges::find( bindings_, task.target,
										   &PreparedBinding::target) ;	// 同じ元の取得対象です
	// 実承認のないtask、元対象を改変したtask、処理済みtaskから公式ページに送信しません
	if( !acquisitionOpen_ || !*acquisitionOpen_ || !utc || !preparation.ownsActiveTask( task) ||
	   binding == bindings_.end() || binding->claimedTask || task.operationId == 0U ||
	   task.planId == 0U || task.scanSessionId != current.scanSessionId ||
	   task.target.terms != OfficialPreparationTerms::INSPECTION_ONLY ||
	   (binding->wixPageVerification && binding->wixPageVerification->task == task)) {
		return E_ACCESSDENIED ;
	}

	std::string reason ;			// 私有の元関係検査にだけ使います
	const auto	initial = utc() ;	// 元期限と時計逆行を確認する最初の時点です
	// 不明時刻や失効元関係には公式ページを取得しません
	if( !initial) {
		return HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
	}

	auto error = validateBinding( *binding, current, initial, reason) ;	// 元関係を全件確認します
	// 継続できない元関係から配布元やURLを取り出しません
	if( error != 0U) {
		return error ;
	}

	const auto &snapshot = lookup_->snapshot() ;	// 今回の固定署名索引です
	const auto	recordIndex =
		// 同じ元行です
		lookup_->relations()[binding->relationIndex].recordIndex ;
	const auto	&record = snapshot.consumerRecords()[recordIndex] ;		// 元承認の署名レコードです
	const auto	 region = snapshot.consumerRecordRegion( recordIndex) ;	// 同じ出典を保つ元領域です
	const auto	&proof	= *record.wixContentEvidence ;					// 公式ページの署名済み原証拠です
	const auto	&descriptor = *record.acquisitionDescriptor ;			// 元アンカーと原期限です
	const auto	 source		= std::ranges::find( region.sources, record.sourceId,
												&IndexRecordSource::sourceId) ;	// 同じ元配布元です
	std::wstring sourceHost ;													// 元公式起点のHTTPS hostです
	std::wstring pageHost ;														// 同じ元ページのHTTPS hostです
	// 原shaは観測の由来に保持し、現ページには同じ公式起点と元アンカーの一致を要求します
	if( source == region.sources.end() || source->distributionPage != proof.pageUrl ||
	   source->officialEvidence.evidenceSha256 != proof.pageSha256 ||
	   !exactHttpsHost( source->officialOrigin, sourceHost) ||
	   !exactHttpsHost( proof.pageUrl, pageHost) || pageHost != sourceHost) {
		return E_ACCESSDENIED ;
	}

	const auto expires = std::min(
		{snapshot.schemaReceipt().assetBytes().manifest().data().expiresAtUtc, region.expiresAtUtc,
		 descriptor.attestation->validUntilUtc}) ;	// 元manifest・領域・個別確認の最短期限です
	auto		lastChecked = *initial ;			// 共通HTTPの各境界で保持する直前の信頼時刻です
	NativeError stopped{} ;							// 最初の停止診断をHTTPの取消し値と区別します
	const HttpCancellationCallback checkpoint = [&] {
		// 元停止を保持し、後続チェックで成功へ戻しません
		if( stopped != 0U) {
			return true ;
		}

		const auto now = utc() ;	// 実送信直前と有限受信中にも元期限を確認します
		// 時刻欠落や逆行の後に前回の時刻を使って送信しません
		if( !now || *now < lastChecked || *now >= expires) {
			stopped = HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
			return true ;
		}

		lastChecked = *now ;
		// 状態が変わった場合は同じ公式ページへの送信も停止します
		if( !acquisitionOpen_ || !*acquisitionOpen_ || !lookup_ ||
		   !lookup_->hasLiveNativeOwner( current) || !preparation.ownsActiveTask( task)) {
			stopped = E_ACCESSDENIED ;
			return true ;
		}

		// 回線や共有待機は同じ停止照会に従います
		if( cancellation && cancellation()) {
			stopped = HRESULT_FROM_WIN32( ERROR_CANCELLED) ;
		}

		return stopped != 0U ;
	} ; // HTTP送受信中は同じ承認と原期限を同期借用します

	// 既に停止した承認からホストや端末の再観測を始めません
	if( checkpoint()) {
		return stopped ;
	}

	// 同じスキャンの完全hostを確認します
	error = reobserveHost( current) ;
	// ホストが変わった場合は端末を開かずに停止します
	if( error == 0U) {
		error = reobservePreparedDevice( record, binding->target, current) ;
	}

	// 端末又は同じ元Hardware IDを再確認できない場合は通信しません
	if( error != 0U) {
		return error ;
	}

	const auto	 url = indexUtf8Text( proof.pageUrl) ;	// 元公式ページの完全URLです
	std::wstring page ;									// 一時メモリにだけ保持する公式応答です
	std::wstring finalUrl ;								// 同じ実応答の最終URLです
	CollectorHttpTransferObservation transfer ;			// 実send直前にも同じ停止照会を通します
	error = client.getCollectorInspectionPage( url, pageHost, checkpoint, page, finalUrl, nullptr,
											  &transfer, nullptr, false, false) ;
	// 受信後も原期限と同じ承認を確認し、HTTPによる取消しの内訳を保持します
	if( checkpoint()) {
		return stopped ;
	}

	// 取得できないページの代わりに収集時のリンクを再利用しません
	if( error != 0U) {
		return error ;
	}

	// 現在のHTMLに同じ元アンカーがある場合だけ、以前の観測と別の実確認として扱います
	if( finalUrl != url || !hasStaticHtmlDocumentLink( page, descriptor.payloadUrl)) {
		return E_ACCESSDENIED ;
	}

	// 解析中に期限や承認が失効した場合は、同じtaskにも確認を残しません
	if( checkpoint()) {
		return stopped ;
	}

	// 元関係の最終確認です
	error = validateBinding( *binding, current, lastChecked, reason) ;
	// 同じ元選択に限定して成功を保持し、次の操作へ引き継ぎません
	if( error == 0U) {
		binding->wixPageVerification = WixPageVerification{task, lastChecked} ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元lookupの関係位置から取得対象を再記述します
 * @param[in] relationIndex 元lookup内の0起点位置。公開tupleは受理しません
 * @param[in] current 現worker context
 * @param[in] nowUtc 信頼UTC
 * @param[in] limits 共通preparationの有限予算
 * @param[out] description 全条件成功時だけtarget。失敗時は不足理由を保持します
 * @param[in] firmwareDeviceName 同じ端末のスキャンにある機器名です。機器別の確認を表示するために使います
 * @return 記述成功0、未知・未対応E_NOTIMPL、stale・権限・期限等の拒否HRESULT
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::describe(
	const std::size_t relationIndex, const IndexLookupContext current,
	const std::optional<std::chrono::sys_seconds> nowUtc, const OfficialPreparationLimits &limits,
	SignedIndexPreparationDescription &description, const std::wstring_view firmwareDeviceName)
{
	description = {} ;
	// 導入開始後に取得計画や未使用権限を増やさず、元成功根拠だけを残します
	if( !acquisitionOpen_ || !*acquisitionOpen_) {
		return E_ACCESSDENIED ;
	}

	const NativeError error =
		// 全元binding再確認
		validateRecord( relationIndex, current, nowUtc, description.reason,
					   RecordValidation::PREPARATION) ;
	// 不足理由のあるrecordから取得対象を生成しません
	if( error != 0) {
		return error ;
	}

	const auto existing =
		std::find_if( bindings_.begin(), bindings_.end(), [&]( const auto &binding) {
			return std::ranges::find( binding.relationIndices, relationIndex) !=
				   binding.relationIndices.end() ;
		}) ; // 同原関係が既に含まれる共有取得bindingだけ
	// 別予算や失効したmemberから旧承認targetを再使用しません
	if( existing != bindings_.end()) {
		const auto groupError =
			// 全member再確認
			validateBinding( *existing, current, nowUtc, description.reason,
							RecordValidation::PREPARATION) ;
		// 記述済み共有targetの全条件が不変な場合だけ同じ対象を返します
		if( groupError != 0U || existing->limits != limits) {
			return groupError != 0U ? groupError : static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		description.target = existing->target ;
		return 0U ;
	}

	const auto &snapshot		 = lookup_->snapshot() ;					// 元署名索引です
	const auto	records			 = snapshot.consumerRecords() ;				// 署名索引の連続領域です
	const auto &selectedRelation = lookup_->relations()[relationIndex] ;	// 元端末を結ぶ関係です
	const auto	recordIndex		 = selectedRelation.recordIndex ;			// 元recordの位置です
	const auto &record			 = records[recordIndex] ;					// 元recordを借用します
	const auto	region	   = snapshot.consumerRecordRegion( recordIndex) ;	// 元取得元を持つ領域です
	const auto &descriptor = *record.acquisitionDescriptor ;				// 元静的ZIP条件
	const bool	wix		   = record.wixContentEvidence.has_value() ;		// 規約確認前の配布です
	const std::uint64_t maximum =
		// 同じ外側tupleだけを予約します
		effectiveIndexPayloadMaximum( record, limits) ;
	// 容量不明は有限取得できるが、既知容量超過を架空sizeで補完しません
	if( maximum == 0U ||
	   (record.packageEvidence.size.value && *record.packageEvidence.size.value > maximum) ||
	   limits.maximumProviderFiles == 0U || limits.maximumSessionFiles == 0U) {
		description.reason = "known size exceeds the finite acquisition capacity" ;
		return HRESULT_FROM_WIN32( ERROR_FILE_TOO_LARGE) ;
	}

	OfficialPreparationTarget target ;	// URL非保持の計画snapshot
	target.identity		   = L"index-acquisition-" + std::to_wstring( relationIndex) ;
	target.providerId	   = SIGNED_INDEX_PROVIDER_ID ;
	target.resourceId	   = INDEX_PAYLOAD_RESOURCE ;
	target.releaseIdentity = hexDigest( record.recordSha256) ;
	target.parserRevision  = 1U ;
	target.maximumBytes	   = maximum ;
	target.deviceCount	   = 1U ;
	target.terms		   = wix ? OfficialPreparationTerms::INSPECTION_ONLY
								 : OfficialPreparationTerms::CONFIRMED_NO_CONSENT ;
	const auto source	   = std::ranges::find_if( region.sources, [&record]( const auto &value) {
		 return value.sourceId == record.sourceId ;
	 }) ; // 元公式主体です
	// 規約出典のないrecordから共通Providerだけの同意を作りません
	if( source == region.sources.end()) {
		return E_ACCESSDENIED ;
	}

	target.eulaSourceSubject =
		std::wstring{source->sourceId.begin(), source->sourceId.end()} + L" (" +
		std::wstring{source->officialOrigin.begin(), source->officialOrigin.end()} + L")" ;
	// 原規約全文の実取得が完了した対象だけを同意可能な計画へ渡します
	if( !wix && descriptor.terms.state == IndexTermsState::ACCEPTANCE_REQUIRED) {
		const auto text = std::ranges::find( terms_, recordIndex,
											&TermsSnapshot::recordIndex) ;	// RAMの同原全文です
		// 未取得全文を空の同意不要へ変更しません
		if( text == terms_.end()) {
			description.reason = "exact terms text has not been acquired" ;
			return E_NOTIMPL ;
		}

		target.terms		   = OfficialPreparationTerms::ACCEPTANCE_REQUIRED ;
		target.eulaText		   = text->text ;
		target.eulaRevision	   = text->revision ;
		target.sharedEulaToken = bindings_.size() + 1U ;
		// 同subject/revision/全文だけへ短命tokenを共有し、他出典の同意を流用しません
		for( const auto &binding : bindings_) {
			const auto &otherRecord = records[lookup_->relations()[binding.relationIndex]
												  .recordIndex] ;	// 保存済み別候補です
			// いずれかが承認後の再確認を要求する場合に異なる配布へ同意を共有しない
			const bool	recheckedTerms =
				requiresApprovedTermsRecheck( descriptor.terms) ||
				(otherRecord.acquisitionDescriptor &&
				 requiresApprovedTermsRecheck( otherRecord.acquisitionDescriptor->terms)) ;
			// 出典と全文が完全一致する先行groupだけを再利用します
			if( binding.target.terms == target.terms &&
			   (!recheckedTerms || sameSharedPayloadEvidence( record, otherRecord)) &&
			   binding.target.eulaSourceSubject == target.eulaSourceSubject &&
			   binding.target.eulaRevision == target.eulaRevision &&
			   binding.target.eulaText == target.eulaText) {
				target.sharedEulaToken = binding.target.sharedEulaToken ;
				break ;
			}
		}
	}

	// 全具体的user条件をEULAとは独立した完全targetへ結びます
	for( const auto &condition : descriptor.prerequisites.items) {
		// 機械確認済みOS条件を利用者への包括確認へ変換しません
		if( condition.kind == IndexPrerequisiteKind::USER_CONFIRMATION) {
			target.requiresPrerequisiteConfirmation = true ;
			target.prerequisiteText += indexUtf8Text( condition.description) + L"\r\n" ;
		}
	}

	// 公式のファームウェア条件は元端末を選んだ本人が個別に確認します
	if( !record.platformFirmwareGroups.empty()) {
		target.firmwareCondition = firmwarePreparationCondition( record, selectedRelation) ;
		// 未確認の群や表示用の機器名が欠けた計画を承認対象にしません
		if( !target.firmwareCondition || firmwareDeviceName.empty()) {
			description.reason = "PLATFORM_FIRMWARE_CONFIRMATION_UNAVAILABLE" ;
			return E_NOTIMPL ;
		}

		std::wstring label{firmwareDeviceName.substr( 0U, 512U)} ;	// 確認画面の機器名一行です
		std::ranges::replace_if(
			label, []( const wchar_t character) { return character < L' ' || character == L'\x7f' ; },
			L' ') ;
		target.requiresPrerequisiteConfirmation = true ;
		target.prerequisiteText += L"対象デバイス " + label +
								   L"\r\n必要なファームウェアバージョン " +
								   target.firmwareCondition->versionLabel + L"\r\n" ;
	}

	std::vector<std::size_t>  members{relationIndex} ;	// 原lookupの既存有限枠内で全関係を保持します
	std::vector<std::wstring> devices{
		*selectedRelation.deviceIdentity} ;	// 最大32のunique deviceです
	// 同deviceの別recordも元位置で保持し、完全内容と全policyを個別に照合します
	for( std::size_t index = 0U;
		index < lookup_->relations().size() && members.size() < index_capacity::RETAINED_RELATIONS;
		++index) {
		const auto &relation = lookup_->relations()[index] ;	// 外部DTOではない元私有relation
		// 元領域外の位置を共有計画へ渡しません
		if( index == relationIndex || relation.recordIndex >= records.size()) {
			continue ;
		}

		const auto &other = records[relation.recordIndex] ;	// 同snapshotの原recordです
		// WiXの承認は別の元行や端末、従来方式と共有しません
		if( (wix || other.wixContentEvidence) &&
		   (relation.recordIndex != recordIndex ||
			relation.deviceIdentity != selectedRelation.deviceIdentity)) {
			continue ;
		}

		// 一台の機器確認から別端末の取得・検査済み候補を作らず、同じ元行と端末へ結びます
		if( (target.requiresPrerequisiteConfirmation || !other.platformFirmwareGroups.empty()) &&
		   (relation.recordIndex != recordIndex ||
			relation.deviceIdentity != selectedRelation.deviceIdentity)) {
			continue ;
		}

		std::string rejectedReason ;	// 保留理由を共有合格へ変換しません
		// 既記述関係と未検証関係を共有targetへ加えません
		if( validateRecord( index, current, nowUtc, rejectedReason, RecordValidation::PREPARATION) !=
			   0U ||
		   std::ranges::any_of( bindings_, [&]( const auto &binding) {
			   return std::ranges::find( binding.relationIndices, index) !=
					  binding.relationIndices.end() ;
		   })) {
			continue ;
		}

		const bool newDevice = std::ranges::find( devices, *relation.deviceIdentity) ==
							   // 重複数ではありません
							   devices.end() ;
		// 32device上限へ達しても、既存deviceの別原recordは保持できます
		if( newDevice && devices.size() >= 32U) {
			continue ;
		}

		// 同じ元領域と同じ配布物を持つ候補だけを一つの承認に束ねます
		if( snapshot.consumerRecordRegion( relation.recordIndex).indexSha256 == region.indexSha256 &&
		   matchesSharedIndexPayloadEvidence( record, other)) {
			members.push_back( index) ;
			// unique deviceだけをUIの作用対象件数へ計上します
			if( newDevice) {
				devices.push_back( *relation.deviceIdentity) ;
			}
		}
	}

	target.deviceCount = static_cast<std::uint32_t>( devices.size()) ;
	// 一issuerの有限記述枠をscan対象全体の上限へ拡大しません
	if( bindings_.size() >= 256U) {
		description.reason = "finite preparation binding capacity exceeded" ;
		return HRESULT_FROM_WIN32( ERROR_BUFFER_OVERFLOW) ;
	}

	bindings_.push_back( {relationIndex, target, limits, std::nullopt, 0U, std::move( members)}) ;

	description.target = std::move( target) ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 私有共有bindingの全原recordと期限を再確認します
 * @param[in] binding 同issuerが記述した未変更の取得binding
 * @param[in] current 元scan context
 * @param[in] nowUtc 信頼UTC
 * @param[out] reason 最初の拒否理由
 * @param[in] purpose 条件表示又は取得権限を検査する用途です
 * @return 全原関係成立0、それ以外は元HRESULTです
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::validateBinding(
	const PreparedBinding &binding, const IndexLookupContext current,
	const std::optional<std::chrono::sys_seconds> nowUtc, std::string &reason,
	const RecordValidation purpose) const
{
	// 関係数とdevice数を混同せず、既存lookup枠と32device枠を独立に検査します
	if( !lookup_ || binding.relationIndices.empty() ||
	   lookup_->relations().size() > index_capacity::RETAINED_RELATIONS ||
	   binding.relationIndices.size() > index_capacity::RETAINED_RELATIONS ||
	   binding.relationIndices.front() != binding.relationIndex ||
	   binding.target.deviceCount == 0U || binding.target.deviceCount > 32U) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	const auto firstError = validateRecord( binding.relationIndex, current, nowUtc, reason,
										   purpose) ;	// 位置を使用する前の独立検証
	// 代表の位置や原tupleが不正なら、他関係で補完しません
	if( firstError != 0U) {
		return firstError ;
	}

	const auto &snapshot = lookup_->snapshot() ;		// 同原snapshotです
	const auto	records	 = snapshot.consumerRecords() ;	// 元recordの連続位置です
	const auto &representativeRelation =
		// 同じ代表原関係です
		lookup_->relations()[binding.relationIndex] ;
	const auto	recordIndex	   = representativeRelation.recordIndex ;				// 検証済み代表の位置です
	const auto &representative = records[recordIndex] ;								// 検証済み代表原recordです
	const auto	region		   = snapshot.consumerRecordRegion( recordIndex) ;		// 代表の元領域です
	const auto &condition	   = binding.target.firmwareCondition ;					// 元端末と必須版の確認条件です
	const bool	wix			   = representative.wixContentEvidence.has_value() ;	// 同じv8元行です
	// 検査専用の作用範囲と元規約の状態を通常の同意や確認条件へ読み替えません
	if( wix != (binding.target.terms == OfficialPreparationTerms::INSPECTION_ONLY) ||
	   (wix &&
		(binding.target.deviceCount != 1U || binding.target.requiresPrerequisiteConfirmation ||
		 !binding.target.prerequisiteText.empty() || condition ||
		 !binding.target.eulaText.empty() || !binding.target.eulaRevision.empty() ||
		 binding.target.sharedEulaToken != 0U ||
		 binding.target.releaseIdentity != hexDigest( representative.recordSha256)))) {
		reason = "WIX_INSPECTION_ONLY_BINDING_MISMATCH" ;
		return E_ACCESSDENIED ;
	}

	// 元行のハッシュと一台分の条件を同じ計画に保持します
	if( condition.has_value() != !representative.platformFirmwareGroups.empty() ||
	   (condition &&
		(binding.target.deviceCount != 1U || !binding.target.requiresPrerequisiteConfirmation ||
		 binding.target.releaseIdentity != hexDigest( representative.recordSha256)))) {
		reason = "platform firmware preparation binding mismatch" ;
		return E_ACCESSDENIED ;
	}

	// 旧上限targetや別tupleを小さいexact予約の承認へ読み替えません
	if( binding.target.maximumBytes == 0U ||
	   binding.target.maximumBytes !=
		   effectiveIndexPayloadMaximum( representative, binding.limits)) {
		reason = "signed outer payload transfer limit mismatch" ;
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	std::vector<bool> seen( lookup_->relations().size(), false) ;	// 原lookup枠を超えない重複検査
	std::vector<std::wstring> devices ;								// Unique deviceを別に再計数します
	// 各原関係を元context/hash/期限へ再照合し、代表recordだけで権限を省略しません
	for( const auto index : binding.relationIndices) {
		// 同じ元位置の二重権限や範囲外位置を拒否します
		if( index >= seen.size() || seen[index]) {
			reason = "duplicate or unavailable original relation" ;
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		seen[index] = true ;
		const auto error =
			// 元recordの独立検証
			validateRecord( index, current, nowUtc, reason, purpose) ;
		// 最初の個別拒否は共有成功へ上書きしません
		if( error != 0U) {
			return error ;
		}

		const auto &relation = lookup_->relations()[index] ;	// 元record/source/hash再照合済みです
		const auto &original = records[relation.recordIndex] ;	// 同じ入力領域内の承認関係です
		// WiXは全関係が同一端末と同じ元レコードを指す場合だけ一つの承認に結合します
		if( (wix || original.wixContentEvidence) &&
		   (relation.recordIndex != recordIndex ||
			relation.deviceIdentity != representativeRelation.deviceIdentity)) {
			reason = "WIX_INSPECTION_ONLY_MEMBER_MISMATCH" ;
			return E_ACCESSDENIED ;
		}

		// 同一配布でも別端末、別の元行、別群へ本人確認を広げません
		if( condition.has_value() != !original.platformFirmwareGroups.empty() ||
		   (condition && (relation.recordIndex != recordIndex ||
						  firmwarePreparationCondition( original, relation) != condition))) {
			reason = "platform firmware preparation member mismatch" ;
			return E_ACCESSDENIED ;
		}

		// 一部のpolicy一致から全groupの取得権限を生成しません
		if( index != binding.relationIndex &&
		   (snapshot.consumerRecordRegion( relation.recordIndex).indexSha256 != region.indexSha256 ||
			!matchesSharedIndexPayloadEvidence( representative, original))) {
			reason = "shared payload evidence or policy mismatch" ;
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		// 同deviceの複数INF/版を複数deviceへ数えません
		if( std::ranges::find( devices, *relation.deviceIdentity) == devices.end()) {
			devices.push_back( *relation.deviceIdentity) ;
		}

		// Claim時にも作用device数を増やす改変を拒否します
		if( devices.size() > 32U) {
			return static_cast<NativeError>( E_ACCESSDENIED) ;
		}
	}

	// Targetの公開件数も全原関係から再計数した値へ完全一致させます
	if( devices.size() != binding.target.deviceCount) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実claim済みtaskから同じRecordScopedDownloadGrantを一回発行します
 * @param[in] preparation 実active taskを所有する同worker session
 * @param[in] task 利用者承認後の未変更task
 * @param[in] current 現worker context
 * @param[in] nowUtcSeconds 発行直前の信頼UTC秒
 * @param[out] grant 未発行object。成功時だけ同じgrant状態機械へ進めます
 * @return 全再照合成功0、改変・再使用・失効・期限は拒否HRESULT
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::claimApprovedRecord(
	OfficialPreparationSession &preparation, const OfficialPreparationTask &task,
	const IndexLookupContext current, const std::uint64_t nowUtcSeconds,
	RecordScopedDownloadGrant &grant)
{
	return grant.issueSignedIndex( *this, preparation, task, current, nowUtcSeconds) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 非公開adapterが実taskとsnapshotを再確認して同じgrantを発行します
 * @param[in,out] adapter 失効可能な元issuer
 * @param[in] preparation 実claimを保持するsession
 * @param[in] task 同じ未完了task
 * @param[in] current 現worker context
 * @param[in] nowUtcSeconds 発行UTC秒
 * @return 全sealed bindingの成立時0。未発行の入力だけを受理します
 */
//------------------------------------------------------------------------------
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
					 }) ; // 私有記述へ完全一致
	// Tokenだけの自己申告、再発行、stale、別sessionやgrant再使用を拒否します
	if( !adapter.acquisitionOpen_ || !*adapter.acquisitionOpen_ ||
	   metadata_.state != OfficialDownloadGrantState::NOT_REQUESTED ||
	   !preparation.ownsActiveTask( task) || binding == adapter.bindings_.end() ||
	   binding->claimedTask || task.scanSessionId != current.scanSessionId ||
	   adapter.nextGrantId_ == 0U) {
		return E_ACCESSDENIED ;
	}

	std::string reason ;										// 再確認不能の理由をworker内だけに保持します
	const auto	issuedAt	= utcFromSeconds( nowUtcSeconds) ;	// 当該grant発行を確認する信頼UTCです
	const NativeError error = adapter.validateBinding( *binding, current, issuedAt,
													  reason) ;	// 共有する全原recordの最終再照合
	// 不足・個別失効からgrantを発行しません
	if( error != 0) {
		return error ;
	}

	// WiXの本体取得は、同じ実taskで現公式ページを照合した場合だけ発行します
	if( binding->target.terms == OfficialPreparationTerms::INSPECTION_ONLY) {
		const auto &page = binding->wixPageVerification ;	// 他taskへ引き継げない確認です
		// 同じ元計画の全fieldが一致し、照合後に時計が逆行していないことを求めます
		if( !page || page->task != task) {
			return E_ACCESSDENIED ;
		}

		// 公式ページを照合した未来時刻から本体への許可を作りません
		if( !issuedAt || *issuedAt < page->verifiedAtUtc) {
			return HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
		}
	}

	const auto hostError = adapter.reobserveHost( current) ;	// 全bindingの成立後、grant公開前です
	// Host拒否時はtask/grantを成功へ消費しません
	if( hostError != 0) {
		return hostError ;
	}

	const auto &lookup = *adapter.lookup_ ;	// 不変の元関係と保存snapshot
	const auto &record =
		lookup.snapshot()
			.consumerRecords()[lookup.relations()[binding->relationIndex].recordIndex] ;	// 元record
	const auto deviceError =
		// 共有検査後の現在の機種と対象端末の群です
		adapter.reobservePreparedDevice( record, binding->target, current) ;
	// 端末条件の拒否は当該承認だけに適用し、取得許可を発行しません
	if( deviceError != 0U) {
		return deviceError ;
	}

	const auto &descriptor = *record.acquisitionDescriptor ;	// 型認証済みexact route
	// 本体の許可を発行するのは、同じ承認済み操作で規約を再取得して照合した場合だけです
	if( SignedIndexAcquisitionAdapter::requiresApprovedTermsRecheck( descriptor.terms) &&
	   (binding->recheckedTermsOperation != task.operationId ||
		binding->recheckedTermsPlan != task.planId || binding->recheckedTermsOperation == 0U)) {
		return E_ACCESSDENIED ;
	}

	// 15分を加算できないUTCを丸めません
	if( nowUtcSeconds > std::numeric_limits<std::uint64_t>::max() - 900U) {
		return E_INVALIDARG ;
	}

	auto	   expires = nowUtcSeconds + 900U ;					// 通常取得許可の最長時間です
	const auto records = lookup.snapshot().consumerRecords() ;	// 全検証済みのrecordを借用します
	// 選択した全候補の、個別証拠と所属領域のどちらの期限も超えません
	for( const auto relationIndex : binding->relationIndices) {
		const auto recordIndex =
			// 選択候補の元位置です
			lookup.relations()[relationIndex].recordIndex ;
		const auto region =
			// 同候補の所属領域です
			lookup.snapshot().consumerRecordRegion( recordIndex) ;
		const auto evidenceExpiry =
			records[recordIndex]
				.acquisitionDescriptor->attestation->validUntilUtc ;		// 元個別期限です
		const auto limit = std::min( region.expiresAtUtc, evidenceExpiry) ;	// 同候補の最短期限です
		expires = std::min( expires, static_cast<std::uint64_t>( limit.time_since_epoch().count())) ;
	}

	// 開始余裕30秒を持たない取得は発行前に拒否します
	if( expires <= nowUtcSeconds || expires - nowUtcSeconds < 30U) {
		return HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
	}

	RecordScopedDownloadGrant pending ;	// 全copy成功後だけ公開する同じgrant型
	pending.metadata_.origin = OfficialDownloadGrantOrigin::SIGNED_INDEX_COLLECTOR_ATTESTATION ;
	pending.signedIndexResolverPending_ = descriptor.anonymousCdn.has_value() ;
	pending.metadata_.scanSessionId		= task.scanSessionId ;
	pending.metadata_.grantId			= adapter.nextGrantId_ ;
	pending.metadata_.recordEvidenceId	= binding->relationIndex + 1U ;
	pending.metadata_.providerId		= SIGNED_INDEX_PROVIDER_ID ;
	pending.metadata_.policyId			= L"signed-index-attestation-v1" ;
	pending.metadata_.rootResourceId	= L"authenticated-index-record" ;
	// 原32byteを既存record fingerprint容器へ表現し、live fingerprintの由来を合成しません
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
	// メーカー公表hashだけを公開hashへ渡し、監視PC計算hashは後段の独立照合へ残します
	if( record.packageEvidence.publishedHash.sha256) {
		pending.publishedSha256_ = hexDigest( *record.packageEvidence.publishedHash.sha256) ;
	}

	// 期待publisherは元申告だけを保持し、索引発行者を代入しません
	if( descriptor.publisher.value) {
		pending.publisher_ = indexUtf8Text( *descriptor.publisher.value) ;
	}

	pending.targetUrl_ =
		SecretOfficialUrl{std::wstring{descriptor.payloadUrl.begin(), descriptor.payloadUrl.end()}} ;
	const auto region = lookup.snapshot().consumerRecordRegion(
		// この配布と同じ署名領域
		lookup.relations()[binding->relationIndex].recordIndex) ;
	const auto source = std::ranges::find( region.sources, record.sourceId,
										  &IndexRecordSource::sourceId) ;	// 同じ元の公開起点
	// 元の公式ページ証拠を持つ直接AMD配布だけへ参照元を結合します
	if( source != region.sources.end() &&
	   source->officialEvidence.state == IndexEvidenceState::PUBLISHED &&
	   source->officialEvidence.kind == IndexOfficialEvidenceKind::OFFICIAL_PAGE &&
	   source->officialEvidence.evidenceSha256 &&
	   source->officialEvidence.evidenceUrl == source->distributionPage &&
	   (source->officialOrigin == "https://www.amd.com" ||
		source->officialOrigin == "https://www.amd.com/")) {
		auto page = indexUtf8Text( source->distributionPage) ;	// 公開された元製品ページ
		// 参照元が必要な配布を、別経路や利用条件の確認なしに取得させません
		if( isAmdProductDownloadRoute( page, pending.targetUrl_.view())) {
			// 順序を持つ転送や同意のない収集設定を直接配布へ読み替えません
			if( descriptor.route.size() != 1U || descriptor.anonymousCdn ||
			   record.wixContentEvidence ||
			   descriptor.terms.state != IndexTermsState::ACCEPTANCE_REQUIRED ||
			   !descriptor.terms.textDocument) {
				return E_ACCESSDENIED ;
			}

			pending.signedAmdProductPage_ = std::move( page) ;
		}
	}

	// Codecで公式導線・一方向CDN・有限回数を検査済みのexact順を全hop封印します
	for( const auto &hop : descriptor.route) {
		pending.signedIndexRoute_.emplace_back( std::wstring{hop.url.begin(), hop.url.end()}) ;
	}

	// WiXの指定先は同じ署名済みレコードの元証拠からだけ追加します
	if( record.wixContentEvidence) {
		const auto &destination = record.wixContentEvidence->downloadUrl ;	// 元301の指定先です
		pending.signedIndexRoute_.emplace_back(
			std::wstring{destination.begin(), destination.end()}) ;
	}

	pending.signedIndexIssuer_			= adapter.issuer_ ;
	pending.signedIndexAcquisitionOpen_ = adapter.acquisitionOpen_ ;
	pending.signedIndexLookup_			= adapter.lookup_ ;
	pending.signedIndexRelationIndex_	= binding->relationIndex ;
	binding->claimedTask				= task ;
	// 全所有値の準備後に実preparation自身で一回発行を確定します
	if( !preparation.claimIndexAcquisition( task)) {
		binding->claimedTask.reset() ;
		return E_ACCESSDENIED ;
	}

	binding->grantId = adapter.nextGrantId_ ;
	*this			 = std::move( pending) ;
	++adapter.nextGrantId_ ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名索引grantを発行した同scanのlookupと元native列挙を照合します
 * @param[in] scanSessionId 現取得sessionです
 * @return 元issuer・同scan・元列挙の生存が成立した場合0です。失効時はE_ACCESSDENIEDです
 */
//------------------------------------------------------------------------------
NativeError RecordScopedDownloadGrant::validateSignedIndexAuthority(
	const ScanSessionId scanSessionId) const noexcept
{
	// 弱issuerと非公開lookupの同一関係が残る場合だけ索引分岐を許可します
	if( metadata_.origin != OfficialDownloadGrantOrigin::SIGNED_INDEX_COLLECTOR_ATTESTATION ||
	   signedIndexIssuer_.expired() || !signedIndexLookup_ ||
	   signedIndexRelationIndex_ >= signedIndexLookup_->relations().size()) {
		return E_ACCESSDENIED ;
	}

	const auto acquisitionOpen = signedIndexAcquisitionOpen_.lock() ;	// 元workerの閉鎖状態
	// 閉鎖後の新claim・各HTTP hopを拒否し、既消費成功根拠の読取りだけを許します
	if( !acquisitionOpen ||
	   (!*acquisitionOpen &&
		(metadata_.state != OfficialDownloadGrantState::CONSUMED ||
		 metadata_.outcome != OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION))) {
		return E_ACCESSDENIED ;
	}

	const auto &relation =
		// 不変の封印関係
		signedIndexLookup_->relations()[signedIndexRelationIndex_] ;
	return metadata_.scanSessionId == scanSessionId &&
				   relation.context.scanSessionId == scanSessionId &&
				   signedIndexLookup_->hasLiveNativeOwner( relation.context)
			   ? 0
			   : E_ACCESSDENIED ;
}

//------------------------------------------------------------------------------
/**
 * @brief 封印した署名索引routeのexact URL順を再照合します
 * @param[in] exactTarget 現HTTP hopのURL。本呼出し中だけ借用します
 * @param[in] hop 0起点のhop位置
 * @param[in] finalResponse HTTP 200に達した場合だけtrue
 * @return 生存権限・URL完全一致・終端位置が成立した場合0
 */
//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/**
 * @brief 同じ署名索引のWiX配布に封印された一回限りの301転送先を借用します
 * @return WiX以外はnullopt、封印が不成立なら空のview、成立時は同じ許可が所有する指定先です
 * @note 同じ要求の同期処理中だけ借用できます。応答のLocationや利用者入力から補完しません
 */
//------------------------------------------------------------------------------
std::optional<std::wstring_view> RecordScopedDownloadGrant::signedWixRedirectDestination()
	const noexcept
{
	// 実運用の署名索引以外にWiX専用の規則を適用しません
	if( !signedIndexLookup_ ||
	   metadata_.origin != OfficialDownloadGrantOrigin::SIGNED_INDEX_COLLECTOR_ATTESTATION) {
		return std::nullopt ;
	}

	// 元索引位置が不正な場合は転送規則の欠落として送信前に拒否します
	if( signedIndexRelationIndex_ >= signedIndexLookup_->relations().size()) {
		return std::wstring_view{} ;
	}

	const auto &relation =
		// 元の照合関係です
		signedIndexLookup_->relations()[signedIndexRelationIndex_] ;
	const auto records =
		// 同じ署名索引の元レコードです
		signedIndexLookup_->snapshot().consumerRecords() ;
	// 不明なレコードを従来の転送へ差し替えません
	if( relation.recordIndex >= records.size()) {
		return std::wstring_view{} ;
	}

	// 従来の索引レコードには既存の厳密経路を使います
	if( !records[relation.recordIndex].wixContentEvidence) {
		return std::nullopt ;
	}

	// 取得中の同じ元アンカーと一つの指定先が封印されている場合だけ借用します
	if( metadata_.state != OfficialDownloadGrantState::ACQUIRING || signedIndexResolverPending_ ||
	   signedIndexRoute_.size() != 2U ||
	   validateSignedIndexAuthority( metadata_.scanSessionId) != 0) {
		return std::wstring_view{} ;
	}

	return signedIndexRoute_.back().view() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元lookupの公開resolver文脈だけを同期借用する
 * @return 生存する同recordの未解決plan。それ以外はnull
 */
//------------------------------------------------------------------------------
const OfficialAnonymousCdnPlan *RecordScopedDownloadGrant::anonymousCdnPlan() const noexcept
{
	// 元lookup/issuer/同用途がなければresolverを起動しない
	if( !signedIndexResolverPending_ || validateSignedIndexAuthority( metadata_.scanSessionId) != 0 ||
	   (metadata_.state != OfficialDownloadGrantState::GRANT_ISSUED &&
		metadata_.state != OfficialDownloadGrantState::ACQUIRING) ||
	   kind_ != OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE) {
		return nullptr ;
	}

	const auto &record =
		signedIndexLookup_->snapshot()
			.consumerRecords()[signedIndexLookup_->relations()[signedIndexRelationIndex_]
								   .recordIndex] ;	// 私有元record
	return record.acquisitionDescriptor && record.acquisitionDescriptor->anonymousCdn
			   ? &*record.acquisitionDescriptor->anonymousCdn
			   : nullptr ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同recordで未解決の匿名CDN protocolがあるか返す
 * @return 元issuerが生存し未解決の同用途ならtrue
 */
//------------------------------------------------------------------------------
bool RecordScopedDownloadGrant::requiresAnonymousCdnResolution() const noexcept
{
	return anonymousCdnPlan() != nullptr ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同recordの公開起点とresponseだけからexact解決routeを封印する
 * @param[in] canonical 元requestが単独所有する公開起点
 * @param[in] resolved 新responseの秘密完全URL
 * @param[in] expires 実responseのUTC Unix秒
 * @param[in] now 送信直前の同worker UTC秒
 * @return 全結合成功0、元HRESULT。失敗時は旧routeを維持する
 */
//------------------------------------------------------------------------------
NativeError RecordScopedDownloadGrant::sealAnonymousCdnResolution( const std::wstring_view canonical,
																  const SecretOfficialUrl &resolved,
																  const std::uint64_t	   expires,
																  const std::uint64_t	   now)
{
	const auto *plan = anonymousCdnPlan() ;	// 元署名recordだけの公開文脈
	// 同じclaim中の元canonical/path/modelと新response以外を封印しない
	if( !plan || metadata_.state != OfficialDownloadGrantState::ACQUIRING ||
	   canonical != asusAnonymousCdnCanonicalUrl( *plan) ||
	   !matchesAsusAnonymousCdnTarget( *plan, resolved.view(), expires)) {
		return E_ACCESSDENIED ;
	}

	const auto deadline = validateRequestStartDeadline( now) ;	// 元grantの時計/期限
	// 期限切れを新responseの未来値で救済しない
	if( deadline != 0) {
		return deadline ;
	}

	const auto effective =
		// 元権限と実外部期限の最小値
		std::min( expires, metadata_.expiresUtcSeconds) ;
	// 30秒の開始余裕は元期限にも外部期限にも要求する
	if( effective <= now || effective - now < 30U) {
		return HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
	}

	std::vector<SecretOfficialUrl> route ;	// 全準備後だけ旧public routeから切り替える
	route.emplace_back( std::wstring( resolved.view())) ;
	signedIndexRoute_				= std::move( route) ;
	metadata_.expiresUtcSeconds		= effective ;
	metadata_.externalExpiryPresent = true ;
	signedIndexResolverPending_		= false ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 共通取得sealを元recordと独立照合し、共通内容検査入力を生成します
 * @param[in] task 発行済みgrantと同じ実task
 * @param[in] current 現worker context
 * @param[in] nowUtcSeconds 封印入力確認直前の信頼UTC秒
 * @param[in] session 元取得sealのissuer
 * @param[in] workspace 元保護fileを所有する領域
 * @param[in] evidence 公開結果から構築できない元取得seal
 * @param[out] hint 全成功時だけ元index／record／実archiveの期待値
 * @param[out] input 全成功時だけ既存DriverArchiveInput。失敗時は空
 * @return 全実byteとrecord結合成功0、元HRESULTまたは拒否HRESULT
 * @note 内容署名・Windows適合・導入は別の共通検査で行います
 * WiXの場合は元バイトとハッシュの結合だけを返し、従来形式のINF指定は生成しません
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::bindInspectionInput(
	const OfficialPreparationTask &task, const IndexLookupContext current,
	const std::uint64_t nowUtcSeconds, const OfficialAcquisitionSession &session,
	const OfficialDownloadWorkspace &workspace, const OfficialAcquiredFileEvidence &evidence,
	IndexedDriverArchiveHint &hint, DriverArchiveInput &input) const
{
	return bindInspectionInputImpl( task, current, nowUtcSeconds, session, workspace, evidence, hint,
								   input, true) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元レコードと保護された取得ファイルを共通検査入力へ結びます
 * @param[in] task 同issuerの元taskです
 * @param[in] current 元スキャンのcontextです
 * @param[in] nowUtcSeconds 元期限を検証する信頼UTC秒です
 * @param[in] session 元封印のissuerです
 * @param[in] workspace 封印したファイルを保持する領域です
 * @param[in] evidence 元取得の封印です
 * @param[out] hint 元領域とレコード、配布物、INFの照合値です
 * @param[out] input 検査に使う同保護ファイルの情報です
 * @param[in] observeHost 全体照合に先行してホスト観測を行う場合trueです
 * @return 同じ所有・元期限・バイトが有効な場合0、元拒否はHRESULTです
 * @note WiXは元の公式ページ照合を要求し、observeHostがtrueの場合に元ホストと端末を再観測します
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::bindInspectionInputImpl(
	const OfficialPreparationTask &task, const IndexLookupContext current,
	const std::uint64_t nowUtcSeconds, const OfficialAcquisitionSession &session,
	const OfficialDownloadWorkspace &workspace, const OfficialAcquiredFileEvidence &evidence,
	IndexedDriverArchiveHint &hint, DriverArchiveInput &input, const bool observeHost) const
{
	hint  = {} ;
	input = {} ;
	const auto binding =
		std::find_if( bindings_.begin(), bindings_.end(), [&task]( const PreparedBinding &entry) {
			return entry.claimedTask && *entry.claimedTask == task ;
		}) ; // 実claim元token
	// 別taskから元取得sealを再bindしません
	if( binding == bindings_.end()) {
		return E_ACCESSDENIED ;
	}

	const auto		  now = utcFromSeconds( nowUtcSeconds) ;	// 同じ検査入力の確認時刻です
	std::string		  reason ;									// 同recordの期限・元binding不足理由
	const NativeError recordError = validateBinding( *binding, current, now,
													reason) ;	// seal後も全原recordと個別期限を再確認
	// 失効原recordや元file再検証失敗を公開成功結果で補完しません
	if( recordError != 0) {
		return recordError ;
	}

	const NativeError sealError =
		// 同issuer・保護fileと原byteの共通検証
		session.verifyAcquiredFile( evidence, workspace) ;
	// 公開DTOや実byte改変から内容入力を生成しません
	if( sealError != 0) {
		return sealError ;
	}

	const auto &snapshot = lookup_->snapshot() ;		// 元index／recordの不変hashです
	const auto	records	 = snapshot.consumerRecords() ;	// 元recordの連続位置です
	const auto	recordIndex =
		// 取得の元位置です
		lookup_->relations()[binding->relationIndex].recordIndex ;
	const auto &record	 = records[recordIndex] ;							// 取得の代表元recordです
	const auto	region	 = snapshot.consumerRecordRegion( recordIndex) ;	// 取得の元領域です
	const auto &observed = evidence.observation() ;							// 私有issuerが発行した実取得結果
	// Grantの由来・opaque record・実hashとsizeを別々に照合します
	if( evidence.signedIndexIssuer_.lock() != issuer_ ||
	   observed.downloadGrantId != binding->grantId ||
	   observed.recordOrigin != OfficialDownloadGrantOrigin::SIGNED_INDEX_COLLECTOR_ATTESTATION ||
	   observed.scanSessionId != task.scanSessionId ||
	   observed.providerId != SIGNED_INDEX_PROVIDER_ID ||
	   observed.resourceId != INDEX_PAYLOAD_RESOURCE || !observed.delegatedRecord ||
	   observed.recordEvidenceId != binding->relationIndex + 1U ||
	   hexDigest( record.recordSha256) != hexDigest( [&evidence]() {
		   IndexManifestSha256 value{} ;	// 既存fingerprint容器の原byte表現
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

	// WiXの保護取得物は同じtaskの元アンカー、原サイズ・ハッシュ及び現在の端末へ結びます
	if( record.wixContentEvidence) {
		// 元ページを確認していないtaskへ流用しません
		if( !now || !binding->wixPageVerification || binding->wixPageVerification->task != task ||
		   !record.packageEvidence.size.value || !record.packageEvidence.calculatedHash.sha256 ||
		   binding->wixPageVerification->verifiedAtUtc > *now) {
			return E_ACCESSDENIED ;
		}

		// 全選択を構造照合する場合は別工程で元端末の観測を行います
		if( observeHost) {
			auto error = reobserveHost( current) ;	// 元の完全ホストに結合します
			// 同じホストの完全Hardware IDだけを現在の属性から再確認します
			if( error == 0U) {
				error = reobservePreparedDevice( record, binding->target, current) ;
			}

			// 変化や観測不能の場合は保護領域のファイルを渡しません
			if( error != 0U) {
				return error ;
			}
		}

		hint  = {hexDigest( region.indexSha256), hexDigest( record.recordSha256), observed.sha256,
				 observed.byteCount} ;
		input = {observed.scanSessionId,
				 observed.inspectionPath,
				 observed.byteCount,
				 observed.sha256,
				 {},
				 workspace.protectionMode()} ;
		return 0U ;
	}

	// Serverも元binding成立後の標準INF入力だけを渡し、適合/候補権限は発行しません
	if( record.targetOs.value == IndexTargetOs::WINDOWS_SERVER &&
	   record.acquisition.value != IndexAcquisitionKind::STANDARD_INF_ARCHIVE) {
		return E_NOTIMPL ;
	}

	// 最低build又は専用Modelsは全record/owner/実seal/原byteの成立後にも原hostを再観測します
	if( observeHost && (record.recordSchemaVersion == 6U || hasClientMinimumBuildMarker( record))) {
		const auto hostError = reobserveHost( current) ;	// 純粋検証で不正scopeは先に拒否済みです
		// 同contextの変化/失敗からhint/inputを発行しません
		if( hostError != 0U) {
			return hostError ;
		}
	}

	hint = {hexDigest( region.indexSha256), hexDigest( record.recordSha256), observed.sha256,
			observed.byteCount} ;
	// 認証済み元recordの閉じたcontent計画だけを渡します
	if( record.acquisitionDescriptor->resourceContent) {
		hint.resourceContent = std::make_shared<const OfficialResourceContentPlan>(
			*record.acquisitionDescriptor->resourceContent) ;
	}

	// 元の共有選択集合だけから一意INFを固定し、別の内包INFへ対象を広げません
	for( const auto relationIndex : binding->relationIndices) {
		const auto &selectedRecord =
			// 元認証recordです
			records[lookup_->relations()[relationIndex].recordIndex] ;
		const auto &identity = selectedRecord.publishedIdentityEvidence ;	// 同recordの元selectorです
		// 標準INFで公開selectorを持つrecordだけを通常内容検査へ結合します
		if( selectedRecord.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE &&
		   identity.state == IndexEvidenceState::PUBLISHED &&
		   identity.kind == IndexIdentityEvidenceKind::INF) {
			IndexedDriverInfSelector selector{indexUtf8Text( identity.nestedArchiveIdentity),
											  // 原Unicode値です
											  indexUtf8Text( identity.infIdentity)} ;
			std::ranges::replace( selector.nestedArchive, L'/', L'\\') ;
			std::ranges::replace( selector.infIdentity, L'/', L'\\') ;
			// 元同一memberをdevice数やModels節数で重複検査しません
			if( std::ranges::find( hint.selectedInfs, selector) == hint.selectedInfs.end()) {
				hint.selectedInfs.push_back( std::move( selector)) ;
			}
		}
	}

	input = {observed.scanSessionId, observed.inspectionPath, observed.byteCount, observed.sha256,
			 hint.resourceContent} ;
	return 0 ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同lookupの配布tupleを比較します。原期限検証は呼出側でも省きません
 * @param[in] task 新しい明示対象です
 * @param[in] sourceTask 元TRANSFER対象です
 * @return 原配布tupleが完全一致した場合だけtrueです
 */
//------------------------------------------------------------------------------
bool SignedIndexAcquisitionAdapter::matchesRetainedBody(
	const OfficialPreparationTask &task, const OfficialPreparationTask &sourceTask) const
{
	// 元owner以外やlocalからの連鎖参照を作りません
	if( !lookup_ || !issuer_ || task.scanSessionId != context_.scanSessionId ||
	   sourceTask.scanSessionId != context_.scanSessionId ||
	   task.target.terms == OfficialPreparationTerms::INSPECTION_ONLY ||
	   sourceTask.target.terms == OfficialPreparationTerms::INSPECTION_ONLY) {
		return false ;
	}

	const auto target =
		// 新原targetです
		std::ranges::find( bindings_, task.target, &PreparedBinding::target) ;
	const auto source = std::ranges::find( bindings_, sourceTask.target,
										  &PreparedBinding::target) ;	// 原所有targetです
	// 原TRANSFERの実claimが存在し、新しいtargetは別recordです
	if( target == bindings_.end() || source == bindings_.end() || target == source ||
	   !source->claimedTask || *source->claimedTask != sourceTask ||
	   source->localInspectionClaimed || source->grantId == 0U) {
		return false ;
	}

	const auto &records = lookup_->snapshot().consumerRecords() ;	// 原署名recordです
	const auto &left =
		records[lookup_->relations()[target->relationIndex].recordIndex] ;	// 新対象です
	const auto &right =
		records[lookup_->relations()[source->relationIndex].recordIndex] ;	// 原ownerです
	return left.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE &&
		   right.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE &&
		   sameSharedPayloadEvidence( left, right, false) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 新LOCAL taskのscopeへ同owned fileを結合します
 * @param[in] task 新しい明示承認taskです
 * @param[in] sourceTask 元所有を説明する過去TRANSFER taskです
 * @param[in] current 元scan contextです
 * @param[in] nowUtcSeconds 信頼UTC秒です
 * @param[in] session 元file sealのissuerです
 * @param[in] workspace 元保護領域です
 * @param[in] evidence 元fileの不変sealです。現在の読取許可ではありません
 * @param[in] localInspection 当該LOCAL claimの照合票です
 * @param[out] hint 新recordの原selectorです
 * @param[out] input 元ownerからの非所有byte入力です
 * @param[in] observeHost 再利用元と再利用先のホストをこの呼出しで確認する場合trueです
 * @return 原A/B期限・所有・全tuple成立0です。通信/旧grant再消費は行いません
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::bindRetainedInspectionInput(
	const OfficialPreparationTask &task, const OfficialPreparationTask &sourceTask,
	const IndexLookupContext current, const std::uint64_t nowUtcSeconds,
	const OfficialAcquisitionSession &session, const OfficialDownloadWorkspace &workspace,
	const OfficialAcquiredFileEvidence	  &evidence,
	const OfficialLocalInspectionEvidence &localInspection, IndexedDriverArchiveHint &hint,
	DriverArchiveInput &input, const bool observeHost) const
{
	hint  = {} ;
	input = {} ;
	const auto target =
		// 原Bです
		std::ranges::find( bindings_, task.target, &PreparedBinding::target) ;
	const auto source =
		// 原Aです
		std::ranges::find( bindings_, sourceTask.target, &PreparedBinding::target) ;
	// 過去TRANSFER証拠は現在の読取許可にせず、新LOCALの実claimを必須にします
	if( !localInspection.matches( task) || !matchesRetainedBody( task, sourceTask) ||
	   target == bindings_.end() || source == bindings_.end() || !target->claimedTask ||
	   *target->claimedTask != task || !target->localInspectionClaimed || target->grantId != 0U) {
		return static_cast<NativeError>( E_ACCESSDENIED) ;
	}

	std::string reason ;	// 原metadataの独立再検証結果です
	auto		error =
		// 原A期限です
		validateBinding( *source, current, utcFromSeconds( nowUtcSeconds), reason) ;
	// 時刻窓が異なっても原Bの実時刻・全relationを独立検証します
	if( error == 0U) {
		error = validateBinding( *target, current, utcFromSeconds( nowUtcSeconds), reason) ;
	}

	// 元issuer/ledger/seal/workspace/全file byteを新LOCAL scopeの下で再検証します
	if( error == 0U) {
		error = bindInspectionInputImpl( sourceTask, current, nowUtcSeconds, session, workspace,
										evidence, hint, input, observeHost) ;
	}

	// 不一致を同hash/pathだけで補完しません
	if( error != 0U) {
		hint  = {} ;
		input = {} ;
		return error ;
	}

	const auto &snapshot = lookup_->snapshot() ;		// 原署名snapshotです
	const auto	records	 = snapshot.consumerRecords() ;	// 元recordの連続位置です
	const auto	recordIndex =
		// 再利用先の元位置です
		lookup_->relations()[target->relationIndex].recordIndex ;
	const auto &record = records[recordIndex] ;							// 原Bです
	const auto	region = snapshot.consumerRecordRegion( recordIndex) ;	// Bを持つ元領域です
	// 元Bも標準INFだけを受け入れ、別recordの適合性を借りません
	if( record.targetOs.value == IndexTargetOs::WINDOWS_SERVER &&
	   record.acquisition.value != IndexAcquisitionKind::STANDARD_INF_ARCHIVE) {
		hint  = {} ;
		input = {} ;
		return E_NOTIMPL ;
	}

	// 元A/Bの全純粋検証と元seal成立後に、最低build又は専用ModelsのBの同hostを最終確認します
	if( observeHost && (record.recordSchemaVersion == 6U || hasClientMinimumBuildMarker( record))) {
		const auto hostError = reobserveHost( current) ;	// Aの成立をBの適合性へ借りません
		// 失敗時は途中のA hint/inputも公開せず空へ戻します
		if( hostError != 0U) {
			hint  = {} ;
			input = {} ;
			return hostError ;
		}
	}

	hint.indexSha256  = hexDigest( region.indexSha256) ;
	hint.recordSha256 = hexDigest( record.recordSha256) ;
	hint.selectedInfs.clear() ;
	// 新Bの元relationだけを実INF検査へ渡します。Aの検査結果は複写しません
	for( const auto relationIndex : target->relationIndices) {
		const auto &selected =
			// Bの原selectorです
			records[lookup_->relations()[relationIndex].recordIndex] ;
		const auto &identity = selected.publishedIdentityEvidence ;	// 認証済みINF名です
		// 元INFの公開selector以外を再利用対象へ広げません
		if( identity.state == IndexEvidenceState::PUBLISHED &&
		   identity.kind == IndexIdentityEvidenceKind::INF) {
			IndexedDriverInfSelector selector{indexUtf8Text( identity.nestedArchiveIdentity),
											  // 元Unicode値です
											  indexUtf8Text( identity.infIdentity)} ;
			std::ranges::replace( selector.nestedArchive, L'/', L'\\') ;
			std::ranges::replace( selector.infIdentity, L'/', L'\\') ;
			// 同一memberを重複検査しません
			if( std::ranges::find( hint.selectedInfs, selector) == hint.selectedInfs.end()) {
				hint.selectedInfs.push_back( std::move( selector)) ;
			}
		}
	}

	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元host拒否を上書きしない診断値を返します
 * @param[in] current 完全contextです
 * @return 最初の拒否又は初回判定です。別contextは空です
 */
//------------------------------------------------------------------------------
std::optional<IndexHostGateResult> SignedIndexAcquisitionAdapter::hostDecision(
	const IndexLookupContext current) const noexcept
{
	// 確保不能でも最初の元拒否は固定領域で保持します
	if( emergencyHostRejection_ && emergencyHostRejection_->context == current) {
		return emergencyHostRejection_->decision ;
	}

	// 一度拒否したcontextを後続正常値で上書きしません
	for( const auto &entry : rejectedHosts_) {
		// 三IDの全一致だけを同contextとします
		if( entry.context == current) {
			return entry.decision ;
		}
	}

	// 有効な別contextへ古い成功を移しません
	if( host_ && host_->context == current) {
		return initialHostDecision_ ;
	}

	return std::nullopt ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元contextへ最初の拒否を不可逆に保存します
 * @param[in] current 完全contextです
 * @param[in] decision 原native値と別のローカル拒否です
 * @return 最初の拒否です。確保不能でも取得を閉じます
 * @note 拒否三fieldと同所有の取得能力だけを取り消し、thread安全性を追加しません
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::rejectHost(
	const IndexLookupContext current, const IndexHostGateResult &decision) const noexcept
{
	const auto previous = hostDecision( current) ;	// 元拒否を再利用します
	// 同contextに既拒否がある場合は原domain/bitsも保持します
	if( previous && previous->state != IndexHostGateState::ALLOW_UNVERIFIED) {
		return previous->error ;
	}

	try {
		rejectedHosts_.push_back( HostRejection{current, decision}) ;
	} catch( ...) {
		// 保存確保不能から同contextの再許可を作りません
		emergencyHostRejection_		= HostRejection{current, decision} ;
		hostRejectionStorageFailed_ = true ;
	}

	// 発行前のgrantだけでなく以後の同scan取得も閉じます
	if( acquisitionOpen_) {
		*acquisitionOpen_ = false ;
	}

	return decision.error ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同scan fullhostと明示observerを所有して開始します
 * @param[in] lookup 原署名とnative所有を保持するlookupです
 * @param[in] current 元scanの全contextです
 * @param[in] host 一度だけ結んだ原観測です
 * @param[in] observer 明示再観測関数です。欠落を補完しません
 * @param[in] nowUtc 原期限UTCです
 * @return 成立0、既拒否/未知/未対応/所有不一致は拒否です
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::beginHost(
	std::shared_ptr<const SignedIndexRecordLookup> lookup, const IndexLookupContext current,
	IndexScanHostSnapshot host, WindowsHostPlatformObserver observer,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	return beginHostImpl( std::move( lookup), current, std::move( host), std::move( observer), nowUtc,
						 AuthorityProfile::PRODUCT) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 内部固定profileで同じfullhost開始を行います
 * @param[in] lookup 原lookupです
 * @param[in] current 全contextです
 * @param[in] host 原観測です
 * @param[in] observer 明示再観測です
 * @param[in] nowUtc 原期限UTCです
 * @param[in] profile 既product/fixture区分です
 * @return 全開始成立0、他は拒否です
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::beginHostImpl(
	std::shared_ptr<const SignedIndexRecordLookup> lookup, const IndexLookupContext current,
	IndexScanHostSnapshot host, WindowsHostPlatformObserver observer,
	const std::optional<std::chrono::sys_seconds> nowUtc, const AuthorityProfile profile) noexcept
{
	// 別scanの観測や既拒否を正常初回へ置換しません
	if( host.context != current) {
		return E_ACCESSDENIED ;
	}

	const auto previous = hostDecision( current) ;	// 同contextの元拒否です
	// invalidate/rebegin/legacyを経由しても元拒否を保持します
	if( previous && previous->state != IndexHostGateState::ALLOW_UNVERIFIED) {
		return previous->error ;
	}

	const auto original = std::ranges::find_if( initialHosts_, [current]( const auto &value) {
		return value.context == current ;
	}) ; // 同contextの最初の原値だけを使用します
	const auto decision = original == initialHosts_.end()
							  ? classifyIndexHost( host.observation)
							  : compareIndexHost( original->observation,
												 host.observation) ;	// ローカル判定は原codeと別です
	const auto target	= host.observation.value && (host.observation.value->productType == 2U ||
													 host.observation.value->productType == 3U)
							  ? IndexTargetOs::WINDOWS_SERVER
						  : host.observation.value && host.observation.value->buildNumber < 22000U
							  ? IndexTargetOs::WINDOWS_10
							  : IndexTargetOs::WINDOWS_11 ;	// 不成立時は権限へ使用しません
	const auto error	= beginImpl( std::move( lookup), current, target, nowUtc, profile,
									true) ;	// 先に原署名/所有/hashを検査します
	// 不正な別lookup入力はhost拒否記録を変更しません
	if( error != 0) {
		return error ;
	}

	// 一度の観測失敗も同contextで後続成功へ置換しません
	if( decision.state != IndexHostGateState::ALLOW_UNVERIFIED) {
		return rejectHost( current, decision) ;
	}

	// 同一初回値だけを一度保存し、後のinvalidateから独立に所有します
	if( original == initialHosts_.end()) {
		try {
			initialHosts_.push_back( host) ;
		} catch( ...) {
			return rejectHost( current, {IndexHostGateState::UNKNOWN, E_OUTOFMEMORY, {}}) ;
		}
	}

	host_				 = std::move( host) ;
	hostObserver_		 = std::move( observer) ;
	initialHostDecision_ = decision ;
	return 0 ;
}
//------------------------------------------------------------------------------
/**
 * @brief 元binding確認後だけhostを再観測します
 * @param[in] current 元scanの全contextです
 * @return 一致0、元拒否/変化/失敗はcontextへ拒否を残します
 * @note 同workerの論理const取消しだけで、原snapshot/observer/issuerを置換しません
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::reobserveHost( const IndexLookupContext current) const
{
	// 別入力はobserverも原contextも消費しません
	if( !issuer_ || !lookup_ || current != context_) {
		return E_ACCESSDENIED ;
	}

	const auto previous = hostDecision( current) ;	// 最初の元拒否です
	// 後続正常callbackを呼んで拒否を解除しません
	if( previous && previous->state != IndexHostGateState::ALLOW_UNVERIFIED) {
		return previous->error ;
	}

	// 旧client互換だけは新観測へfallbackしません
	if( !host_) {
		return targetOs_ == IndexTargetOs::WINDOWS_SERVER ? E_NOTIMPL : 0 ;
	}

	WindowsHostPlatformObservation fresh ;	// callback欠落/例外は原native errorなしのUNKNOWNです
	try {
		// 完全fakeの欠落から実OSを呼びません
		if( hostObserver_) {
			fresh = hostObserver_() ;
		}
	} catch( ...) {
		fresh = {} ;
	}

	const auto decision =
		// fresh既知変化は未対応値でもSTALEです
		compareIndexHost( host_->observation, fresh) ;
	// 正常再観測で原snapshotを差し替えません
	return decision.state == IndexHostGateState::ALLOW_UNVERIFIED ? 0
																  : rejectHost( current, decision) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 実claim済みtaskを再照合してdispatch直前のhostを再観測します
 * @param[in] task 当該issuerがclaimした元taskです
 * @param[in] current 元scanの全contextです
 * @param[in] nowUtc 原全期限UTCです
 * @return 原bindingとhost一致0。変化/観測失敗は同contextに拒否を残します
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::revalidateHostForAcquisition(
	const OfficialPreparationTask &task, const IndexLookupContext current,
	const std::optional<std::chrono::sys_seconds> nowUtc)
{
	const auto binding = std::ranges::find_if( bindings_, [&task]( const auto &entry) {
		return entry.claimedTask && *entry.claimedTask == task ;
	}) ; // 元実taskだけです
	// 別task/hash/leaseではcallbackも拒否状態も変更しません
	if( binding == bindings_.end()) {
		return E_ACCESSDENIED ;
	}

	std::string reason ;												// 元binding診断をhost codeへ置き換えません
	auto error = validateBinding( *binding, current, nowUtc, reason) ;	// 全共有recordを再照合します
	// 純粋検査が成立したtaskだけを現hostの観測へ渡します
	if( error == 0U) {
		error = reobserveHost( current) ;
	}

	// 元OSと全関係が成立した直後に機種と対象端末の群を確認します
	if( error == 0U) {
		const auto &record =
			lookup_->snapshot()
				.consumerRecords()[lookup_->relations()[binding->relationIndex]
									   .recordIndex] ;	// 共有一致を確認した代表の元行です
		error = reobservePreparedDevice( record, binding->target, current) ;
	}

	return error ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ署名元行の機種と、元スキャンの型番を現在の端末で照合します
 * @param[in] record 元関係の純粋検査で照合した同じ元レコードです
 * @param[in] current 同操作・スキャン・inventoryの元contextです
 * @return 機種条件なし又は同じ端末で型番が確認できた場合は0、当該行の条件不足はE_ACCESSDENIEDです
 * @note WindowsのOS再観測と不一致時の全体停止には影響させません
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::reobservePlatformMachine(
	const IndexDistributionRecord &record, const IndexLookupContext current) const
{
	// 従来の取得は機種条件を持たないため観測を追加しません
	if( !record.platformDeviceScope) {
		return 0U ;
	}

	const auto *original = lookup_ && context_ == current
							   ? lookup_->snapshot().platformMachine( current)
							   : nullptr ;					// 同じ元スキャンの端末です
	const auto &scope	 = *record.platformDeviceScope ;	// 元署名で結んだ製造元と型番です
	// 元観測と原行を確認してからだけ現在の型番を読みます
	if( !platformMachineObserver_ || !original ||
	   original->vendor == IndexPlatformMachineVendor::UNKNOWN ||
	   original->vendor != scope.machineVendor ||
	   std::ranges::find( scope.machineTypes, original->machineType) == scope.machineTypes.end()) {
		return E_ACCESSDENIED ;
	}

	try {
		const auto fresh = platformMachineObserver_() ;	// 同じ端末の現在の観測です
		// 同じ元表に載る別型番も別端末として扱います
		return fresh.vendor == original->vendor && fresh.machineType == original->machineType
				   ? 0U
				   : static_cast<NativeError>( E_ACCESSDENIED) ;
	} catch( ...) {
		return E_ACCESSDENIED ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 元承認の機種、完全Hardware ID又は必須群を現在の属性から再確認する
 * @param[in] record 当該取得対象の検証済み元署名レコードです
 * @param[in] target 元の表示と承認を照合した変更不可の取得対象です
 * @param[in] current 元操作・スキャン・インベントリです
 * @return 現在も条件が成立する場合は0、変化や観測不能の場合は元の拒否です
 * @note 本体送信・検査の入口が、承認と元レコードを照合した後に使います
 */
//------------------------------------------------------------------------------
NativeError SignedIndexAcquisitionAdapter::reobservePreparedDevice(
	const IndexDistributionRecord &record, const OfficialPreparationTarget &target,
	const IndexLookupContext current) const
{
	const auto &firmware = target.firmwareCondition ;	// 機器別の元承認だけに保持する条件です
	// 署名元行を持たない表示値や、元条件が抜けた承認から観測を作りません
	if( firmware.has_value() != !record.platformFirmwareGroups.empty() ||
	   (firmware &&
		(!platformDeviceStore_ || target.releaseIdentity != hexDigest( record.recordSha256)))) {
		return E_ACCESSDENIED ;
	}

	const auto machine = reobservePlatformMachine( record, current) ;	// 従来と同じ現在の型番です
	// 機種が変わった場合は端末を開かず元の診断を保持します
	if( machine != 0U) {
		return machine ;
	}

	// 公式ベンダー配布とWiXでは同じ承認に結ぶ一台と元Hardware IDを取り直します
	if( record.archiveHardwareScope || record.wixContentEvidence) {
		// 元署名と同じ凍結索引を要求し、双方の承認の用途を区別します
		if( !lookup_ || !platformDeviceStore_ ||
		   (record.archiveHardwareScope && !target.requiresPrerequisiteConfirmation) ||
		   (record.wixContentEvidence &&
			target.terms != OfficialPreparationTerms::INSPECTION_ONLY) ||
		   target.releaseIdentity != hexDigest( record.recordSha256)) {
			return E_ACCESSDENIED ;
		}

		const auto binding = std::ranges::find(
			bindings_, target, &PreparedBinding::target) ;	// 同じ元選択に発行した承認です
		const auto &relations = lookup_->relations() ;		// 所有者が凍結した元関係です
		// 表示用IDだけで署名レコードや端末を指定できません
		if( binding == bindings_.end() || binding->relationIndex >= relations.size()) {
			return E_ACCESSDENIED ;
		}

		const auto &relation = relations[binding->relationIndex] ;	// 同じ端末の元証拠です
		// 元レコードの照合位置と同じスキャンが維持される場合だけ端末を開きます
		if( relation.context != current || relation.recordSha256 != record.recordSha256 ||
		   relation.sourceId != record.sourceId || relation.recordId != record.recordId ||
		   !relation.deviceIdentity || !relation.publicIdIndex ||
		   !isIndexLookupIdEligible( record, *relation.publicIdIndex)) {
			return E_ACCESSDENIED ;
		}

		// 改めて照合する値は同じ署名済みModelsの元完全IDです
		const auto &required = record.publishedIdentityEvidence.pnpIds[*relation.publicIdIndex] ;
		return platformDeviceStore_->reobserveIndexHardwareId(
			current, *relation.deviceIdentity,
			std::wstring{required.value.begin(), required.value.end()}) ;
	}

	// 機器別の条件がない既存経路に端末の再観測は追加しません
	if( !firmware) {
		return 0U ;
	}

	return platformDeviceStore_->reobserveIndexFirmwareGroup( current, firmware->deviceIdentity,
															 record, firmware->groupIndex) ;
}

namespace signed_index_acquisition_detail {
//------------------------------------------------------------------------------
/**
 * @brief 同じ実開始検査へ固定fixture-main／revision1だけを渡します
 * @param[in,out] adapter 未開始adapter
 * @param[in] lookup 真署名・隔離commit／reload済みlookup
 * @param[in] current 同worker context
 * @param[in] targetOs 既知OS分類
 * @param[in] nowUtc 信頼UTC
 * @return 全開始検査成功0、それ以外は元拒否HRESULT
 */
//------------------------------------------------------------------------------
NativeError Access::beginFixture( SignedIndexAcquisitionAdapter				   &adapter,
								 std::shared_ptr<const SignedIndexRecordLookup> lookup,
								 const IndexLookupContext current, const IndexTargetOs targetOs,
								 const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	return adapter.beginImpl( std::move( lookup), current, targetOs, nowUtc,
							 SignedIndexAcquisitionAdapter::AuthorityProfile::INTERNAL_RAM_FIXTURE) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同じfullhost検査へ既fixture-main profileだけを渡します
 * @param[in,out] adapter 同workerのadapterです
 * @param[in] lookup 真署名・隔離reload済みlookupです
 * @param[in] current 全contextです
 * @param[in] host 同scanの原観測です
 * @param[in] observer 明示fakeだけの再観測です
 * @param[in] nowUtc 原期限UTCです
 * @return 全開始成立0、その他は元拒否です
 */
//------------------------------------------------------------------------------
NativeError Access::beginHostFixture( SignedIndexAcquisitionAdapter				   &adapter,
									 std::shared_ptr<const SignedIndexRecordLookup> lookup,
									 const IndexLookupContext current, IndexScanHostSnapshot host,
									 WindowsHostPlatformObserver				   observer,
									 const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	return adapter.beginHostImpl(
		std::move( lookup), current, std::move( host), std::move( observer), nowUtc,
		SignedIndexAcquisitionAdapter::AuthorityProfile::INTERNAL_RAM_FIXTURE) ;
}
} // namespace signed_index_acquisition_detail
} // namespace drivercrate
