//------------------------------------------------------------------------------
/**
 * @file signed_index_records.cpp
 * @brief 共通strict文法で署名済み配布recordの原byteと元申告を検査します
 * @version 01.27.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  v1互換を維持してv2 descriptorと現policy読取りを接続
 * Ver.01.01.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける
 * Ver.01.02.00 Shunji Ogawa  2026/10/23  全record/qualityの値codecを署名wrapperと共用
 * Ver.01.03.00 Shunji Ogawa  2026/10/24  現行nested member identityと原record完全tupleへ整合
 * Ver.01.04.00 Shunji Ogawa  2026/11/03  共通公式packageの手動索引と選択内容検査を接続
 * Ver.01.05.00 Shunji Ogawa  2026/11/07  原record検証後に全公開ID入力のchecked-add枠を検査
 * Ver.01.05.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.05.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.06.00 Shunji Ogawa  2026/11/19  旧索引と追加索引の元レコードと共通上限を検査
 * Ver.01.07.00 Shunji Ogawa  2026/11/19  追加索引の値検査と元表記の振分けを共有
 * Ver.01.08.00 Shunji Ogawa  2026/11/19  圧縮前の保留候補に同じレコード検査を使用
 * Ver.01.09.00 Shunji Ogawa  2026/11/19  追加欄の元取得元JSONを保持
 * Ver.01.10.00 Shunji Ogawa  2026/11/20  私有Catalog対象を元Modelsと詳細根拠に結合
 * Ver.01.11.00 Shunji Ogawa  2026/11/20  旧本文・追加欄間の同一配布物の対象競合を拒否
 * Ver.01.12.00 Shunji Ogawa  2026/11/20  Catalog対象が一致した元Modelsの位置を導出
 * Ver.01.13.00 Shunji Ogawa  2026/11/20  端末用追加欄の認証済み領域と元レコードを取得
 * Ver.01.14.00 Shunji Ogawa  2026/11/20  機種別の私有索引と同配布物の対象競合を検査
 * Ver.01.15.00 Shunji Ogawa  2026/11/20  機種別配布行から型番の発行元を導出し端末照合へ渡す
 * Ver.01.16.00 Shunji Ogawa  2026/11/20  私有の必須ファームウェア群を元Modelsと対象競合へ結合
 * Ver.01.17.00 Shunji Ogawa  2026/11/20  同一端末が報告する完全対象IDから必須群を判定
 * Ver.01.18.00 Shunji Ogawa  2026/11/22  Catalogの完全な汎用PnP IDを対象集合へ保持
 * Ver.01.19.00 Shunji Ogawa  2026/11/22  署名索引から独立した収集専用Models証拠を検査
 * Ver.01.20.00 Shunji Ogawa  2026/11/22  専用欄の配布行と公式Models原証拠を署名範囲内で結合
 * Ver.01.21.00 Shunji Ogawa  2026/11/22  専用欄の配布票出典と同更新の元詳細を結合
 * Ver.01.22.00 Shunji Ogawa  2026/11/22  専用欄と本文の比較を組み立てと端末読込で共有
 * Ver.01.23.00 Shunji Ogawa  2026/11/22  規約メンバー証拠の私有領域と旧公開拒否を追加
 * Ver.01.24.00 Shunji Ogawa  2026/11/22  公式配布ZIPの完全Hardware IDと条件の別名を検査
 * Ver.01.25.00 Shunji Ogawa  2026/11/23  私有v8の元WiX配布・全役割・規約を取得根拠へ結合
 * Ver.01.26.00 Shunji Ogawa  2026/11/23  WiXレコードに完全Hardware IDの端末照合を要求
 * Ver.01.26.01 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * Ver.01.26.02 Shunji Ogawa  2026/11/26  元配布条件と追加欄の各要素を前置契約で説明
 * Ver.01.27.00 Shunji Ogawa  2026/11/27  二段リンク規約を旧公開本文と分離
 * </pre>
 *
 * @note 元申告を型付きで保持するだけで、公式性・適合・取得・導入を実証しません
 *       全成功前の中間値は公開せず、network・保存・世代更新を行いません
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#include "platform/signed_index_records.h"
#include "platform/signed_index_codec_internal.h"
#include "platform/client_min_build_scope.h"
#include "platform/official_download_workspace.h"
#include "platform/server_index_scope.h"

#include <algorithm>
#include <array>
#include <map>
#include <new>
#include <regex>
#include <set>
#include <string_view>
#include <tuple>
#include <utility>
#include <windows.h>

#include "platform/official_file_verifier.h"
#include "platform/official_http_client.h"
#include "platform/official_html_terms.h"
#include "platform/signed_index_json_internal.h"
#include "platform/signed_index_acquisition_descriptor_internal.h"

namespace drivercrate {
namespace {

// 元申告の文字列と理由を有限に保持する実byte上限
constexpr std::size_t TEXT_MAX_BYTES		  = 512U ;
constexpr int		  MODELS_NAME_UTF16_LIMIT = 254 ;	// SetupAPIへ渡す元節名の上限です
// UTF-16側の制限を満たす元名に許容するUTF-8の最大バイト数
constexpr auto MODELS_NAME_UTF8_LIMIT = static_cast<std::size_t>( MODELS_NAME_UTF16_LIMIT) * 4U ;
// 旧索引で許可するModels節名の最大byte数
constexpr std::size_t LEGACY_MODEL_SECTION_BYTES = 128U ;
// 静的な公開根拠URLのv1準備枠
constexpr std::size_t URL_MAX_BYTES = 2048U ;
// Record原byteをbase64化した時の完全上限
constexpr std::size_t RECORD_BASE64_MAX_BYTES = ((INDEX_RECORD_MAX_BYTES + 2U) / 3U) * 4U ;
/**
 * @brief 共通parserがこの層へ返す失敗値
 */
using Failure = signed_index_json::Failure<IndexRecordsStatus> ;
/**
 * @brief 原byteを正規化しない共通parser
 */
using Reader = signed_index_json::Reader<IndexRecordsStatus> ;
using signed_index_json::require ;
using signed_index_json::decodeHash ;

//------------------------------------------------------------------------------
/**
 * @brief 公開textとして制御byteを除外し、UTF-8は共通readerへ委ねます
 * @param[in] value 解除後のUTF-8
 * @return 非空で512byte以内、ASCII制御byteがない場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validText( const std::string_view value) noexcept
{
	return !value.empty() && value.size() <= TEXT_MAX_BYTES &&
		   std::ranges::all_of( value, []( const unsigned char character) {
			   // UTF-8の非ASCII byteを保持し、表示を変える制御byteを除外する
			   return character >= 0x20U && character != 0x7fU ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 申告identityのASCII文法を検査します
 * @param[in] value 原identity
 * @param[in] limit 固定実byte上限
 * @return 非空で英数字または._-だけの場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validIdentity( const std::string_view value, const std::size_t limit) noexcept
{
	return !value.empty() && value.size() <= limit &&
		   std::ranges::all_of( value, []( const char character) {
			   // 公開identityを曖昧なUnicodeやpath delimiterへ拡張しない
			   return (character >= 'A' && character <= 'Z') ||
					  (character >= 'a' && character <= 'z') ||
					  (character >= '0' && character <= '9') || character == '.' ||
					  character == '_' || character == '-' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 静的証拠URLの有限準備形式を共通URL parserで検査します
 * @param[in] value 原ASCII URL。正規化しません
 * @note DNS・通信・公開宛先実測は行いません。Queryを持つPAGEはv1未対応です
 */
//------------------------------------------------------------------------------
void requireEvidenceUrl( const std::string_view value)
{
	require( !value.empty() && value.size() <= URL_MAX_BYTES && value.starts_with( "https://") &&
				value.find_first_of( "?#@") == std::string_view::npos,
			IndexRecordsStatus::INVALID_URL) ;
	require( std::ranges::all_of( value,
								[]( const unsigned char character) {
									// URLの制御byte・Unicode表記をv1準備枠から除外する
									return character > 0x20U && character < 0x7fU ;
								}),
			IndexRecordsStatus::INVALID_URL) ;
	const std::size_t	   end = value.find( '/', 8U) ;	// Authorityの完全範囲
	const std::string_view authority =
		value.substr( 8U, end == std::string_view::npos ? value.size() - 8U
													   : end - 8U) ;	// 共通parserへ渡すhostの抽出元
	const std::size_t	   colon = authority.find( ':') ;				// 明示portがある場合の位置
	const std::string_view host	 = authority.substr( 0U, colon) ;		// 元DNS名
	require( colon == std::string_view::npos || authority.substr( colon) == ":443",
			IndexRecordsStatus::INVALID_URL) ;
	require( !host.empty() && host.find( '.') != std::string_view::npos && host.back() >= 'a' &&
				host.back() <= 'z' && !host.ends_with( ".localhost") && !host.ends_with( ".local") &&
				!host.ends_with( ".internal") &&
				std::ranges::all_of( host,
									[]( const char character) {
										// IP literalや括弧を認めず、原DNS名をそのまま保持する
										return (character >= 'a' && character <= 'z') ||
											   (character >= '0' && character <= '9') ||
											   character == '.' || character == '-' ;
									}),
			IndexRecordsStatus::INVALID_URL) ;
	std::wstring wide ;	// 共通WinHTTP URL parserだけへ渡すASCII所有copy
	wide.reserve( value.size()) ;
	// 元ASCII URLの全byteを値を変えずUTF-16へ写す
	for( const unsigned char character : value) {
		wide.push_back( static_cast<wchar_t>( character)) ;
	}

	const std::wstring wideHost( host.begin(), host.end()) ;			// 同じ原DNS名だけのpolicy
	const std::array<std::wstring_view, 1U> hosts{wideHost} ;			// 構文照合用。公式trust登録ではない
	const NativeError error = validateOfficialHttpsUrl( wide, hosts) ;	// 共通parserの元診断
	// 共通parserの確保失敗をURL形式の不正へ読み替えない
	if( error == static_cast<NativeError>( E_OUTOFMEMORY)) {
		throw Failure{IndexRecordsStatus::OUT_OF_MEMORY, error} ;
	}

	require( error == 0, IndexRecordsStatus::INVALID_URL) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 固定enum表から一つの元申告へ解決します
 * @tparam Value 型付きenum
 * @tparam Count 固定enum値数
 * @param[in] text 原文字列
 * @param[in] choices 唯一の許可表
 * @return 完全一致の元申告enum
 */
//------------------------------------------------------------------------------
template <class Value, std::size_t Count>
[[nodiscard]] Value choice( const std::string_view										text,
						   const std::array<std::pair<std::string_view, Value>, Count> &choices)
{
	const auto found = std::ranges::find_if( choices, [&]( const auto &item) {
		// 借用textを固定enum表へ完全一致で照合する
		return item.first == text ;
	}) ; // 固定集合の一致位置
	require( found != choices.end(), IndexRecordsStatus::INVALID_EVIDENCE) ;
	return found->second ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既知textとUNKNOWN理由の排他的表現を読みます
 * @param[in,out] reader Record原byteの共通reader
 * @return KNOWNの値かUNKNOWNの理由を所有する値
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexObservedValue<std::string> readTextValue( Reader &reader)
{
	constexpr std::array<std::string_view, 3U> FIELDS{"state", "value", "reason"} ;	// 全必須field
	std::array<std::string, 3U>				   values ;								// Field順によらない所有元値
	// Readerとこの呼出しの所有配列だけを同期借用するhandler
	reader.object( FIELDS,
				  [&]( const std::size_t field) { values[field] = reader.text( TEXT_MAX_BYTES) ; }) ;
	require( values[0] == "KNOWN" || values[0] == "UNKNOWN", IndexRecordsStatus::INVALID_EVIDENCE) ;
	// UNKNOWNは欠損値を補完せず、非空理由をそのまま保持する
	if( values[0] == "UNKNOWN") {
		require( values[1].empty() && validText( values[2]), IndexRecordsStatus::INVALID_EVIDENCE) ;
		return {std::nullopt, std::move( values[2])} ;
	}

	require( validText( values[1]) && values[2].empty(), IndexRecordsStatus::INVALID_EVIDENCE) ;
	return {std::move( values[1]), {}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既知条件を固定enumへ、UNKNOWNをnulloptと理由へ読みます
 * @tparam Value 型付きenum
 * @tparam Count 固定enum値数
 * @param[in,out] reader 共通reader
 * @param[in] choices 固定enum表
 * @return 元申告の条件またはUNKNOWN理由
 */
//------------------------------------------------------------------------------
template <class Value, std::size_t Count>
[[nodiscard]] IndexObservedValue<Value> readEnumValue(
	Reader &reader, const std::array<std::pair<std::string_view, Value>, Count> &choices)
{
	auto text = readTextValue( reader) ;	// UNKNOWN理由を保持した元text
	// 未確認をenumの架空既知値へ変換しない
	if( !text.value) {
		return {std::nullopt, std::move( text.reason)} ;
	}

	return {choice( *text.value, choices), {}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元申告hashと出典原bytehashを別々に読みます
 * @param[in,out] reader 共通reader
 * @param[in] allowCatalogDownload 専用欄の公表ハッシュに正規配布票の出典を認めます
 * @return 出典に結合した既知hashまたはUNKNOWN理由
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexHashEvidence readHashEvidence( Reader &reader, const bool allowCatalogDownload)
{
	constexpr std::array<std::string_view, 5U> FIELDS{"state", "sha256", "evidenceUrl",
													  "evidenceSha256", "reason"} ;	// 全必須field
	std::array<std::string, 5U>				   values ;								// 元申告の所有値
	// 固定5fieldを要求長以内で順序非依存に読むhandler
	reader.object( FIELDS, [&]( const std::size_t field) {
		values[field] = reader.text( field == 2U ? URL_MAX_BYTES : TEXT_MAX_BYTES) ;
	}) ;
	require( values[0] == "KNOWN" || values[0] == "UNKNOWN", IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 不足時は全証拠値を空にしてUNKNOWN理由だけを保持する
	if( values[0] == "UNKNOWN") {
		require( values[1].empty() && values[2].empty() && values[3].empty() && validText( values[4]),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
		return {std::nullopt, {}, std::nullopt, std::move( values[4])} ;
	}

	require( values[4].empty(), IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 元CABの実計算と従来の公表ハッシュには配布票専用の出典例外を適用しません
	if( !allowCatalogDownload ||
	   signed_index_acquisition::catalogDownloadDialogUpdateId( values[2]).empty()) {
		signed_index_acquisition::requireEvidenceUrl( values[2]) ;
	}

	return {decodeHash( values[1], IndexRecordsStatus::INVALID_EVIDENCE),
			std::move( values[2]),
			decodeHash( values[3], IndexRecordsStatus::INVALID_EVIDENCE),
			{}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 正の元byte長またはUNKNOWN理由を読みます
 * @param[in,out] reader 共通reader
 * @return 元申告sizeまたはUNKNOWN理由
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexObservedValue<std::uint64_t> readSize( Reader &reader)
{
	constexpr std::array<std::string_view, 3U> FIELDS{"state", "valueBytes", "reason"} ;	// 必須field
	std::string								   state ;										// 元申告状態
	std::string								   reason ;										// UNKNOWN理由
	std::uint64_t							   bytes{} ;									// 元申告byte長
	// Readerと有限出力だけを同期借用するhandler
	reader.object( FIELDS, [&]( const std::size_t field) {
		// 数値fieldだけを整数型で読む
		if( field == 1U) {
			bytes = reader.number() ;
		} else {
			// その他の状態と理由はtextのまま保持する
			(field == 0U ? state : reason) = reader.text( TEXT_MAX_BYTES) ;
		}
	}) ;
	require( state == "KNOWN" || state == "UNKNOWN", IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 未知sizeに0を既知値として流用しない
	if( state == "UNKNOWN") {
		require( bytes == 0U && validText( reason), IndexRecordsStatus::INVALID_EVIDENCE) ;
		return {std::nullopt, std::move( reason)} ;
	}

	require( bytes > 0U && reason.empty(), IndexRecordsStatus::INVALID_EVIDENCE) ;
	return {bytes, {}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公開／計算hashとsizeの元申告を別々に読みます
 * @param[in,out] reader 共通reader
 * @param[in] scopedModels 専用欄の公表ハッシュで正規の配布票出典を認めます
 * @return 両hashが既知なら完全一致を要求した元申告
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexPackageEvidence readPackage( Reader &reader, const bool scopedModels)
{
	constexpr std::array<std::string_view, 3U> FIELDS{"publishedHash", "calculatedHash",
													  "size"} ;	// 必須field
	IndexPackageEvidence					   value ;			// 全成功前には公開しない元申告
	// 型付きfieldを固定番号へ接続する同期handler
	reader.object( FIELDS, [&]( const std::size_t field) {
		// sizeは正の整数またはUNKNOWNを別に読む
		if( field == 2U) {
			value.size = readSize( reader) ;
		} else {
			// 二つのhashは別々の出典を保持する
			(field == 0U ? value.publishedHash : value.calculatedHash) =
				readHashEvidence( reader, scopedModels && field == 0U) ;
		}
	}) ;
	require( !value.publishedHash.sha256 || !value.calculatedHash.sha256 ||
				value.publishedHash.sha256 == value.calculatedHash.sha256,
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief Source公式性の元申告を読み、公式性の実証へ昇格しません
 * @param[in,out] reader 共通reader
 * @param[in] scopedModels 専用欄の公式配布票を証拠として許す場合trueです
 * @return 元申告の出典またはUNKNOWN理由
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexOfficialEvidence readOfficialEvidence( Reader &reader, const bool scopedModels)
{
	constexpr std::array<std::string_view, 5U> FIELDS{"state", "kind", "evidenceUrl",
													  "evidenceSha256", "reason"} ;	// 必須field
	std::array<std::string, 5U>				   values ;								// 順序に依存しない所有元値
	// URLだけの独立上限を保って固定fieldを読むhandler
	reader.object( FIELDS, [&]( const std::size_t field) {
		values[field] = reader.text( field == 2U ? URL_MAX_BYTES : TEXT_MAX_BYTES) ;
	}) ;
	require( values[0] == "PUBLISHED" || values[0] == "UNKNOWN",
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// UNKNOWNは出典の公式性を架空の既知値にしない
	if( values[0] == "UNKNOWN") {
		require( values[1] == "UNKNOWN" && values[2].empty() && values[3].empty() &&
					validText( values[4]),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
		return {IndexEvidenceState::UNKNOWN,
				IndexOfficialEvidenceKind::UNKNOWN,
				{},
				std::nullopt,
				std::move( values[4])} ;
	}

	constexpr std::array<std::pair<std::string_view, IndexOfficialEvidenceKind>, 3U> KINDS{
		{{"OFFICIAL_PAGE", IndexOfficialEvidenceKind::OFFICIAL_PAGE},
		 {"OFFICIAL_CATALOG", IndexOfficialEvidenceKind::OFFICIAL_CATALOG},
		 {"OFFICIAL_LINK_REVIEW",
		  IndexOfficialEvidenceKind::OFFICIAL_LINK_REVIEW}}} ;	// 固定元申告種別
	require( values[4].empty(), IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 正規の公式配布票は専用欄の出典だけに使います
	if( !scopedModels ||
	   signed_index_acquisition::catalogDownloadDialogUpdateId( values[2]).empty()) {
		signed_index_acquisition::requireUrl( values[2], true) ;
	}

	return {IndexEvidenceState::PUBLISHED,
			choice( values[1], KINDS),
			std::move( values[2]),
			decodeHash( values[3], IndexRecordsStatus::INVALID_EVIDENCE),
			{}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Source identityと元申告の配布pageを読みます
 * @param[in,out] reader Index原byteの共通reader
 * @param[in] scopedModels 専用欄だけに正規配布票の公開出典を認めます
 * @return 全fieldを検査した元申告source
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexRecordSource readSource( Reader &reader, const bool scopedModels)
{
	constexpr std::array<std::string_view, 4U> FIELDS{
		"sourceId", "officialOrigin", "distributionPage", "officialEvidence"} ;	// 必須field
	IndexRecordSource value ;													// 全成功前には公開しないsource
	// Readerと所有sourceだけを借用するhandler
	reader.object( FIELDS, [&]( const std::size_t field) {
		// 証拠objectは全fieldを独立に検査する
		if( field == 3U) {
			value.officialEvidence = readOfficialEvidence( reader, scopedModels) ;
		} else {
			const std::array<std::string *, 3U> targets{&value.sourceId, &value.officialOrigin,
														&value.distributionPage} ;	// 非owning出力先
			*targets[field] = reader.text( field == 0U ? 64U : URL_MAX_BYTES) ;
		}
	}) ;
	require( validIdentity( value.sourceId, 64U), IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 起点を持つUNKNOWN sourceでも静的URL文法は維持する
	if( !value.officialOrigin.empty()) {
		signed_index_acquisition::requireUrl( value.officialOrigin, false) ;
	}

	// 元pageがある場合は未知の公式性とURL構文を分ける
	if( !value.distributionPage.empty() &&
	   (!scopedModels ||
		signed_index_acquisition::catalogDownloadDialogUpdateId( value.distributionPage).empty())) {
		signed_index_acquisition::requireUrl( value.distributionPage, true) ;
	}

	// 公開申告は一つのsource pageへ結合するが、真正性を実証しない
	if( value.officialEvidence.state == IndexEvidenceState::PUBLISHED) {
		require( !value.officialOrigin.empty() && !value.distributionPage.empty() &&
					value.officialEvidence.evidenceUrl == value.distributionPage,
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief メーカー公表側PnP IDの有限文法を確認します
 * @param[in] value 原ID
 * @return 一つのbus delimiterと非空残部、許可ASCIIだけの場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validPnpId( const std::string_view value) noexcept
{
	const std::size_t slash = value.find( '\\') ;	// Busと原公開ID残部の境界
	return value.size() <= TEXT_MAX_BYTES && slash != std::string_view::npos && slash > 0U &&
		   slash + 1U < value.size() && value.find( '\\', slash + 1U) == std::string_view::npos &&
		   std::ranges::all_of( value, []( const char character) {
			   // 原caseを保持し、比較keyだけを別途case非依存へ対応させます
			   return (character >= 'A' && character <= 'Z') ||
					  (character >= 'a' && character <= 'z') ||
					  (character >= '0' && character <= '9') || character == '\\' ||
					  character == '&' || character == '_' || character == '-' ||
					  character == '.' || character == '*' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 検査済みPnP IDのASCII大小文字だけを比較用に揃えます
 * @param[in] value 比較する元IDです。元値を変更しません
 * @return 大文字で揃えた比較値です
 * @throws std::bad_alloc 比較値を確保できません
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string pnpIdComparisonKey( const std::string_view value)
{
	std::string key{value} ;	// 比較用の所有値です
	std::ranges::transform( key, key.begin(), []( const char character) {
		return character >= 'a' && character <= 'z' ? static_cast<char>( character - ('a' - 'A'))
													: character ;
	}) ;
	return key ;
}

//------------------------------------------------------------------------------
/**
 * @brief 追加欄のIDを端末照合と同じ可視ASCIIの元値として検査します
 * @param[in] value 元IDです
 * @return 非空で有限の可視ASCIIならtrueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validOpaqueIndexId( const std::string_view value) noexcept
{
	return !value.empty() && value.size() <= TEXT_MAX_BYTES &&
		   std::ranges::all_of(
			   value, []( const char character) { return character >= '!' && character <= '~' ; }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 追加欄の原Models節を既存のWindows節照合へ渡せる形式か確認します
 * @param[in] value SetupAPIの観測と照合する原節名です
 * @return 原空白を含む有限ASCII節名の場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validSupplementModelSection( const std::string_view value) noexcept
{
	return value.size() <= 255U && value.find_first_not_of( ' ') != value.npos &&
		   std::ranges::all_of( value, []( const char character) {
			   return character >= ' ' && character <= '~' && character != ']' ;
		   }) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 非0のbrace付きClassGUIDの原表記を検査します
 * @param[in] value 元ClassGUID
 * @return 8-4-4-4-12桁のhexで非0の場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validClassGuid( const std::string_view value) noexcept
{
	// 全固定位置を安全に参照できない値は拒否する
	if( value.size() != 38U || value.front() != '{' || value.back() != '}') {
		return false ;
	}

	bool nonzero{} ;	// 全0 sentinelを既知classへ変換しない
	// 固定36byteのGUID本文だけを調べ、区切りと全hex桁を検査する
	for( std::size_t index = 1U; index < 37U; ++index) {
		const char character = value[index] ;	// 元hexまたは区切り
		// 四つの固定区切りだけを許可する
		if( index == 9U || index == 14U || index == 19U || index == 24U) {
			// 区切りが欠損している場合は型付きclassを作らない
			if( character != '-') {
				return false ;
			}

			continue ;
		}

		// 元caseを保ったままhex以外を拒否する
		if( !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') ||
			 (character >= 'A' && character <= 'F'))) {
			return false ;
		}

		nonzero = nonzero || character != '0' ;
	}

	return nonzero ;
}

//------------------------------------------------------------------------------
/**
 * @brief 静的相対INF identityを検査し、実local pathを構築しません
 * @param[in] value Slash区切りの元identity
 * @return 有限componentと.inf suffixを持つ場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validInfIdentity( const std::string_view value)
{
	// Suffixの安全な参照と全identityの独立上限を要求する
	if( value.size() < 5U || value.size() > TEXT_MAX_BYTES) {
		return false ;
	}

	const std::string_view suffix = value.substr( value.size() - 4U) ;	// 元suffix
	// INF以外やabsolute identityへ正規化fallbackしない
	if( suffix[0] != '.' || (suffix[1] != 'i' && suffix[1] != 'I') ||
	   (suffix[2] != 'n' && suffix[2] != 'N') || (suffix[3] != 'f' && suffix[3] != 'F')) {
		return false ;
	}

	return isSafeOfficialArchiveMember( std::wstring{value.begin(), value.end()}, L'/') ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一段nested selectorをnativeと共通のmember文法で検査します
 * @param[in] value 空はflat、非空は原slash相対archive memberです
 * @return 空または安全なZIP/CAB/非実行SFX memberの場合だけtrueです
 * @note 公開memberからfilesystem pathを構築しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validNestedIdentity( const std::string_view value)
{
	// 空だけがflatの明示値です
	if( value.empty()) {
		return true ;
	}

	// ASCII通常名を既存nativeの全上限/予約名へ照合します
	if( !isSafeOfficialArchiveMember( std::wstring{value.begin(), value.end()}, L'/') ||
	   value.size() < 5U) {
		return false ;
	}

	std::string suffix{value.substr( value.size() - 4U)} ;	// 原末尾だけの比較値です
	std::ranges::transform( suffix, suffix.begin(), []( const char character) {
		return character >= 'A' && character <= 'Z' ? static_cast<char>( character + ('a' - 'A'))
													: character ;
	}) ;
	return suffix == ".zip" || suffix == ".cab" || suffix == ".exe" ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原公開IDの種別と値を一つずつ読みます
 * @param[in,out] reader 共通reader
 * @param[in] supplement 真は認証済み追加欄の可視ASCII規則を選びます
 * @return 検査した原公開ID。端末actual IDではありません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexPublishedPnpId readPnpId( Reader &reader, const bool supplement)
{
	constexpr std::array<std::string_view, 2U> FIELDS{"kind", "value"} ;	// 必須field
	std::array<std::string, 2U>				   values ;						// 元ID種別と原value
	// 二fieldを独立上限内で読む同期handler
	reader.object( FIELDS,
				  [&]( const std::size_t field) { values[field] = reader.text( TEXT_MAX_BYTES) ; }) ;
	constexpr std::array<std::pair<std::string_view, IndexPnpIdKind>, 2U> KINDS{
		{{"HARDWARE", IndexPnpIdKind::HARDWARE},
		 {"COMPATIBLE", IndexPnpIdKind::COMPATIBLE}}} ;	// 固定ID種別
	require( supplement ? validOpaqueIndexId( values[1]) : validPnpId( values[1]),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	return {choice( values[0], KINDS), std::move( values[1])} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 現行10fieldの公開identityを一出典へ結合し、明示UNKNOWNを保持します
 * @param[in,out] reader 共通reader
 * @param[in] supplement 真は従来のDCで保持する追加表記を許容します
 * @param[in] scopedModels 真はDMの元証拠と同じUnicode節名を許容します
 * @return 元申告の公開identityまたはUNKNOWN理由
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexPublishedIdentityEvidence readIdentityEvidence( Reader	&reader,
																  const bool supplement,
																  const bool scopedModels)
{
	constexpr std::array<std::string_view, 10U> FIELDS{
		"state",	   "kind",
		"pnpIds",	   "classGuid",
		"infIdentity", "modelSection",
		"evidenceUrl", "evidenceSha256",
		"reason",	   "nestedArchiveIdentity"} ;				// 必須field
	std::array<std::string, 10U>					 values ;	// ID配列以外の元値
	IndexPublishedIdentityEvidence					 value ;	// 全検査前には公開しない元申告
	std::set<std::pair<IndexPnpIdKind, std::string>> seen ;		// 種別と原IDによる重複拒否集合
	// 有限ID配列と固定text fieldを読む同期handler
	reader.object( FIELDS, [&]( const std::size_t field) {
		// メーカー公表側IDだけを一件ずつ型付きで読む
		if( field == 2U) {
			reader.array(
				INDEX_RECORD_PNP_MAX_COUNT,
				[&] {
					auto id = readPnpId( reader, supplement || scopedModels) ;	// 一公開IDの所有値
					require( seen.emplace( id.kind, pnpIdComparisonKey( id.value)).second,
							IndexRecordsStatus::INVALID_EVIDENCE) ;
					value.pnpIds.push_back( std::move( id)) ;
				},
				IndexRecordsStatus::COUNT_LIMIT) ;
		} else {
			const auto maximum = field == 5U && scopedModels ? MODELS_NAME_UTF8_LIMIT
								 : field == 6U				 ? URL_MAX_BYTES
															 : TEXT_MAX_BYTES ;
			values[field]	   = reader.text( maximum) ;
		}
	}) ;
	require( values[0] == "PUBLISHED" || values[0] == "UNKNOWN",
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 不足を既知identityへ補完せず、recordと非空理由を保持する
	if( values[0] == "UNKNOWN") {
		require( values[1] == "UNKNOWN" && value.pnpIds.empty() && values[3].empty() &&
					values[4].empty() && values[5].empty() && values[6].empty() &&
					values[7].empty() && values[9].empty() && validText( values[8]),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
		value.reason = std::move( values[8]) ;
		return value ;
	}

	constexpr std::array<std::pair<std::string_view, IndexIdentityEvidenceKind>, 2U> KINDS{
		{{"INF", IndexIdentityEvidenceKind::INF},
		 {"CATALOG", IndexIdentityEvidenceKind::CATALOG}}} ;	// 固定出典種別
	require(
		!value.pnpIds.empty() && validClassGuid( values[3]) && validInfIdentity( values[4]) &&
			(scopedModels || (supplement ? validSupplementModelSection( values[5])
										 : validIdentity( values[5], LEGACY_MODEL_SECTION_BYTES))) &&
			values[8].empty() && validNestedIdentity( values[9]) &&
			(values[9].empty() || values[1] == "INF"),
		IndexRecordsStatus::INVALID_EVIDENCE) ;
	signed_index_acquisition::requireEvidenceUrl( values[6]) ;
	value.state					= IndexEvidenceState::PUBLISHED ;
	value.kind					= choice( values[1], KINDS) ;
	value.classGuid				= std::move( values[3]) ;
	value.infIdentity			= std::move( values[4]) ;
	value.nestedArchiveIdentity = std::move( values[9]) ;
	value.modelSection			= std::move( values[5]) ;
	value.evidenceUrl			= std::move( values[6]) ;
	value.evidenceSha256		= decodeHash( values[7], IndexRecordsStatus::INVALID_EVIDENCE) ;
	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 私有のCatalog対象条件を固定の四項目から読みます
 * @param[in,out] reader 原レコードを読む共通readerです
 * @param[in] maxTargets 用途が許可する原公式対象の上限です
 * @return 正規詳細URL、本文SHA-256、観測UTCと原表記の非空対象集合です
 * @throws Failure 不正な形、空集合又は固定枠超過です
 * @throws std::bad_alloc 対象条件を確保できません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexCatalogHardwareScope readCatalogHardwareScope(
	Reader &reader, std::size_t maxTargets = INDEX_RECORD_PNP_MAX_COUNT)
{
	constexpr std::array<std::string_view, 4U> FIELDS{
		"detailsUrl", "detailsSha256", "observedAtUtc", "packageHardwareIds"} ;	// 必須の原項目です
	IndexCatalogHardwareScope scope ;											// 全項目を確定する前の所有値です
	reader.object( FIELDS, [&]( const std::size_t field) {
		// 固定の項目名ごとに原値を読みます
		switch( field) {
			// GUIDを含む原実URLです
			case 0U:
				scope.detailsUrl = reader.text( URL_MAX_BYTES) ;
				break ;

			// 原応答本文そのもののdigestです
			case 1U:
				scope.detailsSha256 =
					decodeHash( reader.text( 64U), IndexRecordsStatus::INVALID_EVIDENCE) ;
				break ;

			// 発行時刻に差し替えない原観測UTCです
			case 2U:
				scope.observedAtUtc =
					signed_index_json::utc( reader.text( 20U), IndexRecordsStatus::INVALID_EVIDENCE) ;
				break ;

			// 配布詳細の対象は文字列全体で照合する完全Hardware IDです
			case 3U:
				reader.array(
					maxTargets,
					[&] {
						auto	   id = reader.text( 200U) ;	// 元表記と順序を保持します
						// 先頭記号と英数字だけの汎用PnP IDを完全一致対象として保持する
						const bool generic =
							id.starts_with( '*') && id.size() > 1U &&
							id.find_first_not_of(
								"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
								1U) == id.npos ;
						require( generic || (validPnpId( id) && id.find( '*') == id.npos),
								IndexRecordsStatus::INVALID_EVIDENCE) ;
						scope.packageHardwareIds.push_back( std::move( id)) ;
					},
					IndexRecordsStatus::COUNT_LIMIT) ;
				break ;

			// 未知の項目番号では原条件を生成しません
			default:
				throw Failure{IndexRecordsStatus::INVALID_RECORD} ;
		}
	}) ;
	require( catalogUpdateIdFromDetailsUrl( scope.detailsUrl).has_value() &&
				scope.observedAtUtc > std::chrono::sys_seconds{} &&
				!scope.packageHardwareIds.empty(),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	return scope ;
}

//------------------------------------------------------------------------------
/**
 * @brief MSI又はRTFの元マニフェスト役割を検査して所有する
 * @param[in,out] fields 元ID、CAB名、相対パスを含む読み取り済み文字列です
 * @param[in] cabinetPrefix 添付MSIはa、起動用RTFはuです
 * @param[in] extension 役割に対応する小文字の拡張子です
 * @return 未変更の同じ三属性です
 * @throws Failure 元識別子や相対名が不正です
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexWixMember wixMember( std::array<std::string, 5U> &fields,
									   const char cabinetPrefix, const std::string_view extension)
{
	const auto &key = fields[1] ;	// 元CAB名の先頭と数値部分を確認します
	require(
		validIdentity( fields[0], 96U) && key.size() >= 2U && key.front() == cabinetPrefix &&
			key.find_first_not_of( "0123456789", 1U) == key.npos &&
			std::ranges::all_of( fields[2],
								[]( const unsigned char character) {
									return character >= 32U && character < 127U ;
								}) &&
			isSafeOfficialArchiveMember( std::wstring{fields[2].begin(), fields[2].end()}, L'\\') &&
			pnpIdComparisonKey( fields[2]).ends_with( pnpIdComparisonKey( extension)),
		IndexRecordsStatus::INVALID_EVIDENCE) ;
	return {std::move( fields[0]), std::move( fields[1]), std::move( fields[2])} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 順序付きのMSI役割を評価せずに読み取る
 * @param[in,out] reader 私有v8の同じ閉形式readerです
 * @return 元条件、期待arch、非ゼロ言語番号と元三属性です
 * @throws Failure 必須項目や役割の内容が不正です
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexWixMsi readWixMsi( Reader &reader)
{
	constexpr std::array<std::string_view, 6U> KEYS{
		"id",			"cabinetMember", "filePath", "installCondition",
		"architecture", "language"} ;			// 元役割の全項目です
	std::array<std::string, 5U> fields ;		// 文字列の元表記を保持します
	std::uint64_t				language{} ;	// 元語番号の範囲は読み取り完了時に確認します
	reader.object( KEYS, [&]( const std::size_t field) {
		// 言語だけは文字列へ解釈せず元の整数を読みます
		if( field == 5U) {
			language = reader.number() ;
		} else {
			fields[field] = reader.text( field == 2U ? 160U : 256U) ;
		}
	}) ;
	const bool			   amd64 = fields[4] == "AMD64" ;	// 明示X86と未知値を区別します
	const std::string_view suffix =
		amd64 ? " AND VersionNT64" : " AND NOT VersionNT64" ;	// 閉じた元条件です
	require( (amd64 || fields[4] == "X86") && language > 0U && language <= 65535U &&
				fields[3].ends_with( suffix) &&
				validIdentity(
					std::string_view{fields[3]}.substr( 0U, fields[3].size() - suffix.size()), 96U),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	return {wixMember( fields, 'a', ".msi"), std::move( fields[3]), amd64,
			static_cast<std::uint16_t>( language)} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一言語の原RTFを同じ署名付き役割へ結ぶ申告を読み取る
 * @param[in,out] reader 私有v8の同じ閉形式readerです
 * @return 言語、元三属性、原サイズ・SHA-256を持つ値です
 * @throws Failure 必須項目、言語又は元役割が不正です
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexWixLicense readWixLicense( Reader &reader)
{
	constexpr std::array<std::string_view, 6U> KEYS{
		"id",	  "cabinetMember", "filePath",
		"locale", "sha256",		   "sizeBytes"} ;	// 規約の非本文項目だけです
	std::array<std::string, 5U> fields ;			// SHA-256は元文字形式も検査します
	std::uint64_t				bytes{} ;			// 同じRTF全体の元byte数です
	reader.object( KEYS, [&]( const std::size_t field) {
		// Byte数を文字列や省略値から補完しません
		if( field == 5U) {
			bytes = reader.number() ;
		} else {
			fields[field] = reader.text( field == 2U ? 160U : 256U) ;
		}
	}) ;
	static const std::regex locale( "[a-z]{2,3}-[A-Z]{2}") ;	// 通常定義の言語と地域に一致します
	require( std::regex_match( fields[3], locale) && bytes > 0U && bytes <= 256U * 1024U,
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	return {wixMember( fields, 'u', ".rtf"), std::move( fields[3]), bytes,
			decodeHash( fields[4], IndexRecordsStatus::INVALID_EVIDENCE)} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 内側CABの元Fileキーと論理ファイルの実観測を読み取る
 * @param[in,out] reader 私有v8の同じ閉形式readerです
 * @return 元の名前対、実byte数とハッシュの申告です
 * @throws Failure ファイルキー、論理名又は有限サイズが不正です
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexWixDriverFile readWixDriverFile( Reader &reader)
{
	constexpr std::array<std::string_view, 4U> KEYS{"cabinetMember", "targetName", "sha256",
													"sizeBytes"} ;	// 同じ検査時の四項目です
	std::array<std::string, 3U>				   fields ;				// 名前は元の大小文字で保持します
	std::uint64_t							   bytes{} ;			// 展開済みファイル全体の元byte数です
	reader.object( KEYS, [&]( const std::size_t field) {
		// 実サイズを文字列として解釈しません
		if( field == 3U) {
			bytes = reader.number() ;
		} else {
			fields[field] = reader.text( 96U) ;
		}
	}) ;
	require(
		validIdentity( fields[0], 72U) && validIdentity( fields[1], 96U) &&
			isSafeOfficialArchiveMember( std::wstring{fields[0].begin(), fields[0].end()}, L'\\') &&
			isSafeOfficialArchiveMember( std::wstring{fields[1].begin(), fields[1].end()}, L'\\') &&
			bytes > 0U && bytes <= 2ULL * 1024ULL * 1024ULL * 1024ULL,
		IndexRecordsStatus::INVALID_EVIDENCE) ;
	return {std::move( fields[0]), std::move( fields[1]), bytes,
			decodeHash( fields[2], IndexRecordsStatus::INVALID_EVIDENCE)} ;
}

//------------------------------------------------------------------------------
/**
 * @brief WiXの元配布と全役割を有限な私有v8の一件として読む
 * @param[in,out] reader 同じ署名レコードを借用している閉形式readerです
 * @return 規約本文を含まない元証拠です
 * @throws Failure 元ページ、原時刻、役割の重複又は必須条件の不成立です
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexWixContentEvidence readWixContentEvidence( Reader &reader)
{
	constexpr std::array<std::string_view, 9U> KEYS{
		"pageUrl",	"pageSha256", "observedAtUtc", "downloadUrl", "acceptedPublishers",
		"packages", "licenses",	  "streamName",	   "driverFiles"} ;	// v8の全項目です
	constexpr auto invalid = IndexRecordsStatus::INVALID_EVIDENCE ;	// 不正な元根拠を区別します
	IndexWixContentEvidence proof ;									// この一件で所有する元配布と全役割です
	reader.object( KEYS, [&]( const std::size_t field) {
		// 各項目を元表記と有限枠で読みます
		switch( field) {
			// 元ページのHTTPS URLです
			case 0U:
				proof.pageUrl = reader.text( URL_MAX_BYTES) ;
				break ;

			// 元応答本文のSHA-256です
			case 1U:
				proof.pageSha256 = decodeHash( reader.text( 64U), invalid) ;
				break ;

			// 元ページの確認UTCです
			case 2U:
				proof.observedAtUtc = signed_index_json::utc( reader.text( 20U), invalid) ;
				break ;

			// 署名で固定した同一パスの二番目のoriginです
			case 3U:
				proof.downloadUrl = reader.text( URL_MAX_BYTES) ;
				break ;

			// 外側EXEの元許可署名者を保持します
			case 4U:
				reader.array(
					8U, [&] { proof.acceptedPublishers.push_back( reader.text( 256U)) ; }, invalid) ;
				break ;

			// 元Chain順で全MSIの役割を保持します
			case 5U:
				reader.array( 32U, [&] { proof.packages.push_back( readWixMsi( reader)) ; }, invalid) ;
				break ;

			// 言語別の元規約を保持します
			case 6U:
				reader.array(
					16U, [&] { proof.licenses.push_back( readWixLicense( reader)) ; }, invalid) ;
				break ;

			// 各AMD64で使った内側CABの元名です
			case 7U:
				proof.streamName = reader.text( 62U) ;
				break ;

			// 選択したINFと全参照ファイルを順に保持します
			case 8U:
				reader.array(
					1024U, [&] { proof.driverFiles.push_back( readWixDriverFile( reader)) ; },
					invalid) ;
				break ;

			// 未知項目は閉形式へ入れません
			default:
				throw Failure{IndexRecordsStatus::INVALID_RECORD} ;
		}
	}) ;
	requireEvidenceUrl( proof.pageUrl) ;
	requireEvidenceUrl( proof.downloadUrl) ;
	require( proof.observedAtUtc > std::chrono::sys_seconds{} && !proof.acceptedPublishers.empty() &&
				!proof.licenses.empty() && validIdentity( proof.streamName, 62U) &&
				isSafeOfficialArchiveMember(
					std::wstring{proof.streamName.begin(), proof.streamName.end()}, L'\\') &&
				proof.driverFiles.size() >= 3U &&
				std::ranges::any_of( proof.packages, &IndexWixMsi::amd64),
			invalid) ;
	std::set<std::string> publishers ;	// 許可署名者を重複させません
	// 署名者表は非空の元文字列を含み、大小文字違いの重複を拒否します
	for( const auto &publisher : proof.acceptedPublishers) {
		require( validText( publisher) && publisher.front() != ' ' && publisher.back() != ' ' &&
					publishers.emplace( pnpIdComparisonKey( publisher)).second,
				invalid) ;
	}

	std::set<std::string> ids ;		// 全Payloadで共有する元役割IDの集合です
	std::set<std::string> members ;	// 元CABメンバーの衝突を拒否します
	std::set<std::string> paths ;	// Windows論理パスでの誤置換を防ぎます
	const auto			  uniqueMember = [&]( const IndexWixMember &member) {
		   return ids.emplace( pnpIdComparisonKey( member.id)).second &&
				  members.emplace( pnpIdComparisonKey( member.cabinetMember)).second &&
				  paths.emplace( pnpIdComparisonKey( member.filePath)).second ;
	} ; // 同一レコードを読む間だけ比較用集合を借用します
	// 全MSIを保ち、重複した役割から同じ結果を作りません
	for( const auto &package : proof.packages) {
		require( uniqueMember( package.member), invalid) ;
	}

	std::set<std::string> locales ;	// 言語から一つの元RTFを選べることを確認します
	// 規約は全役割の一意性と言語別の一意性を要求します
	for( const auto &license : proof.licenses) {
		require( uniqueMember( license.member) && locales.insert( license.locale).second, invalid) ;
	}

	std::set<std::string> fileMembers ;	// 内側CABの元Fileキーだけを比較します
	std::set<std::string> fileNames ;	// 展開後の同名の再利用を拒否します
	// 閉包の各ファイルに一意な元キーと論理名の組を要求します
	for( const auto &file : proof.driverFiles) {
		require( fileMembers.emplace( pnpIdComparisonKey( file.cabinetMember)).second &&
					fileNames.emplace( pnpIdComparisonKey( file.targetName)).second,
				invalid) ;
	}

	return proof ;
}

//------------------------------------------------------------------------------
/**
 * @brief 明示OSの元観測値を元Modelsの読取りと同じ範囲に解釈する
 * @param[in,out] reader 収集専用証拠の元JSON reader
 * @return Windows x64の全六項目を保持する明示観測点
 * @throws Failure 項目不正、対象外OSまたは不正な数値です
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialInfModelsPlatform readCollectorModelsPlatform( Reader &reader)
{
	// 元Modelsの観測点を再構成するため必須となるOS・アーキテクチャの欄
	constexpr std::array<std::string_view, 6> fields{"majorVersion", "minorVersion",
													 "buildNumber",	 "processorArchitecture",
													 "productType",	 "suiteMask"} ;
	// 各欄を縮小変換する前に元の符号なし整数で保持する配列
	std::array<std::uint64_t, fields.size()>  values{} ;
	reader.object( fields, [&]( std::size_t index) { values[index] = reader.number() ; }) ;
	require( values[0] == 10U && values[1] == 0U && values[2] <= UINT32_MAX && values[3] == 9U &&
				values[4] >= 1U && values[4] <= 3U && values[5] == 0U,
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 本文と公式範囲を照合する、元証拠のWindows観測点
	const OfficialInfModelsPlatform platform{.buildNumber = static_cast<std::uint32_t>( values[2]),
											 .productType = static_cast<std::uint8_t>( values[4])} ;
	// クライアント製品では採用済みのWindowsビルドと一致することを要求します
	if( platform.productType == 1U) {
		require( platform.buildNumber == 19045U ||
					isSupportedClientMinimumBuild( platform.buildNumber),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	} else {
		// Serverとして認める固定の観測点。各ビルドは公式入手条件へ結び付きます
		constexpr std::array releases{
			ServerIndexRelease::WINDOWS_SERVER_2016, ServerIndexRelease::WINDOWS_SERVER_2019,
			ServerIndexRelease::WINDOWS_SERVER_2022, ServerIndexRelease::WINDOWS_SERVER_2025} ;
		require( std::ranges::any_of( releases,
									[&]( const auto release) {
										return serverIndexModelsPlatform(
												   {release, platform.productType, 0U}) == platform ;
									}),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	return platform ;
}

//------------------------------------------------------------------------------
/**
 * @brief Models節と基本導入節の元表記をWindowsの有限な文字列へ移す
 * @param[in] utf8 JSONから取り出した元UTF-8の節名です
 * @return Unicode表記を保持した安全な元節名
 * @throws Failure 元文字列、UTF-16長さ、節名の禁止文字が不正です
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring decodeModelsName( const std::string_view utf8)
{
	require( utf8.size() <= MODELS_NAME_UTF8_LIMIT, IndexRecordsStatus::INVALID_EVIDENCE) ;
	// UTF-8変換APIが受け取る元のバイト数
	const auto bytes = static_cast<int>( utf8.size()) ;
	// 元UTF-8を変換するために必要なUTF-16コード単位数
	const int  length =
		MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), bytes, nullptr, 0) ;
	require( length > 0 && length <= MODELS_NAME_UTF16_LIMIT, IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 元の節名を無効な文字の補完なしで受け取る変換先
	std::wstring result( static_cast<std::size_t>( length), L'\0') ;
	require( MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), bytes, result.data(),
								length) == length &&
				result.find_first_of( std::wstring_view( L"\0\r\n[]\\/", 7U)) == result.npos,
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元証拠の節名を有限なWindows文字列として読み取ります
 * @param[in,out] reader 収集で保存した元証拠のJSON readerです
 * @return 文字数と禁止文字を検査した元表記です
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring readCollectorModelsName( Reader &reader)
{
	return decodeModelsName( reader.text( MODELS_NAME_UTF8_LIMIT)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一つの元Models節の全行要約と公式対象の元位置を読む
 * @param[in,out] reader 収集専用証拠の元JSON reader
 * @param[in] targetBudget 収集証拠全体に残っている公式対象の読取枠
 * @return 対象のない節も含めた元節の証拠
 * @throws Failure 原項目の不正、範囲超過、重複位置または順序差です
 */
//------------------------------------------------------------------------------
[[nodiscard]] OfficialInfScopedModelsSection readCollectorModelsSection( Reader	   &reader,
																		std::size_t targetBudget)
{
	// 一節の全Models行と公式一致位置を結び付ける必須欄
	constexpr std::array<std::string_view, 5> fields{"modelSection", "modelRows", "idFields",
													 "orderedRowsSha256", "matches"} ;
	// どの必須欄でも元証拠として成立しない場合の共通診断
	const auto								  invalid = IndexRecordsStatus::INVALID_EVIDENCE ;
	// 元節の名前、全行の要約、公式対象との一致位置の組立て先
	OfficialInfScopedModelsSection			  section ;
	reader.object( fields, [&]( std::size_t field) {
		// 一節を再現する宣言を欄ごとの型と予算で読み取ります
		switch( field) {
			// Windowsが実際に選ぶ元Models節の名前を保持します
			case 0U:
				section.modelSection = readCollectorModelsName( reader) ;
				break ;

			// 元節から検査したすべてのModels行数を受け取ります
			case 1U: {
				const auto value = reader.number() ;
				require( value != 0U && value <= OFFICIAL_SCOPED_MODELS_MAX_ROWS, invalid) ;
				section.modelRows = static_cast<std::uint32_t>( value) ;
				break ;
			}
			// 元節のHardware／Compatible ID欄を合わせた実件数を受け取ります
			case 2U: {
				const auto value = reader.number() ;
				require( value != 0U && value <= OFFICIAL_SCOPED_MODELS_MAX_ID_FIELDS, invalid) ;
				section.idFields = static_cast<std::uint32_t>( value) ;
				break ;
			}
			// 元の行順と全ID列を結び付けるSHA-256を受け取ります
			case 3U: {
				const auto value = reader.text( 64U) ;
				static_cast<void>( decodeHash( value, invalid)) ;
				section.orderedRowsSha256.assign( value.begin(), value.end()) ;
				break ;
			}
			// 共通上限内でこの節に一致した公式対象と元行の一式を読み取ります
			case 4U:
				reader.array(
					targetBudget,
					[&] {
						constexpr std::array<std::string_view, 3> matchFields{
							"modelRow", "hardwareId", "installBase"} ;
						OfficialInfScopedModelMatch match ;
						reader.object( matchFields, [&]( std::size_t item) {
							// 一致の元行・完全ID・実導入基本名をそれぞれの型で確定します
							switch( item) {
								// 元節の1始まりの行番号が宣言範囲内であることを確認します
								case 0U: {
									const auto row = reader.number() ;
									require( row != 0U && row <= OFFICIAL_SCOPED_MODELS_MAX_ROWS,
											invalid) ;
									match.modelRow = static_cast<std::uint32_t>( row) ;
									break ;
								}
								// 公式対象と照合する元の完全Hardware IDを読み取ります
								case 1U: {
									const auto id = reader.text( 200U) ;
									require( validOpaqueIndexId( id), invalid) ;
									match.hardwareId.assign( id.begin(), id.end()) ;
									break ;
								}
								// 一致行が実際に指す導入基本名を元の表記で保持します
								default:
									match.installBase = readCollectorModelsName( reader) ;
									break ;
							}
						}) ;
						require( section.matches.empty() ||
									section.matches.back().modelRow < match.modelRow,
								invalid) ;
						section.matches.push_back( std::move( match)) ;
					},
					IndexRecordsStatus::COUNT_LIMIT) ;
				break ;

			// 定義した欄以外を同じ元証拠へ混ぜません
			default:
				throw Failure{invalid} ;
		}
	}) ;
	require( section.idFields >= section.modelRows && section.idFields <= section.modelRows * 63U &&
				(section.matches.empty() || section.matches.back().modelRow <= section.modelRows),
			invalid) ;
	return section ;
}

//------------------------------------------------------------------------------
/**
 * @brief 機種別配布に使う完全PCI Hardware IDの文法を借ります
 * @return 比較用の大文字IDからSUBSYSの8桁を取り出す固定パターンです
 * @throws std::regex_error 固定パターンを初期化できません
 * @throws std::bad_alloc 比較式の記憶を確保できません
 */
//------------------------------------------------------------------------------
[[nodiscard]] const std::regex &platformHardwareIdPattern()
{
	// 完全値だけからSUBSYSの部分を取り出します
	static const std::regex pci(
		R"(PCI\\VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}&SUBSYS_([0-9A-F]{8})(?:&REV_[0-9A-F]{2})?)") ;
	return pci ;
}

//------------------------------------------------------------------------------
/**
 * @brief 機種別配布表の根拠と全対象を私有レコードから読み取ります
 * @param[in,out] reader 原レコードの共通readerです
 * @return 書換え前の公式配布条件です
 * @throws Failure 必須項目又は機種、型番、Hardware IDの文法が不正です
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexPlatformDeviceScope readPlatformDeviceScope( Reader &reader)
{
	// v4とv5に共通する元配布表の閉じた項目です
	constexpr std::array<std::string_view, 6U> FIELDS{
		"pageUrl", "pageSha256", "observedAtUtc", "model", "machineTypes", "packageHardwareIds"} ;
	constexpr auto invalid = IndexRecordsStatus::INVALID_EVIDENCE ;	// 元条件の不備です
	const auto	  &pci	   = platformHardwareIdPattern() ;			// SUBSYSを含む完全Hardware IDだけです
	IndexPlatformDeviceScope scope ;								// 同じ配布表の元条件です
	std::set<std::string>	 machineTypes ;							// 重複型番を元申告の不備として扱います
	reader.object( FIELDS, [&]( const std::size_t field) {
		// 根拠と対象の個別の型を検査します
		switch( field) {
			// 同じZIPを示した公式配布表です
			case 0U:
				scope.pageUrl = reader.text( URL_MAX_BYTES) ;
				break ;

			// 公式配布表の原本文hashです
			case 1U:
				scope.pageSha256 = decodeHash( reader.text( 64U), invalid) ;
				break ;

			// 署名時刻ではなく配布表の元観測です
			case 2U:
				scope.observedAtUtc = signed_index_json::utc( reader.text( 20U), invalid) ;
				break ;

			// 公式機種名を比較用の別名へ変換しません
			case 3U:
				scope.model = reader.text( 128U) ;
				break ;

			// 公式の型番集合を元の並びで保持します
			case 4U:
				reader.array(
					8U,
					[&] {
						auto type = reader.text( 4U) ;	// 配布表の4文字の型番です
						require( type.size() == 4U &&
									type.find_first_not_of(
										"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") == type.npos &&
									machineTypes.emplace( type).second,
								invalid) ;
						scope.machineTypes.push_back( std::move( type)) ;
					},
					IndexRecordsStatus::COUNT_LIMIT) ;
				break ;

			// 完全IDは元Modelsと照合するために元caseを保持します
			case 5U:
				reader.array(
					INDEX_RECORD_PNP_MAX_COUNT,
					[&] {
						auto id = reader.text( 44U) ;	// REVを持てる完全なPCI IDです
						require( std::regex_match( pnpIdComparisonKey( id), pci), invalid) ;
						scope.packageHardwareIds.push_back( std::move( id)) ;
					},
					IndexRecordsStatus::COUNT_LIMIT) ;
				break ;

			// 閉じた配布条件以外のfield番号は受理しません
			default:
				throw Failure{IndexRecordsStatus::INVALID_RECORD} ;
		}
	}) ;
	requireEvidenceUrl( scope.pageUrl) ;
	require( validText( scope.model) && scope.model.front() != ' ' && scope.model.back() != ' ' &&
				scope.model.find_first_not_of(
					"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 -._()") ==
					scope.model.npos &&
				scope.observedAtUtc > std::chrono::sys_seconds{} && !scope.machineTypes.empty() &&
				!scope.packageHardwareIds.empty(),
			invalid) ;
	return scope ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式配布ZIPの元ページと同じ元Modelsの対象を読みます
 * @param[in,out] reader 原レコードの共通readerです
 * @return 元ページの根拠と元表記を保持した非空の完全Hardware ID集合です
 * @throws Failure 項目、元ページ、時刻又は完全Hardware IDの文法が不正です
 * @throws std::bad_alloc 元条件を確保できません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexArchiveHardwareScope readArchiveHardwareScope( Reader &reader)
{
	constexpr std::array<std::string_view, 4U> FIELDS{"pageUrl", "pageSha256", "observedAtUtc",
													  "hardwareIds"} ;	// v7固有の必須項目です
	constexpr auto invalid = IndexRecordsStatus::INVALID_EVIDENCE ;		// 元配布条件の不備です
	IndexArchiveHardwareScope scope ;									// 原表記の所有値です
	reader.object( FIELDS, [&]( const std::size_t field) {
		// 元ページと元Modelsの対象を個別の文法で読みます
		switch( field) {
			// 公式配布ページの元HTTPS URLです
			case 0U:
				scope.pageUrl = reader.text( URL_MAX_BYTES) ;
				break ;

			// 選んだ元応答そのもののSHA-256です
			case 1U:
				scope.pageSha256 = decodeHash( reader.text( 64U), invalid) ;
				break ;

			// 発行時刻へ差し替えない原観測UTCです
			case 2U:
				scope.observedAtUtc = signed_index_json::utc( reader.text( 20U), invalid) ;
				break ;

			// 配布対象は全文を照合し、一般化した識別子へ変換しません
			case 3U:
				reader.array(
					INDEX_RECORD_PNP_MAX_COUNT,
					[&] {
						auto id = reader.text( TEXT_MAX_BYTES) ;	// 元表記と順序を保つ一件です
						require( validPnpId( id) && id.find( '*') == id.npos, invalid) ;
						scope.hardwareIds.push_back( std::move( id)) ;
					},
					IndexRecordsStatus::COUNT_LIMIT) ;
				break ;

			// 開発用の位置や追加の申告を元項目に認めません
			default:
				throw Failure{IndexRecordsStatus::INVALID_RECORD} ;
		}
	}) ;
	signed_index_acquisition::requireUrl( scope.pageUrl, true) ;
	require( scope.observedAtUtc > std::chrono::sys_seconds{} && !scope.hardwareIds.empty(),
			invalid) ;
	return scope ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ公式表の必須ファームウェア群を原順で読み取ります
 * @param[in,out] reader 原レコードの共通readerです
 * @return 空でなくsubsystemが互いに重ならない元の全条件です
 * @throws Failure 群の内容、原表記又は容量が不正です
 * @throws std::bad_alloc 原条件の記憶を確保できません
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::vector<IndexPlatformFirmwareGroup> readPlatformFirmwareGroups( Reader &reader)
{
	// 同じ配布表で必須条件を確認する三つの項目です
	constexpr std::array<std::string_view, 3U> FIELDS{"subsystemIds", "versionLabel",
													  "evidenceUrl"} ;
	constexpr auto invalid = IndexRecordsStatus::INVALID_EVIDENCE ;	// 原の条件を解釈できません
	std::set<std::string>					subsystems ;			// 同じ機器に複数の必須版を与えません
	std::vector<IndexPlatformFirmwareGroup> groups ;				// 同じZIPを指す全群です
	// 通常の配布表と同じ有限範囲だけを読みます
	reader.array(
		16U,
		[&] {
			IndexPlatformFirmwareGroup group ;	// 元表の一群です
			reader.object( FIELDS, [&]( const std::size_t field) {
				// 群の元項目を対応する型で読みます
				switch( field) {
					// 原表が指定したPCI subsystemです
					case 0U:
						reader.array(
							32U,
							[&] {
								auto id = reader.text( 8U) ;	// sub-deviceとsub-vendorの原8桁です
								require( id.size() == 8U &&
											id.find_first_not_of( "0123456789ABCDEF") == id.npos &&
											subsystems.insert( id).second,
										invalid) ;
								group.subsystemIds.push_back( std::move( id)) ;
							},
							IndexRecordsStatus::COUNT_LIMIT) ;
						break ;

					// 比較演算や別バージョンへ解釈しない原表示です
					case 1U:
						group.versionLabel = reader.text( 128U) ;
						break ;

					// 表に記載された非実行の元参照です
					case 2U:
						group.evidenceUrl = reader.text( URL_MAX_BYTES) ;
						break ;

					// 閉じた条件以外は受理しません
					default:
						throw Failure{invalid} ;
				}
			}) ;
			require( !group.subsystemIds.empty() && !group.versionLabel.empty() &&
						group.versionLabel.find_first_not_of(
							"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._-") ==
							group.versionLabel.npos,
					invalid) ;
			requireEvidenceUrl( group.evidenceUrl) ;
			groups.push_back( std::move( group)) ;
		},
		IndexRecordsStatus::COUNT_LIMIT) ;
	require( !groups.empty(), invalid) ;
	return groups ;
}

//------------------------------------------------------------------------------
/**
 * @brief 内容検査済みの行と配布対象の元観測を取得記述に結びます
 * @param[in] record 原時刻、取得記述と全Modelsを持つレコードです
 * @param[in] observedAtUtc 対象を確認した元応答のUTCです
 * @return 行の検査済み取得記述です
 * @throws Failure 原時刻、元証拠又は取得用途の不成立です
 */
//------------------------------------------------------------------------------
const IndexAcquisitionDescriptor &scopedAcquisition( const IndexDistributionRecord &record,
													const std::chrono::sys_seconds observedAtUtc)
{
	const auto &identity = record.publishedIdentityEvidence ;	// 同レコードの全Modelsです
	require( record.inspectionStage == IndexInspectionStage::CONTENT_INSPECTED &&
				record.targetOs.value && record.architecture.value == IndexArchitecture::X64 &&
				record.driverKind.value == IndexDriverKind::NORMAL_DRIVER &&
				record.acquisition.value == IndexAcquisitionKind::STANDARD_INF_ARCHIVE &&
				identity.state == IndexEvidenceState::PUBLISHED &&
				identity.kind == IndexIdentityEvidenceKind::INF && record.acquisitionDescriptor &&
				record.acquisitionDescriptor->state == IndexDescriptorState::KNOWN &&
				record.acquisitionDescriptor->attestation &&
				record.lastSuccessfulObservationUtc.value,
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	const auto &attestation = *record.acquisitionDescriptor->attestation ;	// 同行の元取得確認です
	require( observedAtUtc <= *record.lastSuccessfulObservationUtc.value &&
				observedAtUtc <= attestation.checkedAtUtc &&
				attestation.validUntilUtc <= observedAtUtc + INDEX_ACQUISITION_MAX_VALIDITY,
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	return *record.acquisitionDescriptor ;
}

//------------------------------------------------------------------------------
/**
 * @brief 私有v8のWiX証拠を同じ署名済みの配布元・元期限・元INFへ結ぶ
 * @param[in] record 共通構造を検査済みの元v8行です
 * @param[in] source 同じ署名追加欄の公式配布元です
 * @throws Failure 取得、言語別規約、公式導線、元期限又は元INFの結合が不成立です
 * @pre recordは私有v8の型付き証拠を持ちます
 * @note 通信、適用性、規約同意と導入は発行しません
 */
//------------------------------------------------------------------------------
void bindWixContentEvidence( const IndexDistributionRecord &record, const IndexRecordSource &source)
{
	constexpr auto invalid = IndexRecordsStatus::INVALID_EVIDENCE ;	// 証拠の不一致に共通の拒否です
	const auto	  &proof   = *record.wixContentEvidence ;			// 私有の同じ元WiX証拠です
	const auto	  &descriptor =
		// 元期限と元用途を照合します
		scopedAcquisition( record, proof.observedAtUtc) ;
	const auto &terms		= descriptor.terms ;						// 同意前の埋込みRTF種別です
	const auto &attestation = *descriptor.attestation ;					// 同じ元観測の期限です
	const auto &identity	= record.publishedIdentityEvidence ;		// 元INFと全Modelsを保持します
	const auto &calculated	= record.packageEvidence.calculatedHash ;	// 元EXE全体の実ハッシュです
	const auto &official	= source.officialEvidence ;					// 同じ公式ページの元根拠です
	const std::string_view anchor{descriptor.payloadUrl} ;				// 元公式ページが指す完全URLです
	const std::string_view redirected{proof.downloadUrl} ;				// 同一パスで固定した配布先です
	const auto			   anchorPath	= anchor.find( '/', 8U) ;		// 公式アンカーのパス始点です
	const auto			   redirectPath = redirected.find( '/', 8U) ;	// 配布先の同じパス始点です
	const auto			   host			= []( const std::string_view url, const std::size_t path) {
		return url.substr( 8U, path - 8U).substr( 0U, url.substr( 8U, path - 8U).find( ':')) ;
	} ; // 同じHTTPSの明示443を別ホストとして扱いません
	require( anchorPath != anchor.npos && redirectPath != redirected.npos &&
				anchor.substr( anchorPath) == redirected.substr( redirectPath) &&
				host( anchor, anchorPath) != host( redirected, redirectPath) &&
				anchor.find_first_of( "%?#") == anchor.npos && anchor.ends_with( ".exe") &&
				anchor.substr( anchor.rfind( '/') + 1U) == descriptor.fileName,
			invalid) ;

	require( record.targetOs.value != IndexTargetOs::WINDOWS_SERVER &&
				descriptor.format == IndexPayloadFormat::WIX_BURN_V3 &&
				terms.revisionKind == IndexTermsRevisionKind::WIX_RTF_SHA256 &&
				descriptor.route.size() == 1U && !attestation.manualReview &&
				attestation.authorityMethod ==
					IndexAuthorityMethod::OFFICIAL_SITE_CONTROL_AND_LINK &&
				attestation.authorityEvidenceUrl == proof.pageUrl &&
				attestation.authorityEvidenceSha256 == proof.pageSha256 &&
				record.lastSuccessfulObservationUtc.value == attestation.checkedAtUtc &&
				descriptor.publisher.value &&
				official.kind == IndexOfficialEvidenceKind::OFFICIAL_PAGE &&
				source.distributionPage == proof.pageUrl && official.evidenceUrl == proof.pageUrl &&
				official.evidenceSha256 == proof.pageSha256,
			invalid) ;
	const auto &hop =
		// 臨時転送を別根拠で補完せず、公式アンカーを保持します
		descriptor.route.front() ;
	require( hop.evidenceUrl == proof.pageUrl && hop.evidenceSha256 == proof.pageSha256 &&
				record.packageEvidence.size.value &&
				*record.packageEvidence.size.value <= descriptor.maximumBytes &&
				calculated.sha256 && calculated.evidenceSha256 == calculated.sha256 &&
				(!record.packageEvidence.publishedHash.sha256 ||
				 record.packageEvidence.publishedHash.sha256 == calculated.sha256) &&
				calculated.evidenceUrl == anchor && terms.evidenceSha256 == calculated.sha256 &&
				terms.evidenceUrl == anchor && identity.nestedArchiveIdentity.empty() &&
				identity.evidenceUrl == anchor && identity.evidenceSha256 &&
				std::ranges::any_of( identity.pnpIds, isExactWixHardwareId),
			invalid) ;
	const auto inf =
		std::ranges::find( proof.driverFiles, identity.infIdentity,
						  &IndexWixDriverFile::targetName) ;	// 同じ元表記のINFだけを選びます
	// 同じ元INFと同じ閉包内のCATを要求し、別の内容を元IDへ結びません
	require(
		inf != proof.driverFiles.end() && inf->sha256 == *identity.evidenceSha256 &&
			std::ranges::any_of( proof.driverFiles,
								[]( const IndexWixDriverFile &file) {
									return pnpIdComparisonKey( file.targetName).ends_with( ".CAT") ;
								}),
		invalid) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 完全Hardware IDを照合し、元Modelsの順序で対象の位置を導きます
 * @param[in] identity 同じ行の検査済み全Modelsです
 * @param[in] targets 同じ配布物の公式対象です
 * @return 元Modelsの一致位置です
 * @throws Failure 公式対象の重複又は同じ行に一致するHardware IDがありません
 * @throws std::bad_alloc 有限な比較集合を確保できません
 */
//------------------------------------------------------------------------------
std::vector<std::size_t> scopedHardwareIdIndices( const IndexPublishedIdentityEvidence &identity,
												 const std::vector<std::string>		  &targets)
{
	std::set<std::string> packageIds ;	// 同じ原Hardware IDを探す大小文字非依存の集合です
	// 公式表の同値重複を一つに丸めません
	for( const auto &id : targets) {
		require( packageIds.emplace( pnpIdComparisonKey( id)).second,
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	std::vector<std::size_t> indices ;	// 元Modelsの一致位置です
	// 元Models側のHardware表記だけが配布対象の根拠になります
	for( std::size_t index = 0U; index < identity.pnpIds.size(); ++index) {
		const auto &id = identity.pnpIds[index] ;	// 元順に読む公開ID
		// Compatible表記だけが同じ値でも対象を承認しません
		if( id.kind == IndexPnpIdKind::HARDWARE &&
		   packageIds.contains( pnpIdComparisonKey( id.value))) {
			indices.push_back( index) ;
		}
	}

	require( !indices.empty(), IndexRecordsStatus::INVALID_EVIDENCE) ;
	return indices ;
}

//------------------------------------------------------------------------------
/**
 * @brief Catalog詳細の全対象を同じレコードの元Modelsに結びます
 * @param[in,out] record Catalogの原配布条件と全Modelsを持つ行です
 * @pre catalogHardwareScopeが存在します
 * @throws Failure 同じ詳細又はHardware IDの証拠が成立しません
 */
//------------------------------------------------------------------------------
void bindCatalogHardwareScope( IndexDistributionRecord &record)
{
	auto &scope = *record.catalogHardwareScope ;	// 元配布条件を保持する対象です
	static_cast<void>( scopedAcquisition( record, scope.observedAtUtc)) ;
	const auto &identity	= record.publishedIdentityEvidence ;	// 元順の全Modelsです
	scope.hardwareIdIndices = scopedHardwareIdIndices( identity, scope.packageHardwareIds) ;
	// 同じ元位置から原IDの表記と順序を保持します
	for( const auto index : scope.hardwareIdIndices) {
		scope.hardwareIds.push_back( identity.pnpIds[index].value) ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 機種別対象をServerの元Modelsと同じZIPの公式配布表に結びます
 * @param[in,out] record 機種別対象と検査済みの全Modelsを持つ行です
 * @pre platformDeviceScopeが存在します
 * @throws Failure ZIPの原配布表、Server条件又は元Modelsとの一致が成立しません
 */
//------------------------------------------------------------------------------
void bindPlatformDeviceScope( IndexDistributionRecord &record)
{
	auto	   &scope	   = *record.platformDeviceScope ;						// 元配布表と対象集合です
	const auto &descriptor = scopedAcquisition( record, scope.observedAtUtc) ;	// 同じ行の取得記述です
	const auto &identity   = record.publishedIdentityEvidence ;					// 元順の全Modelsです
	require( record.targetOs.value == IndexTargetOs::WINDOWS_SERVER &&
				descriptor.format == IndexPayloadFormat::ZIP &&
				!descriptor.attestation->manualReview && descriptor.route.size() == 1U &&
				descriptor.route.front().kind == IndexRouteKind::OFFICIAL_PAYLOAD_LINK &&
				descriptor.route.front().evidenceUrl == scope.pageUrl &&
				descriptor.route.front().evidenceSha256 == scope.pageSha256 &&
				descriptor.attestation->authorityEvidenceUrl == scope.pageUrl &&
				descriptor.attestation->authorityEvidenceSha256 == scope.pageSha256 &&
				readServerIndexScope( identity, descriptor.prerequisites).has_value(),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	scope.hardwareIdIndices = scopedHardwareIdIndices( identity, scope.packageHardwareIds) ;
	require( scope.hardwareIdIndices.size() == scope.packageHardwareIds.size(),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式配布ZIPの対象を同じ元ページ、確認、Server条件、取得記述及び元Modelsへ結びます
 * @param[in,out] record 対象条件と元Modelsを保持する原レコードです
 * @param[in] source 同じ署名領域で参照された公式配布元です
 * @pre archiveHardwareScopeが存在し、URLは共通文法で検査済みです
 * @throws Failure 配布元、ZIP、元確認又は完全Hardware IDの結合が不成立です
 * @throws std::bad_alloc 比較用の元位置を確保できません
 */
//------------------------------------------------------------------------------
void bindArchiveHardwareScope( IndexDistributionRecord &record, const IndexRecordSource &source)
{
	auto	   &scope	   = *record.archiveHardwareScope ;						// 元ページと対象です
	const auto &descriptor = scopedAcquisition( record, scope.observedAtUtc) ;	// 同行の元取得記述です
	const auto &attestation = *descriptor.attestation ;							// 同行の元確認です
	const auto &identity	= record.publishedIdentityEvidence ;				// 元順の全Modelsです
	const auto &calculated	= record.packageEvidence.calculatedHash ;			// 同じZIPの実計算です
	const auto &size		= record.packageEvidence.size.value ;				// 同じZIPの長さです
	const auto &official	= source.officialEvidence ;							// 公式配布元の元ページです
	const auto	invalid		= IndexRecordsStatus::INVALID_EVIDENCE ;			// 不成立の元証拠です
	// 検査済みHTTPSから既定ポートを除いたhostだけを借り、配布ページの所属を確認します
	const auto	host = []( const std::string_view url) {
		 return url.substr( 8U, url.find_first_of( ":/?", 8U) - 8U) ;
	} ;
	const auto origin = host( source.officialOrigin) ;	// 配布ページを管理する元hostです
	require( official.state == IndexEvidenceState::PUBLISHED &&
				official.kind == IndexOfficialEvidenceKind::OFFICIAL_PAGE &&
				source.distributionPage == scope.pageUrl && official.evidenceUrl == scope.pageUrl &&
				official.evidenceSha256 == scope.pageSha256 && origin == host( scope.pageUrl) &&
				origin != "www.catalog.update.microsoft.com" &&
				origin != "catalog.update.microsoft.com",
			invalid) ;
	require( record.targetOs.value == IndexTargetOs::WINDOWS_SERVER &&
				descriptor.format == IndexPayloadFormat::ZIP &&
				descriptor.expectedContentType == "application/zip" &&
				!descriptor.terms.archiveNotice && descriptor.route.size() == 1U &&
				!attestation.manualReview &&
				attestation.authorityMethod ==
					IndexAuthorityMethod::OFFICIAL_SITE_CONTROL_AND_LINK &&
				attestation.authorityEvidenceUrl == scope.pageUrl &&
				attestation.authorityEvidenceSha256 == scope.pageSha256 && calculated.sha256 &&
				calculated.evidenceSha256 == calculated.sha256 &&
				calculated.evidenceUrl == descriptor.payloadUrl &&
				identity.evidenceUrl == descriptor.payloadUrl && size &&
				*size <= descriptor.maximumBytes,
			invalid) ;
	const auto &hop = descriptor.route.front() ;	// 元ページが直接指す一つの配布先です
	require( (hop.kind == IndexRouteKind::OFFICIAL_PAYLOAD_LINK ||
			 hop.kind == IndexRouteKind::OFFICIAL_CDN_LINK) &&
				hop.url == descriptor.payloadUrl && hop.evidenceUrl == scope.pageUrl &&
				hop.evidenceSha256 == scope.pageSha256 &&
				descriptor.prerequisites.items.size() == 4U &&
				readServerIndexScope( identity, descriptor.prerequisites).has_value(),
			invalid) ;
	// 既存のServer検査が三つのローカル条件を確定した残り一件を元ページに結びます
	require( std::ranges::any_of( descriptor.prerequisites.items,
								[&]( const auto &condition) {
									return condition.kind ==
											   IndexPrerequisiteKind::USER_CONFIRMATION &&
										   condition.evidenceUrl == scope.pageUrl &&
										   condition.evidenceSha256 == scope.pageSha256 ;
								}),
			invalid) ;
	scope.hardwareIdIndices = scopedHardwareIdIndices( identity, scope.hardwareIds) ;
	require( scope.hardwareIdIndices.size() == scope.hardwareIds.size(), invalid) ;
}

//------------------------------------------------------------------------------
/**
 * @brief ファームウェア群に当てはまる元Modelsの全Hardware IDを対象へ結びます
 * @param[in] record 元の全Modelsと検査済み機種別配布条件を持つレコードです
 * @throws Failure 対象の不足、追加又は所属の不一致です
 * @throws std::bad_alloc 比較用の元位置を確保できません
 * @pre platformDeviceScopeの元位置とファームウェア群は文法検査済みです
 */
//------------------------------------------------------------------------------
void validatePlatformFirmwareTargets( const IndexDistributionRecord &record)
{
	std::set<std::string_view> subsystems ;	// 同じ元表が列挙した対象です
	// 端末に対応するモデルがない公式群も保持します
	for( const auto &group : record.platformFirmwareGroups) {
		subsystems.insert( group.subsystemIds.begin(), group.subsystemIds.end()) ;
	}

	const auto &ids	  = record.publishedIdentityEvidence.pnpIds ;	// 元INFの順序付き全Modelsです
	const auto &scope = *record.platformDeviceScope ;				// 元IDに結合済みの配布対象です
	const auto &pci	  = platformHardwareIdPattern() ;				// 完全なPCI Hardware IDだけです
	std::vector<std::size_t> matched ;								// 公式群に対応する元Models位置です
	// 同じ元レコード内の該当対象を省略せず順に導出します
	for( std::size_t index{}; index < ids.size(); ++index) {
		const auto &id = ids[index] ;	// 同じ元節の一IDです
		// Compatible IDは公式のsubsystemが含まれていても対象にしません
		if( id.kind != IndexPnpIdKind::HARDWARE) {
			continue ;
		}

		const auto	key = pnpIdComparisonKey( id.value) ;	// 比較時だけ大文字へ揃えます
		std::smatch parts ;									// 完全IDから取り出した公式比較値です
		// 元の全IDを保ち、subsystemが宣言された元位置だけを照合します
		if( std::regex_match( key, parts, pci) && subsystems.contains( parts[1].str())) {
			matched.push_back( index) ;
		}
	}

	require( matched == scope.hardwareIdIndices, IndexRecordsStatus::INVALID_EVIDENCE) ;
}

/** @brief 同じ配布行を用途ごとの閉じた文法で読みます */
enum class RecordArea {
	/// 従来本文です
	BASE,
	/// 従来のDC欄です
	SUPPLEMENT,
	/// 公式ModelsのDM欄です
	SCOPED_MODELS
} ;

//------------------------------------------------------------------------------
/**
 * @brief 原record byteを固定schemaに従って読むだけの内部関数です
 * @param[in] raw Hashを照合済みの原UTF-8
 * @param[in] digest rawだけの実SHA-256
 * @param[in] manifest 原認証manifest。観測時刻を昇格しません
 * @param[in] area 原レコードが所属する署名領域です
 * @return 原byteと型付き元申告を所有するrecord
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexDistributionRecord readRecord( std::string raw, const IndexManifestSha256 digest,
												 const IndexManifestData &manifest,
												 const RecordArea		  area)
{
	const bool supplement	= area == RecordArea::SUPPLEMENT ;		// DCだけの対象条件に使用します
	const bool scopedModels = area == RecordArea::SCOPED_MODELS ;	// DM固有の原証拠参照です
	constexpr std::array<std::string_view, 21U> FIELDS{
		"schema",
		"sourceId",
		"recordId",
		"product",
		"targetOs",
		"architecture",
		"driverKind",
		"version",
		"publishedDate",
		"acquisition",
		"packageEvidence",
		"lastSuccessfulObservationUtc",
		"inspectionStage",
		"publishedIdentityEvidence",
		"acquisitionDescriptor",
		"catalogHardwareScope",
		"platformDeviceScope",
		"platformFirmwareGroups",
		"scopedModelsEvidenceSha256",
		"archiveHardwareScope",
		"wixContentEvidence"} ;	// Schema別の閉じたfield集合
	Reader reader( raw, IndexRecordsStatus::INVALID_RECORD, INDEX_RECORD_MAX_BYTES, 8U,
				  // このレコードの閉じた最大field数です
				  FIELDS.size()) ;
	constexpr std::array<std::pair<std::string_view, IndexTargetOs>, 3U> OS{
		{{"WINDOWS_10", IndexTargetOs::WINDOWS_10},
		 {"WINDOWS_11", IndexTargetOs::WINDOWS_11},
		 {"WINDOWS_SERVER", IndexTargetOs::WINDOWS_SERVER}}} ;	// 固定OS条件
	constexpr std::array<std::pair<std::string_view, IndexArchitecture>, 1U> ARCH{
		{{"X64", IndexArchitecture::X64}}} ;	// x64だけの既知条件
	constexpr std::array<std::pair<std::string_view, IndexDriverKind>, 3U> KINDS{
		{{"NORMAL_DRIVER", IndexDriverKind::NORMAL_DRIVER},
		 {"FIRMWARE", IndexDriverKind::FIRMWARE},
		 {"APPLICATION", IndexDriverKind::APPLICATION}}} ;	// 除外種別も保持する元申告
	constexpr std::array<std::pair<std::string_view, IndexAcquisitionKind>, 2U> ACQUISITION{
		{{"STANDARD_INF_ARCHIVE", IndexAcquisitionKind::STANDARD_INF_ARCHIVE},
		 {"OFFICIAL_INSTALLER", IndexAcquisitionKind::OFFICIAL_INSTALLER}}} ;	// 実行許可ではない方式
	constexpr std::array<std::pair<std::string_view, IndexInspectionStage>, 3U> STAGES{
		{{"UNCONFIRMED", IndexInspectionStage::UNCONFIRMED},
		 {"METADATA_ONLY", IndexInspectionStage::METADATA_ONLY},
		 {"CONTENT_INSPECTED", IndexInspectionStage::CONTENT_INSPECTED}}} ;	// 発行側の段階
	IndexDistributionRecord value ;											// Schema全成功前にはreceiptにしない所有record
	std::string				schema ;										// 全fieldの読取り後に確定する原wire版
	// Readerとこのrecordだけを同期借用する型付きhandler
	const std::uint32_t		seen = reader.objectWithPresence( FIELDS, [&]( const std::size_t field) {
		// 固定schema番号ごとに要求型を保って読む
		switch( field) {
			// 新配布schemaだけを受理し研究v3を昇格しない
			case 0U:
				schema = reader.text( 64U) ;
				break ;

			// Source参照は後段で一意なsourceへ結合する
			case 1U:
				value.sourceId = reader.text( 64U) ;
				break ;

			// Source内の原identityを保持する
			case 2U:
				value.recordId = reader.text( 64U) ;
				break ;

			// 製品表示名を適合条件に使わない
			case 3U:
				value.product = reader.text( TEXT_MAX_BYTES) ;
				break ;

			// 公開OS条件またはUNKNOWN理由
			case 4U:
				value.targetOs = readEnumValue( reader, OS) ;
				break ;

			// 公開x64条件またはUNKNOWN理由
			case 5U:
				value.architecture = readEnumValue( reader, ARCH) ;
				break ;

			// 元内容種別またはUNKNOWN理由
			case 6U:
				value.driverKind = readEnumValue( reader, KINDS) ;
				break ;

			// Version原値を比較・正規化しない
			case 7U:
				value.version = readTextValue( reader) ;
				break ;

			// 公開暦日を補正せず検査する
			case 8U:
				value.publishedDate = readTextValue( reader) ;
				// 既知公開日だけを実在する日付へ照合する
				if( value.publishedDate.value) {
					require( value.publishedDate.value->size() == 10U,
								IndexRecordsStatus::INVALID_EVIDENCE) ;
					static_cast<void>(
						signed_index_json::utc( *value.publishedDate.value + "T00:00:00Z",
												   IndexRecordsStatus::INVALID_EVIDENCE)) ;
				}

				break ;

			// 方式は元申告であり導入許可ではない
			case 9U:
				value.acquisition = readEnumValue( reader, ACQUISITION) ;
				break ;

			// 公開hashと計算hashとsizeを独立に保持する
			case 10U:
				value.packageEvidence = readPackage( reader, scopedModels) ;
				break ;

			// 成功観測はmanifest発行時刻へ繰り上げない
			case 11U: {
				auto observed = readTextValue( reader) ;	// 原UTCまたはUNKNOWN理由
				value.lastSuccessfulObservationUtc.reason = std::move( observed.reason) ;
				// 既知観測UTCだけを暦日・秒単位で読む
				if( observed.value) {
					value.lastSuccessfulObservationUtc.value = signed_index_json::utc(
						*observed.value, IndexRecordsStatus::INVALID_EVIDENCE) ;
				}

				break ;
			}
			// Qualityに照合する発行側の三段階
			case 12U:
				value.inspectionStage = choice( reader.text( 32U), STAGES) ;
				break ;

			// 公開identity全体を一出典へ結ぶ
			case 13U:
				value.publishedIdentityEvidence =
					readIdentityEvidence( reader, supplement, scopedModels) ;
				break ;

			// 取得申告を型付きで読むだけで、grantや候補を発行しない
			case 14U:
				value.acquisitionDescriptor =
					signed_index_acquisition::readDescriptor( reader, readTextValue, scopedModels) ;
				break ;

			// 配布対象は私有追加欄でだけ読めます
			case 15U:
				require( supplement, IndexRecordsStatus::INVALID_RECORD) ;
				value.catalogHardwareScope = readCatalogHardwareScope( reader) ;
				break ;

			// 機種別の配布条件も私有追加欄に限ります
			case 16U:
				require( supplement, IndexRecordsStatus::INVALID_RECORD) ;
				value.platformDeviceScope = readPlatformDeviceScope( reader) ;
				break ;

			// ファームウェア条件は機種別の私有追加行に限ります
			case 17U:
				require( supplement, IndexRecordsStatus::INVALID_RECORD) ;
				value.platformFirmwareGroups = readPlatformFirmwareGroups( reader) ;
				break ;

			// 専用の公式Models行だけが元証拠のSHA-256を参照できます
			case 18U:
				require( scopedModels, IndexRecordsStatus::INVALID_RECORD) ;
				value.scopedModelsEvidenceSha256 =
					decodeHash( reader.text( 64U), IndexRecordsStatus::INVALID_EVIDENCE) ;
				break ;

			// 公式配布ZIPの機器別条件は私有追加欄に限ります
			case 19U:
				require( supplement, IndexRecordsStatus::INVALID_RECORD) ;
				value.archiveHardwareScope = readArchiveHardwareScope( reader) ;
				break ;

			// v8の元WiX資料と規約の型付き証拠は私有DCに限る
			case 20U:
				require( supplement, IndexRecordsStatus::INVALID_RECORD) ;
				value.wixContentEvidence = readWixContentEvidence( reader) ;
				break ;

			// 未登録field番号を成功にしない
			default:
				throw Failure{IndexRecordsStatus::INVALID_RECORD} ;
		}
	}) ;
	reader.finish() ;
	// 旧本文と専用Models領域に私有の規約証拠を混在させません
	require( supplement || !signed_index_detail::indexRecordHasPrivateTerms( value),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 追加欄の有無と必須欄の集合を含めて照合する従来レコード形式
	const bool legacySchema =
		(schema == "driver-index-record-v1" && seen == (1U << 14U) - 1U) ||
		(schema == "driver-index-record-v2" && seen == (1U << 15U) - 1U) ||
		(supplement && schema == "driver-index-record-v3" && seen == (1U << 16U) - 1U) ||
		(supplement && schema == "driver-index-record-v4" &&
		 seen == (((1U << 15U) - 1U) | (1U << 16U))) ||
		(supplement && schema == "driver-index-record-v5" &&
		 seen == (((1U << 15U) - 1U) | (1U << 16U) | (1U << 17U))) ||
		(supplement && schema == "driver-index-record-v7" &&
		 seen == (((1U << 15U) - 1U) | (1U << 19U))) ||
		(supplement && schema == "driver-index-record-v8" &&
		 seen == (((1U << 15U) - 1U) | (1U << 20U))) ;
	require( scopedModels
				? schema == "driver-index-record-v6" && seen == (((1U << 15U) - 1U) | (1U << 18U))
				: legacySchema,
			IndexRecordsStatus::INVALID_RECORD) ;
	require( value.wixContentEvidence.has_value() ==
				(value.acquisitionDescriptor &&
				 value.acquisitionDescriptor->format == IndexPayloadFormat::WIX_BURN_V3),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	value.recordSchemaVersion = value.wixContentEvidence				? 8U
								: value.archiveHardwareScope			? 7U
								: scopedModels							? 6U
								: !value.platformFirmwareGroups.empty() ? 5U
								: value.platformDeviceScope				? 4U
								: value.catalogHardwareScope			? 3U
								: value.acquisitionDescriptor			? 2U
																		: 1U ;
	// v1の取得情報不在を理由付きで保持し、既存pageからpayloadを補完しない
	if( value.recordSchemaVersion == 1U) {
		value.acquisitionDescriptorUnavailableReason = "record v1 has no acquisition descriptor" ;
		// v1の既知出典URLは引き続きquery未対応の元文法で検査する
		for( const auto *evidence :
			{&value.packageEvidence.publishedHash, &value.packageEvidence.calculatedHash}) {
			// UNKNOWNの空URLを出典へ補完しない
			if( !evidence->evidenceUrl.empty()) {
				requireEvidenceUrl( evidence->evidenceUrl) ;
			}
		}

		// 公開identityのv1根拠にも同じquery未対応を保持する
		if( !value.publishedIdentityEvidence.evidenceUrl.empty()) {
			requireEvidenceUrl( value.publishedIdentityEvidence.evidenceUrl) ;
		}
	}

	require( validIdentity( value.sourceId, 64U) && validIdentity( value.recordId, 64U) &&
				validText( value.product),
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	require( !value.lastSuccessfulObservationUtc.value ||
				*value.lastSuccessfulObservationUtc.value <= manifest.publishedAtUtc,
			IndexRecordsStatus::INVALID_EVIDENCE) ;
	// 内容検査の元申告には実byte由来の計算hash・size・成功観測を要求する
	if( value.inspectionStage == IndexInspectionStage::CONTENT_INSPECTED) {
		require( value.packageEvidence.calculatedHash.sha256.has_value() &&
					value.packageEvidence.size.value.has_value() &&
					value.lastSuccessfulObservationUtc.value.has_value(),
				IndexRecordsStatus::INVALID_EVIDENCE) ;
	}

	// 元INFと取得証拠の検査が成立した後で対象集合を確認します
	if( value.catalogHardwareScope) {
		bindCatalogHardwareScope( value) ;
	}

	// 機種別条件は同行の配布表、Server条件と元Modelsへ結びます
	if( value.platformDeviceScope) {
		bindPlatformDeviceScope( value) ;
		// 同じ公式群に該当する元Modelsの対象全件を要求します
		if( !value.platformFirmwareGroups.empty()) {
			validatePlatformFirmwareTargets( value) ;
		}
	}

	value.recordSha256	= digest ;
	value.originalBytes = std::move( raw) ;
	return value ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原record byteを既存1MiB共通hash APIで実SHA-256へ結合します
 * @param[in] raw 64KiB以下のdecode原byte
 * @return 原byteの実digest。再serializationしません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexManifestSha256 hashRecord( const std::string_view raw)
{
	std::wstring	  hex ;										// 共通APIが返す実digest
	const NativeError error = computeBytesSha256( raw, hex) ;	// 元診断値
	// API障害を入力hash不一致へ読み替えない
	if( error != 0) {
		throw Failure{error == static_cast<NativeError>( E_OUTOFMEMORY)
						  ? IndexRecordsStatus::OUT_OF_MEMORY
						  : IndexRecordsStatus::CRYPTO_FAILURE,
					  error} ;
	}

	std::string narrow ;	// 共通hexをASCIIのまま固定型へ渡す値
	narrow.reserve( hex.size()) ;
	// 全小文字hex桁を値を変えずcopyし、共通戻り値の形式も検査する
	for( const wchar_t character : hex) {
		require( (character >= L'0' && character <= L'9') ||
					(character >= L'a' && character <= L'f'),
				IndexRecordsStatus::CRYPTO_FAILURE) ;
		narrow.push_back( static_cast<char>( character)) ;
	}

	return decodeHash( narrow, IndexRecordsStatus::CRYPTO_FAILURE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一entryを厳格base64／原hashへ結合してからrecord schemaを読みます
 * @param[in,out] reader Index原byteの共通reader
 * @param[in,out] totalBytes Decode原record合計byte数。上限内でだけ加算します
 * @param[in] manifest 原認証manifest
 * @param[in] area 原レコードが所属する署名領域です
 * @return 原byteに結合した型付きrecord
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexDistributionRecord readEntry( Reader &reader, std::size_t &totalBytes,
												const IndexManifestData &manifest,
												const RecordArea		 area)
{
	constexpr std::array<std::string_view, 2U> FIELDS{"recordBytesBase64",
													  "recordSha256"} ;	// 必須field
	std::array<std::string, 2U>				   values ;					// 原base64と申告hash
	// Decoderへ進む前にもencoded実byte枠を守る同期handler
	reader.object( FIELDS, [&]( const std::size_t field) {
		values[field] = reader.text( field == 0U ? RECORD_BASE64_MAX_BYTES : 64U) ;
	}) ;
	const auto bytes = signed_index_json::decodeBase64(
		values[0], INDEX_RECORD_MAX_BYTES, IndexRecordsStatus::RECORD_SIZE_LIMIT,
		IndexRecordsStatus::INVALID_BASE64) ;	// 元順序のdecode結果
	require( bytes.size() <= INDEX_RECORD_TOTAL_MAX_BYTES - totalBytes,
			IndexRecordsStatus::TOTAL_RECORD_SIZE_LIMIT) ;
	totalBytes += bytes.size() ;
	std::string raw( bytes.begin(), bytes.end()) ;	// 原UTF-8。正規化しない
	const auto	digest = hashRecord( raw) ;			// 原byteだけの実digest
	require( digest == decodeHash( values[1], IndexRecordsStatus::INVALID_RECORD),
			IndexRecordsStatus::RECORD_HASH_MISMATCH) ;
	return readRecord( std::move( raw), digest, manifest, area) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 実件数の全5fieldを署名qualityへ厳格に照合します
 * @param[in] actual 読み取ったsource／record／stage件数
 * @param[in] signedQuality 認証manifestの発行側集計
 * @return 全5fieldが完全一致する場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool sameQuality( const IndexManifestQuality &actual,
							   const IndexManifestQuality &signedQuality) noexcept
{
	return actual.sourceCount == signedQuality.sourceCount &&
		   actual.recordCount == signedQuality.recordCount &&
		   actual.metadataOnlyCount == signedQuality.metadataOnlyCount &&
		   actual.contentInspectedCount == signedQuality.contentInspectedCount &&
		   actual.unconfirmedCount == signedQuality.unconfirmedCount ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 同じ元Modelsを一部の完全Hardware IDに限定する対象条件を確認します
 * @param[in] record 借用する型付き元レコードです
 * @return Catalog、機種別又は公式配布ZIPの対象条件がある場合trueです
 */
//------------------------------------------------------------------------------
bool isIndexHardwareScoped( const IndexDistributionRecord &record) noexcept
{
	return record.catalogHardwareScope || record.platformDeviceScope || record.archiveHardwareScope ;
}

//------------------------------------------------------------------------------
/**
 * @brief 端末のHardwareIdsだけを照合する必要があるレコードを判定します
 * @param[in] record 認証済みの配布条件を保持する借用レコードです
 * @return 元Modelsの対象条件又は私有WiXの配布証拠がある場合trueです
 * @note 署名の確認や照合結果の発行は行いません
 */
//------------------------------------------------------------------------------
bool requiresExactIndexHardwareMatch( const IndexDistributionRecord &record) noexcept
{
	return record.wixContentEvidence || isIndexHardwareScoped( record) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元ModelsのIDがWiX配布の完全Hardware IDとして照合対象になるか判定します
 * @param[in] id 共通codecで構造を確認した元ModelsのIDです
 * @return Hardware ID種別であり、ワイルドカードのない場合trueです
 * @note 端末IDや接続機器は読み取りません
 */
//------------------------------------------------------------------------------
bool isExactWixHardwareId( const IndexPublishedPnpId &id) noexcept
{
	return id.kind == IndexPnpIdKind::HARDWARE && id.value.find( '*') == id.value.npos ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ元PnPインスタンスのHardwareIds全体と元Modelsから公式群を判定します
 * @param[in] record 署名・対象位置・公式群が検査済みの元レコードです
 * @param[in] hardwareIds 同じ端末で完全読取りした大文字のHardwareIdsです
 * @return 完全対象なし、元群の一意一致、異なる群の競合、または判定不能です
 * @note 対象位置は署名付きの完全PCI Hardware IDに結び、原端末IDを返しません
 */
//------------------------------------------------------------------------------
IndexPlatformFirmwareMatch classifyIndexPlatformFirmwareGroup(
	const IndexDistributionRecord &record, const std::span<const std::wstring> hardwareIds) noexcept
{
	using State = IndexPlatformFirmwareMatchState ;
	// 公式群と元Models位置を保持する形式だけを扱います
	if( record.recordSchemaVersion != 5U || !record.platformDeviceScope ||
	   record.platformFirmwareGroups.empty() ||
	   record.platformDeviceScope->hardwareIdIndices.empty()) {
		return {} ;
	}

	const auto &modelIds = record.publishedIdentityEvidence.pnpIds ;	// 署名済みの元Modelsです
	const auto &groups	 = record.platformFirmwareGroups ;				// 同じ配布表の元群です
	std::optional<std::size_t> matchedGroup ;							// 最初に一致した公式群です
	try {
		const auto &pci = platformHardwareIdPattern() ;	// 完全IDからsubsystemを取得します
		// 同一端末の全HardwareIdsと署名済みの各完全対象を比較します
		for( const std::size_t position : record.platformDeviceScope->hardwareIdIndices) {
			// 対象位置と種別は署名済みの元Modelsに結び付きます
			if( position >= modelIds.size() || modelIds[position].kind != IndexPnpIdKind::HARDWARE) {
				return {} ;
			}

			const auto key =
				// 大文字で揃えた署名済みIDです
				pnpIdComparisonKey( modelIds[position].value) ;
			// 配布と端末の文字型が異なるため、正規化後の全コード単位を比較します
			const auto sameId = [&key]( const std::wstring &observed) {
				return std::equal( key.begin(), key.end(), observed.begin(), observed.end()) ;
			} ;
			// 部分文字列やCompatibleIdsへの一致は含めません
			if( !std::ranges::any_of( hardwareIds, sameId)) {
				continue ;
			}

			std::smatch parts ;	// 一致した完全IDのsubsystemを借用します
			// 元対象と一致しても完全形を再確認してから群へ進みます
			if( !std::regex_match( key, parts, pci)) {
				return {} ;
			}

			const auto subsystem =
				std::string_view{key}.substr( static_cast<std::size_t>( parts.position( 1U)),
											 // 同じ元IDの8桁です
											 static_cast<std::size_t>( parts.length( 1U))) ;
			// 元表のsubsystem割当から公式群を求めます
			const auto group = std::ranges::find_if( groups, [subsystem]( const auto &candidate) {
				return std::ranges::find( candidate.subsystemIds, subsystem) !=
					   candidate.subsystemIds.end() ;
			}) ;
			// 署名済み完全対象は元表のいずれかの群に属します
			if( group == groups.end()) {
				return {} ;
			}

			const auto index = static_cast<std::size_t>( group - groups.begin()) ;	// 元群位置です
			// 必須版の表記が同じでも異なる群を統合しません
			if( matchedGroup && *matchedGroup != index) {
				return {State::AMBIGUOUS, {}} ;
			}

			matchedGroup = index ;
		}
	} catch( const std::bad_alloc &) {
		return {} ;
	} catch( const std::regex_error &) {
		return {} ;
	}

	return {matchedGroup ? State::UNIQUE : State::NO_MATCH, matchedGroup} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Schema・参照・hash・qualityの全成功後に値を所有します
 * @param[in] asset 認証済みbyte receiptの所有copy
 * @param[in] sources 検査した所有source
 * @param[in] records 検査した所有record
 * @param[in] quality 実source／record／stage件数
 */
//------------------------------------------------------------------------------
IndexRecordsSchemaReceipt::IndexRecordsSchemaReceipt( AuthenticatedIndexAssetBytes		  asset,
													 std::vector<IndexRecordSource>		  sources,
													 std::vector<IndexDistributionRecord> records,
													 const IndexManifestQuality quality) noexcept
	: asset_( std::move( asset)), sources_( std::move( sources)), records_( std::move( records)),
	  quality_( quality)
{
}

//------------------------------------------------------------------------------
/**
 * @brief 認証byte receiptを変更できない参照で借用します
 * @return 本receiptの寿命まで有効なbyte receipt
 */
//------------------------------------------------------------------------------
const AuthenticatedIndexAssetBytes &IndexRecordsSchemaReceipt::assetBytes() const noexcept
{
	return asset_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 展開index原byteのhashを借用します
 * @return 圧縮hashと各record hashから独立したdigest
 */
//------------------------------------------------------------------------------
const IndexManifestSha256 &IndexRecordsSchemaReceipt::indexSha256() const noexcept
{
	return asset_.expandedSha256() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元申告のsource集合を借用します
 * @return 本receiptの寿命まで有効な不変span
 */
//------------------------------------------------------------------------------
std::span<const IndexRecordSource> IndexRecordsSchemaReceipt::sources() const noexcept
{
	return sources_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原byteに結合したrecord集合を借用します
 * @return 本receiptの寿命まで有効な不変span。端末適合は未評価です
 */
//------------------------------------------------------------------------------
std::span<const IndexDistributionRecord> IndexRecordsSchemaReceipt::records() const noexcept
{
	return records_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名quality全fieldに一致した実件数を借用します
 * @return 発行側の段階別件数。端末の実検査件数ではありません
 */
//------------------------------------------------------------------------------
const IndexManifestQuality &IndexRecordsSchemaReceipt::actualQuality() const noexcept
{
	return quality_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 読取りを実行した現codec policy版を返します
 * @return 現reader revisionの2。保存head互換値とwire record版とは別です
 */
//------------------------------------------------------------------------------
std::uint32_t IndexRecordsSchemaReceipt::schemaPolicyVersion() const noexcept
{
	return INDEX_RECORD_READER_POLICY_VERSION ;
}

//------------------------------------------------------------------------------
/**
 * @brief 認証済みbyteだけから配布schema・原record hash・参照・qualityを読みます
 * @param[in] asset 呼出し中不変で完全な前段byte receipt。DTOや未認証byteは受理しません
 * @param[in] nowUtc 信頼UTCの再確認。発行前・期限以上・確認不能は拒否します
 * @return 全検査成功時だけschema receipt。拒否は理由と元診断を保持します
 * @note 独立入力では同時呼出し可能です。Network・保存・highwater更新・端末ID・通常UI・導入は扱いません
 */
//------------------------------------------------------------------------------
IndexRecordsResult readSignedIndexRecords(
	const AuthenticatedIndexAssetBytes			 &asset,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	const auto &manifest = asset.manifest().data() ;	// 前段が所有する認証済み値
	const auto	expanded = asset.expandedBytes() ;		// 前段の検査済み原UTF-8候補
	// Move元の不完全receiptや必須根拠欠損をscalarと残hashだけで受理しない
	if( manifest.manifestBytes.empty() || manifest.repository.empty() || manifest.channel.empty() ||
	   manifest.keyId.empty() || manifest.asset.tag.empty() || manifest.asset.name.empty() ||
	   expanded.empty() || asset.bytePolicyVersion() != INDEX_ASSET_BYTE_POLICY_VERSION ||
	   asset.maximumExpandedBytes() == 0U || expanded.size() > asset.maximumExpandedBytes()) {
		return {IndexRecordsStatus::INCOMPLETE_BYTE_RECEIPT, 0, std::nullopt} ;
	}

	auto decoded = signed_index_detail::decodeIndexRecordsData( manifest, expanded,
															   nowUtc) ;	// 同じ全値検査です
	// 前段認証済みassetを所有するwrapperだけがschema receiptを構築します
	if( !decoded.data) {
		return {decoded.status, decoded.error, std::nullopt} ;
	}

	return {IndexRecordsStatus::SCHEMA_VALIDATED, 0,
			IndexRecordsSchemaReceipt{asset, std::move( decoded.data->sources),
									  std::move( decoded.data->records), decoded.data->quality}} ;
}

namespace {

/** @brief 署名された元証拠と、その証拠を参照したModels節です */
struct ScopedModelsEntry {
	/// 検査した元文です
	std::shared_ptr<const signed_index_detail::CollectorScopedModelsEvidence> proof ;
	/// 同元証拠内の一意な参照です
	std::set<std::wstring_view>												  usedSections ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 専用欄の一証拠を原base64と実SHA-256から型付きで読みます
 * @param[in,out] reader 専用欄の原値のreaderです
 * @return 収集時の元文・完全な配布物・元Modelsを保つ不変証拠です
 * @throws Failure 原文又は申告hashの不成立です
 */
//------------------------------------------------------------------------------
[[nodiscard]] ScopedModelsEntry readScopedModelsProof( Reader &reader)
{
	// 公式Models証拠の実バイトと照合用SHA-256を結び付ける二つの欄
	constexpr std::array<std::string_view, 2U> fields{"evidenceBytesBase64", "evidenceSha256"} ;
	std::array<std::string, fields.size()>	   values ;	// 元文のbase64とhashです
	reader.object( fields, [&]( const std::size_t field) {
		values[field] = reader.text( field == 0U ? RECORD_BASE64_MAX_BYTES : 64U) ;
	}) ;
	// 元証拠として型付き読取りに渡す、容量制限付きの復号バイト
	const auto raw = signed_index_json::decodeBase64( values[0], INDEX_RECORD_MAX_BYTES,
													 IndexRecordsStatus::RECORD_SIZE_LIMIT,
													 IndexRecordsStatus::INVALID_BASE64) ;
	// 実SHA-256とすべての欄を確認した元証拠のデコード結果
	auto	   decoded = signed_index_detail::decodeCollectorScopedModelsEvidence(
		  std::string_view{reinterpret_cast<const char *>( raw.data()), raw.size()},
		  decodeHash( values[1], IndexRecordsStatus::INVALID_EVIDENCE)) ;
	// 元バイトや内容を検査できなかった場合は元の失敗を伝播します
	if( !decoded.data) {
		throw Failure{decoded.status, decoded.error} ;
	}

	return {std::make_shared<const signed_index_detail::CollectorScopedModelsEvidence>(
				std::move( *decoded.data)),
			{}} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ配布物・INF・OS・Models節の原証拠をv6配布行へ結合します
 * @param[in,out] record 同欄で原byteとhashを検査したv6レコードです
 * @param[in] source 同じ欄から原参照で解決した取得元です
 * @param[in,out] entry 同欄で原byteとhashを検査した証拠と参照済み節です
 * @throws Failure 元配布物・元時刻・元OS・節のいずれかが一致しません
 */
//------------------------------------------------------------------------------
void bindScopedModelsProof( IndexDistributionRecord &record, const IndexRecordSource &source,
						   ScopedModelsEntry &entry)
{
	// 元証拠と索引行の結合が成立しない場合に使用する診断区分
	constexpr auto invalid = IndexRecordsStatus::INVALID_EVIDENCE ;
	// 元配布と明示OSを検査した同じ証拠。同期照合中だけ借用します
	const auto	  &proof = *entry.proof ;
	// 配布行が保持する元のモデルとクラスの識別証拠
	const auto	  &identity = record.publishedIdentityEvidence ;
	// 同じ配布行が持つパッケージのハッシュと元署名の情報
	const auto	  &package = record.packageEvidence ;
	// 元のCatalog観測時刻を使って検証した取得条件
	const auto	  &descriptor = scopedAcquisition( record, proof.catalog.observedAtUtc) ;
	std::string infHex( proof.models.infSha256.size(), '\0') ;	// 元証拠で確認したASCII小文字hexです
	std::ranges::transform( proof.models.infSha256, infHex.begin(),
						   []( const wchar_t digit) { return static_cast<char>( digit) ; }) ;
	// 署名済みの元Models証拠へ照合するレコード側の元INFハッシュ
	const auto infHash = decodeHash( infHex, invalid) ;
	require( descriptor.format == IndexPayloadFormat::CABINET && !descriptor.resourceContent &&
				!descriptor.attestation->manualReview && package.size.value == proof.archiveBytes &&
				proof.archiveBytes <= descriptor.maximumBytes &&
				package.publishedHash.sha256 == proof.archiveSha256 &&
				package.calculatedHash.sha256 == proof.archiveSha256 &&
				identity.nestedArchiveIdentity == proof.nestedArchiveIdentity &&
				identity.infIdentity == proof.infIdentity && identity.evidenceSha256 == infHash &&
				pnpIdComparisonKey( identity.classGuid) == pnpIdComparisonKey( proof.classGuid),
			invalid) ;

	using signed_index_acquisition::catalogDownloadDialogUpdateId ;
	const auto downloadId =
		// 元配布票にある更新IDです
		catalogDownloadDialogUpdateId( source.distributionPage) ;
	// 正規配布票を使うレコードは、明細と同じ公開更新の一応答だけを導線とハッシュの出典にします
	if( !downloadId.empty() ||
	   !catalogDownloadDialogUpdateId( package.publishedHash.evidenceUrl).empty() ||
	   !catalogDownloadDialogUpdateId( descriptor.attestation->authorityEvidenceUrl).empty() ||
	   std::ranges::any_of( descriptor.route, []( const auto &hop) {
		   return !catalogDownloadDialogUpdateId( hop.evidenceUrl).empty() ;
	   })) {
		const auto detailId =
			// 元配布明細にある更新IDです
			catalogUpdateIdFromDetailsUrl( proof.catalog.detailsUrl) ;
		const auto &official	= source.officialEvidence ;	// 同配布票原応答の署名済み出典です
		const auto &attestation = *descriptor.attestation ;	// 同導線の原時刻と出典です
		require( !downloadId.empty() && detailId == downloadId &&
					official.kind == IndexOfficialEvidenceKind::OFFICIAL_PAGE &&
					official.evidenceSha256 && descriptor.route.size() == 1U &&
					descriptor.route.front().evidenceUrl == source.distributionPage &&
					descriptor.route.front().evidenceSha256 == official.evidenceSha256 &&
					attestation.authorityEvidenceUrl == source.distributionPage &&
					attestation.authorityEvidenceSha256 == official.evidenceSha256 &&
					package.publishedHash.evidenceUrl == source.distributionPage &&
					package.publishedHash.evidenceSha256 == official.evidenceSha256 &&
					package.calculatedHash.evidenceUrl == descriptor.payloadUrl &&
					package.calculatedHash.evidenceSha256 == package.calculatedHash.sha256,
				invalid) ;
	}

	// 同じ元INFのModelsを収集した時点で指定されたWindows観測点
	const auto &platform = *proof.models.platform ;
	// Serverでは証拠のビルドと公式Server製品条件の対応を要求します
	if( record.targetOs.value == IndexTargetOs::WINDOWS_SERVER) {
		// 配布行で対象となるWindows Serverの明示リリースと制約
		const auto server = readServerIndexScope( identity, descriptor.prerequisites) ;
		require( server && serverIndexModelsPlatform( *server) == platform, invalid) ;
	} else {
		// 証拠を採取したクライアントのビルドに対応する索引上の対象OS
		const auto expected =
			platform.buildNumber == 19045U ? IndexTargetOs::WINDOWS_10 : IndexTargetOs::WINDOWS_11 ;
		require( platform.productType == 1U && record.targetOs.value == expected, invalid) ;
	}

	// 照合に使う元節名を厳格なWindows文字列へ変換した値
	const auto modelSection = decodeModelsName( identity.modelSection) ;
	// 同じ元INFの証拠中で配布行の元節名と一致する位置
	const auto section = std::ranges::find( proof.models.sections, modelSection,
										   &OfficialInfScopedModelsSection::modelSection) ;
	require( section != proof.models.sections.end() && !section->matches.empty() &&
				std::ranges::equal( identity.pnpIds, section->matches,
								   []( const auto &id, const auto &match) {
									   return id.kind == IndexPnpIdKind::HARDWARE &&
											  std::ranges::equal( id.value, match.hardwareId) ;
								   }),
			invalid) ;
	require( entry.usedSections.emplace( section->modelSection).second,
			IndexRecordsStatus::CATALOG_SCOPE_CONFLICT) ;
	record.catalogHardwareScope = proof.catalog ;
	bindCatalogHardwareScope( record) ;
	record.scopedModelsEvidence = entry.proof ;
}

//------------------------------------------------------------------------------
/**
 * @brief 展開byteの原record/schema/参照と署名qualityを共通codecで検査します
 * @param[in] manifest 同じ原manifestの検査済み値です
 * @param[in] expanded 同じasset値codecの展開byteです
 * @param[in] nowUtc 確認済みUTCです
 * @param[in] area 本文、DC又はDMの閉じた文法です
 * @return 未認証の全値結果です。署名receiptは構築しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] signed_index_detail::DecodedIndexRecords decodeIndexRecords(
	const IndexManifestData &manifest, const std::span<const std::byte> expanded,
	const std::optional<std::chrono::sys_seconds> nowUtc, const RecordArea area) noexcept
{
	// 時刻確認不能ではschema成功を生成しない
	if( !nowUtc) {
		return {IndexRecordsStatus::TIME_UNAVAILABLE, 0, std::nullopt} ;
	}

	// 認証後も発行前の時刻を補正して成功にしない
	if( *nowUtc < manifest.publishedAtUtc) {
		return {IndexRecordsStatus::NOT_YET_VALID, 0, std::nullopt} ;
	}

	// 期限ちょうどからはschema読取りも成功にしない
	if( *nowUtc >= manifest.expiresAtUtc) {
		return {IndexRecordsStatus::EXPIRED, 0, std::nullopt} ;
	}

	// 実原index byteは前段枠を独立に確認する
	if( expanded.size() > INDEX_ASSET_EXPANDED_MAX_BYTES) {
		return {IndexRecordsStatus::INDEX_SIZE_LIMIT, 0, std::nullopt} ;
	}

	try {
		const bool additional	= area != RecordArea::BASE ;			// 追加領域は旧本文のqualityと独立です
		const bool scopedModels = area == RecordArea::SCOPED_MODELS ;	// 原証拠を持つ専用欄です
		require( manifest.quality.sourceCount <= INDEX_RECORD_SOURCE_MAX_COUNT &&
					manifest.quality.recordCount <= INDEX_RECORD_MAX_COUNT,
				IndexRecordsStatus::COUNT_LIMIT) ;
		// 原byteのobject representationだけを共通parserへ借用する境界です
		const std::string_view original{reinterpret_cast<const char *>( expanded.data()),
										expanded.size()} ;
		Reader				   reader( original, IndexRecordsStatus::INVALID_INDEX,
									  // 正規化しないindex reader
									  static_cast<std::size_t>( INDEX_ASSET_EXPANDED_MAX_BYTES)) ;
		constexpr std::array<std::string_view, 5U> FIELDS{
			"schema", "assetGeneration", "sources", "records", "proofs"} ;	// DMだけに証拠があります
		std::uint64_t						 generation{} ;					// 原indexが申告したasset世代
		std::size_t							 totalPublicIds{} ;				// 全recordの公開入力総数です
		std::size_t							 totalBytes{} ;					// Decode原record合計実byte
		std::vector<IndexRecordSource>		 sources ;						// 全参照検査まで公開しないsource集合
		std::vector<IndexDistributionRecord> records ;						// 原byteを所有した有限record集合
		std::map<IndexManifestSha256, ScopedModelsEntry> proofs ;			// 同欄の元証拠と参照状況です
		std::string										 schema ;			// Outer field順に依存しないwire版
		// Field順を固定せず型付きschemaと独立件数枠を検査する同期handler
		const auto fields = reader.objectWithPresence( FIELDS, [&]( const std::size_t field) {
			// Schemaごとの型を維持し、未登録fieldは共通readerが拒否する
			switch( field) {
				// 新配布schemaだけを受理する
				case 0U:
					schema = reader.text( 64U) ;
					break ;

				// 署名manifestと照合する原asset世代
				case 1U:
					generation = reader.number() ;
					break ;

				// 有限sourceを元順序どおり読む
				case 2U:
					reader.array(
						INDEX_RECORD_SOURCE_MAX_COUNT,
						[&] {
							const auto raw = reader.originalValue(
								[&] { sources.push_back( readSource( reader, scopedModels)) ; }) ;
							// 追加欄の取得元は元の署名前バイトを比較用に保持します
							if( additional) {
								sources.back().originalBytes.assign( raw) ;
							}
						},
						IndexRecordsStatus::COUNT_LIMIT) ;
					break ;

				// 各原record byteと実hashを別々に検査する
				case 3U:
					reader.array(
						INDEX_RECORD_MAX_COUNT,
						[&] {
							auto record =
								// 原hashを含む一件です
								readEntry( reader, totalBytes, manifest, area) ;
							require( record.publishedIdentityEvidence.pnpIds.size() <=
										index_capacity::WHOLE_PUBLIC_IDS - totalPublicIds,
									IndexRecordsStatus::INPUT_COUNT_LIMIT) ;
							totalPublicIds += record.publishedIdentityEvidence.pnpIds.size() ;
							records.push_back( std::move( record)) ;
						},
						IndexRecordsStatus::COUNT_LIMIT) ;
					break ;

				// 証拠一覧は公式Models専用の索引形式でだけ受理します
				case 4U:
					require( scopedModels, IndexRecordsStatus::INVALID_INDEX) ;
					reader.array(
						INDEX_RECORD_MAX_COUNT,
						[&] {
							auto	   entry = readScopedModelsProof( reader) ;
							const auto hash	 = entry.proof->evidenceSha256 ;
							require( proofs.emplace( hash, std::move( entry)).second,
									IndexRecordsStatus::INVALID_EVIDENCE) ;
						},
						IndexRecordsStatus::COUNT_LIMIT) ;
					break ;

				// 未登録番号を成功へ変換しない
				default:
					throw Failure{IndexRecordsStatus::INVALID_INDEX} ;
			}
		}) ;
		reader.finish() ;
		// 本文、追加欄、公式Models専用欄の識別子と必須欄集合の照合結果
		const bool validSchema =
			scopedModels
				? fields == 31U && schema == "driver-index-records-scoped-models-v1"
				: fields == 15U && (additional ? schema == "driver-index-records-supplement-v1"
											   : schema == "driver-index-records-v1" ||
													 schema == "driver-index-records-v2") ;
		require( validSchema, IndexRecordsStatus::INVALID_INDEX) ;
		require( generation == manifest.assetGeneration,
				IndexRecordsStatus::ASSET_GENERATION_MISMATCH) ;
		std::map<std::string, std::pair<std::size_t, bool>>
			sourceMap ;	// 一意source位置と参照済み状態
		// 全source identityを完全一致で登録し、重複を黙ってまとめない
		for( std::size_t index = 0U; index < sources.size(); ++index) {
			// 旧outerでは旧PAGE query未対応を維持し、順序に依存してv2へ昇格しない
			if( schema == "driver-index-records-v1") {
				// v1 sourceの全非空URLだけを旧文法へ照合する
				for( const auto *url :
					{&sources[index].officialOrigin, &sources[index].distributionPage,
					 &sources[index].officialEvidence.evidenceUrl}) {
					// UNKNOWNの空値を既知URLにしない
					if( !url->empty()) {
						requireEvidenceUrl( *url) ;
					}
				}
			}

			require( sourceMap.emplace( sources[index].sourceId, std::pair{index, false}).second,
					IndexRecordsStatus::DUPLICATE_SOURCE) ;
		}

		std::set<std::pair<std::string, std::string>>
							 recordIdentities ;	// Source内の原record identity集合
		IndexManifestQuality quality ;			// 署名qualityへ照合する実件数
		quality.sourceCount = sources.size() ;
		quality.recordCount = records.size() ;
		// 全recordを同じsourceへ結合し、実三段階件数を欠落なく数える
		for( auto &record : records) {
			require( schema != "driver-index-records-v1" || record.recordSchemaVersion == 1U,
					IndexRecordsStatus::INVALID_RECORD) ;
			require( recordIdentities.emplace( record.sourceId, record.recordId).second,
					IndexRecordsStatus::DUPLICATE_RECORD) ;
			const auto source = sourceMap.find( record.sourceId) ;	// 原source参照の一意位置
			require( source != sourceMap.end(), IndexRecordsStatus::MISSING_SOURCE) ;
			source->second.second = true ;
			signed_index_acquisition::validateBinding( record, sources[source->second.first],
													  manifest) ;
			// 公式Models行は各元証拠ハッシュに解決してから利用できる形にします
			if( scopedModels) {
				// この配布行が指定した元証拠の格納位置
				const auto proof = proofs.find( *record.scopedModelsEvidenceSha256) ;
				require( proof != proofs.end(), IndexRecordsStatus::INVALID_EVIDENCE) ;
				bindScopedModelsProof( record, sources[source->second.first], proof->second) ;
			}

			// Catalogの対象条件は同じ公式Catalog起点のレコードだけに適用します
			if( record.catalogHardwareScope) {
				require( sources[source->second.first].officialOrigin ==
							"https://www.catalog.update.microsoft.com/",
						IndexRecordsStatus::INVALID_EVIDENCE) ;
			}

			// 機種別配布表は同行の元取得元と同じ公式ページ本文に結びます
			if( record.platformDeviceScope) {
				auto	   &scope	 = *record.platformDeviceScope ;	// 元配布条件です
				const auto &origin	 = sources[source->second.first] ;	// 同じ署名領域の取得元です
				const auto &official = origin.officialEvidence ;		// 元ページです
				require( official.kind == IndexOfficialEvidenceKind::OFFICIAL_PAGE &&
							official.evidenceUrl == scope.pageUrl &&
							official.evidenceSha256 == scope.pageSha256,
						IndexRecordsStatus::INVALID_EVIDENCE) ;
				constexpr std::string_view LENOVO_SERVER_ORIGIN =
					"https://windows-server.lenovo.com/" ;	// 型番を発行する公式配布元です
				// 署名済み取得元と元表が同じ公式起点を指す場合だけ型番の発行元を確定します
				if( origin.officialOrigin == LENOVO_SERVER_ORIGIN &&
				   scope.pageUrl.starts_with( LENOVO_SERVER_ORIGIN)) {
					scope.machineVendor = IndexPlatformMachineVendor::LENOVO ;
				}
			}

			// 公式配布ZIPの完全IDと機器確認を同じ原ページに結びます
			if( record.archiveHardwareScope) {
				bindArchiveHardwareScope( record, sources[source->second.first]) ;
			}

			// WiXの元配布条件と規約を別の原レコードへ転用しません
			if( record.wixContentEvidence) {
				bindWixContentEvidence( record, sources[source->second.first]) ;
			}

			// 公開identityは同sourceの公開申告へ結合するが、公式性を実証しない
			if( record.publishedIdentityEvidence.state == IndexEvidenceState::PUBLISHED) {
				require( sources[source->second.first].officialEvidence.state ==
							IndexEvidenceState::PUBLISHED,
						IndexRecordsStatus::INVALID_EVIDENCE) ;
			}

			// 元申告stageごとに実件数を一つだけ数え、UNKNOWNを成功へ変換しない
			switch( record.inspectionStage) {
				// 未確認は不足のまま集計する
				case IndexInspectionStage::UNCONFIRMED:
					++quality.unconfirmedCount ;
					break ;

				// Metadata段階だけを別集計する
				case IndexInspectionStage::METADATA_ONLY:
					++quality.metadataOnlyCount ;
					break ;

				// 発行側の内容検査申告を端末実績へ変換しない
				case IndexInspectionStage::CONTENT_INSPECTED:
					++quality.contentInspectedCount ;
					break ;
			}
		}

		// 全sourceが一record以上へ結合していることを確認する
		for( const auto &source : sourceMap) {
			require( source.second.second, IndexRecordsStatus::UNREFERENCED_SOURCE) ;
		}

		// 同じ元配布を複数証拠へ割り当てず、対象を持つ各節に一行だけを結びます
		std::set<
			std::tuple<IndexManifestSha256, std::string, std::string, std::uint32_t, std::uint8_t>>
			proofIdentities ;
		// 検証したすべての元証拠について、同じ観測点で署名済み配布行がそろうことを確認します
		for( const auto &[hash, entry] : proofs) {
			// 現在照合している元Models証拠。検査中だけ借用します
			const auto &proof = *entry.proof ;
			// 同じ証拠の全Models節に共通する明示OS観測点
			const auto &platform = *proof.models.platform ;
			require( proofIdentities
						.emplace( proof.archiveSha256,
								 pnpIdComparisonKey( proof.nestedArchiveIdentity),
								 pnpIdComparisonKey( proof.infIdentity), platform.buildNumber,
								 platform.productType)
						.second,
					IndexRecordsStatus::CATALOG_SCOPE_CONFLICT) ;
			// 元節の全公式対象が配布行に対応し、空の観測節を混同していないことを確認します
			for( const auto &section : proof.models.sections) {
				require( section.matches.empty() ||
							entry.usedSections.contains( section.modelSection),
						IndexRecordsStatus::INVALID_EVIDENCE) ;
			}
		}

		require( additional || sameQuality( quality, manifest.quality),
				IndexRecordsStatus::QUALITY_MISMATCH) ;
		return {IndexRecordsStatus::SCHEMA_VALIDATED, 0,
				signed_index_detail::DecodedIndexRecordsData{std::move( sources), std::move( records),
															 quality}} ;
	} catch( const Failure &failure) {
		return {failure.status, failure.error, std::nullopt} ;
	} catch( const std::bad_alloc &) {
		return {IndexRecordsStatus::OUT_OF_MEMORY, static_cast<NativeError>( E_OUTOFMEMORY),
				std::nullopt} ;
	} catch( ...) {
		// Noexcept境界で未知障害を成功にせず、原診断に相当する固定失敗を保持する
		return {IndexRecordsStatus::INTERNAL_FAILURE, static_cast<NativeError>( E_UNEXPECTED),
				std::nullopt} ;
	}
}

/** @brief 元配布物SHA・内包位置・元INF位置とSHA・OS・architectureの組です */
using CatalogAliasCore = std::tuple<IndexManifestSha256, std::string, std::string,
									IndexManifestSha256, IndexTargetOs, IndexArchitecture> ;

//------------------------------------------------------------------------------
/**
 * @brief 別のsource・record・Models名で同じ元INFを示す行を比較可能にします
 * @param[in] record 原byteを検査済みの一レコードです
 * @return 配布物と元INFとOSの組です。必要な元根拠がない行は空です
 * @throws std::bad_alloc 比較用の原位置を確保できません
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<CatalogAliasCore> catalogAliasCore(
	const IndexDistributionRecord &record)
{
	const auto &identity = record.publishedIdentityEvidence ;	// 同行の元INF根拠です
	const auto &payload =
		record.packageEvidence.calculatedHash.sha256 ;	// 発行側が検査した元byteです
	// 既知の元INFと配布物の完全な組だけを比較します
	if( !payload || identity.kind != IndexIdentityEvidenceKind::INF || !identity.evidenceSha256 ||
	   !record.targetOs.value || !record.architecture.value) {
		return std::nullopt ;
	}

	return CatalogAliasCore{*payload,
							pnpIdComparisonKey( identity.nestedArchiveIdentity),
							pnpIdComparisonKey( identity.infIdentity),
							*identity.evidenceSha256,
							*record.targetOs.value,
							*record.architecture.value} ;
}

//------------------------------------------------------------------------------
/**
 * @brief 既知のWindows Server範囲を版とproductに分けます
 * @param[in] record 同じ原OSと元INFを持つレコードです
 * @return Clientは固定値、Serverは版とproduct、不明のServerでは空です
 * @throws std::bad_alloc Server条件の所有文字列を確保できません
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::pair<ServerIndexRelease, std::uint8_t>> catalogAliasPlatform(
	const IndexDistributionRecord &record)
{
	// Client同士は元OSが上位の比較値に含まれます
	if( record.targetOs.value != IndexTargetOs::WINDOWS_SERVER) {
		return std::pair{ServerIndexRelease::UNKNOWN, std::uint8_t{}} ;
	}

	const auto scope = record.acquisitionDescriptor
						   ? readServerIndexScope( record.publishedIdentityEvidence,
												  record.acquisitionDescriptor->prerequisites)
						   : std::nullopt ;	// 同元INFに結ぶ既存のServer条件です
	return scope ? std::optional{std::pair{scope->release, scope->productType}} : std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同じ配布物の対象・Modelsが他の行で上書きされないことを検査します
 * @param[in] base 同じassetの構造検査済み本文です
 * @param[in] additional 本文と重複する元配布対象を照合する追加レコードです
 * @throws Failure 同じ配布物・元INF・適用OSに異なる範囲又はModelsの順序があります
 * @throws std::bad_alloc 有限な比較値を確保できません
 */
//------------------------------------------------------------------------------
void validateScopedAliases( std::span<const IndexDistributionRecord> base,
						   std::span<const IndexDistributionRecord> additional)
{
	/** @brief 同じZIPで保持する導入前確認と、その公式ページの原根拠です */
	struct ArchiveCondition {
		/// 同じZIPと機器の条件を示す公式ページです
		std::string_view	pageUrl ;
		/// 原ページのSHA-256です
		IndexManifestSha256 pageSha256{} ;
		/// 機器ごとに提示する原確認の説明です
		std::string_view	description ;
		/**
		 * @brief 観測を更新しても元ページの条件が一致するか確認します
		 * @param[in] other 同じZIPと適用範囲で比較することが確定した原条件です
		 * @return 元ページのURL・SHA-256と原確認が全て一致した場合trueです
		 */
		bool				operator==( const ArchiveCondition &other) const = default ;
	} ;
	/** @brief 同じ配布物・INF・適用OSで一致させる元配布対象です */
	struct Scope {
		/// Catalogは同じ元更新を示します
		std::string_view													 detailsUrl ;
		/// 機種別の場合の比較用の機種名です
		std::string															 model ;
		/// 元表で確認した全型番です
		std::set<std::string>												 machineTypes ;
		/// 比較用の全配布対象です
		std::set<std::string>												 hardwareIds ;
		/// 公式配布ZIPでだけ要求する元確認と公式ページです
		std::optional<ArchiveCondition>										 archive ;
		/// 群の境界と必須版・根拠が異なる別名を保持しません
		std::map<std::set<std::string>, std::pair<std::string, std::string>> firmwareGroups ;
		/**
		 * @brief 元配布対象の種別と条件を比較します
		 * @param[in] other 同じ元配布物と適用OSの比較対象です
		 * @return 条件の全項目が一致する場合trueです
		 */
		bool operator==( const Scope &other) const = default ;
	} ;
	/** @brief 同じ適用OSの配布対象と各Modelsの元ID群です */
	struct Group {
		/// 同じ元配布物の対象条件です
		Scope														  scope ;
		/// 元順序の比較先です
		std::map<std::string, const IndexPublishedIdentityEvidence *> models ;
	} ;
	constexpr auto catalogConflict =
		IndexRecordsStatus::CATALOG_SCOPE_CONFLICT ;	// 従来の対象競合です
	constexpr auto platformConflict =
		IndexRecordsStatus::PLATFORM_DEVICE_SCOPE_CONFLICT ;	// 機種別の対象競合です
	constexpr auto archiveConflict =
		IndexRecordsStatus::ARCHIVE_HARDWARE_SCOPE_CONFLICT ;	// 公式配布ZIPの対象競合です
	std::map<CatalogAliasCore, std::map<std::pair<ServerIndexRelease, std::uint8_t>, Group>>
		groups ;	// 元INFと適用OSの組です
	// 追加欄の対象範囲を先に登録し、入力の順番による後勝ちを防ぎます
	for( const auto &record : additional) {
		const auto &device	= record.platformDeviceScope ;	// 機種別の元配布条件です
		const auto &catalog = record.catalogHardwareScope ;	// Catalog更新の元配布条件です
		const auto &archive = record.archiveHardwareScope ;	// 公式配布ZIPの元配布条件です
		// 従来の追加レコードを新しい範囲に変換しません
		if( !isIndexHardwareScoped( record)) {
			continue ;
		}

		const auto core		= catalogAliasCore( record) ;		// 同じ物理配布物と元INFです
		const auto platform = catalogAliasPlatform( record) ;	// 正規のOS範囲です
		require( core && platform, archive  ? archiveConflict
								  : device ? platformConflict
										   : catalogConflict) ;
		Scope scope ;	// 原配布条件を比較用に保持します
		// 元月版の表URLが変わっても同じ機種・型番・対象を比較します
		if( device) {
			scope.model = pnpIdComparisonKey( device->model) ;
			scope.machineTypes.insert( device->machineTypes.begin(), device->machineTypes.end()) ;
			// 同じ版表記でも別群を併合せず、所属と元根拠を比較します
			for( const auto &firmware : record.platformFirmwareGroups) {
				scope.firmwareGroups.emplace(
					std::set<std::string>{firmware.subsystemIds.begin(),
										  firmware.subsystemIds.end()},
					std::pair{firmware.versionLabel, firmware.evidenceUrl}) ;
			}
		}
		// ZIPの利用者確認は配布ページ本文と原文の両方が同じ場合だけ再利用できます
		else if( archive) {
			const auto &items = record.acquisitionDescriptor->prerequisites.items ;	// 元の四条件です
			const auto	confirmation =
				std::ranges::find( items, IndexPrerequisiteKind::USER_CONFIRMATION,
								  &IndexAcquisitionPrerequisite::kind) ;	// 同行の機器確認です
			require( confirmation != items.end(), archiveConflict) ;
			scope.archive =
				ArchiveCondition{archive->pageUrl, archive->pageSha256, confirmation->description} ;
		} else {
			scope.detailsUrl = catalog->detailsUrl ;
		}

		// 原表の全対象を、元順序のまま持つ配布レコードと分けて比較します
		for( const auto &id : archive  ? archive->hardwareIds
							 : device ? device->packageHardwareIds
									  : catalog->packageHardwareIds) {
			scope.hardwareIds.insert( pnpIdComparisonKey( id)) ;
		}

		const auto [entry, inserted] = groups[*core].try_emplace( *platform) ;	// 同適用範囲です
		auto	  &group			 = entry->second ;							// 原配布物と適用OSが一致した行の集約先です
		// 入力の順によらず、専用の対象条件が競合した理由を保持します
		const auto conflict = archive || group.scope.archive		 ? archiveConflict
							  : device || !group.scope.model.empty() ? platformConflict
																	 : catalogConflict ;
		// 同じ機種条件の再観測は元配布表の月版、本文と時刻が変わり得ます
		if( inserted) {
			group.scope = std::move( scope) ;
		}
		// 別更新、機種、型番又は対象を同じ範囲に併記させません
		else {
			require( group.scope == scope, conflict) ;
		}

		const auto &identity	  = record.publishedIdentityEvidence ;	// 同じ行の全Modelsです
		const auto [model, first] = group.models.emplace( pnpIdComparisonKey( identity.modelSection),
														 &identity) ;	// 同じModels節の元証拠です
		require( first || std::ranges::equal(
							 model->second->pnpIds, identity.pnpIds,
							 []( const IndexPublishedPnpId &left, const IndexPublishedPnpId &right) {
								 return left.kind == right.kind &&
										pnpIdComparisonKey( left.value) ==
											pnpIdComparisonKey( right.value) ;
							 }),
				conflict) ;
	}

	// 対象付きの配布物がない旧索引は従来の検査だけを通します
	if( groups.empty()) {
		return ;
	}

	// 両欄の対象条件がない行を比較します。旧generic Serverは全版に重なります
	for( const auto records : {base, additional}) {
		// 同じ元配布物を別の行で表す場合も調べます
		for( const auto &record : records) {
			// 対象付き行の同士は上で比較済みです
			if( isIndexHardwareScoped( record)) {
				continue ;
			}

			const auto core	 = catalogAliasCore( record) ;					// 元配布物とINFの組が既知の場合だけです
			const auto group = core ? groups.find( *core) : groups.end() ;	// 同梱の対象条件です
			// 対象付きの行と元配布物が同じ場合だけ適用OSを照合します
			if( group != groups.end()) {
				const auto platform = catalogAliasPlatform( record) ;	// 旧Serverでは空になり得ます
				const auto overlappingArchive =
					std::ranges::any_of( group->second, [&]( const auto &entry) {
						return (!platform || entry.first == *platform) &&
							   entry.second.scope.archive.has_value() ;
					}) ; // 同じServer範囲に確認付き公式配布ZIPがあります
				const auto overlappingDevice =
					std::ranges::any_of( group->second, [&]( const auto &entry) {
						return (!platform || entry.first == *platform) &&
							   !entry.second.scope.model.empty() ;
					}) ; // 同じServer範囲に機種別配布がある場合です
				require( platform && !group->second.contains( *platform),
						overlappingArchive	? archiveConflict
						: overlappingDevice ? platformConflict
											: catalogConflict) ;
			}
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 同じWiX配布物を別条件で取得できるレコードを拒否する
 * @param[in] base 同じ署名assetの旧本文です
 * @param[in] additional 同じ署名assetの私有追加欄です
 * @throws Failure 同一EXEの別名に同じ言語別規約がありません
 * @throws std::bad_alloc 元ハッシュの比較集合を確保できません
 */
//------------------------------------------------------------------------------
void validateWixAliases( const std::span<const IndexDistributionRecord> base,
						const std::span<const IndexDistributionRecord> additional)
{
	std::map<IndexManifestSha256, const IndexWixContentEvidence *>
			   packages ;	// 実EXEのSHA-256ごとの原規約です
	const auto sameLicense = []( const IndexWixLicense &left, const IndexWixLicense &right) {
		return left.locale == right.locale && left.sha256 == right.sha256 &&
			   left.sizeBytes == right.sizeBytes && left.member.id == right.member.id &&
			   left.member.cabinetMember == right.member.cabinetMember &&
			   left.member.filePath == right.member.filePath ;
	} ; // 言語と元マニフェストが同じ原規約か比較します
	// v8は私有追加欄だけに存在し、入力順に依存せず先に全WiXを登録します
	for( const auto &record : additional) {
		// 元証拠を持つ行だけが同じEXEの規約を定義できます
		if( record.wixContentEvidence) {
			const auto &proof = *record.wixContentEvidence ;	// 元配布の型付き規約です
			// 同じ配布物の既存証拠と初回登録の有無を、取得条件の競合判定に使います
			const auto [entry, inserted] =
				packages.emplace( *record.packageEvidence.calculatedHash.sha256, &proof) ;
			require( inserted ||
						std::ranges::equal( entry->second->licenses, proof.licenses, sameLicense),
					IndexRecordsStatus::INVALID_EVIDENCE) ;
		}
	}

	// 同じEXEのv8がなければ従来の判定だけを実行します
	if( packages.empty()) {
		return ;
	}

	// 旧本文と追加欄の原行を走査し、通常書式で元規約を落とした別名を拒否します
	for( const auto records : {base, additional}) {
		// 計算値と公開値の両方を同じ元EXEとの照合に使います
		for( const auto &record : records) {
			const auto &calculated =
				record.packageEvidence.calculatedHash.sha256 ;	// 実取得の元観測です
			const auto &published =
				record.packageEvidence.publishedHash.sha256 ;	// 同じEXEに結び得る公表値です
			// 別名が同じEXEへ到達できる場合はWiX規約の経路を必須にします
			if( (calculated && packages.contains( *calculated)) ||
			   (published && packages.contains( *published))) {
				require( record.wixContentEvidence.has_value(),
						IndexRecordsStatus::INVALID_EVIDENCE) ;
			}
		}
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 旧索引と追加欄の原参照、共通上限、取得候補の元期限を検査します
 * @param[in] baseSources 同じassetの旧本文を構造検査した取得元集合です
 * @param[in] baseRecords 同じassetの旧本文を構造検査したレコード集合です
 * @param[in] additional 同assetの追加欄を構造検査した値です
 * @param[in] expiresAtUtc 追加欄の署名に結合した最短期限です
 * @param[in] nowUtc 確認済みの現在UTCです
 * @param[in] area 追加レコードを読んだ元領域です
 * @throws Failure 両領域で値が矛盾するか、必要な取得根拠が欠けています
 * @throws std::bad_alloc 共通参照集合の割当てに失敗しました
 */
//------------------------------------------------------------------------------
void validateSupplementCollection( const std::span<const IndexRecordSource>			  baseSources,
								  const std::span<const IndexDistributionRecord>	  baseRecords,
								  const signed_index_detail::DecodedIndexRecordsData &additional,
								  const std::chrono::sys_seconds					  expiresAtUtc,
								  const std::chrono::sys_seconds nowUtc, const RecordArea area)
{
	require( !additional.records.empty(), IndexRecordsStatus::INVALID_SUPPLEMENT_PURPOSE) ;
	require( baseRecords.size() <= INDEX_RECORD_MAX_COUNT - additional.records.size(),
			IndexRecordsStatus::COUNT_LIMIT) ;
	std::map<std::string_view, const IndexRecordSource *>
		sourceById ;	// 旧・追加欄が共有する同じ原取得元です
	// 本文と追加欄それぞれの取得元を共通の照合表へ登録します
	for( const auto sources :
		{baseSources, std::span<const IndexRecordSource>{additional.sources}}) {
		// 現在の欄にある全取得元について、同じIDの元情報が一致するかを確認します
		for( const auto &source : sources) {
			const auto [entry, inserted] =
				// 同一source IDの元参照です
				sourceById.emplace( source.sourceId, &source) ;
			require( inserted || *entry->second == source, IndexRecordsStatus::DUPLICATE_SOURCE) ;
			require( sourceById.size() <= INDEX_RECORD_SOURCE_MAX_COUNT,
					IndexRecordsStatus::COUNT_LIMIT) ;
		}
	}

	std::set<std::pair<std::string_view, std::string_view>> ids ;	// 両欄の元sourceとrecordの組です
	std::size_t totalRecordBytes{} ;								// 旧・追加欄のdecode済み元record合計です
	std::size_t totalPublicIds{} ;									// 旧・追加欄の型付きID合計です
	// 本文と追加欄を順に走査してレコード参照の衝突を確認します
	for( const auto records :
		{baseRecords, std::span<const IndexDistributionRecord>{additional.records}}) {
		// 同じ配布行の重複を排除し、すべての取得元参照を照合します
		for( const auto &record : records) {
			require( ids.emplace( record.sourceId, record.recordId).second,
					IndexRecordsStatus::DUPLICATE_RECORD) ;
			require( record.originalBytes.size() <= INDEX_RECORD_TOTAL_MAX_BYTES - totalRecordBytes,
					IndexRecordsStatus::TOTAL_RECORD_SIZE_LIMIT) ;
			totalRecordBytes += record.originalBytes.size() ;
			require( record.publishedIdentityEvidence.pnpIds.size() <=
						index_capacity::WHOLE_PUBLIC_IDS - totalPublicIds,
					IndexRecordsStatus::INPUT_COUNT_LIMIT) ;
			totalPublicIds += record.publishedIdentityEvidence.pnpIds.size() ;
		}
	}

	auto earliest = std::chrono::sys_seconds::max() ;	// 追加行だけの元期限の最小値です
	// 追加欄の全配布物で元証拠の現在の有効性を再確認します
	for( const auto &record : additional.records) {
		require( signed_index_detail::isInspectedIndexAcquisition(
					record, nowUtc, area == RecordArea::SCOPED_MODELS) &&
					record.publishedIdentityEvidence.kind == IndexIdentityEvidenceKind::INF,
				IndexRecordsStatus::INVALID_SUPPLEMENT_PURPOSE) ;
		const auto minimumBuild =
			// 元のOSと最低buildの証拠です
			readClientMinimumBuildScope( record) ;
		require( minimumBuild.state == ClientMinBuildState::NONE ||
					minimumBuild.state == ClientMinBuildState::VALID,
				IndexRecordsStatus::INVALID_SUPPLEMENT_PURPOSE) ;
		// 最低buildも同じ詳細で確認した場合にだけ条件を組み合わせます
		if( record.catalogHardwareScope && minimumBuild.state == ClientMinBuildState::VALID) {
			const auto &catalog = *record.catalogHardwareScope ;	// 同行で保持した原応答です
			require( clientMinimumBuildDetailsUrl( minimumBuild) == catalog.detailsUrl &&
						decodeHash( minimumBuild.evidenceSha256,
								   IndexRecordsStatus::INVALID_SUPPLEMENT_PURPOSE) ==
							catalog.detailsSha256,
					IndexRecordsStatus::INVALID_SUPPLEMENT_PURPOSE) ;
			// 公式Modelsの証拠付きレコードは現在のWindows観測点と照合します
			if( record.scopedModelsEvidence) {
				require( record.scopedModelsEvidence->models.platform->buildNumber ==
							minimumBuild.minimumBuild,
						IndexRecordsStatus::INVALID_EVIDENCE) ;
			}
		}

		earliest = std::min( earliest, record.acquisitionDescriptor->attestation->validUntilUtc) ;
	}

	require( earliest == expiresAtUtc, IndexRecordsStatus::SUPPLEMENT_EXPIRY_MISMATCH) ;
	validateScopedAliases( baseRecords, additional.records) ;
	validateWixAliases( baseRecords, additional.records) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 展開した追加欄又は局所の保留候補を共通検査します
 * @param[in] manifest 同assetの値又は検査用途の世代と時刻です
 * @param[in] expanded 追加欄の展開byteです
 * @param[in] baseSources 構造検査済みの旧取得元です
 * @param[in] baseRecords 構造検査済みの旧レコードです
 * @param[in] expiry 追加行の原期限の最小値です
 * @param[in] nowUtc 確認済み現在UTCです
 * @param[in] area 既存の追加欄又は専用欄の文法です
 * @return 原証拠と参照検査を完了した値です
 */
//------------------------------------------------------------------------------
signed_index_detail::DecodedIndexRecords decodeSupplementValues(
	const IndexManifestData &manifest, const std::span<const std::byte> expanded,
	const std::span<const IndexRecordSource>	   baseSources,
	const std::span<const IndexDistributionRecord> baseRecords,
	const std::chrono::sys_seconds expiry, const std::optional<std::chrono::sys_seconds> nowUtc,
	const RecordArea area) noexcept
{
	auto decoded = decodeIndexRecords( manifest, expanded, nowUtc, area) ;	// 同じ追加欄の原値です
	// 共通文法や期限を確定できなかった場合は元の診断結果を返します
	if( !decoded.data) {
		return decoded ;
	}

	try {
		validateSupplementCollection( baseSources, baseRecords, *decoded.data, expiry, *nowUtc,
									 area) ;
		return decoded ;
	} catch( const Failure &failure) {
		return {failure.status, failure.error, std::nullopt} ;
	} catch( const std::bad_alloc &) {
		return {IndexRecordsStatus::OUT_OF_MEMORY, static_cast<NativeError>( E_OUTOFMEMORY),
				std::nullopt} ;
	} catch( ...) {
		return {IndexRecordsStatus::INTERNAL_FAILURE, static_cast<NativeError>( E_UNEXPECTED),
				std::nullopt} ;
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 既存索引の原recordと全参照を従来の表記規則で検査します
 * @param[in] manifest 同じ原manifestの検査済み値です
 * @param[in] expanded 同じasset値codecの展開byteです
 * @param[in] nowUtc 確認済みUTCです
 * @return 未認証の既存索引検査値です
 */
//------------------------------------------------------------------------------
signed_index_detail::DecodedIndexRecords signed_index_detail::decodeIndexRecordsData(
	const IndexManifestData &manifest, const std::span<const std::byte> expanded,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	return decodeIndexRecords( manifest, expanded, nowUtc, RecordArea::BASE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一系列の元投影を追加欄の内容検査に結びます
 * @param[in] utf8 局所世代1と原行を含む展開byteです
 * @param[in] expiry 各行の最短原期限です
 * @param[in] nowUtc 同じ検査の現在UTCです
 * @return 未署名で圧縮前の値です。公開のための世代や権限は発行しません
 */
//------------------------------------------------------------------------------
signed_index_detail::DecodedIndexRecords signed_index_detail::decodePendingCollectorSupplement(
	const std::span<const std::byte> utf8, const std::chrono::sys_seconds expiry,
	const std::chrono::sys_seconds nowUtc) noexcept
{
	IndexManifestData scope ;	// 局所の値検査に必要な世代と時刻だけです
	scope.assetGeneration = 1U ;
	scope.publishedAtUtc  = nowUtc ;
	scope.expiresAtUtc	  = expiry ;
	return decodeSupplementValues( scope, utf8, {}, {}, expiry, nowUtc, RecordArea::SUPPLEMENT) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 収集履歴のv6投影を端末と共通の文法で検査します
 * @param[in] utf8 局所世代1で保持した圧縮前の原バイトです
 * @param[in] expiry 原取得と内容検査から決まった同じ期限です
 * @param[in] nowUtc 元根拠を評価するUTCです。元観測は変更しません
 * @return 原レコード・元証拠と期限の一致を検査した非認証値です
 * @note 圧縮、公開世代、署名または公開許可を発行しません
 */
//------------------------------------------------------------------------------
signed_index_detail::DecodedIndexRecords signed_index_detail::decodePendingCollectorScopedModels(
	const std::span<const std::byte> utf8, const std::chrono::sys_seconds expiry,
	const std::chrono::sys_seconds nowUtc) noexcept
{
	IndexManifestData scope ;	// 局所の値検査に使う世代と元時刻です
	scope.assetGeneration = 1U ;
	scope.publishedAtUtc  = nowUtc ;
	scope.expiresAtUtc	  = expiry ;
	return decodeSupplementValues( scope, utf8, {}, {}, expiry, nowUtc, RecordArea::SCOPED_MODELS) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 収集専用の原証拠をハッシュ照合し、全元節と公式対象を型付きで保持する
 * @param[in] utf8 収集結果と一緒に保存した元JSONの原UTF-8
 * @param[in] expectedSha256 収集結果が保持する同原文のSHA-256
 * @return 原バイト・文法・全対象の一意な元位置が成立した場合だけ型付き原証拠を返す
 * @note 共通の署名本文・追加欄のreaderは専用のこのスキーマを受け付けない
 */
//------------------------------------------------------------------------------
signed_index_detail::DecodedCollectorScopedModelsEvidence signed_index_detail::
	decodeCollectorScopedModelsEvidence( std::string_view		   utf8,
										const IndexManifestSha256 &expectedSha256) noexcept
{
	// 個別の元証拠サイズを超える入力はハッシュ計算前に拒否します
	if( utf8.size() > INDEX_RECORD_MAX_BYTES) {
		return {IndexRecordsStatus::RECORD_SIZE_LIMIT, 0, std::nullopt} ;
	}

	try {
		// 原文が宣言した証拠と一致するかに使う実SHA-256
		const auto actualSha256 = hashRecord( utf8) ;
		require( actualSha256 == expectedSha256, IndexRecordsStatus::RECORD_HASH_MISMATCH) ;
		// 元証拠の文法・相互参照の不一致を示す共通の診断区分
		const auto									invalid = IndexRecordsStatus::INVALID_EVIDENCE ;
		// 元UTF-8を上限付きの厳格なJSONとして読む入力専用の読取り器
		Reader										reader( utf8, invalid, INDEX_RECORD_MAX_BYTES) ;
		// 元配布・署名・明示OSと全Models節を結び付ける固定の必須欄
		constexpr std::array<std::string_view, 13U> fields{
			"schema",	   "archiveSha256",		  "archiveBytes",		  "nestedArchiveIdentity",
			"infIdentity", "infSha256",			  "catalogIdentity",	  "catalogSha256",
			"classGuid",   "catalogDetailsBytes", "catalogHardwareScope", "modelsPlatform",
			"sections"} ;
		// 全必須欄の整合が成立するまで局所に保持する元証拠
		CollectorScopedModelsEvidence value ;
		// 全元節のModels行数とID欄数を集計する共通予算
		std::uint32_t				  rows{}, ids{} ;
		// 同一証拠に蓄積する公式対象の件数
		std::size_t					  targets{} ;
		reader.object( fields, [&]( std::size_t field) {
			// 元証拠の必須欄を固定の用途と型で読み取ります
			switch( field) {
				// 元の証拠形式を確認し、従来の別形式を同じ欄で受理しません
				case 0U:
					require( reader.text( 64U) == "driver-index-collector-scoped-models-v1", invalid) ;
					break ;

				// 外側の公式配布物の実SHA-256を受け取ります
				case 1U:
					value.archiveSha256 = decodeHash( reader.text( 64U), invalid) ;
					break ;

				// 外側の公式配布物を容量条件へ結び付ける元バイト数を受け取ります
				case 2U:
					value.archiveBytes = reader.number() ;
					break ;

				// 外側の配布物に一段内包されたアーカイブの元相対位置を保持します
				case 3U:
					value.nestedArchiveIdentity = reader.text( TEXT_MAX_BYTES) ;
					break ;

				// 元閉包から検査したINFの完全相対位置を保持します
				case 4U:
					value.infIdentity = reader.text( TEXT_MAX_BYTES) ;
					break ;

				// 元INFそのものを照合する小文字SHA-256を検査します
				case 5U: {
					const auto hash = reader.text( 64U) ;
					static_cast<void>( decodeHash( hash, invalid)) ;
					value.models.infSha256.assign( hash.begin(), hash.end()) ;
					break ;
				}
				// 元INFが宣言する署名カタログとの閉包内の関係を保持します
				case 6U:
					value.catalogIdentity = reader.text( TEXT_MAX_BYTES) ;
					break ;

				// 元カタログの実バイトへ結び付くSHA-256を保持します
				case 7U:
					value.catalogSha256 = decodeHash( reader.text( 64U), invalid) ;
					break ;

				// 元INFと同じドライバークラスの識別子を保持します
				case 8U:
					value.classGuid = reader.text( 38U) ;
					break ;

				// 公式Catalog明細に対する元の応答バイト数を保持します
				case 9U:
					value.catalogDetailsBytes = reader.number() ;
					break ;

				// 同じ掲載として検証する完全Hardware ID集合と元のCatalog欄を読み取ります
				case 10U:
					value.catalog =
						readCatalogHardwareScope( reader, OFFICIAL_SCOPED_MODELS_MAX_TARGETS) ;
					break ;

				// 元Modelsの選択を確認したOS観測点を読み取ります
				case 11U:
					value.models.platform = readCollectorModelsPlatform( reader) ;
					break ;

				// 採用した観測点の全元節を、共通の節数・行数予算に沿って読み取ります
				case 12U:
					reader.array(
						OFFICIAL_SCOPED_MODELS_MAX_SECTIONS,
						[&] {
							auto section = readCollectorModelsSection(
								reader, OFFICIAL_SCOPED_MODELS_MAX_TARGETS - targets) ;
							require( section.modelRows <= OFFICIAL_SCOPED_MODELS_MAX_ROWS - rows &&
										section.idFields <=
											OFFICIAL_SCOPED_MODELS_MAX_ID_FIELDS - ids,
									IndexRecordsStatus::COUNT_LIMIT) ;
							require(
								std::ranges::none_of( value.models.sections,
													 [&]( const auto &old) {
														 return CompareStringOrdinal(
																	old.modelSection.c_str(), -1,
																	section.modelSection.c_str(),
																	-1, TRUE) == CSTR_EQUAL ;
													 }),
								invalid) ;
							rows += section.modelRows ;
							ids += section.idFields ;
							targets += section.matches.size() ;
							value.models.sections.push_back( std::move( section)) ;
						},
						IndexRecordsStatus::COUNT_LIMIT) ;
					break ;

				// 定義範囲にない証拠欄を元検証に使用しません
				default:
					throw Failure{invalid} ;
			}
		}) ;
		reader.finish() ;
		// 同じ階層にある署名対象かを比較するため親部分を返す同期処理
		const auto directory = []( std::string_view path) {
			// 最後の区切り文字の位置。直下のパスでは親部分を空にします
			const auto slash = path.find_last_of( '/') ;
			return slash == path.npos ? std::string_view{} : path.substr( 0U, slash) ;
		} ;
		// 元配布物として認めるアーカイブの最大サイズ。単位はバイト
		constexpr std::uint64_t archiveLimit = 2ULL * 1024ULL * 1024ULL * 1024ULL ;
		// 元Catalog明細の応答として認める最大サイズ。単位はバイト
		constexpr std::uint64_t detailsLimit = 2U * 1024U * 1024U ;
		require( value.archiveBytes != 0U && value.archiveBytes <= archiveLimit &&
					value.catalogDetailsBytes != 0U && value.catalogDetailsBytes <= detailsLimit &&
					validNestedIdentity( value.nestedArchiveIdentity) &&
					validInfIdentity( value.infIdentity) && validClassGuid( value.classGuid) &&
					pnpIdComparisonKey( value.catalogIdentity).ends_with( ".CAT") &&
					isSafeOfficialArchiveMember(
						std::wstring( value.catalogIdentity.begin(), value.catalogIdentity.end()),
						L'/') &&
					pnpIdComparisonKey( directory( value.infIdentity)) ==
						pnpIdComparisonKey( directory( value.catalogIdentity)) &&
					!value.models.sections.empty(),
				invalid) ;

		std::set<std::string> unmatched ;	// 公式応答の全対象を元行に一度だけ消去する
		// 公式の各対象を比較用集合へ一度ずつ登録して多重宣言を拒否します
		for( const auto &id : value.catalog.packageHardwareIds) {
			require( unmatched.emplace( pnpIdComparisonKey( id)).second, invalid) ;
		}

		// 元証拠の全節を走査して公式対象が元行で一意に現れることを確認します
		for( const auto &section : value.models.sections) {
			// 各元行のHardware IDを公式一覧から消費し、余分な一致や重複を拒否します
			for( const auto &match : section.matches) {
				// 元Hardware IDを公式の対象一覧と比較する狭い文字列の領域
				std::string id( match.hardwareId.size(), '\0') ;
				// 節の読取りで確認した可視ASCIIだけを原Catalog値と比較する
				std::ranges::transform( match.hardwareId, id.begin(), []( const wchar_t character) {
					return static_cast<char>( character) ;
				}) ;
				require( unmatched.erase( pnpIdComparisonKey( id)) == 1U, invalid) ;
			}
		}

		require( unmatched.empty(), invalid) ;
		value.originalBytes.assign( utf8) ;
		value.evidenceSha256 = actualSha256 ;
		return {IndexRecordsStatus::SCHEMA_VALIDATED, 0, std::move( value)} ;
	} catch( const Failure &failure) {
		return {failure.status, failure.error, std::nullopt} ;
	} catch( const std::bad_alloc &) {
		return {IndexRecordsStatus::OUT_OF_MEMORY, static_cast<NativeError>( E_OUTOFMEMORY),
				std::nullopt} ;
	} catch( ...) {
		return {IndexRecordsStatus::INTERNAL_FAILURE, static_cast<NativeError>( E_UNEXPECTED),
				std::nullopt} ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 現公開本文から分離する規約契約を同じ記述子から判定する
 * @param[in] record 取得条件を解決した元レコード
 * @return ZIP内の元規約または二段リンク用を持つ場合true
 */
//------------------------------------------------------------------------------
bool signed_index_detail::indexRecordHasPrivateTerms( const IndexDistributionRecord &record) noexcept
{
	// 取得条件が未確認の行へ規約を補わない
	if( !record.acquisitionDescriptor) {
		return false ;
	}

	const auto &terms = record.acquisitionDescriptor->terms ;	// 元署名記述子の規約
	return terms.archiveNotice ||
		   (terms.textDocument && terms.textDocument->htmlExtraction &&
			terms.textDocument->htmlExtraction->profile == LINKED_STATIC_TERMS_PROFILE) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 対象条件と原表記を保って旧索引本文へ記録できるか検査する
 * @param[in] record 共通codecを通過した原証拠付きレコードです
 * @return 元表記や取得規約が旧文法の範囲を超える場合true
 */
//------------------------------------------------------------------------------
bool signed_index_detail::indexRecordNeedsSupplement( const IndexDistributionRecord &record) noexcept
{
	const auto &identity = record.publishedIdentityEvidence ;	// 型と元表記を検査済みの識別証拠です
	return record.wixContentEvidence || isIndexHardwareScoped( record) ||
		   indexRecordHasPrivateTerms( record) ||
		   (identity.state == IndexEvidenceState::PUBLISHED &&
			(!validIdentity( identity.modelSection, LEGACY_MODEL_SECTION_BYTES) ||
			 std::ranges::any_of( identity.pnpIds, []( const IndexPublishedPnpId &id) {
				 return !validPnpId( id.value) ;
			 }))) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 型検査済みレコードが現在有効な内容検査済み取得条件を満たすか確認します
 * @param[in] record 元の取得記述と証拠を持つレコードです
 * @param[in] nowUtc 確認済み現在UTCです
 * @param[in] scopedModels 専用欄の検証で元証拠に結合したv6を照合する場合trueです
 * @return 既知の必須項目と個別期限が成立する場合trueです
 */
//------------------------------------------------------------------------------
bool signed_index_detail::isInspectedIndexAcquisition( const IndexDistributionRecord &record,
													  const std::chrono::sys_seconds nowUtc,
													  const bool scopedModels) noexcept
{
	// 専用欄の行は元証拠に結合した欄の検査から受理します
	if( (record.recordSchemaVersion != 2U &&
		(record.recordSchemaVersion != 3U || !record.catalogHardwareScope) &&
		(record.recordSchemaVersion != 4U || !record.platformDeviceScope) &&
		(record.recordSchemaVersion != 5U || !record.platformDeviceScope ||
		 record.platformFirmwareGroups.empty()) &&
		(record.recordSchemaVersion != 6U || !scopedModels || !record.scopedModelsEvidence) &&
		(record.recordSchemaVersion != 7U || scopedModels || !record.archiveHardwareScope) &&
		(record.recordSchemaVersion != 8U || scopedModels || !record.wixContentEvidence)) ||
	   !record.acquisitionDescriptor ||
	   record.acquisitionDescriptor->state != IndexDescriptorState::KNOWN ||
	   record.inspectionStage != IndexInspectionStage::CONTENT_INSPECTED ||
	   !record.targetOs.value || record.architecture.value != IndexArchitecture::X64 ||
	   record.driverKind.value != IndexDriverKind::NORMAL_DRIVER ||
	   record.acquisition.value != IndexAcquisitionKind::STANDARD_INF_ARCHIVE ||
	   record.publishedIdentityEvidence.state != IndexEvidenceState::PUBLISHED ||
	   !record.packageEvidence.calculatedHash.sha256 || !record.packageEvidence.size.value) {
		return false ;
	}

	const auto &descriptor = *record.acquisitionDescriptor ;	// 元取得条件です
	return descriptor.attestation && descriptor.attestation->policyRevision == 1U &&
		   descriptor.attestation->checkedAtUtc <= nowUtc &&
		   nowUtc < descriptor.attestation->validUntilUtc && descriptor.publisher.value &&
		   descriptor.terms.state != IndexTermsState::UNKNOWN &&
		   descriptor.prerequisites.state == IndexDescriptorState::KNOWN ;
}

//------------------------------------------------------------------------------
/**
 * @brief 追加欄を旧索引と別の結果として読み、両欄の元証拠と容量を検査します
 * @param[in] base 同じ署名済みassetの旧索引receiptです
 * @param[in] nowUtc 確認済み現在UTCです
 * @return 現公開形式で受理できる追加recordの検査結果です。私有の対象条件は拒否します
 */
//------------------------------------------------------------------------------
IndexSupplementRecordsResult readSignedIndexSupplementRecords(
	const IndexRecordsSchemaReceipt				 &base,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	const auto &asset = base.assetBytes() ;	// 同じ署名と転送hashを持つ所有値です
	// 同じassetの検査済み本文を使って、その追加欄を読取り検証した結果
	auto		result = signed_index_detail::decodeIndexSupplementRecordsData(
		   asset.manifest().data(), base.sources(), base.records(), asset.readSupplement( nowUtc),
		   nowUtc) ;
	// 旧公開用の読取り入口では対象付き行を拒否します
	if( std::ranges::any_of( result.records, []( const IndexDistributionRecord &record) {
		   return record.wixContentEvidence || isIndexHardwareScoped( record) ||
				  signed_index_detail::indexRecordHasPrivateTerms( record) ;
	   })) {
		return {result.transportStatus, IndexRecordsStatus::INVALID_SUPPLEMENT_PURPOSE, 0, {}, {}} ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 認証済みの追加欄から端末で使う原レコードと元領域を読み取ります
 * @param[in] base 同じassetの旧本文の元署名と展開内容を確認したreceiptです
 * @param[in] nowUtc 展開・各行の検査に用いる確認済み現在UTCです
 * @return 両欄の共通検査に成功した場合だけ元展開SHA-256と元期限を含む検査結果です
 * @note 対象付き行の端末照合と取得許可は後段で別途確認します。旧公開用は専用入口を使用します
 */
//------------------------------------------------------------------------------
IndexConsumerSupplementResult readSignedIndexConsumerSupplement(
	const IndexRecordsSchemaReceipt				 &base,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	const auto &asset	  = base.assetBytes() ;				// 旧本文と同じ署名と転送hashの根拠です
	const auto	transport = asset.readSupplement( nowUtc) ;	// 追加欄そのものの運搬と元展開byteです
	// 両欄の原レコードと取得元の共通検査結果です
	IndexConsumerSupplementResult result{signed_index_detail::decodeIndexSupplementRecordsData(
		asset.manifest().data(), base.sources(), base.records(), transport, nowUtc)} ;
	// 両領域を検査した元行を、端末の個別照合へ渡します
	if( result.contents.status == IndexRecordsStatus::SCHEMA_VALIDATED) {
		result.expandedSha256 = transport.expandedSha256 ;
		result.expiresAtUtc	  = transport.expiresAtUtc ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 追加欄の元レコードと、同じassetの旧本文との合計を検査します
 * @param[in] manifest 同じassetの元manifest値です
 * @param[in] baseSources 構造検査済みの旧本文の元取得元です
 * @param[in] baseRecords 構造検査済みの旧本文の原レコードです
 * @param[in] transport 追加欄から得た運搬検査値です
 * @param[in] nowUtc 確認済み現在UTCです
 * @return 全検査成功時の元取得元と原レコードです。認証receiptは生成しません
 */
//------------------------------------------------------------------------------
IndexSupplementRecordsResult signed_index_detail::decodeIndexSupplementRecordsData(
	const IndexManifestData &manifest, const std::span<const IndexRecordSource> baseSources,
	const std::span<const IndexDistributionRecord> baseRecords,
	const IndexAssetSupplementResult			  &transport,
	const std::optional<std::chrono::sys_seconds>  nowUtc) noexcept
{
	IndexSupplementRecordsResult result ;	// 失敗時に中間recordを返しません
	result.transportStatus = transport.status ;
	result.error		   = transport.error ;
	// 圧縮追加欄のバイトが検査済みである場合だけレコードを読み取ります
	if( transport.status != IndexAssetSupplementStatus::BYTE_VALIDATED) {
		return result ;
	}

	// 追加欄の入力を元の本文・期限・用途に照合したデコード結果
	auto decoded  = decodeSupplementValues( manifest, transport.expanded, baseSources, baseRecords,
										   transport.expiresAtUtc, nowUtc, RecordArea::SUPPLEMENT) ;
	result.status = decoded.status ;
	result.error  = decoded.error ;
	// 全体を検査できた場合だけ解析された取得元を結果へ移します
	if( decoded.data) {
		result.sources = std::move( decoded.data->sources) ;
		result.records = std::move( decoded.data->records) ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公式Models領域の元レコードと同じ本文との合計枠を検査します
 * @param[in] manifest 同じ圧縮へ結合した元manifestです
 * @param[in] baseSources 同じasset本文の取得元です
 * @param[in] baseRecords 同じasset本文の元レコードです
 * @param[in] transport 同じDMの運搬検査結果です
 * @param[in] nowUtc 元内外期限の評価時刻です
 * @return 元証拠・全レコードが揃う場合にだけ検査済み値を返します
 * @note 署名・公開・取得の許可を発行しません
 */
//------------------------------------------------------------------------------
IndexSupplementRecordsResult signed_index_detail::decodeIndexScopedModelsRecordsData(
	const IndexManifestData &manifest, const std::span<const IndexRecordSource> baseSources,
	const std::span<const IndexDistributionRecord> baseRecords,
	const IndexAssetSupplementResult			  &transport,
	const std::optional<std::chrono::sys_seconds>  nowUtc) noexcept
{
	IndexSupplementRecordsResult result ;	// 途中の原値は後段へ返しません
	result.transportStatus = transport.status ;
	result.error		   = transport.error ;
	// 同じ元gzipの運搬検査に成功した領域だけを読みます
	if( transport.status != IndexAssetSupplementStatus::BYTE_VALIDATED) {
		return result ;
	}

	auto decoded = decodeSupplementValues(
		manifest, transport.expanded, baseSources, baseRecords, transport.expiresAtUtc, nowUtc,
		RecordArea::SCOPED_MODELS) ;	// 本文と独立した専用欄の値検査です
	result.status = decoded.status ;
	result.error  = decoded.error ;
	// 全元行と同じ本文を照合できた場合だけ移します
	if( decoded.data) {
		result.sources = std::move( decoded.data->sources) ;
		result.records = std::move( decoded.data->records) ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 署名済みDM欄を読み、同じ元配布行と公式Modelsの元証拠を結合します
 * @param[in] base 同assetの元署名と本文に結合したreceiptです
 * @param[in] nowUtc 運搬と元レコードの両期限を比較する確認済み現在UTCです
 * @return 元行と証拠の全参照が成立した場合だけ元領域のhashと期限を保持します
 * @note 元本文を更新せず、端末適合又は取得許可を発行しません
 */
//------------------------------------------------------------------------------
IndexConsumerSupplementResult readSignedIndexScopedModels(
	const IndexRecordsSchemaReceipt				 &base,
	const std::optional<std::chrono::sys_seconds> nowUtc) noexcept
{
	const auto					 &asset		= base.assetBytes() ;				// 同じ署名と元配布物のcodecです
	const auto					  transport = asset.readScopedModels( nowUtc) ;	// 期限内の専用欄です
	IndexConsumerSupplementResult result ;										// 成功した追加レコードにだけ元領域を保持します
	result.contents = signed_index_detail::decodeIndexScopedModelsRecordsData(
		asset.manifest().data(), base.sources(), base.records(), transport, nowUtc) ;
	// 同じ認証済み本文との全結合を確認した専用欄だけを返します
	if( result.contents.status == IndexRecordsStatus::SCHEMA_VALIDATED) {
		result.expandedSha256 = transport.expandedSha256 ;
		result.expiresAtUtc =
			std::min( transport.expiresAtUtc, asset.manifest().data().expiresAtUtc) ;
	}

	return result ;
}

} // namespace drivercrate
