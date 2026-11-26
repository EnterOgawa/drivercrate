//------------------------------------------------------------------------------
/**
 * @file client_min_build_scope.h
 * @brief client最低buildの非権限scopeと収集側の厳密照合を定義します
 * @version 01.09.00
 * @date 2026/11/18
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/18  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/19  同認証recordとfullhostの非権限照合を端末境界へ接続
 * Ver.01.02.00 Shunji Ogawa  2026/11/19  旧codec互換の固定baseと条件内GUIDへ詳細根拠を分離
 * Ver.01.03.00 Shunji Ogawa  2026/11/19  一般Client24H2の26100を期待scope別に結合
 * Ver.01.04.00 Shunji Ogawa  2026/11/20  Catalog詳細の正規URL照合を対象条件と共有
 * Ver.01.05.00 Shunji Ogawa  2026/11/20  Catalogの可視製品欄とArchitectureの全体比較を共有
 * Ver.01.06.00 Shunji Ogawa  2026/11/20  同じリリースのClient S表記の併記に対応
 * Ver.01.07.00 Shunji Ogawa  2026/11/20  検索行の同版順序と明細の製品比較を共通化
 * Ver.01.08.00 Shunji Ogawa  2026/11/22  公式Models専用行を同ホスト再観測の対象に追加
 * Ver.01.09.00 Shunji Ogawa  2026/11/23  WiX配布のWindowsクライアント条件を同一端末へ照合
 * </pre>
 * @note JSONは同MTAの同期借用だけです。scopeはmetadata申告であり、取得/導入能力ではありません
 * @see docs/adr/0511-client-minimum-build-index-scope.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/windows_product_type.h"
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <winrt/Windows.Data.Json.h>

namespace drivercrate {

//------------------------------------------------------------------------------
/**
 * @brief 固定Catalog詳細URLから正規の更新GUIDを借用します
 * @param[in] url 呼出し中だけ有効な原実URLです
 * @return 固定host・path・queryの正規GUIDの借用又は空です
 * @note 通信と割当てを行いません。返却viewは元URLと同じ寿命です
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<std::string_view> catalogUpdateIdFromDetailsUrl(
	std::string_view url) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 採用された一般Clientの最低base buildを閉集合で判定します
 * @param[in] minimumBuild 正規数値として読んだ元floorです
 * @return 24H2の26100又は既25H2の26200だけtrueです
 * @note 割当て/JSON/WinRT/host APIを呼ばず、適用性や権限を発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isSupportedClientMinimumBuild( std::uint32_t minimumBuild) noexcept ;

/** @brief 原byteとtyped値の結合を認証codecが保持する不変recordです */
struct IndexDistributionRecord ;

/** @brief scope不在を不正又は未対応と区別します */
enum class ClientMinBuildState {
	/// 真の既存client又は別OSで、新markerがありません
	NONE,
	/// 採用した26100又は26200の単一条件が成立しています
	VALID,
	/// markerの構造/用途/根拠/重複が不正です
	INVALID,
	/// canonicalですが未採用の最低buildです
	UNSUPPORTED
} ;

/** @brief 一recordに署名保持する最低buildと元support根拠です */
struct ClientMinBuildScope {
	/// 不在/成立/不正/未対応を保持します。初期値は成功ではありません
	ClientMinBuildState state{ClientMinBuildState::NONE} ;
	/// VALIDは26100又は26200です。0を成功へ補完しません
	std::uint32_t		minimumBuild{} ;
	/// 同support metadataの固定詳細baseです。INF根拠とは別です
	std::string			evidenceUrl ;
	/// 同support rawの小文字SHA256です
	std::string			evidenceSha256 ;
	/// 同Catalog詳細を一意復元する正規小文字GUIDです。旧数値単独形は不正です
	std::string			catalogUpdateId ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 原recordの最低build条件を非実行で分類します
 * @param[in] record 同期中だけ借用する原JSONです。変更しません
 * @return marker不在はNONE、単一Win11/X64/標準INFの採用floorはVALID、不正/未採用は別stateです
 * @throws std::bad_alloc 所有textの割当て失敗です
 * @note 不正reserved記述をlegacyへ戻しません。完全record codec/host検査を代替しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] ClientMinBuildScope readClientMinimumBuildScope(
	const winrt::Windows::Data::Json::JsonObject &record) ;

//------------------------------------------------------------------------------
/**
 * @brief 同認証recordの原byteで既共通条件parserを再利用します
 * @param[in] record codecで原byte/typed値が結合した不変recordです。同期借用だけです
 * @return markerなしNONE、正規VALID、不正/未対応は別stateです。原byte欠落を補完しません
 * @pre 呼出側が同所有receipt/原hash/期限を先に確認します。reserved recordは同workerのMTAで読みます
 * @note 例外/割当て失敗はINVALIDへ閉じます。JSONの復号は非権限で、原recordを書き換えません
 */
//------------------------------------------------------------------------------
[[nodiscard]] ClientMinBuildScope readClientMinimumBuildScope(
	const IndexDistributionRecord &record) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 同typed条件に正規又は不正reserved記述があるか非割当てで確認します
 * @param[in] record 同所有認証receiptの不変recordです。同期借用だけです
 * @return reserved familyが存在する場合trueです。正規条件の成立は別検証です
 * @note JSON/WinRT/割当てを行わず、後続解析の失敗から再観測を省略しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasClientMinimumBuildMarker( const IndexDistributionRecord &record) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 元OS条件付きの標準INFで同host再観測を必須にします
 * @param[in] record 同所有認証receiptの不変recordです。同期借用だけです
 * @return Server、reserved client条件、公式Models専用行又はWiX配布行の標準INFならtrueです
 * @pre 所有/原byte/期限/同scopeの取得可否は呼出側で先に検証します
 * @note 不正clientは先行検証で拒否し、後続解析失敗でも旧NONEへfallbackしません。旧NONE/installerは対象外です
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool requiresBoundIndexHost( const IndexDistributionRecord &record) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 正規client最低buildを同scanの原fullhostへ照合します
 * @param[in] scope 元recordのVALID scopeです。不正値を既定成功へ補完しません
 * @param[in] observed 同scan所有の一度の原観測です。APIを呼びません
 * @return API不明UNKNOWN、既知未対応UNSUPPORTED、別product/低build INCOMPATIBLE又は未検査取得のALLOWです
 * @note 原domain/bitsを保持し、suite0由来を実host suite等値条件へしません。導入能力は発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexHostGateResult matchClientMinimumBuildHost(
	const ClientMinBuildScope &scope, const WindowsHostPlatformObservation &observed) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 署名索引のWiX配布条件を同じ端末で観測したWindowsの種類とアーキテクチャへ照合します
 * @param[in] record 元OSとアーキテクチャを保持する認証済みレコードです
 * @param[in] observed 同スキャンで取得した端末の観測です
 * @return 未観測、未対応、不一致又は対象条件の一致を表す判定です
 * @note 一致は候補の照合に限ります。通信・導入許可・INFの適用判定は別に行います
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexHostGateResult matchWixIndexHost(
	const IndexDistributionRecord &record, const WindowsHostPlatformObservation &observed) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 固定baseと正規GUIDから同詳細の実URLを一意復元します
 * @param[in] scope 共通parserで得た非権限scopeです。同期借用します
 * @return VALID26100/26200と正規GUIDだけ実URL、他は空です。通信や根拠の取得は行いません
 * @throws std::bad_alloc 有限URLの割当てに失敗しました
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string		  clientMinimumBuildDetailsUrl( const ClientMinBuildScope &scope) ;

//------------------------------------------------------------------------------
/**
 * @brief 同definitionの全retained client scopeを一つへ結びます
 * @param[in] target 元discoveryとretained bindingを持つ定義です
 * @param[in] templates 同targetの全元recordです。変更しません
 * @return 真のlegacyはNONE、全同Win11 targetが同じ採用floorならVALIDです
 * @throws winrt::hresult_error 不正/混在/未対応protocol又は初期未対応のmixed OSです
 * @throws std::bad_alloc 有限textの割当て失敗です
 * @note 初期scopeは単独WINDOWS_11/CATALOG_SEARCH_V1だけです。他入口でscopeを落としません
 */
//------------------------------------------------------------------------------
[[nodiscard]] ClientMinBuildScope declaredClientMinimumBuildScope(
	const winrt::Windows::Data::Json::JsonObject &target,
	const winrt::Windows::Data::Json::JsonArray	 &templates) ;

//------------------------------------------------------------------------------
/**
 * @brief 同Catalog detailsの可視製品集合とArchitecture owner欄を閉じて照合します
 * @param[in] html 最大2MiB文字の同update原本文です。変更/保存しません
 * @param[in] expectedUpdateId 通常候補の正確な原update GUIDです
 * @param[in] minimumBuild 同targetが宣言する26100又は26200です。既定は旧26200です
 * @return productsDivの採用二製品だけとarchDivのAMD64一値が明記されていればtrueです
 * @throws std::bad_alloc 比較本文の割当て失敗です
 * @throws std::regex_error 固定正規表現の処理失敗です
 * @note hidden/未終端/重複owner/未知製品/追加作用/上限は成功へ補完しません。公式性と同updateはcallerが照合します
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool catalogHasClientMinimumBuild( std::wstring_view html,
												std::wstring_view expectedUpdateId,
												std::uint32_t	  minimumBuild = 26200U) ;

//------------------------------------------------------------------------------
/**
 * @brief 可視製品欄を明示Client最低buildの全表記に照合します
 * @param[in] products 同じ更新行又は明細の可視製品欄の原文です
 * @param[in] minimumBuild 期待する正規floorです
 * @return 通常Clientの二表記があり、追加表記が同版Client Sに限られる場合trueです
 * @throws std::bad_alloc 比較値の割当てに失敗しました
 * @throws std::regex_error 固定比較式の処理に失敗しました
 * @note 検索行の結果は明細確認順に限り使用します。Architectureと適用性は明細で確認します
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool clientMinimumBuildProductsMatch( std::wstring_view products,
												   std::uint32_t	 minimumBuild) ;

//------------------------------------------------------------------------------
/**
 * @brief 厳密walkerが取り出した可視二欄だけを原製品集合へ比較します
 * @param[in] products 元ownerのplain support本文です
 * @param[in] architecture 元ownerのplain architecture本文です
 * @param[in] minimumBuild 期待する正規floorです。旧呼出しの既定26200を保持します
 * @return 単独AMD64と通常Clientの二表記が成立し、追加表記が同リリースのClient Sに限られる場合true
 * @throws std::bad_alloc 比較値の割当て失敗です
 * @throws std::regex_error 固定比較式の処理失敗です
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool clientMinimumBuildFieldsMatch( std::wstring_view products,
												 std::wstring_view architecture,
												 std::uint32_t	   minimumBuild = 26200U) ;

//------------------------------------------------------------------------------
/**
 * @brief 可視ArchitectureとSupported productsの全体を既知の製品表記へ照合する
 * @param[in] products 明細の同じ可視欄から読み出した原文です
 * @param[in] architecture 同じ明細のArchitecture欄の原文です
 * @param[in] acceptedProducts ASCII小文字と表示空白で正規化済みの製品欄の許容値です
 * @return Architectureが単独AMD64で、製品欄全体が許容値の一つと等しい場合だけtrueです
 * @throws std::bad_alloc 比較文字列の割当て失敗です
 * @throws std::regex_error 固定比較式の処理失敗です
 * @note 許容値は製品名内のコンマを含めた欄全体です。元明細を変更しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool catalogDetailProductFieldsMatch(
	std::wstring_view products, std::wstring_view architecture,
	std::initializer_list<std::wstring_view> acceptedProducts) ;

//------------------------------------------------------------------------------
/**
 * @brief 可視ArchitectureとSupported productsの全体を既知の製品表記へ照合する
 * @param[in] products 明細の同じ可視欄から読み出した原文です
 * @param[in] architecture 同じ明細のArchitecture欄の原文です
 * @param[in] acceptedProducts ASCII小文字と表示空白で正規化済みの製品欄の許容値です
 * @return Architectureが単独AMD64で、製品欄全体が許容値の一つと等しい場合だけtrueです
 * @throws std::bad_alloc 比較文字列の割当て失敗です
 * @throws std::regex_error 固定比較式の処理失敗です
 * @note 許容値は製品名内のコンマを含めた欄全体です。元明細を変更しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool catalogDetailProductFieldsMatch(
	std::wstring_view products, std::wstring_view architecture,
	std::initializer_list<std::wstring_view> acceptedProducts) ;

//------------------------------------------------------------------------------
/**
 * @brief 元非LOCAL条件を保持して今回support rawへ最低build条件を結び直します
 * @param[in] original 原template recordです。書き換えません
 * @param[in] evidenceUrl 同nativeが確認したGUID queryを持つ実details URLです
 * @param[in] evidenceSha256 同runの原details body SHA256です
 * @return 固定base/条件内GUIDの一LOCALと元非LOCALを元順で保持する独立prerequisitesです
 * @throws winrt::hresult_error 元scope/新根拠/上限が不正です
 * @throws std::bad_alloc 独立JSON/textの割当て失敗です
 * @note 元INF根拠や非LOCAL条件のURL/hashは更新しません。取得/導入権限や期限を発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] winrt::Windows::Data::Json::JsonObject makeClientMinimumBuildPrerequisites(
	const winrt::Windows::Data::Json::JsonObject &original, std::wstring_view evidenceUrl,
	std::wstring_view evidenceSha256) ;

} // namespace drivercrate
