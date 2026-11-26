//------------------------------------------------------------------------------
/**
 * @file server_index_scope.h
 * @brief Server索引のexact版・product別Models観測条件を共通検査します
 * @version 01.02.00
 * @date 2026/11/17
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/17  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/17  未終端hidden拒否と数値空白参照の比較範囲を明示
 * Ver.01.01.00 Shunji Ogawa  2026/11/17  宣言Server scopeとpolicy・Models・identityを分離接続
 * Ver.01.02.00 Shunji Ogawa  2026/11/18  P3同scan fullhost観測と取得直前拒否を接続
 * </pre>
 * @note 所有DTOを同期検査するだけです。host観測・取得・適用性・導入資格は発行しません
 * @see docs/adr/0508-exact-server-release-collection-and-acquisition.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/windows_product_type.h"

#include "platform/official_driver_package.h"
#include "platform/signed_index_records.h"
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <winrt/Windows.Data.Json.h>

namespace drivercrate {

/** @brief 採用した四Server版だけです。UNKNOWNを成功へ補完しません */
enum class ServerIndexRelease {
	/// 未解決または不正な入力です
	UNKNOWN,
	/// 10.0/base14393です
	WINDOWS_SERVER_2016,
	/// 10.0/base17763です
	WINDOWS_SERVER_2019,
	/// 10.0/base20348です
	WINDOWS_SERVER_2022,
	/// 10.0/base26100です
	WINDOWS_SERVER_2025
} ;

/** @brief 一recordの宣言版/productとproducerのsuite観測由来です。host適用性ではありません */
struct ServerIndexScope {
	/// 一つのexact Server版です。UNKNOWNは未検証です
	ServerIndexRelease release{ServerIndexRelease::UNKNOWN} ;
	/// DC=2またはServer=3です。0は未検証であり成功へ変換しません
	std::uint8_t	   productType{} ;
	/// producerの基準Models観測は0だけです。host suite等値条件ではありません
	std::uint16_t	   modelsObservedSuite{} ;
	/**
	 * @brief 版・product・観測suiteを全て比較します
	 * @param[in] other 借用する比較相手です
	 * @return 三fieldが同じ場合だけtrueです
	 */
	bool			   operator==( const ServerIndexScope &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 観測成功と初回hostの対応範囲を分けて検査します
 * @param[in] observed 同期借用する原観測です
 * @return UNKNOWN/UNSUPPORTED又は未検査取得までの判定です。導入能力は発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexHostGateResult classifyIndexHost(
	const WindowsHostPlatformObservation &observed) noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief 初回の原hostとfresh観測を比較します
 * @param[in] original 同scanの元観測です
 * @param[in] fresh 今回の原観測です
 * @return 必要field不明はUNKNOWN、完全tuple変化は未採用値でもSTALEです
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexHostGateResult compareIndexHost(
	const WindowsHostPlatformObservation &original,
	const WindowsHostPlatformObservation &fresh) noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief Server一scopeと実hostを取得前に照合します
 * @param[in] scope 元三条件から得た一版/productです
 * @param[in] observed 同scanの原hostです
 * @return suite0 markerを実suite等値とせず、版/product/architectureを検査した判定です
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexHostGateResult matchServerIndexHost(
	const ServerIndexScope &scope, const WindowsHostPlatformObservation &observed) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 閉じたexact定義literalをServer版へ変換します
 * @param[in] name 呼出し中だけ借用する原ASCII literalです
 * @return 採用四版だけ値あり。generic/未知/clientは空です
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<ServerIndexRelease> serverIndexRelease( std::string_view name) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief Server版のcanonical定義literalを借用します
 * @param[in] release 採用版または未知の値です
 * @return static文字列です。UNKNOWN/不正enumは空です
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string_view serverIndexReleaseName( ServerIndexRelease release) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 観測scopeを明示requested Modelsの全fieldへ変換します
 * @param[in] scope 採用版/product2or3/観測suite0を明示した値です
 * @return 正しいscopeだけ10.0/AMD64/対応base buildのtupleです。未知は空です
 * @note APIを呼びません。host suiteや実適用性の成功を表しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<OfficialInfModelsPlatform> serverIndexModelsPlatform(
	const ServerIndexScope &scope) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 同PUBLISHED/INF根拠に結合した必須三LOCAL_CHECKを有限検査します
 * @param[in] identity 借用する同recordの元INF出典と原hashです
 * @param[in] prerequisites 最大16件の既codec型付き元条件です。書き換えません
 * @return 各条件一個・根拠完全一致のscopeです。欠落/重複/未知LOCAL_CHECKは空です
 * @throws std::bad_alloc 所有文字列の割当て失敗です
 * @note 他種の既条件は保持対象であり、適用性や利用者同意を確認しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<ServerIndexScope> readServerIndexScope(
	const IndexPublishedIdentityEvidence &identity,
	const IndexAcquisitionPrerequisites	 &prerequisites) ;

//------------------------------------------------------------------------------
/**
 * @brief 同INF根拠の必須三条件と既存の非LOCAL_CHECK条件を生成します
 * @param[in] scope 正確な版/product/観測suiteです
 * @param[in] identity 借用するPUBLISHED/INF根拠です。成功時も変更しません
 * @param[in] additional 借用する既条件です。最大13件、未知/LOCAL_CHECKを許しません
 * @return 既条件を省略しないKNOWN集合です。不正/16件超過は空です
 * @throws std::bad_alloc 出力所有値の割当て失敗です
 * @note 出力は申告であり、取得/導入許可や新期限を発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<IndexAcquisitionPrerequisites> makeServerIndexPrerequisites(
	const ServerIndexScope &scope, const IndexPublishedIdentityEvidence &identity,
	std::span<const IndexAcquisitionPrerequisite> additional = {}) ;

//------------------------------------------------------------------------------
/**
 * @brief 有限Catalog本文にexact Server名が明記されているか検査します
 * @param[in] text 最大2MiB文字の借用metadataです。完全なhidden/comment/tagを除きます
 * @param[in] release 一つの宣言Server版です
 * @return 当該版名の明記だけtrueです。generic/and laterから別版を推測しません
 * @throws std::bad_alloc 所有比較本文の割当て失敗です
 * @throws std::regex_error 標準正規表現の解析/実行失敗です
 * @note 未終端hidden/commentは拒否します。decimal/hex空白参照は比較本文だけで変換します
 * @note architecture・公式性・同product・INF/実host適用性は別の検査です。全HTML文法のparserではありません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool catalogHasServerIndexRelease( std::wstring_view text, ServerIndexRelease release) ;

//------------------------------------------------------------------------------
/**
 * @brief strict入力の元Server templateから一意のscopeを読みます
 * @param[in] record 同期中だけ借用する元JSON objectです。変更しません
 * @return KNOWN Server/x64/標準INFと同PUBLISHED/INF三条件のscopeです
 * @throws std::runtime_error 必須条件・根拠・上限が不正です
 * @throws winrt::hresult_error 必須JSON fieldが欠落又は別型です
 * @note strict JSON/record codecを代替しません。MTA内の同期処理です
 */
//------------------------------------------------------------------------------
[[nodiscard]] ServerIndexScope readServerIndexTemplateScope(
	const winrt::Windows::Data::Json::JsonObject &record) ;

//------------------------------------------------------------------------------
/**
 * @brief 新scope markerがないlegacy generic Serverだけを判別します
 * @param[in] record strict入力の借用recordです。変更しません
 * @return LOCAL_CHECKなし又は旧generic一個だけtrueです。部分/未知/重複はfalseです
 * @note raw/key保持の区分であり、取得/公開/導入成功へ変換しません。MTA専用です
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isLegacyServerIndexRecord( const winrt::Windows::Data::Json::JsonObject &record) ;

} // namespace drivercrate
