//------------------------------------------------------------------------------
/**
 * @file vaio_catalog_parser.h
 * @brief VAIO Global公式catalog parser定義。
 * @version 01.00.00
 * @date 2026/09/02
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note VAIO公式のmodel、pre-installed driver、update JSONを有限な値へ変換します。HTML、端末identifier、任意commandは扱いません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"
#include "platform/official_catalog_device.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

//------------------------------------------------------------------------------
// VAIO catalog値型定義。
//------------------------------------------------------------------------------

/**
 * @brief VAIO Global Supportが公開する一つの対応modelである。
 */
struct VaioModel {
	/// Local SMBIOS表示値へ照合する大文字ASCII model code。
	std::wstring code ;
} ;

/**
 * @brief VAIO model別pre-installed driver表の一項目である。
 */
struct VaioPreinstalledDriver {
	/// この項目を提示するmodel code集合。
	std::vector<std::wstring> models ;
	/// Updateとの結合に使う公式category ID。
	std::wstring			  categoryId ;
	/// HTML tagを除去した公式program名。
	std::wstring			  title ;
	/// trueの場合はpre-installed driver表の項目。
	bool					  tableOne{} ;
} ;

/**
 * @brief VAIO Global Supportが公開する一つのdriver update metadataである。
 */
struct VaioDriverRelease {
	/// 適用対象model code集合。
	std::vector<std::wstring> models ;
	/// 適用対象Windows名集合。
	std::vector<std::wstring> osNames ;
	/// VAIO公式category ID。
	std::wstring			  categoryId ;
	/// HTML tagを除去した公式program名。
	std::wstring			  title ;
	/// VAIOが提示するdriver version。
	std::wstring			  version ;
	/// YYYY/MM/DD形式の公開日。
	std::wstring			  releaseDate ;
	/// SPまたはVPで始まる公式Software ID。
	std::wstring			  softwareId ;
	/// VAIO公式HTTPS payload URL。
	std::wstring			  installerUrl ;
	/// Payload全byteの小文字SHA-256。
	std::wstring			  sha256 ;
	/// Payload byte数。
	std::uint64_t			  size{} ;
} ;

//------------------------------------------------------------------------------
// VAIO catalog parser定義。
//------------------------------------------------------------------------------

/**
 * @brief Models.jsonからGlobal support対象model codeを取得する。
 * VAIO Global model JSONを対応model集合へ変換する。
 * 全recordの必須field型を検証し、Global=Yだけを重複なく返す。
 * @param[in] jsonUtf16 HTTPS上限確認済みのUTF-16 JSON。 Models.json UTF-16 text。
 * @param[out] models 成功時の重複しないmodel集合。失敗時は空にする。 Global support対象model集合。
 * @return 成功時は0、schema、型、上限、model code不正時はHRESULT bit pattern。 成功時は0、schemaまたは上限不正時はHRESULT。
 */
[[nodiscard]] NativeError				  parseVaioModelCatalog( std::wstring_view		jsonUtf16,
																std::vector<VaioModel> &models) ;

/**
 * @brief 公式model集合をlocal SMBIOS表示値へ一意に照合する。
 * VAIO公式modelをlocal SMBIOS表示値へ一意に照合する。
 * Model code直前を英数字境界にし、code後のSKU suffixは許可する。Serial値は呼出し側から受け取らない。
 * @param[in] models 検証済みGlobal model集合。
 * @param[in] localValues SystemProductName等の端末内表示値。 SystemProductName等のlocal表示値。
 * @return 一意なmodel code。0件または曖昧な場合は`std::nullopt`。
 */
[[nodiscard]] std::optional<std::wstring> matchVaioModelCode(
	std::span<const VaioModel> models, std::span<const std::wstring> localValues) ;

/**
 * @brief preinstDriversGlobal.jsonからmodelとcategoryの対応を取得する。
 * VAIO pre-installed JSONをmodel／category対応へ変換する。
 * NAの有無にかかわらずTable 1のmodel／category正本を保持する。
 * @param[in] jsonUtf16 HTTPS上限確認済みのUTF-16 JSON。 preinstDriversGlobal.json UTF-16 text。
 * @param[out] drivers 成功時のpre-installed項目群。失敗時は空にする。 検証済みpre-installed項目群。
 * @return 成功時は0、schema、型、上限、識別子不正時はHRESULT bit pattern。 成功時は0、schemaまたは上限不正時はHRESULT。
 */
[[nodiscard]] NativeError parseVaioPreinstalledCatalog(
	std::wstring_view jsonUtf16, std::vector<VaioPreinstalledDriver> &drivers) ;

/**
 * @brief UpdateListGlobal.jsonからinstall可能なdriver updateだけを取得する。
 * VAIO update JSONをdriver release群へ変換する。
 * 無効または非driver recordを除外し、driver metadataの欠損はcatalog全体を拒否する。
 * @param[in] jsonUtf16 HTTPS上限確認済みのUTF-16 JSON。 UpdateListGlobal.json UTF-16 text。
 * @param[out] releases 成功時のdriver release群。失敗時は空にする。 Install可能なdriver release群。
 * @return 成功時は0、schema、型、URL、size、hash不正時はHRESULT bit pattern。 成功時は0、schema、URL、size、hash不正時は
 *         HRESULT。
 * @note 既知の非driver category、無効項目、payload欠損項目は正常に除外する。
 */
[[nodiscard]] NativeError parseVaioUpdateCatalog( std::wstring_view				 jsonUtf16,
												 std::vector<VaioDriverRelease> &releases) ;

/**
 * @brief Category IDが初期版で許可するPnP driver分類か判定する。
 * Category IDが許可するPnP driver分類か判定する。
 * BIOS、firmware、application、utility、serviceを除外する。
 * @param[in] categoryId VAIO公式category ID。
 * @return Driver分類allowlistに完全一致する場合は`true`。
 */
[[nodiscard]] bool		  isVaioDriverCategory( std::wstring_view categoryId) noexcept ;

/**
 * @brief VAIO categoryと公式titleを一意なlocal deviceへ解決する。
 * VAIO driver metadataを一意なlocal deviceへ解決する。
 * Setup class、maker、model tokenだけで一意に解決し、versionと日付を適用性判定へ使用しない。
 * @param[in] categoryId 検証済みVAIO category ID。 検証済みcategory ID。
 * @param[in] officialTitle Updateとpre-installed項目を連結した公式title。 Updateとpre-installedの公式title。
 * @param[in] devices 端末内だけで保持する非機密device snapshot群。 Local device snapshot群。
 * @return 一意に適用可能なopaque device identity。0件または複数件なら`std::nullopt`。 一意なopaque identity。0件または複数件なら
 *         `std::nullopt`。
 * @note Versionと日付は照合に使用せず、Setup class、maker、device modelだけを使用する。
 */
[[nodiscard]] std::optional<std::wstring> matchVaioDriverDevice(
	std::wstring_view categoryId, std::wstring_view officialTitle,
	std::span<const OfficialCatalogDevice> devices) ;

} // namespace drivercrate
