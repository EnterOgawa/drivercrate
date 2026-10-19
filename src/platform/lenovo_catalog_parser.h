//------------------------------------------------------------------------------
/**
 * @file lenovo_catalog_parser.h
 * @brief Lenovo公式catalog parser定義。
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
 * @note Lenovo公式model catalogとpackage descriptorを有限なdriver metadataへ変換します。端末由来identifierと任意install
 *       commandは扱いません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

//------------------------------------------------------------------------------
// Lenovo catalog値型定義。
//------------------------------------------------------------------------------

/**
 * @brief Model catalogが宣言する一つのpackage descriptor参照である。
 */
struct LenovoCatalogReference {
	/// download.lenovo.com配下のdescriptor HTTPS URL。
	std::wstring descriptorUrl ;
	/// Model catalogが提示する分類表示名。
	std::wstring category ;
	/// Descriptor全byteの小文字SHA-256。
	std::wstring sha256 ;
} ;

/**
 * @brief 署名検証前のLenovo driver package metadataである。
 */
struct LenovoDriverRelease {
	/// Lenovoが発行した安全なpackage ID。
	std::wstring			  packageId ;
	/// 英語driver package表示名。
	std::wstring			  title ;
	/// Descriptorが提示するpackage version。
	std::wstring			  version ;
	/// YYYY-MM-DD形式の公開日。
	std::wstring			  releaseDate ;
	/// Descriptorと同じ公式directoryのEXE URL。
	std::wstring			  installerUrl ;
	/// Installer全byteの小文字SHA-256。
	std::wstring			  sha256 ;
	/// Descriptorが宣言するinstaller byte数。
	std::uint64_t			  size{} ;
	/// 1601年起点100ns単位の署名済み時刻。
	std::uint64_t			  signingFiletime{} ;
	/// CriticalまたはRecommendedならtrue。
	bool					  recommended{} ;
	/// Reboot種別が0以外ならtrue。
	bool					  rebootMayBeRequired{} ;
	/// Local照合だけに使うcatalog側ID群。
	std::vector<std::wstring> hardwareIds ;
} ;

/**
 * @brief Lenovo model catalogから検証可能なdescriptor参照を取得する。
 * Lenovo model catalogをdescriptor参照へ変換する。
 * Root宣言件数と実要素数を一致させ、重複矛盾を拒否する。
 * @param[in] xmlUtf16 HTTPS上限確認済みのUTF-16 XML。 HTTPS上限確認済みUTF-16 XML。
 * @param[out] references 成功時の一意なdescriptor参照群。0件も成功とする。
 * @return 成功時は0、schema、URL、hash、件数不正時はHRESULT bit pattern。
 */
[[nodiscard]] NativeError parseLenovoModelCatalog( std::wstring_view					   xmlUtf16,
												  std::vector<LenovoCatalogReference> &references) ;

/**
 * @brief Lenovo package descriptorからdriver package metadataを取得する。
 * Lenovo package descriptorをdriver releaseへ変換する。
 * 任意commandを読まず、local照合とfile検証に必要な値だけ返す。
 * @param[in] xmlUtf16 Catalog hash確認済みのUTF-16 XML。 Catalog hash確認済みUTF-16 XML。
 * @param[in] descriptorUrl Model catalogで検証済みのdescriptor URL。 検証済みdescriptor URL。
 * @param[out] release Driver型ならmetadata、既知の非driver型なら`std::nullopt`。 Driver型のrelease、非driver型は
 *                   nullopt。
 * @return 成功時は0、driver schema、URL、size、hash不正時はHRESULT bit pattern。 成功時は0、driver schema不正時はHRESULT。
 * @note XML Digital Signatureの暗号検証はraw fileに対してProviderが別途必須で行う。
 */
[[nodiscard]] NativeError parseLenovoPackageDescriptor( std::wstring_view xmlUtf16,
													   std::wstring_view descriptorUrl,
													   std::optional<LenovoDriverRelease> &release) ;

} // namespace drivercrate
