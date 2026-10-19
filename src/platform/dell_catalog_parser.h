//------------------------------------------------------------------------------
/**
 * @file dell_catalog_parser.h
 * @brief Dell公式catalog parser定義。
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
 * @note Dell署名済みindexおよびplatform catalog XMLを、上限付きの内部値へ変換します。XML schema逸脱時は候補を推測せずfail-closedにします。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

//------------------------------------------------------------------------------
// Dell catalog値型定義。
//------------------------------------------------------------------------------

/**
 * @brief 端末modelに対応するDell platform catalogの検証metadataである。
 */
struct DellPlatformCatalogReference {
	/// Dell indexへ完全一致したsystem product名。
	std::wstring  model ;
	/// downloads.dell.comを基準とする相対CAB path。
	std::wstring  path ;
	/// Indexが宣言した小文字64桁SHA-256。
	std::wstring  sha256 ;
	/// Indexが宣言したCAB byte数。
	std::uint64_t size{} ;
} ;

/**
 * @brief 一つのDell driver packageとlocal照合に使うcatalog metadataである。
 */
struct DellDriverRelease {
	/// Dellが発行した英数字release ID。
	std::wstring			  releaseId ;
	/// Dell catalogの英語driver名称。
	std::wstring			  title ;
	/// Hardware vendor driver version。
	std::wstring			  version ;
	/// Dell package revision。
	std::wstring			  dellVersion ;
	/// Dell catalogの公開日表示。
	std::wstring			  releaseDate ;
	/// downloads.dell.comを基準とする相対EXE path。
	std::wstring			  path ;
	/// Catalogが宣言した小文字64桁SHA-256。
	std::wstring			  sha256 ;
	/// Catalogが宣言したEXE byte数。
	std::uint64_t			  size{} ;
	/// CriticalityがRecommendedまたはUrgentの場合true。
	bool					  recommended{} ;
	/// Catalogから構成したlocal照合専用ID群。
	std::vector<std::wstring> hardwareIds ;
} ;

/**
 * @brief Dell index XMLから端末modelのplatform catalog参照を取得する。
 * Model Displayを完全一致し、SHA-256付き参照だけを採用する。
 * @param[in] xmlUtf16 署名検証済みCABから展開したUTF-16 XML。 署名検証済みCAB内のUTF-16 XML。
 * @param[in] systemModel local registryから得たsystem product名。 Local system product名。
 * @param[out] reference 成功時の相対path、size、SHA-256。 成功時のplatform CAB metadata。
 * @return 成功時は0、schema不正またはmodel未収録時はHRESULT bit pattern。 成功時は0、model未収録またはschema不正時はHRESULT。
 */
[[nodiscard]] NativeError parseDellCatalogIndex( std::wstring_view			  xmlUtf16,
												std::wstring_view			  systemModel,
												DellPlatformCatalogReference &reference) ;

/**
 * @brief Dell platform catalog XMLから対象OSのdriver releaseを取得する。
 * Dell platform catalogから対象OSのdriver releaseを取得する。
 * Driver、model、OS、x64、SHA-256、Hardware IDを全て満たすSoftwareComponentだけを出力する。
 * @param[in] xmlUtf16 署名・hash検証済みCABから展開したUTF-16 XML。 検証済みplatform CAB内のUTF-16 XML。
 * @param[in] systemModel indexへ完全一致したsystem product名。 Indexへ一致したsystem product名。
 * @param[in] windows11 trueならWindows 11、falseならWindows 10を対象にする。
 * @param[out] releases 成功時のdriver release群。対象0件も成功とする。 成功時のlocal照合可能driver群。
 * @return 成功時は0、schema不正または上限超過時はHRESULT bit pattern。
 */
[[nodiscard]] NativeError parseDellPlatformCatalog( std::wstring_view xmlUtf16,
												   std::wstring_view systemModel, bool windows11,
												   std::vector<DellDriverRelease> &releases) ;

} // namespace drivercrate
