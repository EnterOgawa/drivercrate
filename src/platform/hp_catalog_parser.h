//------------------------------------------------------------------------------
/**
 * @file hp_catalog_parser.h
 * @brief HP公式reference catalog parser定義。
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
 * @note HP署名確認済みplatform listとreference XMLを、有限なdriver metadataへ変換します。端末由来identifierと任意install
 *       commandは扱いません。
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
// HP catalog値型定義。
//------------------------------------------------------------------------------

/**
 * @brief Platform listが宣言する一つのHP reference識別値である。
 */
struct HpPlatformReference {
	/// 4桁大文字hexのHP Platform ID。
	std::wstring  systemId ;
	/// Reference file名に使う`10.0`または`11.0`。
	std::wstring  osVersion ;
	/// Reference file名に使うWindows release ID。
	std::wstring  releaseId ;
	/// 完全一致を要求するWindows build番号。
	std::uint32_t osBuild{} ;
} ;

/**
 * @brief HP referenceが宣言する一つのdriver SoftPaqである。
 */
struct HpDriverRelease {
	/// `sp`と10進数字から成るSoftPaq ID。
	std::wstring			  softpaqId ;
	/// HP referenceのdriver表示名。
	std::wstring			  title ;
	/// HP referenceのdriver version。
	std::wstring			  version ;
	/// HP referenceのdriver vendor表示名。
	std::wstring			  vendor ;
	/// `Driver`または`Driver - ...`分類。
	std::wstring			  category ;
	/// YYYY-MM-DD形式の公開日。
	std::wstring			  releaseDate ;
	/// ftp.hp.com配下をHTTPS化した公式URL。
	std::wstring			  installerUrl ;
	/// Payload全byteの小文字SHA-256。
	std::wstring			  sha256 ;
	/// Referenceが宣言するpayload byte数。
	std::uint64_t			  size{} ;
	/// CriticalまたはRecommendedならtrue。
	bool					  recommended{} ;
	/// Local照合だけに使うcatalog側ID群。
	std::vector<std::wstring> hardwareIds ;
} ;

/**
 * @brief HP platform listから端末のPlatform IDとWindows buildに一致する参照を取得する。
 * HP platform listから端末に一致するreferenceを取得する。
 * Platform ID、x64、buildを完全一致させ、URL用値を検証する。
 * @param[in] xmlUtf16 HP署名確認済みCABから読み取ったUTF-16 XML。 HP署名確認済みplatform list XML。
 * @param[in] systemId 4桁大文字hexへ検証済みのlocal Platform ID。 検証済みlocal Platform ID。
 * @param[in] osBuild local Windows build番号。
 * @param[out] reference 成功時の一意なplatform reference。
 * @return 成功時は0、未対応、重複矛盾、schema不正時はHRESULT bit pattern。
 */
[[nodiscard]] NativeError parseHpPlatformCatalog( std::wstring_view xmlUtf16,
												 std::wstring_view systemId, std::uint32_t osBuild,
												 HpPlatformReference &reference) ;

/**
 * @brief HP platform別referenceからdeviceへ対応するdriver SoftPaqを取得する。
 * HP referenceをdevice対応driver SoftPaqへ変換する。
 * Driver分類だけを分離し、DeviceIdとIdRefの明示対応を保持する。
 * @param[in] xmlUtf16 HP署名確認済みCABから読み取ったUTF-16 XML。 HP署名確認済みreference XML。
 * @param[in] reference 検証済みplatform listから得た期待system／OS値。 Platform list由来の期待system／OS値。
 * @param[out] releases 成功時の一意なdriver SoftPaq群。0件も成功とする。 成功時のdevice対応driver SoftPaq群。
 * @return 成功時は0、schema、URL、hash、device対応不正時はHRESULT bit pattern。
 */
[[nodiscard]] NativeError parseHpReferenceCatalog( std::wstring_view				xmlUtf16,
												  const HpPlatformReference	   &reference,
												  std::vector<HpDriverRelease> &releases) ;

} // namespace drivercrate
