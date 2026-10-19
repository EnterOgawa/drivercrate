//------------------------------------------------------------------------------
/**
 * @file asus_system_identity.h
 * @brief ASUS公式support page用local system識別定義。
 * @version 01.02.00
 * @date 2026/09/04
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/20  Registry実取得sizeに基づく有限decodeを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/24  公開model明示の非registry公式page要求を追加。
 * </pre>
 *
 * @note Serial numberを読まず、SMBIOS表示名とWindows世代だけから固定ASUS support page要求を構築します。Hardware IDをnetworkへ送信
 *       しません。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace drivercrate {

//------------------------------------------------------------------------------
// ASUS local system識別値型定義。
//------------------------------------------------------------------------------

/**
 * @brief ASUS公式製品別support pageを取得するための非機密要求である。
 */
struct AsusSupportPageRequest {
	/// SMBIOSから選択しpageで完全一致させる製品名。
	std::wstring model ;
	/// ASUS page上のWindows x64 OS名。
	std::wstring osName ;
	/// Modelだけをpercent encodeした固定公式HTTPS URL。
	std::wstring pageUrl ;
} ;

/**
 * @brief Registryの確保領域から実取得byte数だけを検証して表示値を取り出す。
 * @param[in] buffer REG_SZ読取りに使用した借用buffer。未使用末尾は照合しない。
 * @param[in] returnedBytes API成功時に返された終端を含むbyte数。
 * @param[out] value 成功時は終端を除いた値、失敗時は空。
 * @return 有限容量内の単一NUL終端文字列ならtrue。
 * @pre bufferとvalueはaliasしない。REG_SZ型とAPI成功は呼出し側で検証する。
 * @note Networkやregistryへ接続しない。途中NULと不正UTF-16境界を拒否する。
 */
[[nodiscard]] bool		  decodeAsusRegistryString( std::span<const wchar_t> buffer,
												   std::uint32_t returnedBytes, std::wstring &value) ;

/**
 * @brief SMBIOS表示値からASUS support page要求を決定的に構築する。
 * SMBIOS表示値からASUS support page要求を構築する。
 * System modelを優先し、該当しない場合だけbaseboard modelを使用する。Model以外をURLへ含めない。
 * @param[in] systemManufacturer SMBIOS System Manufacturer表示値。 SMBIOS system maker表示値。
 * @param[in] systemProduct SMBIOS System Product Name表示値。 SMBIOS system product表示値。
 * @param[in] baseboardManufacturer SMBIOS BaseBoard Manufacturer表示値。 SMBIOS board maker表示値。
 * @param[in] baseboardProduct SMBIOS BaseBoard Product表示値。 SMBIOS board product表示値。
 * @param[in] windowsBuild CurrentBuildNumberを検証した値。 検証済みCurrentBuildNumber。
 * @param[in] windowsServer 実行中OSがWindows Serverの場合は`true`。
 * @param[out] request ASUS clientの場合のmodel、OS名、固定公式URL。 ASUS clientの場合の固定page要求。
 * @param[out] applicable ASUS clientとして安全に識別できた場合は`true`。 ASUS clientと安全に識別した場合`true`。
 * @return 入力構造を判定できた場合は`true`、ASUSなのにmodelまたはbuildが不正なら`false`。 判定成功時は`true`、ASUS必須値が不正なら`false`。
 */
[[nodiscard]] bool		  makeAsusSupportPageRequest( std::wstring_view systemManufacturer,
													 std::wstring_view systemProduct,
													 std::wstring_view baseboardManufacturer,
													 std::wstring_view baseboardProduct,
													 std::uint32_t windowsBuild, bool windowsServer,
													 AsusSupportPageRequest &request, bool &applicable) ;

/**
 * @brief 明示された公開ASUS model・Windows x64条件から公式support page要求を構築します。
 * @param[in] publicModel 利用者または公式製品一覧が示す公開model。端末IDではありません。
 * @param[in] osName `Windows 11 64-bit`または`Windows 10 64-bit`。
 * @param[out] request 成功時だけcanonical page要求を保持します。
 * @return 公開modelとOSが有限かつ正規形の場合true。
 * @note Registryを読まず、機種実在・driver適合・取得許可は証明しません。
 */
[[nodiscard]] bool		  makeAsusPublicModelSupportPageRequest( std::wstring_view		publicModel,
																std::wstring_view		osName,
																AsusSupportPageRequest &request) ;

/**
 * @brief Local registryからASUS support page要求に必要な表示値だけを取得する。
 * Local registryからASUS support page要求を取得する。
 * Serverを除外後、serialを含まない五つのregistry値だけを読み、純粋な要求構築処理へ渡す。
 * @param[out] request ASUS clientの場合のmodel、OS名、固定公式URL。 ASUS clientの場合のmodel、OS、page URL。
 * @param[out] applicable ASUS clientとして安全に識別できた場合は`true`。 ASUS clientの場合は`true`。
 * @return 判定成功時は0、ASUS端末の必須値欠落またはWin32失敗時はHRESULT。 判定成功時は0、必須値またはWin32失敗時はHRESULT。
 * @note Windows Serverでは追加registry値を読まず対象外とする。
 */
[[nodiscard]] NativeError readLocalAsusSupportPageRequest( AsusSupportPageRequest &request,
														  bool					 &applicable) ;

} // namespace drivercrate
