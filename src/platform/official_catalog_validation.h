//------------------------------------------------------------------------------
/**
 * @file official_catalog_validation.h
 * @brief 公式catalog共通schema／CAB検証定義。
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  UTF-8 XML読取り追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 署名確認済みCABの単一XML展開と、外部参照を禁止したMSXML DOM生成を共通化します。Vendor固有schemaと適用性は呼出し側が検証します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <msxml6.h>
#include <wrl/client.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace drivercrate {

//------------------------------------------------------------------------------
// 公式XML policy定義。
//------------------------------------------------------------------------------

/**
 * @brief 公式XMLをMSXMLへ読み込む際の共通上限とvendor固有XPath namespaceである。
 */
struct OfficialXmlPolicy {
	/// 入力UTF-16文字数の許容上限。
	std::size_t		  maximumCharacters{} ;
	/// 空または固定XPath namespace宣言。
	std::wstring_view selectionNamespaces ;
} ;

//------------------------------------------------------------------------------
// 公式catalog共通検証定義。
//------------------------------------------------------------------------------

/**
 * @brief CAB entry名と展開後sizeが単一XML候補として安全か判定する。
 * Path解決や文字置換をせず、Windowsで危険な名前を拒否する。
 * @param[in] entryName CAB metadataが示すentry名。
 * @param[in] expandedBytes CAB metadataが示す展開後byte数。
 * @param[in] maximumExpandedBytes Providerが定めた展開後byte数上限。 Provider指定上限。
 * @return 平坦な「.xml」 basenameかつsizeが範囲内なら`true`。
 */
[[nodiscard]] bool		  isAllowedOfficialCatalogEntry( std::wstring_view entryName,
														std::uint64_t	  expandedBytes,
														std::uint64_t	  maximumExpandedBytes) noexcept ;

/**
 * @brief 署名確認済みCABから一つの平坦なXMLだけを展開する。
 * 既存fileとmulti-cabを拒否し、失敗時は今回の出力を削除する。
 * @param[in] cabPath Providerが事前に署名を確認したlocal CAB絶対path。 署名確認済みlocal CAB絶対path。
 * @param[in] outputPath 保護workspace内にある未作成のlocal固定XML絶対path。 保護workspace内の未作成local XML絶対path。
 * @param[in] maximumExpandedBytes 許容する展開後XML byte数上限。
 * @return 成功時は0、CAB／path／size／API失敗時はHRESULT bit pattern。
 * @pre `outputPath`の親directoryはSYSTEM／Administrators限定でreparse pointではないこと。
 */
[[nodiscard]] NativeError extractOfficialCatalogXml( std::wstring_view cabPath,
													std::wstring_view outputPath,
													std::uint64_t	  maximumExpandedBytes) ;

/**
 * @brief 展開済みUTF-16LE XMLを上限付きで読み取る。
 * 推測変換を行わずUTF-16LEと先頭`<`、埋込みnullを強制する。
 * @param[in] path 保護workspace内の通常file絶対path。
 * @param[in] maximumBytes 許容する入力byte数上限。
 * @param[out] xml 成功時のBOMを除いたUTF-16 XML。失敗時は空にする。 成功時のBOMを除くUTF-16 XML。
 * @return 成功時は0、file／size／encoding検証失敗時はHRESULT bit pattern。
 */
[[nodiscard]] NativeError readOfficialUtf16Xml( std::wstring_view path, std::uint64_t maximumBytes,
											   std::wstring &xml) ;

/**
 * @brief Download済みUTF-8 XMLを上限付きで読み取る。
 * UTF-8 BOMだけを任意で許可し、不正列と埋込みnullを拒否する。
 * @param[in] path 保護workspace内の通常file絶対path。
 * @param[in] maximumBytes 許容する入力byte数上限。
 * @param[out] xml 成功時のUTF-16 XML。失敗時は空にする。
 * @return 成功時は0、file／size／UTF-8検証失敗時はHRESULT bit pattern。
 */
[[nodiscard]] NativeError readOfficialUtf8Xml( std::wstring_view path, std::uint64_t maximumBytes,
											  std::wstring &xml) ;

/**
 * @brief 外部参照とDTDを禁止したMSXML 6.0 DOMへ公式XMLを読み込む。
 * DTD、外部参照、inline schema、過大size／depthを拒否する。
 * @param[in] xmlUtf16 事前にtransport上限を確認したUTF-16 XML。 Transport上限確認済みUTF-16 XML。
 * @param[in] policy 文字数上限と任意の固定XPath namespace宣言。 文字数上限と任意XPath namespace宣言。
 * @param[out] document 成功時のsecurity設定済みDOM。失敗時は空にする。
 * @return 成功時は0、policy／COM／XML検証失敗時はHRESULT bit pattern。
 * @pre 呼出しthreadでCOM apartmentが初期化されていること。
 */
[[nodiscard]] NativeError loadOfficialXmlDocument(
	std::wstring_view xmlUtf16, const OfficialXmlPolicy &policy,
	Microsoft::WRL::ComPtr<IXMLDOMDocument2> &document) ;

} // namespace drivercrate
