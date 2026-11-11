//------------------------------------------------------------------------------
/**
 * @file official_html_terms.h
 * @brief 静的HTML許諾の一意な公開selectorと全文の共通検査を宣言します。
 * @version 01.01.01
 * @date 2026/10/14
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/14  共通HTML許諾のselector・原文書・全文検査を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/11/05  独立静的規約の原文書・公式リンクと既存同意を共通接続。
 * Ver.01.01.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 *
 * @note 通信、script/CSS評価、同意、取得grantを発行しません。
 * @see docs/adr/0339-common-static-html-terms-binding.md
 */
//------------------------------------------------------------------------------
#pragma once

#include <string>
#include <cstddef>
#include <string_view>
#include "core/update_types.h"
#include "platform/signed_index_records.h"

namespace drivercrate {

/** @brief 一つの原文書とtitle付き全文を呼出し中のRAMへ保持します。 */
struct HtmlTermsTextObservation {
	/// 一意なtextarea原文書または独立sectionの原HTMLです。通常logへ渡しません。
	std::wstring  document ;
	/// 切り詰めないtitle付き抽出全文です。通常logへ渡しません。
	std::wstring  text ;
	/// 構造失敗の段階番号です。本文は失敗時も空です。
	std::uint32_t checkStage{} ;
	/// その段階の有限な原文字位置です。内容を通常logへ出しません。
	std::size_t	  checkOffset{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 明示したtextareaまたは独立sectionの原文書と全文を共通抽出します。
 * @param[in] page 厳密UTF-8復号pageです。旧profileは256KiB、新sectionだけ2MiB相当以内です。
 * @param[in] extraction 認証前producerまたは認証後adapterが持つ元selectorです。
 * @param[in] payloadUrl 元descriptorの完全ASCII HTTPS URLです。
 * @param[in] revision 原公開titleです。空の場合だけ原titleを保持し比較しません。
 * @param[out] observation 全成功時だけ原文書と全文です。失敗時は本文空と数値診断だけです。
 * @return 全構造成功0、未対応/不一致は元HRESULTです。
 * @note 所有権を借用し、メーカー別parser、ネットワーク、許可状態は使用しません。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError extractStaticHtmlTerms( std::wstring_view				 page,
												 const IndexHtmlTermsExtraction &extraction,
												 std::string_view				 payloadUrl,
												 std::wstring_view				 revision,
												 HtmlTermsTextObservation		&observation) ;

//------------------------------------------------------------------------------
/**
 * @brief 共通抽出した原文書と全文の二つのexact size/hashを検査します。
 * @param[in] page 同じ使用時HTTPから復号した原pageです。
 * @param[in] extraction 署名recordの原文書/全文hashとselectorです。
 * @param[in] payloadUrl 同じ署名recordの原payload URLです。
 * @param[in] revision 同じ署名recordの原公開revisionです。
 * @param[out] text 全検査成立時だけ全文です。失敗時は空です。
 * @return 成功0、構造/全文/原文書不一致は元HRESULTです。
 * @note 観測pageのprovenance hashを新観測へ更新せず、HTMLの明示契約だけを検査します。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyStaticHtmlTerms( std::wstring_view				page,
												const IndexHtmlTermsExtraction &extraction,
												std::string_view				payloadUrl,
												std::wstring_view revision, std::wstring &text) ;

//------------------------------------------------------------------------------
/**
 * @brief 外pageに一つだけ存在する非実行script参照を確認します。
 * @param[in] page 保存された元pageです。Textarea/script/style内部を外要素へ数えません。
 * @param[in] absoluteUrl 公式originへ照合済みの元script URLです。
 * @param[in] relativePath 同じURLの原root-relative pathです。
 * @return 原srcへ一意に一致する場合true。実通信やJSの意味確認は行いません。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool		  hasSingleStaticHtmlScriptReference( std::wstring_view page,
															 std::wstring_view absoluteUrl,
															 std::wstring_view relativePath) ;

//------------------------------------------------------------------------------
/**
 * @brief 公式根拠HTMLの実anchorが明示された規約URLを参照するか確認します。
 * @param[in] page 最大2MiB相当の厳密UTF-8復号HTMLです。
 * @param[in] documentUrl queryなしの明示HTTPS原URLです。
 * @param[out] rejectedOffset 任意の構造停止文字位置です。本文は返しません。
 * @return script/comment外に同URLへの実anchorが一つ以上あればtrueです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool hasStaticHtmlDocumentLink( std::wstring_view page, std::string_view documentUrl,
											 std::size_t *rejectedOffset = nullptr) ;

} // namespace drivercrate
