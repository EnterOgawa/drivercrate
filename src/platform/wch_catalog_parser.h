//------------------------------------------------------------------------------
/**
 * @file wch_catalog_parser.h
 * @brief WCH公式serial配布metadata検証契約
 * @version 01.03.00
 * @date 2026/09/05
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/05  WCH公開JSONの限定解析を追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加
 * Ver.01.00.02 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.00.03 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.01.00 Shunji Ogawa  2026/11/24  公開ファイル番号の主レコード検証を共通化
 * Ver.01.02.00 Shunji Ogawa  2026/11/24  公開主レコード照会URLの構成と検証を追加
 * Ver.01.03.00 Shunji Ogawa  2026/11/24  配布名の共通検査を外部定義に提供
 * </pre>
 *
 * @note 公式取得先は検証済み整数IDだけから構成する。署名検証は別途行う
 */
//------------------------------------------------------------------------------

#pragma once

#include <string>
#include <string_view>

namespace winrt::Windows::Data::Json {
struct JsonObject ;
}

namespace drivercrate {
struct OfficialReleaseRecord ;

inline constexpr std::wstring_view WCH_PUBLIC_METADATA_HOST = L"api1.wch.cn" ;	// 照会先の完全host名

//------------------------------------------------------------------------------
/**
 * @brief 指定配布名を単一ピリオド付きのASCIIファイル名へ制限する
 * @param[in] name 収集定義が指定する元配布名
 * @return 100文字以内の単純な配布名の場合true
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool				   isWchPublicFileName( std::wstring_view name) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 公開配布ページ名から固定の公式JSON照会URLを構成する
 * @param[in] pageName 一つの公開ファイルを表す正規のページ名
 * @return 名前が有効な場合は完全HTTPS URL、不正な場合は空文字列
 * @throws std::bad_alloc URLの保持領域を確保できない場合
 * @note 取得元を決める文字列の構成だけを行う。通信や取得許可の発行は行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring		   makeWchPublicMetadataUrl( std::wstring_view pageName) ;

//------------------------------------------------------------------------------
/**
 * @brief 公開主レコードの照会URLが固定形式に完全一致するか調べる
 * @param[in] url 検査する完全HTTPS URL
 * @return 固定のhostとpathおよび一つの公開ページ名に一致する場合true
 * @note URLの置換や正規化、通信は行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool				   isWchPublicMetadataUrl( std::wstring_view url) noexcept ;

/** @brief WCH公式metadataで許可した二つのZIP配布種別 */
enum class WchOfficialPackageKind {
	/// CH340／CH341用CH341SER.ZIP
	CH341,
	/// CH342／CH343系用CH343SER.ZIP
	CH343,
} ;

//------------------------------------------------------------------------------
/**
 * @brief 公開主レコードから得た一配布の選択情報
 * @note URLは再照合と取得の入力に限り、適用性や内容の証明を示さない
 */
//------------------------------------------------------------------------------
struct WchPublicDownload {
	/// 検査済み整数ファイル番号の十進表記
	std::wstring releaseKey ;
	/// 公式メタデータの配布表示版
	std::wstring packageVersion ;
	/// 固定公式パスと同じファイル番号で構成した取得先
	std::wstring downloadUrl ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 公式JSONの一意な主レコードを指定配布名と照合する
 * @param[in] expectedName 収集条件が指定した配布ファイル名
 * @param[in] root 公式応答のJSONオブジェクトを呼出し中だけ借用する
 * @param[out] download 全条件の成立時に選択情報を返し、失敗時は初期値にする
 * @return 公開状態、名称、番号、版、固定配布先が有効な場合true
 * @pre 呼出し側で公式の取得元、元バイトの上限、UTF-8と重複JSONキーを検査済み
 * @note 空またはnullの代替URLを受理する。内容検査、取得、導入は行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readWchPublicDownload( std::wstring_view							   expectedName,
										 const winrt::Windows::Data::Json::JsonObject &root,
										 WchPublicDownload							  &download) ;

//------------------------------------------------------------------------------
/**
 * @brief WCHの主recordを検証して明示配布版と公開整数IDを保持する
 * @param[in] kind 固定した審査済み配布系列
 * @param[in] html 上限付き公式landing本文
 * @param[in] json 上限付き公式lookup本文
 * @param[out] record 成功時のworker専用record。拒否時は初期値
 * @return 既存公開ZIPの全検証条件が成立した場合true
 * @note 版をINF版として扱わず、未知の日付、容量、hash、許諾を補完しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool parseWchOfficialRelease( WchOfficialPackageKind kind, std::wstring_view html,
										   std::wstring_view json, OfficialReleaseRecord &record) ;

//------------------------------------------------------------------------------
/**
 * @brief 公式landingとJSONを検証して一つの主recordのZIP URLを得る。任意URLや関連配布物ではなく検証済み整数IDだけを使用する。Windows JSONの型／構文例
 *        外はmetadata拒否に変換する
 * @param[in] kind 検索対象に固定する配布種別。未知enumは拒否する。 審査済み配布種別
 * @param[in] html 対応する公式landingのUTF-16本文。2 Mi文字以内。 公式landing本文
 * @param[in] json 固定lookupで得たUTF-16 JSON。2 Mi文字以内。 公式lookup本文
 * @param[out] url 成功時のworker内URL。拒否時は空。 成功時だけの取得URL
 * @return Schema、公開状態、family、ID範囲が有効な場合true。 主recordの全条件が有効な場合true。拒否時は出力を空にする
 * @note 通信と署名検証は行わない。JSON表示版をINF版や適用性へ流用しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool parseWchOfficialZipUrl( WchOfficialPackageKind kind, std::wstring_view html,
										  std::wstring_view json, std::wstring &url) ;
} // namespace drivercrate
