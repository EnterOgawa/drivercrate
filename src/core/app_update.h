//------------------------------------------------------------------------------
/**
 * @file app_update.h
 * @brief App自身の版と有限な更新policyを定義します。
 * @version 01.00.01
 * @date 2026/11/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/11  App専用の通知付き更新を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 * @note ドライバー候補・索引・導入許可とは独立した値だけを扱います。
 * @see docs/adr/0481-app-inno-setup-and-update-checks.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/update_types.h"
#include <array>
#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace drivercrate {
/** @brief canonicalな三要素のApp版を表します。 */
struct AppVersion {
	/// major/minor/patchの16bit値です。PEの末尾は0に固定します。
	std::array<std::uint16_t, 3U> parts{} ;
	/**
	 * @brief 数値の辞書順で版を比較します。
	 * @param[in] other 比較するApp版。
	 * @return 各要素を数値比較した順序。
	 */
	[[nodiscard]] auto			  operator<=>( const AppVersion &other) const = default ;
} ;

/** @brief URLや実行commandを保持しない公式Setupの宣言です。 */
struct AppUpdateRelease {
	/// 正式tagとPEへ対応する期待版です。
	AppVersion		   version ;
	/// 実取得で一致を要求する正のbyte数です。
	std::uint64_t	   sizeBytes{} ;
	/// GitHub assetが宣言した小文字64桁SHA-256です。
	std::string		   sha256 ;
	/**
	 * @brief 確認時の全宣言を比較します。
	 * @param[in] other 比較先の宣言。
	 * @return 版・size・hashが全て一致する場合はtrue。
	 */
	[[nodiscard]] bool operator==( const AppUpdateRelease &other) const = default ;
} ;

/** @brief App更新だけの固定失敗区分です。 */
enum class AppUpdateFailureKind {
	/// 失敗していません。
	NONE,
	/// HTTPまたはOSの通信に失敗しました。
	NETWORK,
	/// GitHubの必要な宣言が不正です。
	METADATA,
	/// size/hash/署名/版/発行元が一致しません。
	VERIFICATION,
	/// 一時fileまたは設定fileを扱えません。
	STORAGE,
	/// 通常userのExplorerへ渡せません。
	LAUNCH,
	/// 利用者または終了による取消しです。
	CANCELLED,
	/// 配布元が指定した待機中です。
	WAIT,
	/// 自動確認の設定を読み書きできません。
	SETTINGS,
} ;

/** @brief 元の数値だけをUIへ渡すApp更新結果です。 */
struct AppUpdateFailure {
	/// 固定の失敗分類です。
	AppUpdateFailureKind kind{AppUpdateFailureKind::NONE} ;
	/// OSの元HRESULTまたはWin32変換値です。
	NativeError			 error{} ;
	/// 実際に受信したHTTP statusです。未観測は0です。
	std::uint32_t		 httpStatus{} ;
	/// 配布元が要求した待機秒数です。時刻本文は保持しません。
	std::uint64_t		 retryAfterSeconds{} ;
} ;

// 更新取得の最大実byte数です。
inline constexpr std::uint64_t			APP_UPDATE_MAX_BYTES = 128U * 1024U * 1024U ;
// 通常起動中の一回の自動確認間隔です。
inline constexpr std::uint64_t			APP_UPDATE_INTERVAL_MS = 24ULL * 60ULL * 60ULL * 1000ULL ;

//------------------------------------------------------------------------------
/**
 * @brief ASCIIのcanonical三要素版をoverflowなしで読みます。
 * @param[in] text ASCIIの三要素版です。text.size() byteのviewを呼出し中だけ借用し、NUL終端を要求せず保持しません。
 * @return 全て成立した値。不正はnulloptです。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<AppVersion> parseAppVersion( std::string_view text) noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief canonicalな三要素版を表示と固定tag用に作ります。
 * @param[in] version 表示する版。
 * @return major.minor.patchのASCII文字列。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::string				formatAppVersion( const AppVersion &version) ;
//------------------------------------------------------------------------------
/**
 * @brief 正しい版・size/hashだけをSetup取得へ渡します。
 * @param[in] release 検査対象の宣言。
 * @return sizeとhashが正しい場合はtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool		   validAppUpdateRelease( const AppUpdateRelease &release) noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief 公式repoと正確asset名だけの起点を組み立てます。
 * @param[in] release 正しい版・size/hashを持つ宣言。
 * @return 成立時の固定HTTPS URL。不正時は空文字列です。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring appUpdateAssetUrl( const AppUpdateRelease &release) ;

/** @brief 単調時計の起動一回と24hを管理する非通信policyです。 */
class AppUpdateSchedule	   final {
public:
	   /**
	    * @brief 初回または24h期限の到来を照会します。
	    * @param[in] nowMilliseconds 現在の単調millisecond。
	    * @return 期限に達している場合はtrue。
	    */
	   [[nodiscard]] bool due( std::uint64_t nowMilliseconds) noexcept ;
	   /**
	    * @brief 実際に受理した一回から次の24hを予約します。
	    * @param[in] nowMilliseconds 受理時の単調millisecond。
	    */
	   void				  attempted( std::uint64_t nowMilliseconds) noexcept ;

private:
	   /// 期限を一度予約した場合だけtrueです。
	   bool			 scheduled_{} ;
	   /// 次回の単調millisecondです。過去分を積み上げません。
	   std::uint64_t nextDue_{} ;
	   /// 時計の逆行を早期再試行にしないための前回値です。
	   std::uint64_t lastNow_{} ;
} ;
}
