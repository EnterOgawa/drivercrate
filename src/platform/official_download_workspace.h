//------------------------------------------------------------------------------
/**
 * @file official_download_workspace.h
 * @brief 公式配布file用保護一時領域定義。
 * @version 01.01.00
 * @date 2026/10/24
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  Package階層fileの安全な作成を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  失敗file破棄と空き容量照会を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  SetupAPI展開fileの所有取込み追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/04  子要素の保護DACL継承／再適用。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * Ver.01.01.00 Shunji Ogawa  2026/10/24  現行nested member identityと原record完全tupleへ整合。
 * </pre>
 *
 * @note 公式Providerの取得／展開fileをAdministratorsおよびSYSTEMだけが変更できる一時directoryへ保存し、自身が追跡する既知fileだけを削除します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <Windows.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

/** @brief nativeと公開identityに共通する安全なarchive member文法だけを検査します。
 * @param[in] value 原ASCII相対member。全体160文字、要素96文字までです。
 * @param[in] separator nativeはbackslash、公開identityはslashを明示します。
 * @return 全要素が安全で指定以外の区切りを含まない場合だけtrueです。
 * @note 正規化、filesystem path構築、I/O、取得/導入許可の発行を行いません。
 */
[[nodiscard]] bool isSafeOfficialArchiveMember( std::wstring_view value, wchar_t separator) noexcept ;

//------------------------------------------------------------------------------
// 保護一時領域class定義。
//------------------------------------------------------------------------------

/**
 * @brief 公式配布fileの新規作成と所有を追跡し、scope終了時に既知pathだけを削除する。
 *
 * @note Directoryと全子要素はSYSTEMとAdministratorsだけにfull accessを許可する。
 * Archive由来pathはASCII相対pathに限定し、再帰削除は行わない。
 */
class OfficialDownloadWorkspace final {
public:
	/**
     * @brief 空の一時領域を作成する。
     */
	OfficialDownloadWorkspace() = default ;

	/**
	 * @brief 作成済みfileとdirectoryをbest-effortで削除する。
	 * 自身が追跡する絶対pathだけを削除し、列挙や再帰削除は行わない。
	 */
	~OfficialDownloadWorkspace() ;

	// File pathとdirectoryを単独所有するためcopy/moveを禁止する。
	/**
	 * @brief 追跡fileとdirectoryの削除責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	OfficialDownloadWorkspace( const OfficialDownloadWorkspace &) = delete ;
	/**
	 * @brief 追跡fileとdirectoryの削除責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	OfficialDownloadWorkspace &operator=( const OfficialDownloadWorkspace &) = delete ;
	/**
	 * @brief 追跡fileとdirectoryの削除責務を元の保護workspaceに留めるため、移動構築を禁止する。
	 */
	OfficialDownloadWorkspace( OfficialDownloadWorkspace &&) = delete ;
	/**
	 * @brief 元の保護workspaceへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	OfficialDownloadWorkspace &operator=( OfficialDownloadWorkspace &&) = delete ;

	/**
	 * @brief Windows Temp配下へ保護された固有directoryを作成する。
	 * SYSTEMとAdministratorsだけが利用できるdirectoryを、既存pathを再利用せず有限回の試行で作成する。
	 * @param[in] providerTag 小文字ASCII英数字とhyphenだけのProvider識別子。 安全なProvider識別子。
	 * @param[in] scanSessionId 0ではないscan session ID。
	 * @return 成功時は0、入力またはWin32処理失敗時はHRESULT bit pattern。
	 */
	[[nodiscard]] NativeError  initialize( std::wstring_view providerTag,
										  ScanSessionId		scanSessionId) ;

	/**
	 * @brief 一時領域内へ検証済み相対pathの新規fileを作成する。
	 * 親directoryとfileを自身で新規作成し、作成済みpathだけをcleanup対象へ登録する。
	 * @param[in] name `\\`で階層を区切る安全なASCII相対path。 Provider内部で指定する安全なASCII相対path。
	 * @param[out] handle 成功時に呼出し側がCloseHandleするread/write handle。 成功時に呼出し側がCloseHandleするhandle。
	 * @return 成功時は0、既存file、入力、Win32処理失敗時はHRESULT bit pattern。
	 */
	[[nodiscard]] NativeError  createFile( std::wstring_view name, HANDLE &handle) ;

	/**
	 * @brief SetupAPIが新規fileを作成できる追跡付き非存在pathを準備する。
	 * 外部writer用の追跡付き非存在file pathを準備する。
	 * CREATE_NEWで衝突を検出した後に空fileを削除し、同期展開を待つ。
	 * @param[in] name `\\`で階層を区切る安全なASCII相対path。 SetupAPIに作成を許可する安全な相対path。
	 * @param[out] outputPath 成功時にSetupAPIへ渡すworkspace内絶対path。 成功時のworkspace内絶対path。
	 * @return 親directory、非存在、cleanup追跡の準備成功時は0。 親directory作成、非存在確定、予約追跡の成功時は0。
	 * @note 同期の外部writerだけに使用し、完了時は`adoptFile`を呼ぶ。
	 */
	[[nodiscard]] NativeError prepareExternalFile( std::wstring_view name, std::wstring &outputPath) ;

	/**
	 * @brief 自身が作成した既知fileを直ちに削除して追跡対象から除く。
	 * 自身が作成した既知fileを直ちに削除する。
	 * 追跡済み絶対pathだけを削除し、失敗時はdestructor用追跡を維持する。呼出し側は事前に全handleを閉じる。
	 * @param[in] name `createFile`または`prepareExternalFile`の検証済み相対path。 作成済みまたは外部writer用の検証済み相対path。
	 * @return 削除成功時は0、未知pathまたはWin32処理失敗時はHRESULT bit pattern。
	 * @note 呼出し前に対象fileの全handleを閉じる。未作成の予約解除も成功とする。
	 */
	[[nodiscard]] NativeError discardFile( std::wstring_view name) ;

	/**
	 * @brief SetupAPIがworkspace内に作成したfileを検証して所有へ取り込む。
	 * SetupAPIが作成したfileをworkspace所有へ取り込む。
	 * 同期SetupAPI callback直後に通常fileとsizeを検証し、保護DACLを再適用する。失敗時は未追跡fileを削除する。
	 * @param[in] name `prepareExternalFile`で予約した安全な相対path。 事前に親directoryと非存在を固定した相対path。
	 * @param[in] expectedBytes SetupAPIがCAB entryで通知した展開後byte数。 CAB entryが通知した展開後byte数。
	 * @return 通常fileのsize検証とcleanup追跡への登録成功時は0。 通常file、sizeおよび所有追跡登録の成功時は0。
	 * @note 通常fileとsizeを検証し、保護DACLの再適用失敗時はfileを削除する。
	 */
	[[nodiscard]] NativeError adoptFile( std::wstring_view name, std::uint64_t expectedBytes) ;

	/**
	 * @brief Workspaceを置くvolumeで呼出しprocessが利用可能なbyte数を取得する。
	 * Workspace volumeの利用可能byte数を取得する。
	 * Workspaceと同じvolumeを対象とし、quotaを反映した値を返す。
	 * @param[out] availableBytes 成功時の利用可能byte数。失敗時は0。 成功時に呼出しprocessが利用可能なbyte数。失敗時は0。
	 * @return 取得成功時は0、未初期化またはWin32処理失敗時はHRESULT bit pattern。
	 */
	[[nodiscard]] NativeError queryAvailableBytes( std::uint64_t &availableBytes) const noexcept ;

	/**
	 * @brief 作成済み一時領域内の検証済み相対pathを絶対pathへ変換する。
	 * 作成済みかどうかは判定せず、directory境界だけを保証する。
	 * @param[in] name `\\`で階層を区切る安全なASCII相対path。 Provider内部で指定する安全なASCII相対path。
	 * @return 有効な入力なら絶対path、それ以外は空文字列。 入力有効時は絶対path、それ以外は空文字列。
	 */
	[[nodiscard]] std::wstring path( std::wstring_view name) const ;

private:
	/// Destructorで削除する保護directory絶対path。
	std::wstring			  directory_ ;
	/// 自身が作成し、逆順削除するfile絶対path群。
	std::vector<std::wstring> files_ ;
	/// 外部writer用に予約した未取込みpath群。
	std::vector<std::wstring> pendingFiles_ ;
	/// 自身が作成し、逆順削除する子directory群。
	std::vector<std::wstring> directories_ ;
} ;

} // namespace drivercrate
