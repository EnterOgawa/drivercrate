//------------------------------------------------------------------------------
/**
 * @file user_selected_inf_package.h
 * @brief 利用者選択INF ZIP共通検証定義。
 * @version 01.01.01
 * @date 2026/09/03
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  固定subdirectory選択検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  固定archive整合性mode追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  固定file集合の選択検証追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  共通個別INF検査の所有結果を追加。
 * Ver.01.01.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * </pre>
 *
 * @note 利用者が明示した一つのZIPだけを保護領域で検証します。入手元を公式と証明せず、INF、CAT、参照fileの内容を検証します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"
#include "platform/common_driver_package.h"
#include "platform/official_driver_package.h"
#include "platform/official_zip.h"

#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

class OfficialDownloadWorkspace ;

/**
 * @brief 検証済みINFがProvider固有のdriver familyに属するか判定する関数。
 */
using OfficialInfPackagePredicate = bool ( *)( const OfficialInfPackage &) ;

/**
 * @brief 利用者選択INF ZIP検証で最後に完了した安全な段階を表す。
 *
 * @note Path、Hardware ID、payload名を含まないため、失敗診断へ安全に表示できる。
 */
enum class UserSelectedInfPackageVerificationStage {
	/// 入力検証より前、または入力検証失敗。
	NOT_STARTED,
	/// 共有なしで保護workspaceへの複製を完了。
	ARCHIVE_COPIED,
	/// 外側ZIPの構造検証と有限展開を完了。
	OUTER_ARCHIVE_EXTRACTED,
	/// 許可された一段nested ZIPを含む全展開を完了。
	ARCHIVE_STRUCTURE_VERIFIED,
	/// 全INFの構造、Class、Provider、family検証を完了。
	INF_METADATA_VALIDATED,
	/// 全CAT member、署名、publisher検証を完了。
	PACKAGE_INTEGRITY_VERIFIED,
	/// 全driver entry coverageを含む検証を完了。
	COMPLETED,
} ;

/**
 * @brief 利用者選択INF ZIPへ適用するpackage整合性検証方式を表す。
 */
enum class UserSelectedInfPackageIntegrityMode {
	/// INFと全参照fileをSHA-256 CAT memberとして検証する。
	CATALOG_SHA256_MEMBERS,
	/// 固定ZIP hashと全binary埋込み署名を検証する。
	PINNED_ARCHIVE_AND_EMBEDDED_SIGNATURES,
} ;

/**
 * @brief 利用者選択INF ZIPのProvider固有検証条件を表す。
 *
 * @note 全spanと関数pointerはscanおよびinstallが完了するまで有効であること。
 */
struct UserSelectedInfPackagePolicy {
	/// 保護一時directoryのProvider識別子。
	std::wstring_view					workspaceTag ;
	/// 入力と展開量の有限上限。
	OfficialZipExtractionPolicy			zipPolicy ;
	/// 一入力から検証するINF数上限。
	std::size_t							maximumInfCount ;
	/// 外側ZIPに許可する一段のZIP数上限。
	std::size_t							maximumNestedArchiveCount ;
	/// 空でなければZIP全体を検査し、この固定directory内だけを展開する。
	std::wstring_view					archiveSubdirectory ;
	/// 空でなければZIP全体を検査し、この固定相対path群だけを展開する。
	std::span<const std::wstring_view>	archiveSelectedFiles ;
	/// Package内容を拘束する検証方式。
	UserSelectedInfPackageIntegrityMode integrityMode ;
	/// PinnedArchiveAndEmbeddedSignaturesで許可する64桁SHA-256群。
	std::span<const std::wstring_view>	acceptedArchiveSha256 ;
	/// 固定archive modeでINF参照と埋込み署名を要求するworkspace相対path群。
	std::span<const std::wstring_view>	embeddedSignatureFiles ;
	/// Class、Provider、PnP ID数の条件。
	OfficialInfInspectionPolicy			infPolicy ;
	/// 許可するWindows driver signer名群。
	std::span<const std::wstring_view>	signers ;
	/// Provider固有のdriver family判定関数。
	OfficialInfPackagePredicate			packagePredicate{} ;
} ;

/**
 * @brief 検証済み利用者選択ZIPのscan session内package情報を表す。
 *
 * @note `archiveSha256`は同一payload識別だけに使用し、入手元の証明にしない。
 */
struct UserSelectedInfPackageContents {
	/// 共通経路だけが保持する個別INF結果と保護閉包。従来経路ではnull。
	std::unique_ptr<CommonDriverPackageInspection> commonInspection ;
	/// 保護領域へ複製した入力ZIP全体のSHA-256。
	std::wstring								   archiveSha256 ;
	/// 検証した入力ZIPのbyte数。
	std::uint64_t								   archiveSize{} ;
	/// 安全に展開した全通常fileの相対path群。
	std::vector<OfficialZipEntry>				   entries ;
	/// 署名と全CAT memberを検証したINF群。
	std::vector<OfficialInfPackage>				   packages ;
	/// 最後の完了段階。
	UserSelectedInfPackageVerificationStage		   verificationStage{} ;
} ;

/**
 * @brief 利用者選択ZIPを保護領域へ複製して全driverを検証する。
 * 利用者選択INF ZIPを共通policyで検証する。
 * 実行fileを起動せず、全INFをfail-closedで検証する。
 * @param[in] selectedPath File dialogで利用者が一件だけ選択したlocal ZIP path。 利用者が選択したlocal ZIP path。
 * @param[in] scanSessionId 呼出し側が割り当てた0ではないscan session ID。
 * @param[in] policy Provider固有の有限上限、INF条件、signerおよびfamily条件。 Provider固有の安全性とfamily条件。
 * @param[in,out] workspace 未初期化の保護workspace。作成fileを単独所有する。 保護された複製・展開先。
 * @param[out] contents 成功時のarchive hash、entry、検証済みINF。失敗時は完了段階だけを保持する。 全検証成功時のpackage情報。
 * @return 全検証成功時は0、入力、ZIP、INF、CATまたは署名違反時はHRESULT。 全ZIP、INF、CAT、参照file検証成功時は0。
 * @note Nested ZIPはpolicyが許す場合も一段だけで、展開量を全archive合計で検証する。
 */
[[nodiscard]] NativeError inspectUserSelectedInfPackageFile(
	std::wstring_view selectedPath, ScanSessionId scanSessionId,
	const UserSelectedInfPackagePolicy &policy, OfficialDownloadWorkspace &workspace,
	UserSelectedInfPackageContents &contents) ;

/**
 * @brief 一つの利用者選択INFをinstall直前に再検証する。
 * 利用者選択INFを共通policyでinstall直前に再検証する。
 * Admin競合による展開file差替えをSetupAPI呼出し前に拒否する。
 * @param[in] workspace Scan時の複製ZIPと展開fileを所有する保護workspace。 Scan時の展開fileを所有する保護領域。
 * @param[in] entries Scan時に確定した全ZIP entry。 Scan時に確定した全file entry。
 * @param[in] expected Scan時に検証してcandidateへ対応付けたINF metadata。 Scan時に保持したINF metadata。
 * @param[in] policy Scan時と同一のProvider固有検証条件。 Scan時と同じProvider固有条件。
 * @return 構造、署名、CAT member、family、全metadataが一致する場合は0。 構造、family、署名、CAT member、metadata一致時は0。
 */
[[nodiscard]] NativeError reverifyUserSelectedInfPackage(
	const OfficialDownloadWorkspace &workspace, std::span<const OfficialZipEntry> entries,
	const OfficialInfPackage &expected, const UserSelectedInfPackagePolicy &policy) ;

} // namespace drivercrate
