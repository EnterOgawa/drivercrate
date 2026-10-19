//------------------------------------------------------------------------------
/**
 * @file inf_dependency_native.h
 * @brief 実INFの非実行依存観測と個別署名診断の定義。
 * @version 01.04.00
 * @date 2026/10/06
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  安全path・署名・OS固定の読取専用adapterを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/06  封印所有者限定のnative由来入口を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/07  到達file用途と固定file累積量の独立観測を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/13  元共通内容の選択依存検査を私有factory入口へ限定。
 * Ver.01.04.00 Shunji Ogawa  2026/10/15  同元選択の依存と効果へ非機密拒否診断を追加。
 * </pre>
 *
 * @note Workerで同期借用し、実device、実行command、導入許可を扱わない。
 * @see docs/adr/0270-read-only-inf-dependency-native-adapter.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/inf_dependency_plan.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
class OfficialDownloadWorkspace ;
class OfficialAcquisitionSession ;
class OfficialInfArchiveBinding ;
struct CommonInfInspection ;
struct OfficialInfPackage ;
class RequiredDriverComponentPlan ;
struct RequiredInfBindingDiagnostic ;

/** @brief 抽出済みpackage INFの固定member。公式取得由来の証明ではない。 */
struct InfDependencyPackageMember {
	/// 保護workspace内の有限ASCII相対INF位置。
	std::wstring  relativePath ;
	/// 抽出器で固定した小文字SHA-256。
	std::wstring  sha256 ;
	/// 1～4 MiBの実INF size。
	std::uint64_t byteCount{} ;
} ;

/** @brief 一documentの署名／由来に付いた元診断。包括的不適合ではない。 */
struct InfDependencyNativeFinding {
	/// 共通graph内の一意document identity。
	std::uint64_t identity{} ;
	/// 署名不足の元HRESULT。検査合格の場合0。
	NativeError	  signatureError{} ;
	/// system由来照合の元HRESULT。未検査または合格では0の場合がある。
	NativeError	  provenanceError{} ;
} ;

/** @brief 到達INFの具体的file用途。payload位置・byte・署名は未検査。 */
struct InfDependencyNativeFileUse {
	/// 同runの原document identity。
	std::uint64_t identity{} ;
	/// 原明示節名。worker内だけに保持する。
	std::wstring  section ;
	/// 元file用途または未解釈宣言名。
	std::wstring  directive ;
	/// 展開後の原参照値。位置を推測せず、UI／logへ渡さない。
	std::wstring  target ;
} ;

/** @brief 実byteへ結合した非実行観測。型は導入用計画と互換でない。 */
struct InfDependencyNativeResult {
	/// 同OS・同runへ結合した共通依存graph。
	InfDependencyResult						dependency ;
	/// 全発見documentの署名／由来診断。
	std::vector<InfDependencyNativeFinding> findings ;
	/// 到達節・Version／sourceの最大4,096用途。空でも全payload検査の証明ではない。
	std::vector<InfDependencyNativeFileUse> fileUses ;
	/// 一runで固定したINF／CAT／Store file数。最大256、全体失敗時0。
	std::size_t								fixedFileCount{} ;
	/// 同じ固定fileの累積byte。最大128 MiB、全体失敗時0。
	std::uint64_t							fixedByteCount{} ;
} ;

/**
 * @brief 相対member位置と絶対local DOS位置の構文を検査する。
 * @param[in] path 原位置。正規化やfilesystem探索を行わない。
 * @param[in] absolute trueの場合は通常のdrive絶対path、falseの場合はASCII相対path。
 * @return 構文合格の場合true。実path認証ではない。
 */
[[nodiscard]] bool		  validInfDependencyPath( std::wstring_view path, bool absolute) noexcept ;

/**
 * @brief 保護packageと現在WindowsのINFを共通核へ非実行接続する。
 * @param[in] workspace 全package memberを呼出し終了まで所有する保護領域。
 * @param[in] members 全抽出INFの閉じた固定一覧。1～64件、重複を禁止する。
 * @param[in] rootIndex members内の開始INF位置。
 * @param[in] seeds 同じroot内の明示節群。作用完全性を認定しない。
 * @param[in] observationId 非零のworker内観測世代。
 * @param[out] result 全再確認成功時だけ保持し、全体失敗では空。
 * @return 観測完了0、不正入力・path・改変・OS差・容量・例外のHRESULT。
 * @pre 入力と出力の所有storageはaliasしない。同期workerで呼び、再入しない。
 * @note Packageの公式由来は未検査に固定する。署名成功を由来・導入許可へ流用しない。
 * OS trustがrevocation照会する場合がある。scan・staging・device導入は行わない。
 */
[[nodiscard]] NativeError inspectNativeInfDependencies(
	const OfficialDownloadWorkspace &workspace, std::span<const InfDependencyPackageMember> members,
	std::size_t rootIndex, std::span<const std::wstring> seeds, std::uint64_t observationId,
	InfDependencyNativeResult &result) ;

/** @brief 封印所有者だけが呼べるnative接続。公開boolや任意callbackを認証にしない。 */
class AcquiredInfNativeAccess final {
private:
	friend class OfficialInfArchiveBinding ;
	/**
	 * @brief 使用中固定した封印集合を同じnative loaderへ渡す。
	 * @param[in] binding 同期使用中固定を所有する封印結果。
	 * @param[in] session 元証拠の生存issuer。
	 * @param[in] archiveWorkspace 元取得領域。
	 * @param[in] rootIndex 全INF内の開始位置。
	 * @param[in] seeds 明示節群。
	 * @param[in] observationId 非零の観測世代。
	 * @param[out] result 全成功時だけの非実行結果。
	 * @return 完了0、最初の検証／API／例外のHRESULT。
	 * @pre 呼出し元が元／派生全fileを呼出し終了まで固定する。
	 */
	[[nodiscard]] static NativeError inspect( const OfficialInfArchiveBinding  &binding,
											 const OfficialAcquisitionSession &session,
											 const OfficialDownloadWorkspace  &archiveWorkspace,
											 std::size_t					   rootIndex,
											 std::span<const std::wstring>	   seeds,
											 std::uint64_t					   observationId,
											 InfDependencyNativeResult		  &result) ;
} ;
/** @brief 実内容factoryだけが呼べる選択節依存と効果の検査です。 */
class CommonInfNativeAccess final {
private:
	friend NativeError makeRequiredDriverComponentPlan(
		const CommonInfInspection &, std::span<const OfficialInfPackage>,
		std::shared_ptr<const RequiredDriverComponentPlan> &, RequiredInfBindingDiagnostic *) ;
	/** @brief 元内容を前後確認し、選択節の全Needs効果を検査します。
	 * @param[in] inspected 元保護byteと全署名を所有する内容です。
	 * @param[in] selected 同元packageの私有node選択copyです。
	 * @param[out] result 非実行graphです。効果は独立に検査します。
	 * @param[out] diagnostic 任意の非機密数値です。合否を変更する入力ではありません。
	 * @return 全依存と有限効果の充足0、未観測・未知・不合格のHRESULTです。
	 */
	[[nodiscard]] static NativeError inspect( const CommonInfInspection	  &inspected,
											 const OfficialInfPackage	  &selected,
											 InfDependencyNativeResult	  &result,
											 RequiredInfBindingDiagnostic *diagnostic) ;
} ;
} // namespace drivercrate
