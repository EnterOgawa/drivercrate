//------------------------------------------------------------------------------
/**
 * @file official_inf_archive_binding.h
 * @brief 封印公式取得からZIP／PE内INFと署名補助CATへ結合する所有境界。
 * @version 01.03.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  生存sessionと明示ZIP経路の全INF結合を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/06  最終PE形式を明示して同じ封印結果へ接続。
 * Ver.01.02.00 Shunji Ogawa  2026/10/06  使用中全file固定のnative依存観測を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/06  原CAT全体の保持と署名根拠限定を追加。
 * </pre>
 *
 * @note 同期worker専用。由来の瞬時再照合と署名・作用・導入可否を分離する。
 * @see docs/adr/0274-sealed-zip-inf-member-binding.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/official_acquisition.h"
#include "platform/official_download_workspace.h"
#include "platform/official_zip.h"
#include "platform/inf_dependency_native.h"
#include "platform/official_inf_metadata_extraction.h"

#include <memory>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {
/**
 * @brief 取得証拠・明示member経路と最終ZIP／PEの全INF／CATを単独所有する。
 * @note 公開一覧だけから認証を復元できない。borrowはmove・再bind・破棄で失効する。
 */
class OfficialInfArchiveBinding final {
public:
	/** @brief 認証とworkspaceを持たない空結果を作る。 */
	OfficialInfArchiveBinding() = default ;
	/** @brief 所有する派生fileだけをworkspaceの追跡に従って回収する。 */
	~OfficialInfArchiveBinding() = default ;
	/** @brief 所有と認証の複写を禁止する。
	 * @param[in] other 複写不能の元結果。
	 */
	OfficialInfArchiveBinding( const OfficialInfArchiveBinding &other) = delete ;
	/** @brief 複写代入を禁止する。
	 * @param[in] other 複写不能の元結果。
	 * @return 本演算子は呼出し不能である。
	 */
	OfficialInfArchiveBinding &operator=( const OfficialInfArchiveBinding &other) = delete ;
	/** @brief 派生workspaceと証拠を移動する。
	 * @param[in,out] other 移動後は検証不能となる元結果。
	 */
	OfficialInfArchiveBinding( OfficialInfArchiveBinding &&other) noexcept = default ;
	/** @brief 既存派生fileを回収し、所有を移動する。
	 * @param[in,out] other 自身以外の移動元。
	 * @return 移動先の自身。
	 * @pre 自己moveを行わない。
	 */
	OfficialInfArchiveBinding &operator=( OfficialInfArchiveBinding &&other) noexcept = default ;
	/**
	 * @brief 生存取得sessionから元archive・明示member経路・全INFを固定する。
	 * @param[in] session 当該証拠を発行した生存session。
	 * @param[in,out] evidence 成功commit時だけ所有を移す証拠。失敗時は不変。
	 * @param[in] archiveWorkspace 元取得fileを全使用期間所有する領域。
	 * @param[in] nestedMembers ZIP内の原相対member位置。最大二段、空なら直接の最終file。
	 * @param[in] format 最終fileの明示形式。既定はZIPで、拡張子から推測しない。
	 * @return 全INF結合0、入力・形式・path・容量・CRC・byte差・例外のHRESULT。
	 * @post 失敗時は自身を空にする。元fileを削除・修復しない。
	 * @note 最終ZIPまたは唯一PE表の全INF／CATの原byteを結合する。署名・作用閉包・端末適合ではない。
	 */
	[[nodiscard]] NativeError  bind(
		 const OfficialAcquisitionSession &session, OfficialAcquiredFileEvidence &&evidence,
		 const OfficialDownloadWorkspace &archiveWorkspace,
		 std::span<const std::wstring>	  nestedMembers,
		 OfficialInfContainerFormat		  format = OfficialInfContainerFormat::ZIP) ;
	/**
	 * @brief 元byte・全内側ZIPと全INF／CATを同じ生存sessionへ再結合する。
	 * @param[in] session 元証拠を発行したsession。
	 * @param[in] archiveWorkspace 元取得領域。別領域への付替えを拒否する。
	 * @return 全再確認0、失効・変更・path・競合・例外のHRESULT。
	 * @note 成功は呼出し中の観測で、後続のfile使用を固定し続ける許可ではない。
	 */
	[[nodiscard]] NativeError					   verify( const OfficialAcquisitionSession &session,
														  const OfficialDownloadWorkspace  &archiveWorkspace) const ;
	/** @brief 全INFと署名補助CATを所有する領域をworkerへ同期借用する。
	 * @return 空結果ではnullptr。取得由来の再照合を代替しない。
	 */
	[[nodiscard]] const OfficialDownloadWorkspace *workspace() const noexcept ;
	/** @brief 最終containerから確定した全INFの固定一覧を借用する。
	 * @return 原相対位置・実size・SHA-256の全INF。空結果では空。
	 * @note 原pathはworker内だけで使用し、logや永続JSONへ出さない。
	 */
	[[nodiscard]] std::span<const InfDependencyPackageMember> members() const noexcept ;
	/** @brief 全署名補助CATの原metadataだけをworkerへ同期借用する。
	 * @return 原相対位置・実size・SHA-256。CATなしまたは空結果では空。
	 * @note 値の複写を認証へ使わず、native使用中の封印所有者を移動・変更しない。
	 */
	[[nodiscard]] std::span<const OfficialZipEntry>			  catalogs() const noexcept ;
	/**
	 * @brief 全元／派生fileを使用中固定して公式由来をnative依存観測へ結合する。
	 * @param[in] session 元証拠を発行した生存session。
	 * @param[in] archiveWorkspace 元取得物を所有する同じ領域。
	 * @param[in] rootIndex 封印全INF一覧内の開始位置。
	 * @param[in] seeds 開始INF内の有限明示節群。
	 * @param[in] observationId 非零のworker内観測世代。
	 * @param[out] result 全再確認成功時だけ返し、失敗時は空にする。
	 * @return 完了0、取得失効・path・byte差・native確認・例外のHRESULT。
	 * @pre 同期workerで呼び、再入・move・再bind・破棄と入力出力aliasを行わない。
	 * @note 署名・作用・device適用性・導入許可は別軸。返却後のfile使用は固定しない。
	 */
	[[nodiscard]] NativeError inspectDependencies( const OfficialAcquisitionSession &session,
												  const OfficialDownloadWorkspace &archiveWorkspace,
												  std::size_t					   rootIndex,
												  std::span<const std::wstring>	   seeds,
												  std::uint64_t					   observationId,
												  InfDependencyNativeResult		  &result) const ;

private:
	/// 元公式取得の非永続証拠。外部からsetterを持たない。
	OfficialAcquiredFileEvidence							evidence_ ;
	/// 明示経路順のZIP member（最終PEを含む）を単独所有する有限領域。
	std::vector<std::unique_ptr<OfficialDownloadWorkspace>> archiveWorkspaces_ ;
	/// 明示memberの原位置と実size・hash。領域と同順。
	std::vector<OfficialZipEntry>							archiveMembers_ ;
	/// 最終containerから抽出した全INFと全署名補助CATを所有する領域。
	std::unique_ptr<OfficialDownloadWorkspace>				infWorkspace_ ;
	/// 最終containerで列挙した全INF。呼出し側一覧を取り込まない。
	std::vector<InfDependencyPackageMember>					infMembers_ ;
	/// 全原CATの固定metadata。INF memberとは別に保持し、使用中も全て再照合する。
	std::vector<OfficialZipEntry>							catalogMembers_ ;
} ;
} // namespace drivercrate
