//------------------------------------------------------------------------------
/**
 * @file collector_distribution_candidate.h
 * @brief 同じnative jobの私有観測から既存v2候補を生成します。
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/23  私有所有観測と全分母の決定的投影を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/24  現行nested member identityと原record完全tupleへ整合。
 * </pre>
 * @note 公開JSON decoderや成功boolから観測を構築しません。取得/導入能力はありません。
 * @see docs/adr/0396-collector-distribution-pipeline-connection.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/collector_inspection_acquisition.h"
#include "platform/official_driver_package.h"
#include "platform/official_http_client.h"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
class CollectorRegistryJobRunner ;
class CollectorRegistryJobProtectedCaller ;
class CollectorRegistryJobTestAccess ;
class CollectorDistributionCandidate ;

/** @brief 同通常検査が返した個別INFの全公開観測です。 */
struct CollectorRegistryInfObservation {
	/// Archive内の元相対INF名です。
	std::wstring				 infIdentity ;
	/// 空はflat、非空はouter内一段nestedの元相対memberです。現行identityへ投影します。
	std::wstring				 nestedArchiveIdentity ;
	/// 元内容検査の到達区分です。
	std::uint32_t				 contentState{} ;
	/// 元内容検査診断です。
	NativeError					 contentError{} ;
	/// 同公開identity読取り診断です。
	NativeError					 identityError{} ;
	/// 同検査からの公開ID/ClassGUID/INF hash/全Models集合です。
	OfficialInfPublishedIdentity identity ;
	/// 実検証INFの原class名です。
	std::wstring				 className ;
	/// 実検証INFの原versionです。
	std::wstring				 driverVersion ;
	/// 実検証INFの原日付です。
	std::wstring				 driverDate ;
	/// INFの原providerです。署名者と混同しません。
	std::wstring				 provider ;
	/// 実CATの原相対名です。
	std::wstring				 catalogIdentity ;
	/// 同じWindows CAT検査の署名者です。
	std::wstring				 verifiedPublisher ;
} ;

/** @brief 通常runnerだけが同じ実結果から作る所有観測です。 */
class CollectorRegistryVerifiedObservation final {
public:
	/** @brief 私有生成済み観測の所有権移動だけを許します。
	 * @param[in,out] other 同じrunnerが生成した観測です。
	 */
	CollectorRegistryVerifiedObservation( CollectorRegistryVerifiedObservation &&other) noexcept =
		default ;
	/** @brief 私有観測を結果objectへ移譲します。
	 * @param[in,out] other 私有生成済みの観測です。
	 * @return 同じ移譲先です。
	 */
	CollectorRegistryVerifiedObservation &operator=(
		CollectorRegistryVerifiedObservation &&other) noexcept = default ;
	/** @brief 実結果の暗黙複写を禁止します。
	 * @param[in] other 複写しない元観測です。
	 */
	CollectorRegistryVerifiedObservation( const CollectorRegistryVerifiedObservation &other) =
		delete ;

private:
	friend class CollectorRegistryJobRunner ;
	friend NativeError makeCollectorDistributionRecords(
		const CollectorRegistryVerifiedObservation &, std::chrono::sys_seconds,
		CollectorDistributionCandidate &) noexcept ;
	/** @brief 通常runnerだけが未確定の内部所有値を開始します。 */
	CollectorRegistryVerifiedObservation() = default ;
	/// 意味検証済みの原jobです。結果JSONから取得しません。
	std::string									 jobBytes_ ;
	/// 原job実byteのhashです。
	std::wstring								 jobSha256_ ;
	/// 同実取得archiveの実hashです。
	std::wstring								 archiveSha256_ ;
	/// 同実取得archiveの実byte数です。
	std::uint64_t								 archiveBytes_{} ;
	/// 同実PAGEの完全原観測です。
	CollectorInspectionPageObservation			 page_ ;
	/// 同内容検査の元UTCです。
	std::chrono::sys_seconds					 checkedAt_{} ;
	/// 同監視PCの元buildです。
	std::uint32_t								 windowsBuild_{} ;
	/// 同監視PCの元Server区分です。
	bool										 windowsServer_{} ;
	/// 同監視PCの元SKUです。
	std::uint32_t								 windowsProductSku_{} ;
	/// 同検査の全体診断です。失敗時は先行合格を投影しません。
	NativeError									 jobError_{} ;
	/// 同jobの公式導線検査が成立した事実です。外部から指定できません。
	bool										 routeVerified_{} ;
	/// 同検査の全個別INFです。個別拒否と原集合も保持します。
	std::vector<CollectorRegistryInfObservation> infs_ ;
} ;

/** @brief 保存用の既存v2値とsidecarだけを所有する未署名候補です。 */
class CollectorDistributionCandidate final {
public:
	/** @brief 空の未生成候補を作ります。 */
	CollectorDistributionCandidate() = default ;
	/** @brief 明示保存用の候補原byteを借用します。
	 * @return 代入/破棄まで有効です。失敗時空です。
	 */
	[[nodiscard]] std::string_view json() const noexcept ;
	/** @brief 切捨てず投影できたrecord件数を返します。
	 * @return 新v2 recordの実件数です。0は成功空索引を意味しません。
	 */
	[[nodiscard]] std::size_t	   recordCount() const noexcept ;

private:
	friend NativeError makeCollectorDistributionRecords(
		const CollectorRegistryVerifiedObservation &, std::chrono::sys_seconds,
		CollectorDistributionCandidate &) noexcept ;
	/// 通常logへ出さない保存用原byteです。
	std::string bytes_ ;
	/// 新候補の実件数です。
	std::size_t records_{} ;
} ;

/** @brief 同じ私有観測からINF/Models/観測OS単位の既存v2値を作ります。
 * @param[in] observation 同じnative結果objectの私有所有値です。
 * @param[in] nowUtc 保護callerの現在UTCです。元時刻/期限を更新しません。
 * @param[out] candidate 全原分母と投影可能行です。例外/不正時は空です。
 * @return 保存可能0、取得/投影不能は候補内へ理由を保持し、API/確保失敗は元診断です。
 * @note JSON decoder、通信、署名、端末照合、導入を行いません。
 */
[[nodiscard]] NativeError makeCollectorDistributionRecords(
	const CollectorRegistryVerifiedObservation &observation, std::chrono::sys_seconds nowUtc,
	CollectorDistributionCandidate &candidate) noexcept ;
} // namespace drivercrate
