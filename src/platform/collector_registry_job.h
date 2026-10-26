//------------------------------------------------------------------------------
/**
 * @file collector_registry_job.h
 * @brief 外部収集jobの非通信検証と保護caller限定の取得・通常検査を定義します。
 * @version 01.03.00
 * @date 2026/10/23
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/23  外部jobの厳密検証と一回取得・公開INF結果を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/23  私有実行上限・同run PAGE借用とtyped転送結果を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/23  保護caller結合と私有の全体/個別失敗区分を保持。
 * Ver.01.03.00 Shunji Ogawa  2026/10/23  同じ通常検査から私有所有の全公開観測を保持。
 * </pre>
 *
 * @note 実行は後続の保護caller専用です。公開JSONから取得証拠・実行権限を作りません。
 * @see docs/adr/0395-data-driven-collector-expansion.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/collector_inspection_acquisition.h"
#include "platform/common_driver_package.h"
#include "platform/collector_distribution_candidate.h"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace drivercrate {

inline constexpr std::size_t COLLECTOR_REGISTRY_JOB_MAX_BYTES =
	1024U * 1024U ;	// 一jobの有限読取枠です。

class CollectorRegistryJobProtectedCaller ;
class CollectorRegistryJobTestAccess ;

/** @brief 保護callerだけが元jobと独立して縮小する今回の実行枠です。
 * @note JSONから生成できず、通信許可・予約・native admission自体は発行しません。
 */
class CollectorRegistryExecutionLimits final {
private:
	friend class CollectorRegistryJobProtectedCaller ;
	friend class CollectorRegistryJobTestAccess ;
	friend class CollectorRegistryJobRunner ;
	/** @brief 今回の正のpayload capと固定期限を所有します。
	 * @param[in] payloadCapBytes 原job/32MiB以下の正の上限です。
	 * @param[in] deadline 延長しない実行期限です。
	 * @param[in] now 空は実steady clock、試験だけfake時計です。
	 */
	CollectorRegistryExecutionLimits(
		std::uint64_t payloadCapBytes, std::chrono::steady_clock::time_point deadline,
		std::function<std::chrono::steady_clock::time_point()> now = {}) ;
	/** @brief 元期限を同じ単調時計へ再確認します。
	 * @return 期限到達または時計障害時trueです。
	 */
	[[nodiscard]] bool									   expired() const noexcept ;
	/// 原jobを書き換えず今回だけ適用する上限です。
	std::uint64_t										   payloadCapBytes_{} ;
	/// 同runで延長しない実行期限です。
	std::chrono::steady_clock::time_point				   deadline_ ;
	/// 専用fixture以外では空です。
	std::function<std::chrono::steady_clock::time_point()> now_ ;
} ;

/** @brief 厳密検証した原jobだけを保持します。公式性や通信許可を持ちません。 */
class CollectorRegistryJob final {
public:
	/** @brief 無効な空jobを作ります。 */
	CollectorRegistryJob() = default ;
	/** @brief 元jobに結合した製品参照件数を返します。
	 * @return 有効な一jobの製品件数。無効時0です。
	 */
	[[nodiscard]] std::size_t productCount() const noexcept ;

private:
	friend class CollectorRegistryJobRunner ;
	friend class CollectorRegistryJobProtectedCaller ;
	friend NativeError parseCollectorRegistryJob( std::string_view, CollectorRegistryJob &) noexcept ;
	/// 入力原byteです。通常logへ出しません。
	std::string		   bytes_ ;
	/// 原byteの実CNG SHA-256です。
	std::wstring	   sha256_ ;
	/// 検証済みの多対多製品参照件数です。
	std::size_t		   products_{} ;
} ;

/** @brief 一jobの全field・重複・型・境界・内部参照を非通信で検証します。
 * @param[in] bytes UTF-8原jobです。最大1MiB、呼出し中は変更しません。
 * @param[out] job 成功時だけ原byteへ結合したjobです。失敗時は空です。
 * @return 成功0、入力拒否E_INVALIDARG、API/確保失敗は元HRESULTです。
 * @note 元台帳との全体参照再計算・lock・予約・待機は保護callerが別途確認します。
 */
[[nodiscard]] NativeError		 parseCollectorRegistryJob( std::string_view		 bytes,
														   CollectorRegistryJob &job) noexcept ;

/** @brief 同じ一回native実行だけが生成する明示結果です。JSONから復元できません。 */
class CollectorRegistryJobResult final {
public:
	/** @brief 未実行の空結果を作ります。 */
	CollectorRegistryJobResult() = default ;
	/** @brief 明示保存用JSONを同期借用します。
	 * @return 次の実行・代入・破棄まで有効な結果です。未実行時は空です。
	 * @note 公開INF ID/公式URLを含むため通常log/stdoutへ出しません。導入権限ではありません。
	 */
	[[nodiscard]] std::string_view						  json() const noexcept ;
	/** @brief 同じnative I/Oの元PAGE転送を返します。
	 * @return 未実行/途中失敗もUNKNOWNとして保持します。
	 */
	[[nodiscard]] const CollectorHttpTransferObservation &pageTransfer() const noexcept ;
	/** @brief 同じjobのpayload転送を返します。
	 * @return 後段INF/CATの判定と独立した実観測です。
	 */
	[[nodiscard]] const CollectorHttpTransferObservation &payloadTransfer() const noexcept ;
	/** @brief 同run PAGE借用の今回の事実を返します。
	 * @return trueなら今回の増分PAGE課金は0要求/0byteです。
	 */
	[[nodiscard]] bool									  pageReusedInRun() const noexcept ;

private:
	friend class CollectorRegistryJobRunner ;
	friend class CollectorRegistryJobProtectedCaller ;
	friend class CollectorRegistryJobTestAccess ;
	/// Nativeが元入力と同取得・検査を結合して生成した結果です。
	std::string											bytes_ ;
	/// 同実PAGEの原観測です。共有時も元値を保持します。
	CollectorHttpTransferObservation					pageTransfer_ ;
	/// 同jobの実payload観測です。
	CollectorHttpTransferObservation					payloadTransfer_ ;
	/// 同じ実検査が確定した全体区分です。公開JSONから設定できません。
	std::wstring										outcome_ ;
	/// 同じ実検査が確定した固定理由です。
	std::wstring										reason_ ;
	/// 全体検査の元HRESULTです。S_FALSEの個別拒否とは区別します。
	NativeError											error_{} ;
	/// 同runの元PAGEだけを借用した事実です。
	bool												pageReusedInRun_{} ;
	/// 同じ通常検査だけが構築する公開metadataの私有所有観測です。
	std::optional<CollectorRegistryVerifiedObservation> observation_ ;
} ;

/** @brief 保護予約caller以外に実行入口を公開しない一回native runnerです。
 * @note setup親の専用callerだけが実lock/admission/予約を保持して接続します。
 */
class CollectorRegistryJobRunner final {
public:
	/** @brief 一回scopeの暗黙複写を禁止します。 */
	CollectorRegistryJobRunner( const CollectorRegistryJobRunner &) = delete ;
	/** @brief 一回scopeの状態上書きを禁止します。
	 * @return 呼出し不能です。
	 */
	CollectorRegistryJobRunner &operator=( const CollectorRegistryJobRunner &) = delete ;
	/** @brief 内部adapterを解放します。保護fileはrun終了時に回収済みです。 */
	~CollectorRegistryJobRunner() = default ;

private:
	friend class CollectorRegistryJobProtectedCaller ;
	friend class CollectorRegistryJobTestAccess ;
	/** @brief 構築だけでは通信しない実HTTP runnerを作ります。 */
	CollectorRegistryJobRunner() = default ;
	/** @brief 試験TUだけが完全fake HTTPを接続します。
	 * @param[in] transport Nativeで補完しない全I/O表です。通常jobから設定できません。
	 */
	explicit CollectorRegistryJobRunner( OfficialHttpTransport transport) ;
	/** @brief 同じ原jobを一回取得し、全INFまたは明示集合を通常検査します。
	 * @param[in] job 原入力を検証済みのjobです。
	 * @param[in] sessionId 保護callerが所有する0でないoperation IDです。
	 * @param[in,out] costReader 実回線照会または試験依存です。
	 * @param[in] cancellation 非blockingの協調停止照会です。
	 * @param[in] limits 親が全段予約から計算した今回のcapと期限です。
	 * @param[out] result 元入力・通常の全失敗を保持する明示結果です。再使用拒否・例外時は空です。
	 * @param[in,out] pageScope 任意の同run私有PAGE所有者です。Nullは共有なしです。
	 * @param[in] pageProof 任意の同scope完全PAGEです。無効時は新GETへfallbackしません。
	 * @return 全INFと公開metadataの成立0、部分拒否S_FALSE、全体失敗は元HRESULTです。
	 * @pre 保護callerが同じrootのlock/admission・PAGE/payload全段予約を保持します。
	 * @note 原成功JSONを受け付けず、検査中も封印取得証拠を再照合します。端末列挙は行いません。
	 *       結果欠損を保護callerでUNKNOWN_OUTCOMEへ残し、予約を取り消して再実行してはなりません。
	 */
	[[nodiscard]] NativeError	   run( const CollectorRegistryJob &job, ScanSessionId sessionId,
									   IOfficialNetworkCostReader			  &costReader,
									   const HttpCancellationCallback		  &cancellation,
									   const CollectorRegistryExecutionLimits &limits,
									   CollectorRegistryJobResult			  &result,
									   CollectorRunPageScope				  *pageScope = nullptr,
									   const CollectorRunPageProof			  *pageProof = nullptr) ;
	/// 同scopeの実取得adapterです。二回目の実行を拒否します。
	CollectorInspectionAcquisition acquisition_ ;
	/// 成否にかかわらず初回runでtrueになります。
	bool						   used_{} ;
#ifdef DRIVERCRATE_REGISTRY_JOB_TESTING
	/// 専用unit targetだけの通常検査I/O置換です。製品binaryとjobには存在しません。
	std::function<NativeError( const DriverArchiveInput &, OfficialDriverArchiveFormat,
							  CommonDriverPackageInspection &)>
		inspectionProbe_ ;
	/// 同unitだけの公開metadata I/O置換です。保存成功JSONの読取りではありません。
	std::function<NativeError( const CommonInfInspection &, OfficialInfPublishedIdentity &,
							  std::wstring &)>
		identityProbe_ ;
#endif
} ;
} // namespace drivercrate
