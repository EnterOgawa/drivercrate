//------------------------------------------------------------------------------
/**
 * @file local_collector_http_control.h
 * @brief 収集予約に結合した一回permitと有限I/O観測を定義します。
 * @version 01.06.01
 * @date 2026/09/28
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  予約permit・二clock期限・固定観測を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/27  台帳非依存の共通HTTP制御interfaceを実装。
 * Ver.01.02.00 Shunji Ogawa  2026/09/27  Run共通取消しをcheckpointへ結合。
 * Ver.01.03.00 Shunji Ogawa  2026/09/28  本文検証後の実二時計読取りを追加。
 * Ver.01.04.00 Shunji Ogawa  2026/09/28  新世代の永続射影予約へ許可発行を接続。
 * Ver.01.05.00 Shunji Ogawa  2026/09/29  専用四slot executorへ制御所有を接続。
 * Ver.01.06.00 Shunji Ogawa  2026/10/02  全controlの実所有を元storeのticketへ結合。
 * Ver.01.06.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note 本部品は通信やworker起動を行いません。台帳の書込みは予約を発行するthreadだけです。
 * 発行済みcontrolとpoolは元監督を参照せず、最後の所有解放まで元storeの閉鎖を止めます。
 * @see docs/adr/0218-collector-controlled-http-lifetime.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "local_collector_recovery.h"
#include "official_collector_http_control.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>

namespace drivercrate {

class CollectorHttpPermitPool ;
class LocalCollectorExecutor ;
class LocalCollectorProjectedExecutor ;

/** @brief Slot所有の制御状態です。Mutex中に通信やstore操作は行いません。 */
class CollectorHttpControl final : public OfficialCollectorHttpControl {
public:
	/** @brief 通信できない未予約状態に時計と結果領域を確保します。
	 * @param[in] clock Thread-safeな所有時計callback。
	 * @param[in] cancellation 任意runの取消しsignal。共有所有し、空では旧動作を維持します。
	 * @throws std::invalid_argument 空時計の場合。
	 * @note Capture先はこのcontrolの最後の所有参照が解放されるまで存続する必要があります。
	 */
	explicit CollectorHttpControl( CollectorHttpClock					  clock,
								  std::shared_ptr<const std::atomic_bool> cancellation = {}) ;
	/** @brief 新I/Oの直前に停止・二clockを検査します。
	 * @param[in] stage 次の固定段階。
	 * @param[in] phaseLimitMillis 正数のphase上限。
	 * @return 許可時の正数timeout、停止または期限到達は0。
	 */
	[[nodiscard]] std::uint32_t begin( CollectorIoStage stage,
									  std::uint32_t	   phaseLimitMillis) override ;
	/** @brief 一回送信のAPIを明示的に呼ぶ直前に計数します。
	 * @return SEND開始確定済みで未取消し・未呼出しの場合true。
	 */
	[[nodiscard]] bool			noteSendCall() override ;
	/** @brief 成功readをconsumer・取消し確認より先に計数します。
	 * @param[in] requested 実際の正数read要求量。
	 * @param[in] received 成功APIが返した量。
	 * @return 要求量・残予算以内ならtrue。不正値はSETUP拒否です。
	 */
	[[nodiscard]] bool			noteRead( std::uint32_t requested, std::uint32_t received) override ;
	/** @brief Header時刻を元clockで一度だけ記録します。
	 * @return 送信済みで停止していなければtrue。
	 */
	[[nodiscard]] bool			noteHeaders() override ;
	/** @brief API失敗直後の原値と未知量を保持します。
	 * @param[in] cause 最初に確定させる失敗原因。
	 * @param[in] error 元数値・domain・段階。
	 * @param[in] bytesUnknown 全受信量が確定しないAPI失敗の場合true。
	 */
	void fail( CollectorIoCause cause, CollectorIoError error, bool bytesUnknown) override ;
	/** @brief 外部停止を先着確定します。Clock異常を同時検出した場合はそちらを優先します。
	 * @param[in] cause CANCELLEDまたはSHARED_STOP。それ以外はSETUP拒否です。
	 */
	void requestStop( CollectorIoCause cause = CollectorIoCause::CANCELLED) ;
	/** @brief 所有workerがnative資源の利用開始／全解放を記録します。
	 * @param[in] released 全所有資源の解放確認値。
	 */
	void setNativeReleased( bool released) override ;
	/** @brief Cleanup後に結果を一度だけ確定します。
	 * @return 今回確定できた場合true。重複確定はfalse。
	 * @note この成功値はmetadataの品質やOBSERVEDの認定ではありません。
	 */
	[[nodiscard]] bool									  finish() ;
	/** @brief 同じlock下の固定観測を取得します。
	 * @return Allocationを必要としない値のコピー。
	 */
	[[nodiscard]] CollectorIoSnapshot					  snapshot() const override ;
	/** @brief 直前のbeginが採取した実二時計を読みます。
	 * @return 欠測・後退時は空。新規採取や期限延長は行いません。
	 */
	[[nodiscard]] std::optional<CollectorHttpClockSample> lastClockSample() const ;
	/** @brief 元の永続予約を参照します。
	 * @return Slot存続中だけ有効な不変予約。URLは含みません。
	 */
	[[nodiscard]] const CollectorRecoveryDispatch		 &binding() const noexcept ;

private:
	friend class CollectorHttpPermitPool ;
	friend class CollectorHttpPermit ;
	/// Pool消滅後もclient／permit所有が残る間、元storeの閉鎖を止めます。
	std::shared_ptr<const CollectorStoreHttpLease> httpActivity_ ;
	/** @brief 保存済み予約をallocationなしでslotへ移します。
	 * @param[in,out] dispatch 監督が永続予約した所有値。
	 */
	void			   arm( CollectorRecoveryDispatch &&dispatch) noexcept ;
	/** @brief 同じslotを一clientへ一度だけ引き渡します。
	 * @param[in] client Workerが所有するclientの非null identity。
	 * @param[in] binding 呼出し側が照合した元予約。
	 * @return 全結合が一致して未消費の場合true。
	 */
	[[nodiscard]] bool claim( const void *client, const CollectorRecoveryDispatch &binding) ;
	/** @brief Lock保持中に二clock・run取消しを確認します。
	 * @param[in] checkDeadline 期限も停止原因として確定する場合true。
	 * @return 後退・欠測がなく、検査対象の期限前ならtrue。
	 */
	[[nodiscard]] bool sampleLocked( bool checkDeadline = true) ;
	/** @brief 未確定の終端だけへ最初の原因を設定します。
	 * @param[in] cause 終端原因。
	 * @param[in] error 分類値。
	 */
	void			   stopLocked( CollectorIoCause cause, CollectorIoError error) noexcept ;
	/// 全観測と先着確定を保護する短時間lock。
	mutable std::mutex mutex_ ;
	/// 全slotへ事前に設定する非blocking時計。
	CollectorHttpClock clock_ ;
	/// Run内で安定した取消しsignal。Workerは読取りだけを行います。
	std::shared_ptr<const std::atomic_bool> cancellation_ ;
	/// 永続予約済みの不変結合。
	CollectorRecoveryDispatch				binding_ ;
	/// 原値だけで構成する結果領域。
	CollectorIoSnapshot						observation_ ;
	/// 巻戻し検出用の直前観測。
	CollectorHttpClockSample				previous_ ;
	/// 予約を移した後だけtrue。
	bool									armed_{} ;
	/// 一つのclientがclaim済みの場合true。
	bool									claimed_{} ;
	/// SEND開始確定済みの場合true。
	bool									sendCommitted_{} ;
	/// 時計異常は再観測によって解除しません。
	bool									clockValid_{true} ;
} ;

/** @brief 永続予約からのみ発行されるmove専用の一回許可です。 */
class CollectorHttpPermit final {
public:
	/** @brief 送信できない空permitを作ります。 */
	CollectorHttpPermit() = default ;
	/**
	 * @brief 永続予約に結合した一回送信許可の二重管理を防ぐため、コピー構築を禁止する。
	 */
	CollectorHttpPermit( const CollectorHttpPermit &) = delete ;
	/**
	 * @brief 永続予約に結合した一回送信許可を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	CollectorHttpPermit &operator=( const CollectorHttpPermit &) = delete ;
	/** @brief 所有許可を移します。
	 * @param[in,out] other 移動元。移動後は空です。
	 */
	CollectorHttpPermit( CollectorHttpPermit &&other) noexcept = default ;
	/** @brief 所有許可を移します。
	 * @param[in,out] other 移動元。
	 * @return このobject。
	 */
	CollectorHttpPermit &operator=( CollectorHttpPermit &&other) noexcept = default ;
	/** @brief 元予約に一致するclientへ一度だけ渡します。
	 * @param[in] client Worker専用clientのidentity。
	 * @param[in] binding 再照合した予約。
	 * @return 成功時だけ所有control。二回目・別結合・空permitはnullです。
	 */
	[[nodiscard]] std::shared_ptr<CollectorHttpControl> claim(
		const void *client, const CollectorRecoveryDispatch &binding) ;
	/** @brief 許可値を保持しているか確認します。
	 * @return 空でない場合true。未消費や送信可能の保証ではありません。
	 */
	[[nodiscard]] bool							   present() const noexcept ;
	/** @brief 元予約の非変更照合に使います。
	 * @return Permit存続中だけ有効な予約。空permitはnullです。
	 */
	[[nodiscard]] const CollectorRecoveryDispatch *binding() const noexcept ;

private:
	friend class CollectorHttpPermitPool ;
	/// 発行slotと同じcontrol。Value自作から生成する入口はありません。
	std::shared_ptr<CollectorHttpControl> control_ ;
} ;

/** @brief 予約前に四slotを確保する開発用の許可発行元です。Workerは起動しません。 */
class CollectorHttpPermitPool final {
public:
	/** @brief Native I/Oより前に全controlを確保します。
	 * @param[in] clock Thread-safeかつ非blockingの時計。空は拒否します。
	 * @param[in] cancellation 任意runの共有取消し。四controlより長く保持します。
	 * @throws std::invalid_argument 空時計の場合。
	 * @throws std::bad_alloc 予約前の資源確保に失敗した場合。
	 */
	explicit CollectorHttpPermitPool( const CollectorHttpClock				&clock,
									 std::shared_ptr<const std::atomic_bool> cancellation = {}) ;
	/**
	 * @brief 四slotと発行済みcontrolの管理状態の二重管理を防ぐため、コピー構築を禁止する。
	 */
	CollectorHttpPermitPool( const CollectorHttpPermitPool &) = delete ;
	/**
	 * @brief 四slotと発行済みcontrolの管理状態を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	CollectorHttpPermitPool &operator=( const CollectorHttpPermitPool &) = delete ;
	/**
	 * @brief 四slotと発行済みcontrolの管理状態を元のpermit poolに留めるため、移動構築を禁止する。
	 */
	CollectorHttpPermitPool( CollectorHttpPermitPool &&) = delete ;
	/**
	 * @brief 元のpermit poolへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	CollectorHttpPermitPool &operator=( CollectorHttpPermitPool &&) = delete ;
	/** @brief 空slotと台帳の永続予約が成立した後だけpermitを返します。
	 * @param[in,out] recovery 元の生存中の単一writer監督。呼出し中に解放しません。
	 * @param[out] permit 空である必要があります。成功時だけ一回許可を受け取ります。
	 * @return 成功0、枠待ち1237、または元error。HTTPは行いません。
	 * @note 全操作は同じ監督threadで行います。発行済みpoolは元監督を参照せず、最後の所有までticketを保持します。
	 */
	[[nodiscard]] DWORD		 reserve( LocalCollectorRecovery &recovery, CollectorHttpPermit &permit) ;
	/** @brief 登録済みv3の専用予約を全保存した後だけ一回permitを返します。
	 * @param[in,out] recovery 元新世代の生存中の監督。呼出し中に解放しません。
	 * @param[out] permit 空である必要があり、失敗時は空のままです。
	 * @return 成功0、枠待ち1237、または元error。HTTPは行いません。
	 * @note 開発nativeの専用executorとv4受領保存で使用します。通常CLIには未接続です。
	 */
	[[nodiscard]] DWORD		 reserveProjected( LocalCollectorRecovery &recovery,
											  CollectorHttpPermit	 &permit) ;
	/** @brief 発行済みslotだけへ取消しを通知します。
	 * @param[in] cause CANCELLEDまたはSHARED_STOP。
	 */
	void					 requestStop( CollectorIoCause cause = CollectorIoCause::CANCELLED) ;
	/** @brief 結果保存・join前に再利用しない占有数です。
	 * @return 0～4。単一監督threadから使用します。
	 */
	[[nodiscard]] std::size_t occupied() const noexcept ;

private:
	friend class LocalCollectorExecutor ;
	friend class LocalCollectorProjectedExecutor ;
	/** @brief 世代別の予約入口だけを分け、一回slot管理を共用します。
	 * @param[in,out] recovery 固定writer。
	 * @param[out] permit 空の許可出力。
	 * @param[in] projected 新世代専用ならtrue。
	 * @return 元予約結果。
	 */
	[[nodiscard]] DWORD reserveForMode( LocalCollectorRecovery &recovery,
									   CollectorHttpPermit &permit, bool projected) ;
	/// 空slotを含め予約前に確保する最大四control。
	std::array<std::shared_ptr<CollectorHttpControl>, 4> controls_ ;
	/// Joinと保存の後にだけ後続executorが解放する占有状態。
	std::array<bool, 4>									 occupied_{} ;
	/// 予約直前のclock対を採取します。
	CollectorHttpClock									 clock_ ;
	/// 外部停止後は別slotへ新たな予約を発行しません。
	bool												 stopped_{} ;
	/// Address再利用でも変わる元監督の強所有identity。
	std::shared_ptr<const std::byte>					 recoveryOwner_ ;
	/// 全四controlと共有し、最後の実所有解放まで存続する元store登録。
	std::shared_ptr<const CollectorStoreHttpLease>		 httpActivity_ ;
} ;
} // namespace drivercrate
