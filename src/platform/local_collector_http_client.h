//------------------------------------------------------------------------------
/**
 * @file local_collector_http_client.h
 * @brief 永続permitと共通公式HTTPの開発用adapterを定義します。
 * @version 01.02.03
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  有限DNS・共通HTTP制御接続を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/28  新modeの一回200本文所有型を追加。
 * Ver.01.01.01 Shunji Ogawa  2026/09/28  本文所有fieldの前置コメント形式を補修。
 * Ver.01.01.02 Shunji Ogawa  2026/09/28  未pinの304・validatorを拒否する契約へ変更。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  不変入力GETと本文の明示消費・同一制御を追加。
 * Ver.01.02.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * Ver.01.02.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.02.03   Shunji Ogawa  2026/10/16 本文moveの移譲元・戻り値と自己代入時の状態保持を明記。
 * </pre>
 *
 * @note 台帳・公式parser・導入処理は実行しません。
 * @see docs/adr/0218-collector-controlled-http-lifetime.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "platform/official_collector_dns.h"
#include "platform/local_collector_http_control.h"
#include "platform/local_driver_collector.h"
#include "platform/local_collector_projected_input.h"
#include "platform/official_http_client.h"

#include <optional>

namespace drivercrate {
/** @brief 一回の正常200だけから作る秘密本文のmove-only所有値です。 */
class CollectorMetadataBody final {
public:
	/**
	 * @brief 未消費の正常200本文と有効状態の二重管理を防ぐため、コピー構築を禁止する。
	 */
	CollectorMetadataBody( const CollectorMetadataBody &) = delete ;
	/**
	 * @brief 未消費の正常200本文と有効状態を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	CollectorMetadataBody &operator=( const CollectorMetadataBody &) = delete ;
	/**
	 * @brief 本文と有効状態を移し、元objectを必ず無効にします。
	 * @param[in,out] other 本文と検証状態の移譲元。move後は無効となり、本文と本文hashを空にします。
	 */
	CollectorMetadataBody( CollectorMetadataBody &&other) noexcept ;
	/**
	 * @brief 自身以外から本文と有効状態を移し、移譲元を無効にします。
	 * @param[in,out] other 移譲元。自身へのmoveは状態不変、それ以外はmove後に無効となります。
	 * @return このobject自身の参照。自身へのmoveでも同じ参照を返します。
	 */
	CollectorMetadataBody &operator=( CollectorMetadataBody &&other) noexcept ;
	/**
	 * @brief 未消費の正常200本文がある場合だけtrueです。
	 * @return 未消費の正常200を保持する場合true。移動元または消費後はfalse。
	 */
	[[nodiscard]] bool	   valid() const noexcept
	{
		return valid_ ;
	}
	/** @brief 変更不能jobへ本文を一回だけ結合し、元controlを返します。
	 * @param[in] campaign 元保存inputから全再構築した所有campaign。
	 * @param[in] jobIndex 元永続予約のjob index。
	 * @param[out] control 成功時だけ同じGETのcontrol。失敗時は空です。
	 * @return 全bindingと未確定観測が一致し、一回消費した場合true。
	 * @note 成否にかかわらず最初の試行で消費します。PARSEの期限確認はcallerが行います。
	 */
	[[nodiscard]] bool consumeForProjection(
		const CollectorPreparedProjectedCampaign &campaign, std::size_t jobIndex,
		std::shared_ptr<CollectorHttpControl> &control) noexcept ;
	/**
	 * @brief 同一GETからdecodeした本文をworker内だけで借用します。
	 * @return 内部本文への非所有view。このobjectの移動・破棄まで有効。valid()の判定は呼出し側が行う。
	 */
	[[nodiscard]] std::wstring_view text() const noexcept
	{
		return text_ ;
	}
	/**
	 * @brief 元200のraw byte SHA-256を返します。
	 * @return 内部raw byte SHA-256への非所有参照。このobjectの移動・破棄まで有効。
	 */
	[[nodiscard]] const std::wstring &bodySha256() const noexcept
	{
		return bodySha256_ ;
	}
	/**
	 * @brief Header実観測時刻を返します。
	 * @return Header実観測UTCのUnix epoch millisecond。
	 */
	[[nodiscard]] std::uint64_t headerUtcMillis() const noexcept
	{
		return headerUtcMillis_ ;
	}
	/**
	 * @brief Decode・hash・解放を確認した実時刻を返します。
	 * @return 本文検証完了UTCのUnix epoch millisecond。
	 */
	[[nodiscard]] std::uint64_t validatedUtcMillis() const noexcept
	{
		return validatedUtcMillis_ ;
	}
	/**
	 * @brief 元予約の所有copyを返します。
	 * @return 内部に所有した元予約へのconst借用参照。このobjectの移動・破棄まで有効。
	 */
	[[nodiscard]] const CollectorRecoveryDispatch &binding() const noexcept
	{
		return binding_ ;
	}
	/**
	 * @brief 元の全対象scope hashを返します。
	 * @return 内部に所有した全対象scope hashへの非所有参照。このobjectの移動・破棄まで有効。
	 */
	[[nodiscard]] const std::wstring &scopeSha256() const noexcept
	{
		return scopeSha256_ ;
	}
	/**
	 * @brief 元公式Provider IDを返します。
	 * @return 内部に所有した公式Provider IDへの非所有参照。このobjectの移動・破棄まで有効。
	 */
	[[nodiscard]] const std::wstring &providerId() const noexcept
	{
		return providerId_ ;
	}
	/**
	 * @brief 元組み込みpolicy IDを返します。
	 * @return 内部に所有した組み込みpolicy IDへの非所有参照。このobjectの移動・破棄まで有効。
	 */
	[[nodiscard]] const std::wstring &policyId() const noexcept
	{
		return policyId_ ;
	}

private:
	friend class LocalCollectorHttpClient ;
	/**
	 * @brief 同じclientの正常200だけが呼ぶ所有constructorです。
	 * @param[in,out] text 同じ正常200からdecodeした本文。moveして所有し、呼出し後の元文字列の内容は未規定。
	 * @param[in,out] bodySha256 同じ200のraw byte SHA-256。moveして所有する。
	 * @param[in] headerUtcMillis 元headerの実観測UTC、Unix epochからのmillisecond。
	 * @param[in] validatedUtcMillis Decode・hash・解放を確認したUTC millisecond。
	 * @param[in] binding 本文を取得した元予約。必要なfieldをcopyして所有する。
	 * @param[in] job 同じ予約へ結合した公開job。scope・Provider・policyの識別子をcopyする。
	 * @param[in] control 同じGETを管理する非nullの共有制御。共有所有権を保持する。
	 */
	CollectorMetadataBody( std::wstring &&text, std::wstring &&bodySha256,
						  std::uint64_t headerUtcMillis, std::uint64_t validatedUtcMillis,
						  const CollectorRecoveryDispatch			  &binding,
						  const CollectorProjectedJobInput			  &job,
						  const std::shared_ptr<CollectorHttpControl> &control) ;
	/// 外部から差替えできない本文。
	std::wstring						  text_ ;
	/// 元raw byte hash。
	std::wstring						  bodySha256_ ;
	/// 元header UTC millisecond。
	std::uint64_t						  headerUtcMillis_{} ;
	/// 本文検証終了UTC millisecond。
	std::uint64_t						  validatedUtcMillis_{} ;
	/// 元予約の全field。
	CollectorRecoveryDispatch			  binding_ ;
	/// 元全対象scope。
	std::wstring						  scopeSha256_ ;
	/// 組み込みProvider。
	std::wstring						  providerId_ ;
	/// Sourceと別のpolicy。
	std::wstring						  policyId_ ;
	/// 同一GETの所有制御。別のcontrolを解析へ差し込まない。
	std::shared_ptr<CollectorHttpControl> control_ ;
	/// 移動元・消費後を明示的に拒否します。
	bool								  valid_{} ;
} ;

/** @brief 一つのworkerだけが所有する、一回GET専用adapterです。 */
class LocalCollectorHttpClient final {
public:
	/** @brief 明示nativeの一回clientを作ります。構築だけでは通信しません。 */
	LocalCollectorHttpClient() ;
	/** @brief 完全な非通信API表で一回clientを作ります。
	 * @param[in] transport 全使用関数をfakeへ置換した表。Native混在を拒否します。
	 * @param[in] dnsApi 全関数をfakeへ置換したDNS表。
	 */
	LocalCollectorHttpClient( OfficialHttpTransport transport, OfficialCollectorDnsApi dnsApi) ;
	/**
	 * @brief 一回GETの使用状態とHTTP・DNS依存の二重管理を防ぐため、コピー構築を禁止する。
	 */
	LocalCollectorHttpClient( const LocalCollectorHttpClient &) = delete ;
	/**
	 * @brief 一回GETの使用状態とHTTP・DNS依存を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	LocalCollectorHttpClient &operator=( const LocalCollectorHttpClient &) = delete ;
	/** @brief 永続予約と再構築requestを照合して最大一回GETします。
	 * @param[in] target 検証済み公開製品条件。
	 * @param[in] binding 元dispatch。全fieldをpermitと照合します。
	 * @param[in,out] permit 同じworkerへ移された一回許可。
	 * @param[in] entityTag 空または元cacheのvalidator。Basis受入は後続です。
	 * @param[out] text 成功200の厳密UTF-8本文。失敗・304では空。
	 * @param[out] observation 元status／待機と成功時hash。
	 * @param[out] control claimできた場合の所有制御。最終parser・finish用で、再送許可ではありません。
	 * @return 共通HTTP成功0、または拒否HRESULT。導入・grant発行は行いません。
	 * @note 同一threadのCOM apartment内で呼びます。Client再使用・依存欠損では通信0です。
	 */
	[[nodiscard]] NativeError get( const LocalCollectorTarget	  &target,
								  const CollectorRecoveryDispatch &binding,
								  CollectorHttpPermit &permit, std::wstring_view entityTag,
								  std::wstring							&text,
								  CollectorControlledHttpObservation	&observation,
								  std::shared_ptr<CollectorHttpControl> &control) ;
	/** @brief 元canonicalから再構築したjobだけを新接続から受け付けます。
	 * @param[in] campaign 全scopeと専用Gを所有する変更不能campaign。
	 * @param[in] jobIndex 元予約の共有job index。
	 * @param[in] binding 同じjobの永続予約。
	 * @param[in,out] permit 一回GETの元許可。
	 * @param[in] entityTag 元200 pin前のため空だけを受理します。
	 * @param[out] body 正常200だけの一回消費可能な本文。
	 * @param[out] observation 原HTTP観測。
	 * @param[out] control cleanupを担当する同じ制御。
	 * @return 成功0。拒否時は送信せず本文を作りません。
	 */
	[[nodiscard]] NativeError getMetadataBody( const CollectorPreparedProjectedCampaign &campaign,
											  std::size_t								jobIndex,
											  const CollectorRecoveryDispatch		   &binding,
											  CollectorHttpPermit					   &permit,
											  std::wstring_view							entityTag,
											  std::optional<CollectorMetadataBody>	   &body,
											  CollectorControlledHttpObservation	   &observation,
											  std::shared_ptr<CollectorHttpControl>	   &control) ;

private:
	/** @brief prepared型からだけ呼び、固定一jobの元GETを発行します。
	 * @param[in] job 元canonicalから再構築した一job。
	 * @param[in] binding 専用永続予約。
	 * @param[in,out] permit 一回許可。
	 * @param[in] entityTag 元200 pin前は空だけを受理します。
	 * @param[out] body 正常200本文だけを所有します。
	 * @param[out] observation 原HTTP観測。
	 * @param[out] control 同一GETのcleanup制御。
	 * @return 正常200は0、拒否はHRESULT。
	 */
	[[nodiscard]] NativeError getMetadataBody( const CollectorProjectedJobInput		&job,
											  const CollectorRecoveryDispatch		&binding,
											  CollectorHttpPermit					&permit,
											  std::wstring_view						 entityTag,
											  std::optional<CollectorMetadataBody>	&body,
											  CollectorControlledHttpObservation	&observation,
											  std::shared_ptr<CollectorHttpControl> &control) ;
	/**
	 * @brief 旧／新modeごとに同じ一回GETとpermit検査を実行します。
	 * @param[in] target 同じ予約から再構築した公開対象。同期呼出し中だけ借用する。
	 * @param[in] binding 元dispatch。modeを含む全結合を一回許可と照合する。
	 * @param[in,out] permit 同じworkerが所有する未使用の一回許可。claim後は再利用できない。
	 * @param[in] entityTag 空または元cacheからのvalidator。viewは同期呼出し中だけ有効。
	 * @param[in] mode 受理する旧／投影経路の予約mode。異なるmodeを流用しない。
	 * @param[out] text 正常200のdecode済み本文。失敗・304では空。
	 * @param[out] observation 元status・待機・hashを保持する観測値。失敗時も到達した観測を残す。
	 * @param[out] control claim後の同じGETの共有制御。取得できなかった場合は空。
	 * @return 共通HTTP処理成功は0、拒否・取得失敗は元HRESULT。
	 * @note 同一workerのCOM apartmentから同期呼出しする。処理中にこのclientを再利用しない。
	 */
	[[nodiscard]] NativeError getCore( const LocalCollectorTarget	  &target,
									  const CollectorRecoveryDispatch &binding,
									  CollectorHttpPermit &permit, std::wstring_view entityTag,
									  CollectorRecoveryDispatch::Mode mode, std::wstring &text,
									  CollectorControlledHttpObservation	&observation,
									  std::shared_ptr<CollectorHttpControl> &control) ;
	/// 同じworkerで生成・破棄するcacheなしclient。
	OfficialHttpClient		  client_ ;
	/// 同期scopeで借用する完全DNS表。
	OfficialCollectorDnsApi	  dns_ ;
	/// Fixture依存が完全で、nativeが混在しない場合true。
	bool					  dependenciesValid_{true} ;
	/// 成否にかかわらず最初の呼出し後はtrue。
	bool					  used_{} ;
} ;
} // namespace drivercrate
