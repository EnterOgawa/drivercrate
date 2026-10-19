//------------------------------------------------------------------------------
/**
 * @file official_record_resolution.h
 * @brief 未信頼URL入力を組み込み公式rootへ限定して解決するworker契約を定義します。
 * @version 01.01.01
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  有限command、root resolver、session registryを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  非cacheの一回grant再解決契約を追加。
 * Ver.01.01.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note 一objectをProvider worker threadだけで直列使用します。利用者またはAIが提示したURLへ通信せず、
 *       明示Provider・resourceに登録済みの固定rootだけをresolverへ渡します。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/official_download_grant.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

namespace drivercrate {

//------------------------------------------------------------------------------
// Worker command／result定義。
//------------------------------------------------------------------------------

/**
 * @brief 未信頼URLの文字列を直接取得しない一回のrecord探索commandを所有します。
 * @note `submittedUrl`は選択材料であって公式根拠ではなく、resolver呼出し前に消去します。
 */
struct OfficialRecordResolutionCommand {
	/// Application全体で単調増加する0ではないoperation ID。
	OperationId		  operationId{} ;
	/// Workerが発行済みの現在scan session ID。
	ScanSessionId	  scanSessionId{} ;
	/// 利用者またはlocal resolverが明示選択した組み込みProvider stable ID。
	std::wstring	  providerId ;
	/// 同じProvider policyに登録済みの固定metadata endpoint resource ID。
	std::wstring	  rootResourceId ;
	/// Root応答に許可する有限byte上限。4 MiB以下です。
	std::uint64_t	  maximumRecordBytes{} ;
	/// 直接通信せず、command処理中だけ所有して消去する未信頼URL。
	SecretOfficialUrl submittedUrl ;
} ;

/**
 * @brief 一回のrecord解決commandが到達した非機密状態を表します。
 */
enum class OfficialRecordResolutionState {
	/// Commandをまだ実行していません。
	NOT_STARTED,
	/// 組み込みrootから一つの検証済みrecordを保持しました。
	RESOLVED,
	/// Resolver呼出し前または処理中に取消しました。
	CANCELLED,
	/// Command、registry、root evidenceまたはrecordを拒否しました。
	REJECTED,
	/// 公式root取得またはparser処理が失敗しました。
	FAILED,
} ;

/**
 * @brief UIまたは診断へ渡せるURL非保持のrecord解決結果を表します。
 */
struct OfficialRecordResolutionResult {
	/// Commandのoperation ID。0入力も拒否結果として保持します。
	OperationId					  operationId{} ;
	/// Commandが指定したscan session ID。
	ScanSessionId				  scanSessionId{} ;
	/// Registry照合成功後だけ設定する組み込みProvider stable ID。
	std::wstring				  providerId ;
	/// Registry照合成功後だけ設定する固定root resource ID。
	std::wstring				  rootResourceId ;
	/// Commandの終端状態。
	OfficialRecordResolutionState state{OfficialRecordResolutionState::NOT_STARTED} ;
	/// 拒否または失敗のHRESULT bit pattern。成功時は0です。
	NativeError					  error{} ;
	/// 成功時だけ保持するscan session内のopaque record証拠ID。
	std::uint64_t				  recordEvidenceId{} ;
	/// 成功後にsession registryが保持する未claim record件数。
	std::uint32_t				  retainedRecordCount{} ;
} ;

/**
 * @brief 公式record本文を取得するcache policyを表します。
 */
enum class OfficialRecordFetchMode {
	/// 秘密URLを含む応答を永続cacheへ保存せず、cacheから読み戻しません。
	BYPASS_CACHE,
} ;

/**
 * @brief Expiring grantを組み込みrootから一回だけ再解決するcommandです。
 */
struct OfficialGrantReresolutionCommand {
	/// Application全体で単調増加する0ではないoperation ID。
	OperationId	  operationId{} ;
	/// 現在のworker scan session ID。
	ScanSessionId scanSessionId{} ;
	/// Root応答に許可する4 MiB以下の有限byte上限。
	std::uint64_t maximumRecordBytes{} ;
	/// URL更新時に新grantへ割り当てる0ではないID。
	std::uint64_t replacementGrantId{} ;
	/// 再解決recordから新grantを発行するUTC秒。
	std::uint64_t issuedUtcSeconds{} ;
} ;

/**
 * @brief 一回のgrant再解決が到達したURL非保持状態を表します。
 */
enum class OfficialGrantReresolutionState {
	/// 再解決を開始していません。
	NOT_STARTED,
	/// URLだけが更新され、新しい一回使用grantを発行しました。
	REFRESHED,
	/// 元grant、期限理由、sessionまたは再解決回数が条件外です。
	NOT_ELIGIBLE,
	/// URL以外のstable record fieldまたはEULAが変化しました。
	RECORD_CHANGED,
	/// Root取得前または取得後に取消しました。
	CANCELLED,
	/// Registry、root binding、recordまたは同一URLを拒否しました。
	REJECTED,
	/// Resolver、hashまたはgrant発行が失敗しました。
	FAILED,
} ;

/**
 * @brief UIまたは診断へ渡せるgrant再解決のURL非保持結果です。
 */
struct OfficialGrantReresolutionResult {
	/// Commandのoperation ID。
	OperationId					   operationId{} ;
	/// Commandのscan session ID。
	ScanSessionId				   scanSessionId{} ;
	/// Eligibility照合後だけ設定する組み込みProvider stable ID。
	std::wstring				   providerId ;
	/// Eligibility照合後だけ設定する固定root resource ID。
	std::wstring				   rootResourceId ;
	/// 再解決の終端状態。
	OfficialGrantReresolutionState state{OfficialGrantReresolutionState::NOT_STARTED} ;
	/// 拒否または失敗のHRESULT bit pattern。成功時は0です。
	NativeError					   error{} ;
	/// 消費済みの元grant ID。
	std::uint64_t				   previousGrantId{} ;
	/// 成功時だけ発行した新grant ID。
	std::uint64_t				   replacementGrantId{} ;
} ;

/**
 * @brief 組み込み固定rootから一つの型付きrecordを取得・解析するProvider callbackです。
 * @param[in] scanSessionId 現在のworker scan session ID。
 * @param[in] recordEvidenceId Sessionが割り当てた0ではないrecord証拠ID。
 * @param[in] providerId Registryで照合済みのProvider stable ID。
 * @param[in] rootResourceId Registryで照合済みの固定root resource ID。
 * @param[in] builtInRootUrl 組み込みsource policyから得た固定HTTPS URL。
 * @param[in] maximumRecordBytes Root応答へ許可する有限byte上限。
 * @param[in] fetchMode 秘密URL応答に必須のcache禁止mode。
 * @param[out] record 成功時の型付きrecord。秘密payload URLをworker内だけで所有します。
 * @return Root取得・parser成功時は0、それ以外はHRESULT bit pattern。
 * @warning `builtInRootUrl`だけをnetwork起点にし、commandへ提出されたURLを推測・再構成しません。
 */
using OfficialRecordRootResolver = std::function<NativeError(
	ScanSessionId scanSessionId, std::uint64_t recordEvidenceId, std::wstring_view providerId,
	std::wstring_view rootResourceId, std::wstring_view builtInRootUrl,
	std::uint64_t maximumRecordBytes, OfficialRecordFetchMode fetchMode,
	OfficialDistributionRecord &record)> ;

/**
 * @brief 一commandの協調取消し状態を非blockingで返すcallbackです。
 * @return 取消し要求済みの場合true。
 */
using OfficialRecordResolutionCancellation = std::function<bool()> ;

/**
 * @brief 一つの組み込みProvider・固定rootと専用resolverを結合します。
 */
struct OfficialRecordResolverRegistration {
	/// Provider registryのstable ID。
	std::wstring_view		   providerId ;
	/// Source policyの固定metadata endpoint resource ID。
	std::wstring_view		   rootResourceId ;
	/// 未信頼URLを受け取らないProvider固有root resolver。
	OfficialRecordRootResolver resolver ;
} ;

/**
 * @brief Registryから一回だけclaimしたrecordとURL非保持証拠を所有します。
 * @note Grant発行またはsession失効までProvider worker内だけで保持します。
 */
struct ResolvedOfficialDistributionRecord {
	/// URL非保持のroot・record・stable fingerprint証拠。
	OfficialDistributionRecordEvidence evidence ;
	/// 秘密payload URLを含む型付きrecord。
	OfficialDistributionRecord		   record ;
} ;

/**
 * @brief Root resolver registryが組み込みProvider・policy・endpointと一意に対応するか検証します。
 * @param[in] registrations 一Provider・resourceにつき一件の有限registration集合。
 * @return 全件が組み込み公式network Providerと固定endpointへ一致する場合true。
 */
[[nodiscard]] bool validateOfficialRecordResolverRegistrations(
	std::span<const OfficialRecordResolverRegistration> registrations) noexcept ;

//------------------------------------------------------------------------------
// Worker session registry定義。
//------------------------------------------------------------------------------

/**
 * @brief 一つのscan sessionで最大64 recordと単調operationを管理します。
 * @note Mutexを持たず、Provider worker threadだけで直列使用します。失効時に全秘密URLを破棄します。
 */
class OfficialRecordResolutionSession final {
public:
	/**
	 * @brief 有効sessionを持たないregistryを作成します。
	 */
	OfficialRecordResolutionSession() = default ;

	/**
	 * @brief 保持中recordと秘密URLを破棄します。
	 */
	~OfficialRecordResolutionSession() = default ;

	/**
	 * @brief 秘密URLとrecordのsession結合の二重管理を防ぐため、コピー構築を禁止する。
	 */
	OfficialRecordResolutionSession( const OfficialRecordResolutionSession &) = delete ;
	/**
	 * @brief 秘密URLとrecordのsession結合を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	OfficialRecordResolutionSession &operator=( const OfficialRecordResolutionSession &) = delete ;
	/**
	 * @brief 秘密URLとrecordのsession結合を元のrecord registryに留めるため、移動構築を禁止する。
	 */
	OfficialRecordResolutionSession( OfficialRecordResolutionSession &&) = delete ;
	/**
	 * @brief 元のrecord registryへの結合を保つため、移動代入による管理状態の置換を禁止する。
	 */
	OfficialRecordResolutionSession &operator=( OfficialRecordResolutionSession &&) = delete ;

	/**
	 * @brief 旧recordを失効させ、より新しいscan sessionを開始します。
	 * @param[in] scanSessionId Workerが単調発行した0ではないscan session ID。
	 * @return 開始成功時は0、0または再使用・逆行IDはHRESULT bit pattern。
	 * @post 成功時は保持record 0件、次record証拠ID 1です。
	 */
	[[nodiscard]] NativeError		 beginSession( ScanSessionId scanSessionId) noexcept ;

	/**
	 * @brief 一つの未信頼URL commandを固定root resolverへ限定して実行します。
	 * @param[in] command 秘密URLの所有権を渡す一回のcommand。
	 * @param[in] registrations 組み込み正本と照合する有限resolver registry。
	 * @param[in] cancellation Workerが所有する同一operationの取消しcallback。
	 * @return URL、host、path、query、record本文を含まない終端結果。
	 * @post 受理したoperation IDは失敗・取消しでも再使用できません。
	 */
	[[nodiscard]] OfficialRecordResolutionResult resolve(
		OfficialRecordResolutionCommand					  &&command,
		std::span<const OfficialRecordResolverRegistration> registrations,
		const OfficialRecordResolutionCancellation		   &cancellation) noexcept ;

	/**
	 * @brief Expiring grantを同じ組み込みrootからcacheなしで一回だけ再解決します。
	 * @param[in] command 単調operation、新grant ID、時刻と有限root上限。
	 * @param[in] consumedGrant 期限切れまたは最初の401／403で消費済みの初回grant。
	 * @param[in] registrations 組み込み正本と照合する有限resolver registry。
	 * @param[in] cancellation Workerが所有する同一operationの取消しcallback。
	 * @param[out] replacementGrant URLだけが変わった場合に発行する新grant。開始時は未発行が必須です。
	 * @return URL、host、query、record本文を含まない終端結果。
	 * @post 成功時だけ`replacementGrant`は再解決回数1の`GRANT_ISSUED`です。
	 */
	[[nodiscard]] OfficialGrantReresolutionResult reresolveGrant(
		const OfficialGrantReresolutionCommand			   &command,
		const RecordScopedDownloadGrant					   &consumedGrant,
		std::span<const OfficialRecordResolverRegistration> registrations,
		const OfficialRecordResolutionCancellation		   &cancellation,
		RecordScopedDownloadGrant						   &replacementGrant) noexcept ;

	/**
	 * @brief 保持recordをsession・証拠IDで一回だけclaimします。
	 * @param[in] scanSessionId 現在のworker scan session ID。
	 * @param[in] recordEvidenceId `resolve`が返した0ではないopaque ID。
	 * @param[out] record 成功時だけ所有権を受け取るworker内record。失敗時は既定値です。
	 * @return Claim成功時は0、stale、未知または再使用IDはHRESULT bit pattern。
	 * @post 成功したrecordはregistryから除かれ、同じIDを再claimできません。
	 */
	[[nodiscard]] NativeError claimResolvedRecord(
		ScanSessionId scanSessionId, std::uint64_t recordEvidenceId,
		ResolvedOfficialDistributionRecord &record) noexcept ;

	/**
	 * @brief 現在sessionと全未claim recordを失効させます。
	 * @post `activeSessionId()`は0、`retainedRecordCount()`は0です。
	 */
	void						invalidate() noexcept ;

	/**
	 * @brief 現在有効なscan session IDを返します。
	 * @return 有効session ID。未開始・失効後は0です。
	 */
	[[nodiscard]] ScanSessionId activeSessionId() const noexcept ;

	/**
	 * @brief 未claimで保持するrecord件数を返します。
	 * @return 0件以上64件以下の保持数。
	 */
	[[nodiscard]] std::size_t	retainedRecordCount() const noexcept ;

private:
	/// 現在recordを受理できるscan session ID。
	ScanSessionId														  activeSessionId_{} ;
	/// 再使用・逆行を拒否する過去最大scan session ID。
	ScanSessionId														  latestSessionId_{} ;
	/// 再使用・逆行を拒否する過去最大operation ID。
	OperationId															  latestOperationId_{} ;
	/// 現在sessionで次に割り当てるrecord証拠ID。
	std::uint64_t														  nextRecordEvidenceId_{1U} ;
	/// Opaque record証拠IDから秘密recordへの最大64件のworker内索引。
	std::unordered_map<std::uint64_t, ResolvedOfficialDistributionRecord> records_ ;
} ;

} // namespace drivercrate
