//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_input.h
 * @brief 全共有jobの新収集profileを非保存canonical入力へ結合します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/28  v3入力・専用世代identityの非保存builderを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/28  保存byteの全再構築decoderを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  変更不能な予約前prepared jobを追加。
 * Ver.01.02.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * Ver.01.02.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.02.03   Shunji Ogawa  2026/10/16 private準備済み所有constructorの移譲元を明記。
 * </pre>
 *
 * @note 保存、予約、HTTP、導入を行いません。root v3は後続工程です。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "platform/local_collector_projected_job.h"

#include <string>
#include <string_view>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace drivercrate {

/** @brief 新profileだけのmanifest実byteと組み込みsource契約です。 */
struct CollectorProjectedCampaignDefinition {
	/// 検証する元manifest実byte。公開製品値のみを含みます。
	std::string							 manifestBytes ;
	/// Callerが組み込んだsource registry。manifestから追加許可を作りません。
	std::vector<CollectorCampaignSource> sources ;
	/// 実artifactの小文字SHA-256。
	std::wstring						 artifactSha256 ;
} ;

/** @brief 予約前に検査する全jobと専用世代identityです。 */
struct CollectorProjectedCampaignIdentity {
	/// 入力v3のcanonical UTF-8実byte。秘密URL・EULAを含みません。
	std::string								canonicalInput ;
	/// canonicalInput実byteの小文字SHA-256。
	std::wstring							inputSha256 ;
	/// schema-v3とinputSha256へ結合した専用世代SHA-256。
	std::wstring							generationKey ;
	/// 元manifestの固定順。各jobは全公開targetを所有します。
	std::vector<CollectorProjectedJobInput> jobs ;
} ;

/** @brief 元manifestと全jobを再計算して新v3入力・世代を固定します。
 * @param[in] definition 元manifest、組み込みsource、実artifact。
 * @param[in] startDay 予約開始JST日。YYYYMMDDの実在日付。
 * @param[out] identity 成功時だけ所有するcanonical入力と全job。
 * @return schema、全scope、768 KiB以下のcanonical化と二段SHA-256が成立した場合true。
 * @note 旧generation算法は呼ばず、旧request／job keyだけをbuilderで再利用します。
 * 通信・保存・予約・root移行は行いません。
 */
[[nodiscard]] bool makeCollectorProjectedCampaignIdentity(
	const CollectorProjectedCampaignDefinition &definition, std::wstring_view startDay,
	CollectorProjectedCampaignIdentity &identity) ;

/** @brief 保存input-v3を元manifestから再構築し、実byteまで照合します。
 * @param[in] canonicalInput 最大768 KiBの保存UTF-8本文。
 * @param[out] definition 全検査後だけ返す元公開定義。失敗時は空です。
 * @param[out] identity 全再構築した所有jobと実byte指紋。失敗時は空です。
 * @return 元builderの全fieldと保存byteが一致する場合true。
 * @note 保存sourceを新しい通信許可へ変換せず、未知fieldや重複fieldも拒否します。
 */
[[nodiscard]] bool parseCollectorProjectedCampaignIdentity(
	std::string_view canonicalInput, CollectorProjectedCampaignDefinition &definition,
	CollectorProjectedCampaignIdentity &identity) ;

class CollectorPreparedProjectedCampaign ;

/** @brief 検査済みcanonicalからのみ作られる一つの公開jobです。 */
class CollectorPreparedProjectedJob final {
public:
	/**
	 * @brief 検査済み公開jobの所有fieldを複製して保持する。
	 * @note 無名のコピー元から各fieldの既定コピーを行う。再解析や通信許可の発行は行わない。
	 */
	CollectorPreparedProjectedJob( const CollectorPreparedProjectedJob &) = default ;
	/**
	 * @brief 検査済み公開jobの所有fieldを複製して置き換える。
	 * @return 代入後の自分自身への参照。
	 * @note 無名のコピー元から各fieldの既定コピーを行う。再解析や通信許可の発行は行わない。
	 */
	CollectorPreparedProjectedJob &operator=( const CollectorPreparedProjectedJob &) = default ;
	/**
	 * @brief 検査済み公開jobの所有fieldを移動して保持する。
	 * @note 無名の移動元から各fieldの既定移動を行う。再解析や通信許可の発行は行わない。
	 */
	CollectorPreparedProjectedJob( CollectorPreparedProjectedJob &&) noexcept = default ;
	/**
	 * @brief 検査済み公開jobの所有fieldを移動して置き換える。
	 * @return 代入後の自分自身への参照。
	 * @note 無名の移動元から各fieldの既定移動を行う。再解析や通信許可の発行は行わない。
	 */
	CollectorPreparedProjectedJob &operator=( CollectorPreparedProjectedJob &&) noexcept = default ;
	/**
	 * @brief 元manifestから所有した読み取り専用の全scopeを返します。
	 * @return 所有する変更不能なjob値への非所有参照。このobjectの移動・破棄まで有効。
	 */
	[[nodiscard]] const CollectorProjectedJobInput &value() const noexcept
	{
		return value_ ;
	}

private:
	friend bool prepareCollectorProjectedCampaign(
		std::string_view, std::wstring_view, std::wstring_view, std::wstring_view,
		std::span<const CollectorCampaignSource>,
		std::shared_ptr<const CollectorPreparedProjectedCampaign> &) ;
	/**
	 * @brief 元canonicalの再構築後だけ一jobを所有します。
	 * @param[in,out] value 再構築済みjobの移譲元。所有値をmoveし、呼出し後の元内容は未規定です。
	 */
	explicit CollectorPreparedProjectedJob( CollectorProjectedJobInput &&value) noexcept
		: value_( std::move( value))
	{
	}
	/// 旧可変DTOをprivateに封じた元job。
	CollectorProjectedJobInput value_ ;
} ;

/** @brief 一回準備した全jobをworkerまで変更不能で所有します。 */
class CollectorPreparedProjectedCampaign final {
public:
	/**
	 * @brief 準備済み全jobの変更不能な所有状態の二重管理を防ぐため、コピー構築を禁止する。
	 */
	CollectorPreparedProjectedCampaign( const CollectorPreparedProjectedCampaign &) = delete ;
	/**
	 * @brief 準備済み全jobの変更不能な所有状態を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	CollectorPreparedProjectedCampaign &operator=( const CollectorPreparedProjectedCampaign &) =
		delete ;
	/**
	 * @brief 入力順のjob数を返します。
	 * @return 保持している入力順jobの要素数。
	 */
	[[nodiscard]] std::size_t jobCount() const noexcept
	{
		return jobs_.size() ;
	}
	/**
	 * @brief 有効indexのjobだけを借用します。範囲外はnullです。
	 * @param[in] index 入力順の0始まりjob位置。
	 * @return 有効位置ではcampaign破棄まで有効な非所有pointer。範囲外ではnull。
	 */
	[[nodiscard]] const CollectorPreparedProjectedJob *job( std::size_t index) const noexcept
	{
		return index < jobs_.size() ? &jobs_[index] : nullptr ;
	}
	/**
	 * @brief 元保存入力の実byte SHA-256を返します。
	 * @return 元保存入力のSHA-256への非所有参照。Campaign破棄まで有効。
	 */
	[[nodiscard]] const std::wstring &inputSha256() const noexcept
	{
		return inputSha256_ ;
	}
	/**
	 * @brief 元保存入力から再構築した専用Gを返します。
	 * @return 元保存入力から再構築した世代keyへの非所有参照。Campaign破棄まで有効。
	 */
	[[nodiscard]] const std::wstring &generationKey() const noexcept
	{
		return generationKey_ ;
	}

private:
	friend bool prepareCollectorProjectedCampaign(
		std::string_view, std::wstring_view, std::wstring_view, std::wstring_view,
		std::span<const CollectorCampaignSource>,
		std::shared_ptr<const CollectorPreparedProjectedCampaign> &) ;
	/**
	 * @brief 検査済み全jobだけを引き取るprivate constructorです。
	 * @param[in,out] jobs 検査済みの元順job集合。moveして所有し、元内容は未規定です。
	 * @param[in,out] inputSha256 元canonical入力のhash。moveして所有し、元内容は未規定です。
	 * @param[in,out] generationKey 専用世代G。moveして所有し、元内容は未規定です。
	 */
	CollectorPreparedProjectedCampaign( std::vector<CollectorPreparedProjectedJob> &&jobs,
									   std::wstring								  &&inputSha256,
									   std::wstring &&generationKey) noexcept
		: jobs_( std::move( jobs)), inputSha256_( std::move( inputSha256)),
		  generationKey_( std::move( generationKey))
	{
	}
	/// 元jobの入力順を保つ変更不能集合。
	std::vector<CollectorPreparedProjectedJob> jobs_ ;
	/// 保存canonical inputのhash。
	std::wstring							   inputSha256_ ;
	/// 専用世代G。
	std::wstring							   generationKey_ ;
} ;

/** @brief 保存v3入力から組み込み契約を一度だけ再照合して全jobを準備します。
 * @param[in] canonicalInput 元登録済みのcanonical実byte。
 * @param[in] expectedInputSha256 元登録のinput hash。
 * @param[in] expectedGenerationKey 元登録の専用G。
 * @param[in] currentArtifactSha256 実行中の組み込みartifact hash。
 * @param[in] builtInSources 実行中の組み込みsource全契約。保存本文の値を流用しません。
 * @param[out] prepared 成功時だけ全jobを変更不能で所有します。失敗時は空です。
 * @return 実byte、G、artifact、全sourceと全jobの再構築が一致した場合true。
 * @note 予約・HTTP・保存は行いません。外から作った可変jobを引き取りません。
 */
[[nodiscard]] bool prepareCollectorProjectedCampaign(
	std::string_view canonicalInput, std::wstring_view expectedInputSha256,
	std::wstring_view expectedGenerationKey, std::wstring_view currentArtifactSha256,
	std::span<const CollectorCampaignSource>				   builtInSources,
	std::shared_ptr<const CollectorPreparedProjectedCampaign> &prepared) ;

} // namespace drivercrate
