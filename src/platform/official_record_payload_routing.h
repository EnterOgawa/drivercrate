//------------------------------------------------------------------------------
/**
 * @file official_record_payload_routing.h
 * @brief 検証済み公式record payloadのURL非保持方式分類定義。
 * @version 01.03.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  三方式のURL非保持payload descriptorを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  方式別の表示専用候補評価を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  自動探索のdevice別表示専用候補生成を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/23  開発用取得専用型の製品descriptor拒否を明示。
 * </pre>
 *
 * @note 本descriptorはworker内recordから表示可能metadataだけを複製します。秘密URL、hash値、EULA本文、
 *       local path、取得権限または導入権限を保持しません。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/candidate_assessment.h"
#include "platform/official_download_grant.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {
struct OfficialDiscoveryDeviceHint ;
struct OfficialDiscoveryPackageGroup ;

/**
 * @brief Recordが明示したpayload方式に対応する次の検査境界です。
 */
enum class OfficialRecordPayloadRoute {
	/// ADR 0151のZIP／CAB共通INF内容検査です。
	COMMON_INF_INSPECTION,
	/// 実行と分離した公式installer専用監査です。現在は未接続です。
	DEDICATED_INSTALLER_AUDIT,
	/// 取得・検査・実行を行わずrecord情報だけを表示します。
	DISPLAY_ONLY_UNSUPPORTED,
} ;

/**
 * @brief 一つの検証済みrecord payloadから作るURL非保持の表示・routing descriptorです。
 */
struct OfficialRecordPayloadDescriptor {
	/// Descriptorを所有する0ではないscan session IDです。
	ScanSessionId					scanSessionId{} ;
	/// Grant発行元と同じopaque record証拠IDです。
	std::uint64_t					recordEvidenceId{} ;
	/// Provider registryのstable IDです。
	std::wstring					providerId ;
	/// 組み込み公式取得元policyのstable IDです。
	std::wstring					policyId ;
	/// Recordを得たlandingまたはmetadata resource IDです。
	std::wstring					rootResourceId ;
	/// URLを含まないstable record fingerprintです。
	OfficialStableRecordFingerprint recordFingerprint ;
	/// Record内のpayload総数です。
	std::uint32_t					payloadCount{} ;
	/// Record内の0起点payload行番号です。
	std::uint32_t					payloadOrdinal{} ;
	/// Payload用途のstable resource IDです。
	std::wstring					payloadResourceId ;
	/// Parserが明示した方式です。拡張子から変更しません。
	OfficialDistributionPayloadKind payloadKind{OfficialDistributionPayloadKind::UNSUPPORTED} ;
	/// Payload方式だけから決めた次の検査境界です。
	OfficialRecordPayloadRoute		route{OfficialRecordPayloadRoute::DISPLAY_ONLY_UNSUPPORTED} ;
	/// 公式recordが表示するbasenameです。保存先pathへ使用しません。
	std::wstring					fileDisplayName ;
	/// Recordが明示した公開製品系列です。
	std::wstring					productFamily ;
	/// Recordが明示した対象Windows releaseまたはbranchです。
	std::wstring					operatingSystem ;
	/// Recordが明示したpackage版です。欠落時は空です。
	std::wstring					packageVersion ;
	/// Recordが明示した公開日です。欠落時は空です。
	std::wstring					publishedDate ;
	/// Recordが明示したexact byte数です。欠落時は未指定です。
	std::optional<std::uint64_t>	publishedSizeBytes ;
	/// RecordがSHA-256を明示した場合trueです。Hash値自体は表示descriptorへ複製しません。
	bool							publishedSha256Available{} ;
	/// Recordが自己申告するpublisherです。署名検証済みを意味しません。
	std::wstring					declaredPublisher ;
	/// Download前利用条件の区分です。今回の同意を意味しません。
	OfficialDistributionTerms		terms{OfficialDistributionTerms::ACCEPTANCE_REQUIRED} ;
	/// 同意対象の改訂識別子です。同意不要の場合は空です。
	std::wstring					eulaRevision ;
	/// Record限定grantを発行できる方式の場合trueです。利用者同意や取得済みを意味しません。
	bool							downloadGrantSupported{} ;
	/// 現時点でroute先の静的内容検査が製品実装済みの場合trueです。
	bool							contentInspectorAvailable{} ;
	/// 当該方式をsystemへ導入するexecutorが接続済みの場合だけtrueです。
	bool							executorAvailable{} ;
} ;

/**
 * @brief Record payload descriptor一件の有限値と方式別能力を検証します。
 * @param[in] descriptor 検証するURL非保持descriptorです。
 * @return ID、route、公開metadata、能力の組が既知で整合する場合trueです。
 */
[[nodiscard]] bool isOfficialRecordPayloadDescriptorValid(
	const OfficialRecordPayloadDescriptor &descriptor) noexcept ;

/**
 * @brief 検証済みrecordの全payloadをURL非保持descriptorへ変換します。
 * @param[in] record 秘密URLと全型付きmetadataを所有するworker内recordです。
 * @param[in] evidence 同じrecordから作成したURL非保持証拠です。
 * @param[out] descriptors 成功時にrecord順の全descriptor、失敗時に空です。
 * @return Record・証拠の完全一致と全descriptor構築に成功すれば0です。
 * @post `record`と全秘密URLは変更しません。Unsupported方式も表示専用descriptorとして保持します。
 * @note Routeはpayload kindだけから決め、file名、拡張子、content typeから別方式へ変更しません。
 *       開発用DOWNLOAD_ONLY_FILEは製品descriptorへ変換せず、全件を拒否します。
 */
[[nodiscard]] NativeError describeOfficialDistributionRecordPayloads(
	const OfficialDistributionRecord &record, const OfficialDistributionRecordEvidence &evidence,
	std::vector<OfficialRecordPayloadDescriptor> &descriptors) noexcept ;

/**
 * @brief URL非保持payload descriptorを未取得の表示専用候補評価へ結合します。
 * @param[in] descriptor 検証済みrecordから作成した方式別descriptorです。
 * @param[in] candidate 公式探索経路、opaque identity、Providerと表示専用状態を設定済みの候補です。
 * @param[out] assessment 成功時のrecord由来だけが合格した八軸評価です。失敗時は空です。
 * @return Session、Provider、候補状態とdescriptorを安全に結合できればtrueです。
 * @post INF、installer、unsupportedのいずれもexecutorなしで導入可能になりません。
 * @note INFとinstallerは未取得、unsupportedと不正拡張子は内容検査未対応として区別します。
 */
[[nodiscard]] bool makeOfficialRecordPayloadDisplayAssessment(
	const OfficialRecordPayloadDescriptor &descriptor, const UpdateCandidate &candidate,
	CandidateAssessment &assessment) ;

/**
 * @brief 一つの自動探索payloadを結合済みdeviceごとの非選択表示行へ変換します。
 * @param[in] group Record fingerprintから重複排除した一取得単位です。
 * @param[in] descriptor 同じgroupから再生成したURL非保持表示metadataです。
 * @param[in] devices 同じscanの完全なraw ID非保持device hint集合です。
 * @param[in] provider Provider registryへ登録された同じ取得元の定義です。
 * @return 全deviceを一意な表示行へ変換できた場合はgroup順の候補集合、それ以外は値なしです。
 * @post 成功行は`action=NONE`、導入不可、未取得監査でありinstall routingを発行しません。
 * @note Recordのpackage版はProvider表示値として保持するだけで、現在版との比較に使用しません。
 */
[[nodiscard]] std::optional<std::vector<UpdateCandidate>>
makeOfficialRecordPayloadDisplayCandidates( const OfficialDiscoveryPackageGroup		   &group,
										   const OfficialRecordPayloadDescriptor	   &descriptor,
										   std::span<const OfficialDiscoveryDeviceHint> devices,
										   const ProviderDescriptor					   &provider) ;

} // namespace drivercrate
