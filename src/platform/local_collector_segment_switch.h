//------------------------------------------------------------------------------
/**
 * @file local_collector_segment_switch.h
 * @brief 切替前条件と有限intent／非循環draftの非保存契約を定義します。
 * @version 01.00.00
 * @date 2026/10/02
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  切替draftの非循環結合と有限契約を追加。
 * </pre>
 *
 * @note 開発用coreです。実seal・監督・保護保存・HTTP許可を発行しません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "local_collector_shared_ledger.h"
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
/** @brief 切替前のcaller観測です。実worker／summary検査済み証明ではありません。 */
struct CollectorSegmentSwitchObservation {
	/// 全workerの停止・joinをcallerが観測した場合true。
	bool		  workersJoined{} ;
	/// 最後のgeneration完了をcallerが観測した場合true。
	bool		  lastGenerationComplete{} ;
	/// Summaryとpointerの整合をcallerが観測した場合true。
	bool		  summaryPointerConsistent{} ;
	/// 未受領数。0以外ではdraftを作りません。
	std::uint64_t unreceived{} ;
	/// 未精算数。元台帳の未精算も別に検査します。
	std::uint64_t unsettled{} ;
	/// 元commitが活動中の場合true。
	bool		  activeCommit{} ;
} ;
/** @brief 履歴順に保持する封印参照です。実sealの由来は後続で検査します。 */
struct CollectorSegmentSealReference {
	/// 元区間の完全小文字SHA-256。
	std::wstring segment ;
	/// 元seal本文の完全小文字SHA-256。
	std::wstring seal ;
	/** @brief 元二hashの完全一致を比較します。
	 * @param[in] other 比較する元参照。
	 * @return 全field一致の場合true。
	 */
	bool		 operator==( const CollectorSegmentSealReference &other) const = default ;
} ;
/** @brief Writer能力なしでdraftへ渡す元切替identityです。 */
struct CollectorSegmentSwitchRequest {
	/// 元区間key。新旧と過去のkeyを区別します。
	std::wstring							   oldSegment ;
	/// 新区間key。未作成や未使用を証明する値ではありません。
	std::wstring							   newSegment ;
	/// 元head本文hash。実handleからの由来は未検査です。
	std::wstring							   oldHead ;
	/// 元登録ROOT本文hash。実ROOT検証済み証明ではありません。
	std::wstring							   oldRoot ;
	/// 元seal本文hash。実履歴検証済み証明ではありません。
	std::wstring							   seal ;
	/// 今回旧区間のinventory shard hash。元ordinal順の1～16件です。
	std::vector<std::wstring>				   inventory ;
	/// 旧区間のordinal。初回は0で、最大1022です。
	std::uint64_t							   oldOrdinal{} ;
	/// 元accepted UTC millisecond。回復時計で置換しません。
	std::uint64_t							   accepted{} ;
	/// 既存seal参照。旧ordinal個を元履歴順で保持します。
	std::vector<CollectorSegmentSealReference> sealed ;
	/// Caller所有の切替前観測。実監督の代行ではありません。
	CollectorSegmentSwitchObservation		   observation ;
} ;
/** @brief 固定schemaの切替intentです。単体codecは保存許可を発行しません。 */
struct CollectorSegmentSwitchIntent {
	/// 恒久collectionの完全hash。
	std::wstring			  collection ;
	/// 元区間の完全hash。
	std::wstring			  oldSegment ;
	/// 新区間の完全hash。
	std::wstring			  newSegment ;
	/// 元head本文hash。
	std::wstring			  oldHead ;
	/// 新区間ordinal。1～1023です。
	std::uint64_t			  ordinal{} ;
	/// 元accepted UTC millisecond。
	std::uint64_t			  accepted{} ;
	/// 元66本文hashを固定順で結合した台帳digest。
	std::wstring			  ledger ;
	/// 元登録ROOT本文hash。
	std::wstring			  oldRoot ;
	/// 今回の旧seal本文hash。
	std::wstring			  seal ;
	/// 元ordinal順のinventory shard本文hash。
	std::vector<std::wstring> inventory ;
	/// 新base本文hash。
	std::wstring			  base ;
	/// 新bootstrap本文hash。intent hashを含まず循環させません。
	std::wstring			  bootstrap ;
	/// 次ready head本文hash。intent hashを含みません。
	std::wstring			  nextHead ;
	/** @brief 固定field全値を比較します。
	 * @param[in] other 比較する元intent。
	 * @return 全field一致の場合true。
	 */
	bool					  operator==( const CollectorSegmentSwitchIntent &other) const = default ;
} ;
/** @brief 原値から作る非保存draftです。envelopeや保護fileではありません。 */
struct CollectorSegmentSwitchDraft {
	/// 関係検査後だけの型付きintent。
	CollectorSegmentSwitchIntent  intent ;
	/// 予算・group・64 requestの元本文hash。最高時計も変えません。
	std::array<std::wstring, 66U> images ;
	/// 最大16 KiBのcanonical新base本文。
	std::string					  base ;
	/// 最大16 KiBのcanonical新bootstrap本文。
	std::string					  bootstrap ;
	/// 最大256 KiBのcanonical新ready head本文。
	std::string					  nextHead ;
	/// 最大16 KiBのcanonical元切替intent本文。
	std::string					  intentBytes ;
	/// 元intent本文の実CNG hash。
	std::wstring				  intentHash ;
} ;
/** @brief 固定intentを字句・関係検査してcanonical本文にします。
 * @param[in] intent Caller所有の型付き元値。
 * @param[out] bytes 成功時だけの全本文。失敗時は空です。aliasは禁止です。
 * @return 成功0、形式13、容量68、確保8。
 */
[[nodiscard]] DWORD encodeCollectorSegmentSwitchIntent( const CollectorSegmentSwitchIntent &intent,
													   std::string &bytes) noexcept ;
/** @brief 最大16 KiBの全field順・型・値を完全一致で復号します。
 * @param[in] bytes 呼出し中に変更しない所有本文。
 * @param[out] intent 成功時だけの元値。失敗時は空です。aliasは禁止です。
 * @return 成功0、形式13、容量68、確保8。
 */
[[nodiscard]] DWORD decodeCollectorSegmentSwitchIntent(
	std::string_view bytes, CollectorSegmentSwitchIntent &intent) noexcept ;
/** @brief 閉鎖済み同一台帳と元観測から非循環の全draftを導出します。
 * @param[in] before 元台帳。出力とのaliasは禁止です。
 * @param[in] carried 次区間へ持ち越す値。全66本文の非変更を必須とします。
 * @param[in] request Caller所有の元切替identityと観測。
 * @param[out] draft 全検査後だけの非保存出力。失敗時は空です。aliasは禁止です。
 * @return 成功0、形式13、容量68、確保8、第一CNG code。
 * @note 実seal／worker／ROOT／summary・未使用区間・保存容量・I/Oは検査しません。
 */
[[nodiscard]] DWORD prepareCollectorSegmentSwitchDraft( const CollectorSharedLedgerSnapshot &before,
													   const CollectorSharedLedgerSnapshot &carried,
													   const CollectorSegmentSwitchRequest &request,
													   CollectorSegmentSwitchDraft &draft) noexcept ;
/** @brief 元入力から独立再導出し、全body・全hashの一致を検査します。
 * @param[in] before 元台帳。
 * @param[in] carried 非変更で持ち越す台帳。
 * @param[in] request 元切替identityと観測。
 * @param[in] draft 照合する非保存draft。
 * @return 成功0、形式13、容量68、確保8、第一CNG code。
 * @note 一致は元hashの公式性や切替保存・通信許可を意味しません。
 */
[[nodiscard]] DWORD checkCollectorSegmentSwitchDraft(
	const CollectorSharedLedgerSnapshot &before, const CollectorSharedLedgerSnapshot &carried,
	const CollectorSegmentSwitchRequest &request,
	const CollectorSegmentSwitchDraft	&draft) noexcept ;
} // namespace drivercrate
