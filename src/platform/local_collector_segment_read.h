//------------------------------------------------------------------------------
/**
 * @file local_collector_segment_read.h
 * @brief 初回最終headのbyte検査と同親読取りcontextを定義します。
 * @version 01.01.01
 * @date 2026/10/03
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/03  初回readyとcarry／checkpointの有限結合を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/03  非作成の同親readerと変更不能contextを追加。
 * Ver.01.01.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note Byte codecと実handle読取り証明を分けます。保存・HTTP・旧CACHE検証能力を発行しません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "local_collector_segment_recovery.h"
#include "local_collector_collection_store.h"
#include <Windows.h>
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
/** @brief 同期呼出しだけに借用する初回最終headの入力です。 */
struct CollectorSegmentInitialReadBytes {
	/// 全intent／activation／ROOT／head／carry66像の元rawです。
	CollectorSegmentRecoveryBytes	  recovery ;
	/// 新子の固定base envelopeです。本文16 KiBです。
	std::string_view				  base ;
	/// 新子の固定bootstrap envelopeです。本文16 KiBです。
	std::string_view				  bootstrap ;
	/// 旧子の直接seal envelopeです。本文16 KiBです。
	std::string_view				  oldSeal ;
	/// 元ordinal順の1～16 shardです。各本文256 KiBです。
	std::span<const std::string_view> oldInventory ;
	/// 親budget／group／全64requestの元rawです。carryとの完全一致を要求します。
	std::array<std::string_view, 66U> currentImages ;
} ;
/** @brief checkpointに登録されたraw identityです。実file照合の証明ではありません。 */
struct CollectorSegmentReadFile {
	/// parent／segment／historyだけの元scopeです。
	std::wstring  scope ;
	/// current／runs直下の有限ASCII JSON名です。任意pathを開きません。
	std::wstring  name ;
	/// 外側を含む元rawの小文字SHA-256です。
	std::wstring  sha256 ;
	/// 登録rawの元sizeです。1 byte以上、2 MiB以下で、実I/O計数ではありません。
	std::uint64_t bytes{} ;
} ;
/** @brief 旧sealの有限集計と参照です。旧payloadやsourceの再検証を示しません。 */
struct CollectorSegmentReadCheckpoint {
	/// 元historyのROOT keyです。実ROOTはこのcodecで読みません。
	std::wstring  rootKey ;
	/// 元history封印の本文hashです。文法だけを検査します。
	std::wstring  historySeal ;
	/// 元shared封印の本文hashです。文法だけを検査します。
	std::wstring  sharedSeal ;
	/// 元完了世代数です。最大300です。
	std::uint64_t generations{} ;
	/// 元完了history操作数です。最大300です。
	std::uint64_t historyOperations{} ;
	/// 元shared操作数です。最大64です。
	std::uint64_t sharedOperations{} ;
	/// 元CACHE登録数です。最大300です。本文検証数ではありません。
	std::uint64_t cacheCount{} ;
	/// history scopeの登録数です。全scope合計8192以内です。
	std::uint64_t historyFiles{} ;
	/// parent／segment scopeの登録数です。合計256以内です。
	std::uint64_t sharedFiles{} ;
	/// history scopeの登録raw byte合計です。
	std::uint64_t historyBytes{} ;
	/// parent／segment scopeの登録raw byte合計です。
	std::uint64_t sharedBytes{} ;
} ;
/** @brief 全byte結合後の所有値です。実handle readerのcontextとは異なります。 */
struct CollectorSegmentInitialReadState {
	/// saved3だけの再導出値と全carry台帳です。
	CollectorSegmentRecoveryState		  recovery ;
	/// 旧sealの有限参照と集計です。
	CollectorSegmentReadCheckpoint		  checkpoint ;
	/// 元順・重複なしの最大8192登録行です。旧payloadは読んでいません。
	std::vector<CollectorSegmentReadFile> files ;
	/// 親headと親66像の二回分の入力byteです。marker／実I/Oは含みません。
	std::uint64_t						  sharedInputBytes{} ;
	/// 直接switch根拠とcarryの二回分の入力byteです。実名監査は含みません。
	std::uint64_t						  segmentInputBytes{} ;
} ;
/** @brief 初回最終headとcarry／checkpointを有限byteだけから検査します。
 * @param[in] bytes 同期呼出し中に変更しない借用raw集合です。
 * @param[out] state 全成功時だけの所有値です。全失敗時は空です。
 * @return 成功0、内容13、容量68、後続ordinal50、確保8、第一CNG errorです。
 * @pre 入力と出力の所有領域をaliasさせないでください。
 * @note 保存・時計採取・実file読取り・HTTP・能力発行を行いません。
 * 実marker／名数／usage／ACLと最終再読取りは、後続の保護handle readerに別途必要です。
 */
[[nodiscard]] DWORD decodeCollectorSegmentInitialRead(
	const CollectorSegmentInitialReadBytes &bytes,
	CollectorSegmentInitialReadState	   &state) noexcept ;

/** @brief readerの部分数値です。失敗時の値も能力として使用できません。 */
struct CollectorSegmentReadDiagnostics {
	/// 同handleのsizeから先払いした親現在値raw byteです。失敗したreadの先払いも含みます。
	std::uint64_t sharedBytes{} ;
	/// 同handleのsizeから先払いした直接switch根拠raw byteです。
	std::uint64_t segmentBytes{} ;
	/// 親現在値の実store read呼出し数です。失敗した試行も含みます。
	std::uint64_t sharedReadCalls{} ;
	/// 直接根拠の実store read呼出し数です。
	std::uint64_t segmentReadCalls{} ;
	/// 親現在値のscope付き重複なし参照名数です。最大256です。
	std::uint64_t sharedNames{} ;
	/// 直接根拠のscope付き重複なし参照名数です。最大6000です。
	std::uint64_t segmentNames{} ;
	/// 最終照合で試みた実store read数です。
	std::uint64_t finalReadCalls{} ;
	/// 旧ROOT／応答／CACHE本文read数です。このreaderでは0です。
	std::uint64_t oldPayloadReads{} ;
	/// 取得後と最終照合の同親二子集合検査数です。
	std::uint64_t collectionChecks{} ;
	/// 現在対象の固定directory名／usage検査数です。本文read数ではありません。
	std::uint64_t directoryChecks{} ;
} ;

/** @brief readerだけが発行する同親の変更不能読取り証明です。
 * @note 同writer threadで破棄します。更新／HTTPへの変換APIとmutable store参照を持ちません。
 */
class CollectorSegmentReadContext final {
private:
	friend class LocalCollectorSegmentReader ;
	/** @brief 呼出し元のhashや成功boolでは構築できない私有keyです。 */
	class ConstructionKey {
		friend class LocalCollectorSegmentReader ;
		/** @brief 実readerだけがkeyを構築します。外部brace初期化を拒否します。 */
		ConstructionKey() = default ;
	} ;

public:
	/** @brief 実readerの全検査結果と同親所有を引き取ります。
	 * @param[in] key 実readerだけが生成するkeyです。
	 * @param[in] hold 最後のcontextまで同親四handleを保持する所有です。
	 * @param[in] state 全byte結合と最終実再検査を通過した所有値です。
	 * @note 公開宣言はmake_shared用です。私有keyを外部から生成できません。
	 */
	CollectorSegmentReadContext( ConstructionKey									   key,
								std::shared_ptr<const CollectorCollectionReadHold> hold,
								CollectorSegmentInitialReadState				   state) ;
	/** @brief 変更不能値を解放してから同親handleの参照を返します。 */
	~CollectorSegmentReadContext() ;
	/**
	 * @brief 検査済み値と同親handleの保持責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	CollectorSegmentReadContext( const CollectorSegmentReadContext &) = delete ;
	/**
	 * @brief 検査済み値と同親handleの保持責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	CollectorSegmentReadContext &operator=( const CollectorSegmentReadContext &) = delete ;
	/** @brief contextの寿命に限定した所有値を読みます。
	 * @return 同親最終再検査を通過した値です。現時点の更新許可ではありません。
	 */
	[[nodiscard]] const CollectorSegmentInitialReadState &state() const noexcept ;

private:
	/// 値より長く保持する同親四handleです。保存／HTTP能力へ公開しません。
	std::shared_ptr<const CollectorCollectionReadHold> hold_ ;
	/// 最終実再照合後の変更不能所有値です。
	CollectorSegmentInitialReadState				   state_ ;
} ;

/** @brief 初回最終headだけを非作成の保護handleから検査します。 */
class LocalCollectorSegmentReader final {
public:
	/** @brief 全直接raw・固定集合と最終再照合から同親読取り証明を発行します。
	 * @param[in,out] collection 初期化済みの同親writerです。成功contextが寿命を延長します。
	 * @param[in] intentKey 実intent本文hashの完全小文字名です。任意pathを受理しません。
	 * @param[in,out] context 空入力だけを受理します。成功時だけ発行し、失敗時は空です。
	 * @param[out] diagnostics 部分計数です。開始時に初期化し、能力へ使用しません。
	 * @param[in] beforeFinalRecheck 同threadの非通信診断です。成功後も全固定集合とrawを再検査します。
	 * @return 成功0、内容13、容量68、後続ordinal50、別親／能力87、再入170、確保8、第一CNG／I/Oです。
	 * @pre callbackからcontext／diagnosticsの領域を変更・aliasさせないでください。
	 * @note 非空context入力は170で保持します。必須欠損は2。保存・旧payload再生・HTTP・時計採取を行いません。
	 */
	[[nodiscard]] static DWORD inspect(
		LocalCollectorCollectionStore &collection, std::wstring_view intentKey,
		std::shared_ptr<const CollectorSegmentReadContext> &context,
		CollectorSegmentReadDiagnostics					   &diagnostics,
		const std::function<DWORD()>					   &beforeFinalRecheck = {}) noexcept ;
} ;
} // namespace drivercrate
