//------------------------------------------------------------------------------
/**
 * @file local_collector_segment_recovery.cpp
 * @brief 全保存像と固定intent／ROOT／元head記録の非保存結合を検査します。
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/02  元byte・非循環結合と四保存状態の有限検査を追加。
 * </pre>
 *
 * @note DTO検査は実旧台帳・履歴由来や回復予約の証明ではありません。通常readerを変更しません。
 * @see docs/adr/0223-local-collector-segments-and-shared-ledger.md
 */
//------------------------------------------------------------------------------
#include "local_collector_segment_recovery.h"
#include "local_collector_projected_json.h"
#include "local_collector_shared_ledger.h"
#include "official_file_verifier.h"
#include <cstdint>
#include <initializer_list>
#include <new>
#include <utility>

namespace drivercrate {
namespace {
using collector_projected_json::Reader ;					// 用途別有限readerです。
using collector_projected_json::Writer ;					// 元canonical byteの独立再導出です。
using collector_projected_json::Failure ;					// 字句・容量を区別する内部失敗です。
using collector_projected_json::Status ;					// 第一公開数値への変換だけに使います。
constexpr std::size_t RAW_LIMIT	  = 2U * 1024U * 1024U ;	// 一rawの既存上限です。
constexpr std::size_t SMALL_LIMIT = 16U * 1024U ;			// Intent／ROOTの独立本文上限です。
/** @brief 第一失敗数値を保持します。
 * @param[in] code 元APIの数値です。
 * @throws DWORD 成功以外の第一数値です。
 */
void				  io( const DWORD code)
{
	// Codec・CNGの第一失敗を内容13へ読み替えません。
	if( code != ERROR_SUCCESS) {
		throw code ;
	}
}
/** @brief 必須結合の不成立を拒否します。
 * @param[in] condition 成立が必要な関係です。
 * @throws DWORD 内容13です。
 */
void require( const bool condition)
{
	// 部分的に正しいbyteから成功値を補完しません。
	if( !condition) {
		throw static_cast<DWORD>( ERROR_INVALID_DATA) ;
	}
}
/** @brief 実本文のCNG指紋を求めます。
 * @param[in] body 元有限本文です。
 * @return 完全小文字SHA-256です。
 * @throws DWORD 第一CNG errorです。
 */
std::wstring digest( const std::string_view body)
{
	std::wstring hash ;	// 成功時だけの元指紋です。
	io( static_cast<DWORD>( computeCollectorMetadataSha256( body, hash))) ;
	return hash ;
}
/** @brief Canonical envelopeを元hashと結合します。
 * @param[in] body 元用途別有限本文です。
 * @return 既存shared envelopeの完全rawです。
 * @throws Failure 字句・有限byte拒否です。
 * @throws DWORD 第一CNG errorです。
 */
std::string pack( const std::string_view body)
{
	Writer writer( RAW_LIMIT) ;	// 一rawの枠を拡大しません。
	writer.append( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
	writer.text( body) ;
	writer.append( ",\"sha256\":") ;
	writer.wideText( digest( body)) ;
	writer.append( "}") ;
	return writer.take() ;
}
/** @brief 元外側raw・実CNGとcanonical表現を確認します。
 * @param[in] raw 一rawの借用byteです。
 * @param[in] limit 用途別の独立本文上限です。
 * @return 全検査後の元本文です。
 * @throws Failure 字句・有限枠拒否です。
 * @throws DWORD 内容13・第一CNG errorです。
 */
std::string unpack( const std::string_view raw, const std::size_t limit)
{
	Reader reader( raw, RAW_LIMIT) ;	// 確保前に外側上限を確認します。
	reader.literal( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
	auto body = reader.text( limit) ;	// 用途別枠内の本文だけを所有します。
	reader.literal( ",\"sha256\":") ;
	const auto hash = reader.text( 64U) ;	// 余分なhash文字を受理しません。
	reader.literal( "}") ;
	reader.finish() ;
	require( hash.size() == 64U && std::wstring( hash.begin(), hash.end()) == digest( body) &&
			pack( body) == raw) ;
	return body ;
}
/** @brief 同じ既存draftと元最高UTCから専用初期ROOTを再導出します。
 * @param[in] draft 全66像から再導出した元draftです。
 * @param[in] lastUtc 元台帳の最高UTCです。acceptedへ置換しません。
 * @return 固定17fieldのcanonical本文です。
 * @throws Failure 有限sink拒否です。
 */
std::string rootBody( const CollectorSegmentSwitchDraft &draft, const std::uint64_t lastUtc)
{
	const auto &intent = draft.intent ;	// 全identityは元intentに一致済みです。
	Writer		root( SMALL_LIMIT) ;	// 一ROOTの独立上限です。
	root.append( "{\"schema\":\"collector-segment-history-root-v1\",\"collection\":") ;
	root.wideText( intent.collection) ;
	root.append( ",\"segment\":") ;
	root.wideText( intent.newSegment) ;
	root.append( ",\"ordinal\":") ;
	root.number( intent.ordinal) ;
	root.append( ",\"accepted\":") ;
	root.number( intent.accepted) ;
	root.append( ",\"lastUtc\":") ;
	root.number( lastUtc) ;
	root.append( ",\"oldSegment\":") ;
	root.wideText( intent.oldSegment) ;
	root.append( ",\"oldRoot\":") ;
	root.wideText( intent.oldRoot) ;
	root.append( ",\"seal\":") ;
	root.wideText( intent.seal) ;
	root.append( ",\"ledger\":") ;
	root.wideText( intent.ledger) ;
	root.append( ",\"base\":") ;
	root.wideText( intent.base) ;
	root.append( ",\"bootstrap\":") ;
	root.wideText( intent.bootstrap) ;
	root.append( ",\"switchIntent\":") ;
	root.wideText( draft.intentHash) ;
	root.append( ",\"images\":[") ;
	// 全66元hashを固定順で結合し、空shardを省略しません。
	for( std::size_t n = 0U; n < draft.images.size(); ++n) {
		// 先頭以外へ元delimiterを置きます。
		if( n != 0U) {
			root.append( ",") ;
		}

		root.wideText( draft.images[n]) ;
	}

	root.append( "],\"generations\":[],\"operations\":[],\"active\":null}") ;
	return root.take() ;
}
/** @brief 既存登録headだけを再導出します。
 * @param[in] draft 全byte一致した元draftです。
 * @return 固定登録headのcanonical本文です。
 * @throws Failure 有限sink拒否です。
 */
std::string registeredBody( const CollectorSegmentSwitchDraft &draft)
{
	Writer writer( SMALL_LIMIT) ;	// 元登録headの独立枠です。
	writer.append( "{\"schema\":\"collector-segment-switch-registered-v1\",\"collection\":") ;
	writer.wideText( draft.intent.collection) ;
	writer.append( ",\"oldHead\":") ;
	writer.wideText( draft.intent.oldHead) ;
	writer.append( ",\"intent\":") ;
	writer.wideText( draft.intentHash) ;
	writer.append( ",\"nextHead\":") ;
	writer.wideText( draft.intent.nextHead) ;
	writer.append( "}") ;
	return writer.take() ;
}
/** @brief 元head記録の固定七fieldと独立枠を検査します。
 * @param[in] bytes 元借用入力です。
 * @param[in,out] state 全結合前の私有候補です。
 * @throws Failure 有限reader／sink拒否です。
 * @throws DWORD 内容13・第一CNG errorです。
 */
void originalHead( const CollectorSegmentRecoveryBytes &bytes, CollectorSegmentRecoveryState &state)
{
	Writer record( 256U * 1024U) ;	// 元headを含む既存記録枠です。
	record.append( "{\"schema\":\"collector-segment-switch-activation-v1\",\"collection\":") ;
	record.wideText( state.draft.intent.collection) ;
	record.append( ",\"intent\":") ;
	record.wideText( state.draft.intentHash) ;
	record.append( ",\"oldHead\":") ;
	record.wideText( state.draft.intent.oldHead) ;
	record.append( ",\"oldHeadRaw\":") ;
	// 未保存記録を現在の登録／最終headから推定しません。
	if( bytes.activation.empty()) {
		state.oldHeadRaw = bytes.head ;
	} else {
		const auto body = unpack( bytes.activation, 256U * 1024U) ;	// 元記録の全byteです。
		Reader	   reader( body, 256U * 1024U) ;					// 元prefixを完全一致で結合します。
		reader.literal( record.view()) ;
		state.oldHeadRaw = reader.text( 128U * 1024U) ;
		Writer tail( 4096U) ;	// ROOT／nextHeadの元参照だけです。
		tail.append( ",\"initialRoot\":") ;
		tail.wideText( state.initialRootSha256) ;
		tail.append( ",\"nextHead\":") ;
		tail.wideText( state.draft.intent.nextHead) ;
		tail.append( "}") ;
		reader.literal( tail.view()) ;
		reader.finish() ;
	}

	// Raw上限も元head本文hashとは別に先払いします。
	if( state.oldHeadRaw.size() > 128U * 1024U) {
		throw static_cast<DWORD>( ERROR_TOO_MANY_NAMES) ;
	}

	require( digest( unpack( state.oldHeadRaw, 128U * 1024U)) == state.draft.intent.oldHead) ;
	record.text( state.oldHeadRaw) ;
	record.append( ",\"initialRoot\":") ;
	record.wideText( state.initialRootSha256) ;
	record.append( ",\"nextHead\":") ;
	record.wideText( state.draft.intent.nextHead) ;
	record.append( "}") ;
	require( bytes.activation.empty() || pack( record.take()) == bytes.activation) ;
}
} // namespace
/** @see local_collector_segment_recovery.h */
DWORD decodeCollectorSegmentRecovery( const CollectorSegmentRecoveryBytes &bytes,
									 CollectorSegmentRecoveryState		 &state) noexcept
{
	state = {} ;
	try {
		// 外側上限をどの用途の本文確保よりも先に検査します。
		for( const auto raw : {bytes.intent, bytes.activation, bytes.root, bytes.head}) {
			// 任意の用途だけ大きいrawをfallbackへ渡しません。
			if( raw.size() > RAW_LIMIT) {
				throw static_cast<DWORD>( ERROR_TOO_MANY_NAMES) ;
			}
		}

		// 全66固定rawの枠を確保前に確認し、欠損像を補完しません。
		for( const auto raw : bytes.images) {
			// 最大66×2 MiBの独立枠を越えた入力を読取りません。
			if( raw.size() > RAW_LIMIT) {
				throw static_cast<DWORD>( ERROR_TOO_MANY_NAMES) ;
			}
		}

		const auto intentBody = unpack( bytes.intent, SMALL_LIMIT) ;	// 元有限intent本文です。
		CollectorSegmentSwitchIntent intent ;							// 失敗時は外へ公開しません。
		io( decodeCollectorSegmentSwitchIntent( intentBody, intent)) ;
		// 過去seal集合を検査しない初回decoderで後続ordinalを成功にしません。
		if( intent.ordinal != 1U) {
			return ERROR_NOT_SUPPORTED ;
		}

		CollectorSharedLedgerBytes bodies ;	// 元像を固定順で再結合します。
		// Budget／group／全requestを既存codecへ渡す本文だけに復号します。
		for( std::size_t n = 0U; n < bytes.images.size(); ++n) {
			auto body = unpack( bytes.images[n], 768U * 1024U) ;	// 一像の独立本文枠です。
			// 二先頭像をrequest shardと取り違えません。
			if( n < 2U) {
				(n == 0U ? bodies.budget : bodies.groups) = std::move( body) ;
			} else {
				bodies.requests[n - 2U] = std::move( body) ;
			}
		}

		CollectorSegmentRecoveryState next ;	// 最終結合後だけ所有値を公開します。
		io( decodeCollectorSharedLedger( bodies, next.carried)) ;
		CollectorSharedLedgerBytes canonical ;	// 全実本文と型付き再出力の一致を別に確認します。
		io( encodeCollectorSharedLedger( next.carried, canonical)) ;
		require( bodies.budget == canonical.budget && bodies.groups == canonical.groups &&
				bodies.requests == canonical.requests) ;
		CollectorSegmentSwitchRequest request ;	// Hashの由来はまだDTOに限定されています。
		request.oldSegment = intent.oldSegment ;
		request.newSegment = intent.newSegment ;
		request.oldHead	   = intent.oldHead ;
		request.oldRoot	   = intent.oldRoot ;
		request.seal	   = intent.seal ;
		request.inventory  = intent.inventory ;
		request.accepted   = intent.accepted ;
		// Coreのcarry条件だけを再導出します。実worker停止／履歴完了の証明ではありません。
		request.observation = {true, true, true, 0U, 0U, false} ;
		io( prepareCollectorSegmentSwitchDraft( next.carried, next.carried, request, next.draft)) ;
		require( next.draft.intentBytes == intentBody && next.draft.intent == intent) ;
		const auto expectedRoot =
			// 元最高UTCです。
			rootBody( next.draft, next.carried.lastUtcMillis) ;
		require( unpack( bytes.root, SMALL_LIMIT) == expectedRoot) ;
		next.initialRootSha256 = digest( expectedRoot) ;
		originalHead( bytes, next) ;
		(void)unpack( bytes.head, 256U * 1024U) ;
		// 記録がなければ元headだけを許し、不足記録を推定修復しません。
		if( bytes.activation.empty()) {
			require( bytes.head == next.oldHeadRaw) ;
		} else {
			next.saved = bytes.head == next.oldHeadRaw					  ? 1U
						 : bytes.head == pack( registeredBody( next.draft)) ? 2U
						 : bytes.head == pack( next.draft.nextHead)		  ? 3U
																		  : 0U ;
			require( next.saved != 0U) ;
		}

		state = std::move( next) ;
		return ERROR_SUCCESS ;
	} catch( const DWORD code) {
		return code ;
	} catch( const Failure &failure) {
		return failure.status == Status::SIZE_LIMIT		 ? ERROR_TOO_MANY_NAMES
			   : failure.status == Status::OUT_OF_MEMORY ? ERROR_NOT_ENOUGH_MEMORY
														 : ERROR_INVALID_DATA ;
	} catch( const std::bad_alloc &) {
		return ERROR_NOT_ENOUGH_MEMORY ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}
} // namespace drivercrate
