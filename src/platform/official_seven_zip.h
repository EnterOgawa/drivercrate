//------------------------------------------------------------------------------
/**
 * @file official_seven_zip.h
 * @brief 公式7z package有限展開定義。
 * @version 01.00.00
 * @date 2026/09/06
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  有限memory decoder境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  保護workspace選択展開を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Solid選択展開量の事前判定を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Metadataとdecodeの上限契約を明確化。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note 未信頼7zの全entryとcoderを事前検証し、選択fileが要求するsolid展開量をfile作成前に判定します。真正性とdriver適用性は後段で検証します。
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {

class OfficialDownloadWorkspace ;

/**
 * @brief 公式7zを解析およびmemory展開するときの有限上限を表す。
 */
struct OfficialSevenZipExtractionPolicy {
	/// 7z入力全体の最大byte数。
	std::uint64_t maximumArchiveBytes ;
	/// 一fileの展開後最大byte数。
	std::uint64_t maximumSingleFileBytes ;
	/// 全通常file合計の展開後最大byte数。
	std::uint64_t maximumTotalExpandedBytes ;
	/// Metadataで許可する一folderの最大byte数。
	std::uint64_t maximumSolidBlockBytes ;
	/// LZMA／LZMA2 dictionaryの最大byte数。
	std::uint64_t maximumDictionaryBytes ;
	/// SDK metadataを含む一allocatorの同時保持上限。
	std::uint64_t maximumAllocatorBytes ;
	/// Packed dataをdecodeする連続出力bufferの最大byte数。
	std::uint64_t maximumSingleAllocationBytes ;
	/// Directoryを含むentry数上限。
	std::uint32_t maximumEntryCount ;
	/// 終端文字を除く相対path文字数上限。
	std::uint32_t maximumPathCharacters ;
} ;

/**
 * @brief 検証済み7z内の一つの通常fileを表す。
 */
struct OfficialSevenZipEntry {
	/// 元archiveでSDKへ渡す検証済みentry index。
	std::uint32_t archiveIndex{} ;
	/// `\\`区切りの安全なASCII相対path。
	std::wstring  relativePath ;
	/// 展開後のbyte数。
	std::uint64_t uncompressedSize{} ;
	/// Workspace展開内容の64桁小文字SHA-256。Metadata列挙時は空。
	std::wstring  sha256 ;
} ;

/**
 * @brief 選択fileが要求するsolid folderを現decoderで展開できるか表す。
 */
enum class OfficialSevenZipSelectionDisposition {
	/// 全ての必要folderが一allocation上限以下である。
	WITHIN_DECODER_LIMIT,
	/// 一つ以上の必要folderが一allocation上限を超える。
	SOLID_BLOCK_TOO_LARGE,
} ;

/**
 * @brief 選択fileが共有する一つの7z folderとdecode要求量を表す。
 */
struct OfficialSevenZipFolderRequirement {
	/// Archive内の検証済みfolder index。
	std::uint32_t folderIndex{} ;
	/// Folder全体をdecodeするために必要なbyte数。
	std::uint64_t uncompressedBytes{} ;
	/// 本folderを必要とする選択file数。
	std::uint32_t selectedFileCount{} ;
} ;

/**
 * @brief 選択file集合からmetadataだけで算出した一意folder要求を表す。
 */
struct OfficialSevenZipSelectionAssessment {
	/// 現decoderの上限判定。
	OfficialSevenZipSelectionDisposition disposition{
		OfficialSevenZipSelectionDisposition::WITHIN_DECODER_LIMIT} ;
	/// 一意な必要folderの展開後byte数合計。
	std::uint64_t								   totalRequiredUncompressedBytes{} ;
	/// Folder index昇順の要求一覧。
	std::vector<OfficialSevenZipFolderRequirement> folders ;
} ;

/**
 * @brief 公式7zの全entry、coder、展開量を、fileを作成せず検証する。
 * Fileを作成せず、全検証成功時だけ通常file一覧を公開する。
 * @param[in] archive 7z container全体。有効期間は本呼出し中に限る。 7z container全byte列。
 * @param[in] policy Providerが固定したmetadataとallocatorの有限上限。 Providerが固定した有限上限。
 * @param[out] entries 成功時の通常file一覧。Directory entryは含めない。
 * @return 成功時は0、形式、path、codec、dictionary、容量不正時はHRESULT bit pattern。 全entryとfolderが安全なら0、拒否時はHRESULT
 *         bit pattern。
 * @note ASCII名、Copy／LZMA／LZMA2およびx86 BCJ／BCJ2だけを受理する。
 */
[[nodiscard]] NativeError inspectOfficialSevenZip( std::span<const std::byte>			  archive,
												  const OfficialSevenZipExtractionPolicy &policy,
												  std::vector<OfficialSevenZipEntry>	 &entries) ;

/**
 * @brief 公式7zを再検証し、選択fileが要求する一意なsolid folder量を算出する。
 * Archiveをmetadata用の総allocation上限で再preflightし、packed dataのdecodeやfile作成を行わず、現在decoderで必要な連続buffer量を
 * 個別allocation上限と比較する。
 * @param[in] archive 7z container全体。有効期間は本呼出し中に限る。 7z container全byte列。
 * @param[in] policy Metadata上限と現decoderの一allocation上限。 Metadataとdecoder allocationの有限上限。
 * @param[in] selectedArchiveIndices 一件以上の検証済み通常file index集合。 選択する通常file index集合。
 * @param[out] assessment 成功時の一意folder要求。失敗時は既定値に戻す。 成功時の一意folder要求と上限判定。
 * @return Metadataと選択が有効なら0、形式、上限、重複、未知indexはHRESULT bit pattern。 Metadataと選択が有効なら0、拒否時はHRESULT bit
 *         pattern。
 * @note `SOLID_BLOCK_TOO_LARGE`は判定成功だが、現decoderでの展開許可ではない。
 * @note Metadata解析は総allocator上限、decode可否は一allocation上限で個別に判定する。
 */
[[nodiscard]] NativeError assessOfficialSevenZipSelection(
	std::span<const std::byte> archive, const OfficialSevenZipExtractionPolicy &policy,
	std::span<const std::uint32_t>		 selectedArchiveIndices,
	OfficialSevenZipSelectionAssessment &assessment) ;

/**
 * @brief 公式7zの全体を再検証し、明示indexの通常file一件をmemoryへ展開する。
 * SDK bufferのrangeとadvertised size一致後にだけ内容を複写し、失敗時は部分byteを公開しない。
 * @param[in] archive 7z container全体。有効期間は本呼出し中に限る。 7z container全byte列。
 * @param[in] policy Providerが固定した全有限上限。 Providerが固定した有限上限。
 * @param[in] archiveIndex 直前の検証済み一覧から選んだ元archiveのentry index。 検証済み一覧から選んだentry index。
 * @param[out] content 成功時のCRC検証済みfile内容。失敗時は空にする。
 * @return 成功時は0、事前検証、index照合、CRCまたは展開失敗時はHRESULT bit pattern。 再検証と選択file展開の成功時は0、拒否時はHRESULT。
 * @note 本関数はfileを作成せず、選択外fileを呼出側へ公開しない。
 */
[[nodiscard]] NativeError extractOfficialSevenZipFile(
	std::span<const std::byte> archive, const OfficialSevenZipExtractionPolicy &policy,
	std::uint32_t archiveIndex, std::vector<std::byte> &content) ;

/**
 * @brief 公式7z全体を再検証し、明示indexの通常fileだけを保護workspaceへ展開する。
 * 重複、directory、未知indexを作成前に拒否し、途中失敗時は今回作成したfileだけを逆順cleanupする。
 * @param[in] archive 7z container全体。有効期間は本呼出し中に限る。 7z container全byte列。
 * @param[in] policy Providerが固定した全有限上限。 全entryとSDK allocationへ適用する有限上限。
 * @param[in] selectedArchiveIndices 一件以上の検証済み通常file index集合。 選択する通常file index集合。
 * @param[in,out] workspace 初期化済みの保護workspace。既存fileは変更しない。 今回のfileを追跡する初期化済み保護領域。
 * @param[out] entries 成功時のSHA-256付き選択file一覧。失敗時は空にする。
 * @return 全entry再検証、CRC、file作成、完全書込み、hash成功時は0。 再検証、選択照合、CRC、書込み、hash成功時は0。
 * @note 重複、directory、未知indexをfile作成前に拒否し、途中失敗時は今回作成分を破棄する。
 */
[[nodiscard]] NativeError extractOfficialSevenZipFiles(
	std::span<const std::byte> archive, const OfficialSevenZipExtractionPolicy &policy,
	std::span<const std::uint32_t> selectedArchiveIndices, OfficialDownloadWorkspace &workspace,
	std::vector<OfficialSevenZipEntry> &entries) ;

} // namespace drivercrate
