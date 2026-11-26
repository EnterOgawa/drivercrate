//------------------------------------------------------------------------------
/**
 * @file official_wix_manifest.h
 * @brief 署名付きWiX v3の添付コンテナー、MSIと利用規約の照合契約
 * @version 01.00.00
 * @date 2026/11/23
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/23  新規作成
 * </pre>
 *
 * @note 同期呼出し中だけ元XMLと選択指定を借用する。出力は元バイトに照合すべき宣言の所有値
 * @see docs/adr/0572-signed-wix-burn-driver-content.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

/**
 * @brief 検査指定がMSIの元宣言に求めるarchitecture
 */
enum class OfficialWixMsiArchitecture {
	/// AMD64を選ぶ条件が一致した宣言。実MSIの形式は別に照合する
	AMD64,
	/// x86を選ぶ条件が一致した宣言。内容の適用候補には渡さない
	X86,
} ;

/**
 * @brief 元マニフェストの一つの内容役割を指定する
 */
struct OfficialWixMemberSelector {
	/// 大文字小文字を区別する元Payload ID
	std::wstring_view id ;
	/// 元CAB内にあるASCII一要素のSourcePath
	std::wstring_view cabinetMember ;
	/// 元Payloadの論理FilePath
	std::wstring_view filePath ;
} ;

/**
 * @brief 同じ配布のChainに含まれる一件のMSIを指定する
 */
struct OfficialWixMsiSelector {
	/// 添付CABの元Payloadと一対一で対応する指定
	OfficialWixMemberSelector  member ;
	/// 元のInstallCondition全体。比較用にだけ借用し、評価しない
	std::wstring_view		   installCondition ;
	/// 元条件が持つarchitectureの指定
	OfficialWixMsiArchitecture architecture ;
	/// 元MSIの言語宣言。後続のSummaryInformationと照合する
	std::uint16_t			   language ;
} ;

/**
 * @brief Win32に渡す前に照合すべきCABメンバーの元宣言
 */
struct OfficialWixManifestMember {
	/// 元文書内のPayload ID
	std::wstring  id ;
	/// 元CAB内のSourcePath。抽出に使えるASCII一要素の名前
	std::wstring  cabinetMember ;
	/// 論理FilePath。照合用の値
	std::wstring  filePath ;
	/// マニフェストが宣言した未展開メンバーの展開後byte数
	std::uint64_t bytes{} ;
	/// 配布元マニフェストの40桁小文字SHA-1
	std::wstring  sha1 ;
} ;

/**
 * @brief 全宣言と内容指定の構造が一致した場合のWiX v3マニフェスト
 */
struct OfficialWixManifest {
	/// 添付CABの元宣言byte数
	std::uint64_t						   attachedCabinetBytes{} ;
	/// 添付CABに対する元宣言の40桁小文字SHA-1
	std::wstring						   attachedCabinetSha1 ;
	/// 起動用CABの元Payload群。マニフェスト自体を含まない
	std::vector<OfficialWixManifestMember> uxMembers ;
	/// 添付CABの全MSIの元Payload群。指定と元Chainの順序で保持する
	std::vector<OfficialWixManifestMember> msiMembers ;
	/// 規約指定順の起動用Payload index
	std::vector<std::size_t>			   licenseIndices ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief WiX v3の元宣言と指定した全MSI・規約の対応を確認する
 * @param[in] xml 保護一時領域で読み取った元UTF-16マニフェスト。同期中だけ借用する
 * @param[in] packages 元Chainの順序で指定したMSI全件。AMD64を一件以上含む
 * @param[in] licenses 同意表示が必要な言語順の元規約指定。一件以上
 * @param[out] manifest 元宣言の構造が全て成立したときだけ設定する所有出力。失敗時は空
 * @return 成功時0、XML、選択指定、形式、境界またはCOMのエラー時はHRESULT
 * @pre 呼出しthreadでCOMを初期化する
 * @note 証明書、CAB・MSI・規約の実バイトの照合は別途必要。条件・設定・実行命令は評価しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectOfficialWixManifest(
	std::wstring_view xml, std::span<const OfficialWixMsiSelector> packages,
	std::span<const OfficialWixMemberSelector> licenses, OfficialWixManifest &manifest) ;

} // namespace drivercrate
