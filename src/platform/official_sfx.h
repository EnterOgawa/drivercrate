//------------------------------------------------------------------------------
/**
 * @file official_sfx.h
 * @brief 公式自己解凍形式の静的識別定義
 * @version 01.06.00
 * @date 2026/09/06
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  PE末尾7z形式の静的識別を追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  Certificate直前zero paddingへ対応
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.00.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.01.00 Shunji Ogawa  2026/11/23  WiX v3の署名領域と内蔵CABの境界検査を追加
 * Ver.01.02.00 Shunji Ogawa  2026/11/23  公式取得の同一原本へWiXの境界と配布署名を結合
 * Ver.01.03.00 Shunji Ogawa  2026/11/23  PE直後の署名領域内ZIPの範囲検査を追加
 * Ver.01.04.00 Shunji Ogawa  2026/11/23  署名済みPEから元取得に結び付くZIPメンバーを読み取る
 * Ver.01.05.00 Shunji Ogawa  2026/11/24  審査済みNSISの選択メンバーを非実行で読み取る
 * Ver.01.06.00 Shunji Ogawa  2026/11/24  審査済みNSISを取得済みの元ZIPに結ぶ
 * </pre>
 *
 * @note 公式EXEを実行せず、PE後方の7z、ZIP、WiX v3のCAB、審査済みNSISを形式ごとに扱う
 *       取得証拠を照合する入口だけで配布署名を検証し、端末適用性は呼出し側が別に扱う
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace drivercrate {

class OfficialMappedFile ;
struct DriverArchiveInput ;
struct OfficialZipFile ;

/**
 * @brief PE末尾7z自己解凍形式を識別するときの有限上限を表す
 */
struct OfficialSfxInspectionPolicy {
	/// 入力EXE全体の最大byte数
	std::uint64_t maximumExecutableBytes ;
	/// PE image末尾から7z開始までの最大byte数
	std::uint64_t maximumStubBytes ;
	/// Certificateを除く7z streamの最大byte数
	std::uint64_t maximumArchiveBytes ;
} ;

/**
 * @brief 構造とCRCを検証したPE末尾7z streamのfile内範囲を表す
 */
struct OfficialSfxLayout {
	/// 7z signature先頭のfile offset
	std::uint64_t archiveOffset{} ;
	/// Paddingを含まない7z streamのbyte数
	std::uint64_t archiveSize{} ;
	/// Certificate直前の検証済みzero byte数
	std::uint64_t certificatePaddingSize{} ;
	/// 7z Next Header先頭のfile offset
	std::uint64_t nextHeaderOffset{} ;
	/// CRC検証済みNext Headerのbyte数
	std::uint64_t nextHeaderSize{} ;
	/// PE certificate table先頭。未存在時は0
	std::uint64_t certificateOffset{} ;
	/// PE certificate table長。未存在時は0
	std::uint64_t certificateSize{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief PE image後方の単一7z streamを、実行も展開もせず識別する。PE image後方の単一7z streamを識別する。EXEを実行・展開せず、全検査成功後だけ出力範囲を
 *        確定する
 * @param[in] executable 公式取得後のEXE全体。有効期間は本呼出し中に限る
 * @param[in] policy 入力、stub走査、7z streamへ適用する有限上限。 入力、stub走査、7z streamの有限上限
 * @param[out] layout 成功時の7z、zero padding、certificate table範囲。失敗時は既定値。 成功時の7zおよびcertificate範囲
 * @return 成功時は0、引数、上限、PE／7z構造またはCRC不正時はHRESULT bit pattern。 成功時は0、引数、上限、PE／7z構造、CRC不正時はHRESULT
 * @note 本関数はfileを実行・展開せず、署名、publisher、driver適用性も判定しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectOfficialSevenZipSfx( std::span<const std::byte>			executable,
													 const OfficialSfxInspectionPolicy &policy,
													 OfficialSfxLayout &layout) noexcept ;

/** @brief PE直後のZIPの走査と領域記録に使う有限上限 */
struct OfficialSignedPeZipInspectionPolicy {
	/// 元EXE全体の最大byte数
	std::uint64_t maximumExecutableBytes ;
	/// ディレクトリを含むZIPの最大エントリ数
	std::uint32_t maximumEntryCount ;
} ;

/** @brief 末尾証明書の前にある単一ZIPの構造検査結果 */
struct OfficialSignedPeZipLayout {
	/// PEの生セクション直後にあるZIPのfile offset
	std::uint64_t archiveOffset{} ;
	/// 末尾証明書との整列を除いたZIPのbyte数
	std::uint64_t archiveSize{} ;
	/// 同じ元EXE末尾の証明書テーブルのfile offset
	std::uint64_t certificateOffset{} ;
	/// 証明書テーブル全体のbyte数
	std::uint64_t certificateSize{} ;
	/// ZIP内のオフセットの基準が元EXE先頭の場合true、ZIP先頭の場合false
	bool		  offsetsFromExecutableStart{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 末尾証明書を持つPEから、直後に続く単一ZIPの完全な範囲を識別する
 * @param[in] executable 呼出し中だけ借用する取得済み元EXE全体
 * @param[in] policy 元EXEのbyte数とZIPエントリ数に適用する有限上限
 * @param[out] layout 検証済みの範囲とオフセット基準。失敗時は空
 * @return 成功時は0、引数、上限または構造の不成立はHRESULT
 * @note 原署名の信頼、ZIP内容・CRC・適用性は別に検証する。元EXEの実行・展開は行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectOfficialSignedPeZip(
	std::span<const std::byte> executable, const OfficialSignedPeZipInspectionPolicy &policy,
	OfficialSignedPeZipLayout &layout) noexcept ;

/** @brief 元EXEのSHA-256とともに定義する審査済みNSISメンバーの読取り条件 */
struct OfficialReviewedNsisMember {
	/// 大文字小文字を含む原名と審査済みディレクトリ。区切りはbackslash
	std::wstring_view relativePath ;
	/// 原命令表にあるディレクトリ記録の0始まり位置
	std::uint32_t	  directoryIndex ;
	/// 原命令表にあるファイル記録の0始まり位置
	std::uint32_t	  fileIndex ;
	/// 元データ領域からの長さタグ位置
	std::uint32_t	  dataOffset ;
	/// 審査済みの展開後バイト数
	std::uint32_t	  expandedBytes ;
	/// 展開後の小文字64桁SHA-256。呼出し中は原定義から借用する
	std::wstring_view sha256 ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 審査済みの非solid NSIS 2 ANSI書庫から、固定した元レコードだけを読み取る
 * @param[in] executable 呼出し中に不変で借用する内側の元EXE全体
 * @param[in] executableSha256 審査済み内側EXEの小文字64桁SHA-256
 * @param[in] expected 元原本へ結び付けた通常メンバー。元名・位置・長さと内容を指定する
 * @param[out] files 成功時だけ同じ順序の相対パスと展開バイトを保持。失敗時は空
 * @return 全条件の一致は0、定義、構造、展開またはハッシュの不一致はHRESULT
 * @note 命令は位置と名前の照合にだけ使う。呼出し側は元ZIPの配布根拠とINF・CATを別に検証する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readOfficialReviewedNsisMembers(
	std::span<const std::byte> executable, std::wstring_view executableSha256,
	std::span<const OfficialReviewedNsisMember> expected,
	std::vector<OfficialZipFile>			   &files) noexcept ;

/**
 * @brief 一件の審査済みNSIS配布を外側ZIPと内側メンバーの両方に結び付ける
 * @note 各viewは同期検査中だけ外部定義から借用する
 */
struct OfficialReviewedNsisZip {
	/// 公式配布で確認した外側ZIPの元長
	std::uint64_t								archiveBytes ;
	/// 同じ審査済み外側ZIP全体の小文字64桁SHA-256
	std::wstring_view							archiveSha256 ;
	/// ZIP直下に置かれた唯一のEXE名。大小文字を保持する
	std::wstring_view							executableName ;
	/// 同じEXEの展開後バイト数
	std::uint64_t								executableBytes ;
	/// 同じEXEの展開後の小文字64桁SHA-256
	std::wstring_view							executableSha256 ;
	/// 同じ元EXEの選択パス、元位置と内容を結ぶ審査条件
	std::span<const OfficialReviewedNsisMember> members ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 私有収集の元ZIPから、審査済みの唯一のNSISにある選択ファイルを読み取る
 * @param[in] input 同じ収集取得で固定した現在user検査領域の原本と元同一性
 * @param[in] reviewed 公式元配布と内側EXEを固定した版別の審査条件
 * @param[out] files 元位置と内容が一致した全メンバー。失敗時は空
 * @return 全原本照合と選択展開成功は0、取得、形式、内容、上限または確保の失敗はHRESULT
 * @note 元ZIPは検査中に読み取り専用で固定する。CATや同梱依存は後続の私有内容検査で確認する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readOfficialReviewedNsisZipMembers(
	const DriverArchiveInput &input, const OfficialReviewedNsisZip &reviewed,
	std::vector<OfficialZipFile> &files) ;

/**
 * @brief WiX v3の署名付き二CAB形式を識別するときの有限上限を表す
 */
struct OfficialWixBurnInspectionPolicy {
	/// 元EXE全体の最大byte数
	std::uint64_t maximumExecutableBytes ;
	/// 各CABの最大格納byte数
	std::uint64_t maximumCabinetBytes ;
} ;

/**
 * @brief 元EXE内で位置と長さを確認したWiX v3のCABと証明書テーブル範囲
 */
struct OfficialWixBurnLayout {
	/// 起動用CABのfile offset
	std::uint64_t uxCabinetOffset{} ;
	/// 起動用CABのbyte数
	std::uint64_t uxCabinetSize{} ;
	/// 起動部の元証明書テーブルのfile offset
	std::uint64_t engineCertificateOffset{} ;
	/// 起動部の元証明書テーブルのbyte数
	std::uint64_t engineCertificateSize{} ;
	/// 添付CABのfile offset
	std::uint64_t attachedCabinetOffset{} ;
	/// 添付CABのbyte数
	std::uint64_t attachedCabinetSize{} ;
	/// 元EXE末尾の証明書テーブルのfile offset
	std::uint64_t certificateOffset{} ;
	/// 元EXE末尾の証明書テーブルのbyte数
	std::uint64_t certificateSize{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief WiX v3の元宣言に従って、二つのCABと二つの証明書テーブルの範囲を識別する
 * @param[in] executable 呼出し中だけ借用する取得済み元EXE全体
 * @param[in] policy 入力全体と各CABに適用する有限上限
 * @param[out] layout 全境界の検証が成立した場合だけ保持する元範囲。失敗時は既定値
 * @return 成功時は0、引数、上限または書式不正時はHRESULT
 * @note EXEの実行やCABの展開は行わない。Authenticodeの信頼検証と内容検査は別に必要
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectOfficialWixBurn( std::span<const std::byte>				executable,
												 const OfficialWixBurnInspectionPolicy &policy,
												 OfficialWixBurnLayout &layout) noexcept ;

/**
 * @brief 公式取得時に固定した元EXEと許可する主署名者を指定する
 */
struct OfficialSignedExecutableSource {
	/// 保護された取得領域内の元EXEの絶対path
	std::wstring_view				   executablePath ;
	/// 元取得証拠にある正のbyte数
	std::uint64_t					   expectedBytes ;
	/// 元取得証拠にある64桁SHA-256
	std::wstring_view				   expectedSha256 ;
	/// 公式配布元定義で許可した署名者の表示名
	std::span<const std::wstring_view> acceptedPublishers ;
	/// 保存済み応答の検証など、証明書取得をcacheだけに制限するときtrue
	bool							   cachedOnly ;
} ;

struct OfficialZipExtractionPolicy ;

//------------------------------------------------------------------------------
/**
 * @brief 元取得と主署名の照合を通過したPEから、指定された内側ZIPの原バイトを読み取る
 * @param[in] source 元取得証拠と配布元定義で照合した入力
 * @param[in] policy 元EXE全体と外側ZIPの入力、エントリ数、展開量に適用する有限上限
 * @param[in] member 検査した外側ZIP内の完全な相対名。大文字小文字を保持する
 * @param[out] innerZip 全検証成功時だけ返す内側ZIPの原バイト。失敗時は空
 * @return 成功時0、取得、署名、構造、ZIP読取りまたはメンバー照合の失敗時はHRESULT
 * @note 元ファイルを実行・変更しない。内側ZIPの形式、INF・CATと適用性は呼出し側が検証する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readVerifiedOfficialSignedPeZipMember(
	const OfficialSignedExecutableSource &source, const OfficialZipExtractionPolicy &policy,
	std::wstring_view member, std::vector<std::byte> &innerZip) ;

//------------------------------------------------------------------------------
/**
 * @brief 元取得と署名に結び付いたWiX配布の二つのCAB範囲を読み取り専用で開く
 * @param[in] source 元取得証拠と配布元定義で照合した入力
 * @param[in] policy 元EXE全体と各CABへ適用する有限上限
 * @param[in,out] executable 空で渡す。成功時は署名と同じ元ファイルを固定する所有者
 * @param[out] layout 全検証成功時に確定した元範囲。失敗時は既定値
 * @return 成功時0、元取得情報、保護、範囲、署名が不成立の場合はHRESULT
 * @note 実行や展開は行わない。成功時の元範囲は所有者の寿命内で利用する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError openVerifiedOfficialWixBurn( const OfficialSignedExecutableSource	&source,
													  const OfficialWixBurnInspectionPolicy &policy,
													  OfficialMappedFile	&executable,
													  OfficialWixBurnLayout &layout) ;

} // namespace drivercrate
