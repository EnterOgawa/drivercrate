//------------------------------------------------------------------------------
/**
 * @file official_resource_content.h
 * @brief 署名された親byte範囲と非実行resource内容選択を定義する。
 * @version 01.00.01
 * @date 2026/11/03
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  collector resource解決と端末原範囲選択を分離。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 * @note 構造・原byte結合だけを扱い、由来・適合・導入権限を発行しない。
 * @see docs/adr/0430-signed-resource-ranges-for-driver-content.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/update_types.h"
#include "platform/official_zip.h"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {
class OfficialDownloadWorkspace ;
/** @brief PE resourceの数値IDと原UTF-16名を区別する。 */
struct OfficialResourceIdentifier {
	/// trueなら文字列、falseなら数値ID。
	bool		  named{} ;
	/// 数値の場合だけ使う0～65535のID。
	std::uint32_t id{} ;
	/// 文字列の場合だけ使う原名。
	std::wstring  text ;
	/**
	 * @brief 型を含む原identityを比較する。
	 * @param[in] other 比較対象。
	 * @return 全原値が等しい場合true。
	 */
	bool		  operator==( const OfficialResourceIdentifier &other) const = default ;
} ;
/** @brief 表示pathへ変換しない三段の原resource identity。 */
struct OfficialResourceTuple {
	/// 第一段の原type。
	OfficialResourceIdentifier type ;
	/// 第二段の原name。
	OfficialResourceIdentifier name ;
	/// 第三段の明示language ID。
	std::uint32_t			   language{} ;
	/**
	 * @brief 三段の完全一致を比較する。
	 * @param[in] other 比較対象。
	 * @return 全原値が等しい場合true。
	 */
	bool					   operator==( const OfficialResourceTuple &other) const = default ;
} ;
/** @brief 直近の親byteへ結合した原resource範囲。 */
struct OfficialResourceSlice {
	/// collectorが確認した原tuple。端末はtreeを再走査しない。
	OfficialResourceTuple resource ;
	/// 親の先頭からのraw offset。
	std::uint64_t		  offset{} ;
	/// 正の原byte数。
	std::uint64_t		  length{} ;
	/// 原byteの小文字SHA-256。
	std::wstring		  sha256 ;
	/**
	 * @brief 元範囲と全証拠を比較する。
	 * @param[in] other 比較対象。
	 * @return 全原値が等しい場合true。
	 */
	bool				  operator==( const OfficialResourceSlice &other) const = default ;
} ;
/** @brief 明示した最終driver fileの役割。 */
enum class OfficialResourceRole {
	/// 元署名INF。
	INF,
	/// 元CAT。
	CATALOG,
	/// 元INFに結ぶ必要本体。
	DRIVER_FILE
} ;
/** @brief 原resourceを検証済みlogical basenameへ結ぶ。 */
struct OfficialResourceRoleFile {
	/// driver内の閉じた役割。
	OfficialResourceRole  role{OfficialResourceRole::DRIVER_FILE} ;
	/// 安全な原flat file名。
	std::wstring		  basename ;
	/// inner PE内の原範囲。
	OfficialResourceSlice slice ;
	/**
	 * @brief 役割と元byte結合を比較する。
	 * @param[in] other 比較対象。
	 * @return 全原値が等しい場合true。
	 */
	bool				  operator==( const OfficialResourceRoleFile &other) const = default ;
} ;
/** @brief outer slice→7z一member→flat roleに限定した非authority計画。 */
struct OfficialResourceContentPlan {
	/// 原outerの正のbyte数。
	std::uint64_t						  rootBytes{} ;
	/// 原outerの小文字SHA-256。
	std::wstring						  rootSha256 ;
	/// outer内7z全体の原resource範囲。
	OfficialResourceSlice				  archive ;
	/// 7z内の一意な原相対名。
	std::wstring						  memberPath ;
	/// 中間memberの正のbyte数。
	std::uint64_t						  memberBytes{} ;
	/// 中間memberの小文字SHA-256。
	std::wstring						  memberSha256 ;
	/// 最終role inventory。INF/CATALOG各一件、最大32file。
	std::vector<OfficialResourceRoleFile> files ;
	/// inventory内一件のINF原名。
	std::wstring						  selectedInf ;
	/**
	 * @brief 原取得と全選択証拠の完全一致を比較する。
	 * @param[in] other 比較対象。
	 * @return 全原値が等しい場合true。
	 */
	bool operator==( const OfficialResourceContentPlan &other) const = default ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 形式・byte数・親範囲・役割の有限な静的契約を検査する。
 * @param[in] plan 元recordに結んだ計画。
 * @return 全静的契約を満たす場合true。I/O・署名検証はしない。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool validOfficialResourceContentPlan(
	const OfficialResourceContentPlan &plan) noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief 固定親の範囲と子hashを検査し、借用viewだけを返す。
 * @param[in] parent 呼出し後も借用viewより長く生存する固定親。
 * @param[in] slice 署名record由来の正の範囲とhash。
 * @param[out] result 成功時だけ借用する原範囲。失敗時は空。
 * @return 全範囲/hash一致0、元HRESULT。PE treeは解析しない。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError bindOfficialResourceSlice( std::span<const std::byte>	 parent,
													const OfficialResourceSlice &slice,
													std::span<const std::byte>	&result) ;
//------------------------------------------------------------------------------
/**
 * @brief collector専用に原PEのtyped leafとraw範囲を有界列挙する。
 * @param[in] executable 固定したPE32/PE32+原byte。最大64MiB。
 * @param[out] resources 成功時だけ原tuple/range。hashは未計算。
 * @return 全構造受理0、曖昧・破損・上限はHRESULT。fileを作らない。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError collectOfficialPeResourceRanges(
	std::span<const std::byte> executable, std::vector<OfficialResourceSlice> &resources) ;
//------------------------------------------------------------------------------
/**
 * @brief collector専用に親identityと既知leaf hashから正式範囲を解決する。
 * @param[in] path 非reparseの原outer絶対path。
 * @param[in] requested 原root/7z/member/role size/hashとouter tuple。inner範囲は未確定可。
 * @param[out] result 全原byte検証後だけinnerの一意tuple/offsetを確定する。
 * @param[in] cancellation 任意の非blocking取消し照会。
 * @return 解決成功0、曖昧・不一致・取消し等はHRESULT。中間EXEは保存しない。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError resolveOfficialResourceContentPlan(
	std::wstring_view path, const OfficialResourceContentPlan &requested,
	OfficialResourceContentPlan &result, const std::function<bool()> &cancellation = {}) ;
/** @brief 端末でresource treeを解析せず固定親とinnerを単独所有する。 */
class OfficialResourceContentReader final {
public:
	/**
	 * @brief 空のownerを作る。
	 */
	OfficialResourceContentReader() noexcept ;
	/**
	 * @brief 全借用viewより後に原ownerを回収する。
	 */
	~OfficialResourceContentReader() ;
	/**
	 * @brief 所有者の複写を禁止する。
	 */
	OfficialResourceContentReader( const OfficialResourceContentReader &) = delete ;
	/**
	 * @brief 所有者の複写代入を禁止する。
	 */
	OfficialResourceContentReader &operator=( const OfficialResourceContentReader &) = delete ;
	/**
	 * @brief 全親子hash/CRCを検証してflat role inventoryを確定する。
	 * @param[in] path 非reparse原outer絶対path。
	 * @param[in] plan 原record由来の完全な計画。
	 * @param[in] cancellation 任意の非blocking取消し照会。
	 * @return 全検証成功0、元HRESULT。中間EXEはfile化しない。
	 */
	[[nodiscard]] NativeError	   initialize( std::wstring_view					 path,
											  const OfficialResourceContentPlan &plan,
											  const std::function<bool()>		&cancellation = {}) ;
	/**
	 * @brief 全原hashに結んだrole一覧を借用する。
	 * @return owner生存中の原名/size/hash。未初期化では空。
	 */
	[[nodiscard]] std::span<const OfficialZipEntry> entries() const noexcept ;
	/**
	 * @brief 選択roleだけを所有workspaceへ新規保存する。
	 * @param[in] selected inventory内の重複しない原名集合。
	 * @param[in,out] workspace 初期化済みの出力所有者。
	 * @param[out] entries 全成功時だけ保存済み原名/size/hash。
	 * @return 全保存成功0、取消し/保存失敗時は今回所有分だけ回収し元HRESULT。
	 */
	[[nodiscard]] NativeError extract( std::span<const std::wstring_view> selected,
									  OfficialDownloadWorkspace			&workspace,
									  std::vector<OfficialZipEntry>		&entries) ;

private:
	/// 固定outer、innerと借用roleを同scopeで所有する。
	struct State ;
	/// 全成功時だけ公開する実装。
	std::unique_ptr<State> state_ ;
} ;
} // namespace drivercrate
