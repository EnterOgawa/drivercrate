//------------------------------------------------------------------------------
/**
 * @file local_collector_legacy.h
 * @brief 全旧契約の非変更検査と公開request待機の引継ぎを定義します。
 * @version 01.04.01
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  旧v4全契約の非変更読込みを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/27  公式requestと恒久keyの生成を共用。
 * Ver.01.02.00 Shunji Ogawa  2026/09/28  旧算法target keyの公開builderを追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/03  旧待機の非変更export準備を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/17  全旧targetの実request射影をメモリへ保持。
 * Ver.01.04.01 Shunji Ogawa  2026/10/17  待機export引数名と定義の文書対応を整合。
 * </pre>
 *
 * @note 単一監督threadで使用します。通信・保存・旧cache昇格を行いません。
 */
//------------------------------------------------------------------------------
#pragma once

#include <Windows.h>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
class LocalCollectorStateStore ;
struct LocalCollectorTarget ;

/** @brief 公開targetから再構築するメモリ内だけの公式GET契約です。 */
struct LocalCollectorRequest {
	/// 組み込みsource識別子。
	std::wstring source ;
	/// 組み込みprovider識別子。
	std::wstring provider ;
	/// 当該providerのmetadata用途。
	std::wstring resource ;
	/// 検証済み公式URL。保存・logへ渡しません。
	std::wstring url ;
	/// 既存GETと同じ固定Accept値。
	std::wstring accept ;
	/// 恒久待機を共有するgroup。
	std::wstring group ;
	/// 既存canonical requestのSHA-256。
	std::wstring requestKey ;
} ;

/** @brief 公式経路と恒久request keyを同じ入力から生成します。
 * @param[in] target 元keyを含む公開target。
 * @param[out] request 成功時の所有値。失敗時は空です。
 * @return 既知の公式入口とcanonical hashが成立した場合true。
 * @note 通信・保存は行わず、COM apartmentは呼出しthreadが所有します。
 */
[[nodiscard]] bool makeLocalCollectorRequest( const LocalCollectorTarget &target,
											 LocalCollectorRequest		&request) ;

/** @brief 公開fieldから旧算法のtarget keyを作り、検証済み公式requestに限定します。
 * @param[in] source 組み込みsourceラベル。
 * @param[in] publicModel ASUS公開model。Intel固定pageでは空。
 * @param[in] operatingSystem 既存requestのOS表記。
 * @param[in] category ASUS分類。Intel固定pageでは空。
 * @param[out] target 成功時のkey付き公開target。失敗時は空。
 * @return 旧target keyと公式requestを再構築できた場合true。
 */
[[nodiscard]] bool makeLocalCollectorTarget( std::wstring_view source, std::wstring_view publicModel,
											std::wstring_view	  operatingSystem,
											std::wstring_view	  category,
											LocalCollectorTarget &target) ;

/** @brief 旧target／sourceから引き継ぐ期限と要確認条件です。 */
struct CollectorLegacyWait {
	/// 組み込みのasusまたはintel group。
	std::wstring  group ;
	/// 公開requestのhash。source単位の待機では空です。
	std::wstring  requestKey ;
	/// 元観測UTC millisecond最高値。
	std::uint64_t observed{} ;
	/// 元の絶対待機期限。9999年まで保持します。
	std::uint64_t notBefore{} ;
	/// 自動解除しない要確認。
	bool		  review{} ;
} ;

/** @brief 全v4契約を検査した非変更の引継ぎ結果です。 */
struct CollectorLegacySnapshot {
	/// 正常な旧run／pointer／source cooldownの相対名・実byte hash集合のSHA-256。
	std::wstring					   digest ;
	/// digestに含む旧file件数。
	std::uint32_t					   fileCount{} ;
	/// 旧run開始日と実試行日の最大JST日。履歴なしは空です。
	std::wstring					   lastUsedDay ;
	/// 同じ公開requestを統合した最大320待機。
	std::vector<CollectorLegacyWait>   waits ;
	/// 全保存targetから再構築した重複のない公式GET。URLはメモリ内だけで使用します。
	std::vector<LocalCollectorRequest> requests ;
} ;

/** @brief 公開製品から公式requestの恒久keyを非通信で構築します。
 * @param[in] target 元keyの一致が検証済みの公開target。
 * @param[out] group 成功時の組み込みgroup。
 * @param[out] requestKey method／URL／固定header／locale／OS／sourceのSHA-256。
 * @return 既知の公式入口を構築できた場合true。失敗時出力は空です。
 */
[[nodiscard]] bool	makeLocalCollectorRequestKey( const LocalCollectorTarget &target,
												 std::wstring &group, std::wstring &requestKey) ;

/** @brief 全旧v4契約を同じwriter下で検証して待機を集約します。
 * @param[in,out] store 初期化済みの借用保護store。
 * @param[in] utcMillis 現在のUTC millisecond。
 * @param[out] snapshot 成功時の非変更観測。失敗時は空です。
 * @param[out] reason 成功時は空、それ以外は固定の拒否理由です。
 * @return 成功0、形式拒否13、回収必要1237、容量68または元I/O code。
 * @note v1／v2 campaign prefixの照合は別の監督が担当し、本関数では更新しません。
 */
[[nodiscard]] DWORD inspectLocalCollectorLegacy( LocalCollectorStateStore &store,
												std::uint64_t			  utcMillis,
												CollectorLegacySnapshot	 &snapshot,
												std::wstring			 &reason) ;

/** @brief 既存の旧storeだけをlockし、待機の持出し用JSONを非変更で作ります。
 * @param[in] candidate 現workspaceのwork/state直下に既にある旧専用root。
 * @param[in] utcMillis 信頼する現在UTC millisecond。CLIはOS時計だけを渡します。
 * @param[out] snapshot 完全検証後だけの旧待機。失敗時は空です。
 * @param[out] bytes 成功時だけの最大1 MiBのUTF-8 JSON。URL・path・端末IDを含めません。
 * @return 成功0、能力87、旧回収1237、破損13、確保8または元I/O error。
 * @note 新規root作成・旧file更新・campaign待機の出力・HTTP許可発行は行いません。
 * COM apartmentはcallerが所有し、出力fileの保存と全書込み確認もcallerが行います。
 */
[[nodiscard]] DWORD prepareLocalCollectorLegacyExport( const std::filesystem::path &candidate,
													  std::uint64_t				   utcMillis,
													  CollectorLegacySnapshot	  &snapshot,
													  std::string				  &bytes) noexcept ;
} // namespace drivercrate
