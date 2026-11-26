//------------------------------------------------------------------------------
/**
 * @file windows_product_type.h
 * @brief Windows client／server種別判定定義
 * @version 01.01.00
 * @date 2026/09/02
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
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成
 * Ver.0.1.0    Shunji Ogawa  2026/09/06  実OS build番号取得を追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Product SKU取得を追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.00.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.01.00 Shunji Ogawa  2026/11/18  P3同scan fullhost観測と取得直前拒否を接続
 * </pre>
 *
 * @note 実行中WindowsのServer種別、major build、product SKUを判定します。判定不能値で対象外OS向け処理や前回観測の再利用を許可しません
 */
//------------------------------------------------------------------------------

#pragma once

#include <cstdint>
#include <functional>
#include <optional>

namespace drivercrate {

/** @brief 実APIから観測した六fieldです。既定値だけでは成功になりません */
struct WindowsHostPlatform {
	/// RtlGetVersionの元majorです
	std::uint32_t majorVersion{} ;
	/// RtlGetVersionの元minorです。0も観測値です
	std::uint32_t minorVersion{} ;
	/// UBRを含まない元base buildです
	std::uint32_t buildNumber{} ;
	/// GetNativeSystemInfoの元native architectureです
	std::uint16_t nativeArchitecture{} ;
	/// SKUではないVER_NT_*の元値です
	std::uint8_t  productType{} ;
	/// 元wSuiteMaskです。0も実観測値です
	std::uint16_t suiteMask{} ;
	/**
	 * @brief 六つの元fieldを完全比較します
	 * @param[in] other 同期借用する別観測です
	 * @return 六field一致だけtrueです
	 */
	bool		  operator==( const WindowsHostPlatform &other) const = default ;
} ;
/** @brief API観測の状態です。対応可否のローカル判定とは別です */
enum class WindowsHostObservationState {
	/// 未呼出し/依存欠落/例外です
	UNOBSERVED,
	/// APIが失敗を返しました。raw0も失敗です
	API_FAILED,
	/// APIが成功し、元六fieldを保持します
	OBSERVED
} ;
/** @brief 変換していない元codeのdomainです */
enum class WindowsHostErrorDomain {
	/// 元codeは得ていません
	NONE,
	/// GetLastErrorの原DWORDです
	WIN32_CODE,
	/// RtlGetVersionの原LONGです
	NTSTATUS
} ;
/** @brief 元codeを得た段階です */
enum class WindowsHostObservationStage {
	/// 元APIは未呼出しです
	NOT_CALLED,
	/// 明示依存が不足しました
	DEPENDENCY,
	/// module解決の段階です
	MODULE,
	/// entry解決の段階です
	ENTRY,
	/// version観測の段階です
	VERSION
} ;
/** @brief 成功/失敗と元codeを分離して保持するhost観測です。権限ではありません */
struct WindowsHostPlatformObservation {
	/// UNOBSERVEDや失敗を元code0で成功へ補完しません
	WindowsHostObservationState		   state{WindowsHostObservationState::UNOBSERVED} ;
	/// OBSERVEDの実fieldだけを所有します。欠損値は後段でUNKNOWNです
	std::optional<WindowsHostPlatform> value ;
	/// 元API codeのdomainです。ローカルHRESULTを保存しません
	WindowsHostErrorDomain			   domain{WindowsHostErrorDomain::NONE} ;
	/// 元API呼出し段階です
	WindowsHostObservationStage		   stage{WindowsHostObservationStage::NOT_CALLED} ;
	/// 元Win32またはNTSTATUSの32bit patternです
	std::uint32_t					   rawBits{} ;
} ;
/** @brief 同workerが所有する明示observerです。空をnativeで補完しません */
using WindowsHostPlatformObserver = std::function<WindowsHostPlatformObservation()> ;
/** @brief API原観測とは別の取得前ローカル判定です */
enum class IndexHostGateState {
	/// 元hostに限定した未検査取得だけを許可します
	ALLOW_UNVERIFIED,
	/// API失敗/未観測/必要field不足です
	UNKNOWN,
	/// 初回に既知の未対応tupleを観測しました
	UNSUPPORTED,
	/// 元hostと当該recordのrelease/productが一致しません
	INCOMPATIBLE,
	/// 作用直前の完全tupleが元scanから変わりました
	STALE
} ;
/** @brief 原domain/bitsをローカルHRESULTと分離します */
struct IndexHostGateResult {
	/// host一致でも実device/導入適用性の合格ではありません
	IndexHostGateState			   state{IndexHostGateState::UNKNOWN} ;
	/// 呼出側へのローカルHRESULTです。原API codeではありません
	std::int32_t				   error{} ;
	/// 原観測と元native bit patternを所有します
	WindowsHostPlatformObservation observation ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 一回のSDK version/architecture観測を返します
 * @return 元status/domain/bitsと六fieldです。API失敗/例外は成功へ補完しません
 * @note bool/build/SKU互換APIを使わず、観測成功と対応可否を分けます
 */
//------------------------------------------------------------------------------
[[nodiscard]] WindowsHostPlatformObservation observeWindowsHostPlatform() noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 既復旧modeと互換のVersion Helper boolをそのまま返します
 * @return IsWindowsServerの非FALSEでtrueです。VerifyVersionInfoWの拒否理由を分離しません
 * @note 既復旧意味を保持します。false/trueから新fullhostの成功や六fieldを合成しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool							 isWindowsServer() noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 実行中Windowsのmajor build番号を取得する。Processに既に存在するntdllのRtlGetVersionを使用し、固定OS向け公式配布を別世代へ表示しないため
 *        に使用する
 * @return 取得できたbuild番号。判定不能、0、32bit超過の場合は0。 実行中Windowsのmajor build番号。判定不能時は0
 * @note Manifestによるversion仮想化を避けるためworker内のOS境界判定に使用する
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint32_t					 currentWindowsBuildNumber() noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 実行中Windowsのproduct SKUを取得する。Windows 10以降の10.0 versionを指定して実product SKUを取得し、edition変更時に前回
 *        release観測を失効可能にする
 * @return GetProductInfoが返したPRODUCT_*値。取得不能または未定義時は0。 GetProductInfoが返すPRODUCT_*値。取得不能時は0
 * @note 端末内OS fingerprintへedition差を反映するためだけに使用する
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::uint32_t					 currentWindowsProductSku() noexcept ;

} // namespace drivercrate
