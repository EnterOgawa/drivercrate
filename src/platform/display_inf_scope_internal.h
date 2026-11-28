//------------------------------------------------------------------------------
/**
 * @file display_inf_scope_internal.h
 * @brief 現用INFが指定するDisplay補助サービスとイベント源の作用を読み取る
 * @version 01.06.00
 * @date 2026/11/27
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/27  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/27  同じ実節、依存と旧新の必須子の作用の比較を定義
 * Ver.01.02.00 Shunji Ogawa  2026/11/27  Display変更直前の照会と元承認の順序を定義
 * Ver.01.03.00 Shunji Ogawa  2026/11/27  Type 1登録処理が到達する現在の親子を照合
 * Ver.01.04.00 Shunji Ogawa  2026/11/27  Type 1が設定する二つの参照先と旧マーカーを照合
 * Ver.01.05.00 Shunji Ogawa  2026/11/27  WindowsのType 1実行記録を同じ導入と必須子の観測へ結合
 * Ver.01.05.01 Shunji Ogawa  2026/11/27  読取り不能時の元診断を事後状態の契約へ記載
 * Ver.01.06.00 Shunji Ogawa  2026/11/27  共有コピーの事後照合と反映待ちの契約を追加
 * </pre>
 *
 * @note INFの宣言だけを読み取る。導入時の作用や端末上の所有関係は呼出し元が確認する
 * @see docs/adr/0605-validate-selected-display-auxiliary-service-declaration.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "core/update_types.h"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
struct OfficialDisplayAuxiliaryService ;	// 同一計画の補助サービスとイベント源の元宣言
class OfficialDownloadWorkspace ;
struct OfficialInfComponentReference ;
struct OfficialInfPackage ;
struct OfficialSoftwareComponentSharedCopy ;
struct ProtectedExecutableSnapshot ;
struct DisplayType1ClassSnapshot ;
struct DisplayType1RegistrySnapshot ;

//------------------------------------------------------------------------------
/**
 * @brief 現用登録の対象サービスとイベント源に影響する静的宣言を保持する
 */
//------------------------------------------------------------------------------
struct DisplayInfUse {
	/// 同名サービスへのAddService又はDelServiceを確認した場合true
	bool					  serviceDeclaration{} ;
	/// 同名Applicationイベント源への登録又はレジストリ作用を確認した場合true
	bool					  applicationEvent{} ;
	/// 同名サービスのレジストリキーへの絶対パスの作用を確認した場合true
	bool					  serviceRegistry{} ;
	/// 選択節で唯一のサービスキー作用がDIRID 13のCheckRegistration書込みだった場合true
	bool					  scopedChildRegistration{} ;
	/// 読み取った節から参照された外部INFの重複しない元ファイル名
	std::vector<std::wstring> includeFiles ;
	/**
	 * @brief 同じ元INFと実節から独立に読み取った作用を比較する
	 * @param[in] other 同じ対象サービスとイベント源の別観測
	 * @return 全作用と外部INFが同じ場合true
	 */
	bool					  operator==( const DisplayInfUse &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 登録済みINFの対象サービスとイベント源への作用を読取専用で調べる
 * @param[in] path 呼出し元が確認した元登録INFの絶対パス
 * @param[in] actualSection Windowsが記録した実DDInstall節。空の場合は全節を調べる
 * @param[in] target 照合する元サービス名とApplicationイベント源
 * @param[out] result 成功時の観測と外部INF参照。読取失敗時は空
 * @return 有限範囲内の読取成功は0、構文・元API・予算の失敗はHRESULT
 * @note 外部INFの解決、署名、親子関係及び導入の可否は呼出し元の責務
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectRegisteredDisplayInfUse(
	const std::wstring &path, std::wstring_view actualSection,
	const OfficialDisplayAuxiliaryService &target, DisplayInfUse &result) ;

//------------------------------------------------------------------------------
/**
 * @brief 現用子の主IDを旧新の直接必須子と候補の同じ補助サービスの限定作用へ照合する
 * @param[in] workspace 候補の元署名を検査済みの保護領域
 * @param[in] parent 現用親の署名付き選択節が宣言した元ComponentIDs
 * @param[in] packages 候補の選択済み親と同じ閉包の子。同じ元親を先頭に置く
 * @param[in] id 現用子の唯一の主Hardware ID
 * @param[in] target 同じ候補Displayの選択節による補助サービスの元宣言
 * @param[out] child 指定時に一意な選択済み子を借用で返す。失敗時はnullを設定する
 * @return 直接必須子が一件で同じサービスキーへの限定一値だけを確認したら0、それ以外はHRESULT
 * @note 現用子の署名・実親子関係は呼出し元で確認する。実行しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyDisplayPeerCandidateChild(
	const OfficialDownloadWorkspace				  &workspace,
	std::span<const OfficialInfComponentReference> parent,
	std::span<const OfficialInfPackage> packages, const std::wstring &id,
	const OfficialDisplayAuxiliaryService &target, const OfficialInfPackage **child = nullptr) ;

//------------------------------------------------------------------------------
/**
 * @brief Displayの登録・適用直前に元操作、端末の再観測、最後の元承認を順に確認する
 * @param[in] ownsOperation 同じ選択と実行中の索引操作を照合する同期読取り
 * @param[in] reobserve 同じ署名元、端末の所有及び付随参照の不在を再確認する同期読取り
 * @param[in] authorize 同じ元署名レコードと実UTCの最終照合
 * @return 全照合成立で0、最初の元失敗または操作失効ならHRESULT
 * @note 各処理を同期中だけ借用する。変更作用自体は呼び出さない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyDisplayMutationBoundary(
	const std::function<bool()> &ownsOperation, const std::function<NativeError()> &reobserve,
	const std::function<NativeError()> &authorize) ;

/** @brief Type 1実行物の検索対象に入る現在の子と、その実親のWindows登録 */
struct DisplayType1DevicePath {
	/// Windowsが返した子の完全インスタンスID。worker外に公開しない
	std::wstring childInstance ;
	/// 同じ子に対するWindowsの最初のHardware ID
	std::wstring firstHardwareId ;
	/// 子の正式なクラスGUIDと4桁の登録を結ぶDriver属性
	std::wstring childDriver ;
	/// 同じ子の直接の親の完全インスタンスID
	std::wstring parentInstance ;
	/// 親の正式なクラスGUIDと4桁の登録を結ぶDriver属性
	std::wstring parentDriver ;
	/**
	 * @brief 別の読み取りで同じ現在親子を比較する
	 * @param[in] other 同じWindowsの別の観測
	 * @return 現在親子、元ID及び登録属性が一致すればtrue
	 */
	bool		 operator==( const DisplayType1DevicePath &other) const = default ;
} ;

/** @brief Type 1が読む現在PnPツリーの走査結果 */
struct DisplayType1Topology {
	/// Hardware IDの最初の値を読み、正式不在も含めて終端まで観測した機器数
	std::size_t							scannedNodes{} ;
	/// 同じツリーの検索対象すべて。インスタンスID順
	std::vector<DisplayType1DevicePath> paths ;
	/**
	 * @brief 同じ実行物の別の現在PnP観測を比較する
	 * @param[in] other 別の時点の読み取り
	 * @return 母集合の件数とすべての対象が一致すればtrue
	 */
	bool operator==( const DisplayType1Topology &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同じWindowsの現在ツリーから実行物が到達し得る子と親をすべて読む
 * @param[in] families 静的検査が確定した同じ実行物のHardware ID接頭辞
 * @param[out] topology 母集合の読み取りが完了した場合の観測。失敗時は空
 * @return 現在PnPツリーと全対象の読み取り成立時0、その他はHRESULT
 * @note 実行物と同じANSIの最初のHardware IDを使用する。署名や元機器の選択は別途確認する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readDisplayType1Topology( std::span<const std::wstring_view> families,
												   DisplayType1Topology				 &topology) ;

//------------------------------------------------------------------------------
/**
 * @brief 現在の全到達先が同じ署名の現用子と選択親に一意に一致するか確認する
 * @param[in] classes 現用クラス登録の完全な読み取り
 * @param[in] topology 同じ実行物の全候補の現在PnPツリー
 * @param[in] families 静的検査が確定した実行物のHardware ID接頭辞
 * @param[in] parentInstance 元候補が適合した現用親の完全ID
 * @param[in] childInstance 同じ候補の必須子の署名を確認した現用子の完全ID
 * @param[in] childHardwareId 同じ現用子の一意な主Hardware ID
 * @param[in] childStoreInf 同じ現用子について保護付きで読んだ署名元のStore INF絶対位置
 * @param[out] parentDriver 全照合が成立した親のWindows Driver登録名。失敗時は空
 * @return 一件のクラスとPnP子が元署名、元値と選択親に一致すれば0、それ以外はHRESULT
 * @note 操作の承認、適用、非同期実行の完了には別の条件が必要
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyDisplayType1ParentBinding(
	const DisplayType1ClassSnapshot &classes, const DisplayType1Topology &topology,
	std::span<const std::wstring_view> families, std::wstring_view parentInstance,
	std::wstring_view childInstance, std::wstring_view childHardwareId,
	std::wstring_view childStoreInf, std::wstring &parentDriver) ;
//------------------------------------------------------------------------------
/**
 * @brief 観測した型付き参照と旧マーカーを同じ署名済み子の結果へ照合する
 * @param[in] registry 同じ選択親から保護付きで取得した全対象値
 * @param[in] nativePath 同じ子の正規Driver Store内に属する64ビット元ファイルの全位置
 * @param[in] wow64Path 同じ子の正規Driver Store内に属する32ビット元ファイルの全位置
 * @return REG_SZの両位置が一致して対象旧値が不在ならtrue。欠損・別の位置・型はfalse
 * @note Windowsの実行記録やファイルの内容、適用完了は呼出側で別に確認する
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchesDisplayType1ReflectedRegistry(
	const DisplayType1RegistrySnapshot &registry, std::wstring_view nativePath,
	std::wstring_view wow64Path) noexcept ;

/** @brief 正規の共有宛先を保護付きで読む同期処理の型 */
using DisplayType1SharedFileRead =
	std::function<NativeError( std::wstring_view, bool, ProtectedExecutableSnapshot &)> ;

//------------------------------------------------------------------------------
/**
 * @brief 同じ選択の共有コピー全件の事後状態を署名済み元ファイルと照合する
 * @param[in] copies 元の必要子から取り出した重複しないコピー先と完全ハッシュ
 * @param[in] before 同じ順序で導入前に得た宛先の保護付き観測
 * @param[in] read 正規の共有宛先を同期中だけ読み取る処理
 * @return 全件の内容が元と一致して0、安定した不在または異なる内容はS_FALSE、競合や読取失敗はHRESULT
 * @note 二回の観測を照合する。以前の内容が残っていてもWindowsによる省略の確定根拠にはしない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyDisplayType1SharedCopies(
	std::span<const OfficialSoftwareComponentSharedCopy> copies,
	std::span<const ProtectedExecutableSnapshot> before, const DisplayType1SharedFileRead &read) ;

/** @brief 固定DeviceSetupManagerイベントから読み取るType 1の実行段階 */
enum class DisplayType1EventKind {
	/// 165の版0が示す元コマンドの開始
	STARTED,
	/// 160の版0が示す同じ子の実行終了
	COMPLETED,
	/// 161が示すソフトウェアの構成見送り。実行結果は示さない
	NOT_CONFIGURED,
	/// 162または163が示すWindowsの実行失敗
	FAILED,
	/// 164が示すWindows側の遅延再試行
	RETRY_PENDING,
} ;

/** @brief 同一チャネルから型を検査して取り出した一件の実行記録。worker内の同期利用に限る */
struct DisplayType1InstallEvent {
	/// 同じチャネル世代で単調増加するEventRecordID
	std::uint64_t		  record{} ;
	/// 元イベントの実行コンテキストのWindowsプロセス番号
	std::uint32_t		  process{} ;
	/// 同じコンテキストでのWindowsスレッド番号
	std::uint32_t		  thread{} ;
	/// Windowsが示す実行段階
	DisplayType1EventKind kind{} ;
	/// 元INFに記載するソフトウェア名
	std::wstring		  software ;
	/// 終了または該当する版で取得した必要子のWindows完全ID
	std::wstring		  childInstance ;
	/// 開始イベントが保持する元コマンド。ログやUIへ出力しない
	std::wstring		  command ;
	/// 型を検査したWindowsの元失敗値。該当項目なしの場合0
	NativeError			  error{} ;
} ;

/** @brief 同じ導入で照合するType 1の固定条件と事後状態 */
struct DisplayType1InstallObservation {
	/// 選択操作の変更前に固定したイベント位置。これ以前は対象外
	std::uint64_t				  afterRecord{} ;
	/// 取得の欠損なしに同じチャネルの現在位置まで読み取れた場合true
	bool						  streamIntact{} ;
	/// 署名済み子INFから取り出したソフトウェア名。同期中だけ借用する
	std::wstring_view			  software ;
	/// 同じ元実行物を固定したWindows Storeの完全位置。同期中だけ借用する
	std::wstring_view			  binary ;
	/// 元INFで検査した順序の引数。同期中だけ借用する
	std::span<const std::wstring> arguments ;
	/// 同じ親に属する必須子のWindows完全ID。同期中だけ借用する
	std::wstring_view			  childInstance ;
	/// 署名と元ファイルが一致する必須子が現用として読み取れた場合true
	bool						  childApplied{} ;
	/// 同じ親の参照値と全旧マーカーの事後状態が一致した場合true
	bool						  registryReflected{} ;
	/// 共有コピーの全宛先で保護付きの元内容が確認された場合true
	bool						  sharedFilesVerified{} ;
} ;

/** @brief Windowsの実行終了と実機への反映を別に扱うType 1の事後状態 */
enum class DisplayType1InstallState {
	/// 現位置までに元対象の開始がない、又は対応する終了がまだない
	WAITING,
	/// Windowsが同じ子の遅延再試行を記録した
	RETRY_PENDING,
	/// Windowsが同じ子の実行失敗と原値を記録した
	FAILED,
	/// 実行は終わったが、同じ子・登録値・共有先の実在確認が残っている
	REFLECTION_PENDING,
	/// 実行終了と同じ子・登録値・共有先の実在確認がそろった
	REFLECTED,
	/// 部分取得・競合・順序破綻により同じ操作へ結合できない
	UNCONFIRMED,
} ;

/** @brief Type 1事後照合の非機密な表示用状態と元診断 */
struct DisplayType1InstallResult {
	/// 指定操作に対する現在の判定
	DisplayType1InstallState state{DisplayType1InstallState::UNCONFIRMED} ;
	/// Windowsの確定失敗・再試行または読取り不能の元診断値。診断がない場合は0
	NativeError				 error{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同じ導入以後の実行記録を選択子と署名済み元実行物の事後事実へ結び付ける
 * @param[in] observation 同じ導入の変更前位置と署名・選択・現在値を同期中だけ借用する
 * @param[in] events 同じチャネル世代の対象イベント。昇順で同期中だけ借用する
 * @return 実行と反映の状態。重複起動、別対象の同名実行、未確認の順序や欠損はUNCONFIRMED
 * @note 元コマンドを実行せず、Windowsの設定、再試行、ドライバーを変更しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] DisplayType1InstallResult classifyDisplayType1Install(
	const DisplayType1InstallObservation	 &observation,
	std::span<const DisplayType1InstallEvent> events) noexcept ;

} // namespace drivercrate
