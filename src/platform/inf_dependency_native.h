//------------------------------------------------------------------------------
/**
 * @file inf_dependency_native.h
 * @brief 実INFの非実行依存観測と個別署名診断の定義
 * @version 01.16.00
 * @date 2026/10/06
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/06  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/06  封印所有者限定のnative由来入口を追加
 * Ver.01.02.00 Shunji Ogawa  2026/10/07  到達file用途と固定file累積量の独立観測を追加
 * Ver.01.03.00 Shunji Ogawa  2026/10/13  元共通内容の選択依存検査を私有factory入口へ限定
 * Ver.01.04.00 Shunji Ogawa  2026/10/15  同元選択の依存と効果へ非機密拒否診断を追加
 * Ver.01.05.00 Shunji Ogawa  2026/11/08  正規選択Include文脈と同名Needs転送を有限接続
 * Ver.01.05.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.05.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.05.03 Shunji Ogawa  2026/11/13  Needs AddRegの元拒否leafを既匿名診断へ接続
 * Ver.01.05.04 Shunji Ogawa  2026/11/13  847kの検証済みSYSTEM媒体作用と限定資格を接続
 * Ver.01.05.05 Shunji Ogawa  2026/11/13  847p9の型付きSYSTEM全作用と全選択資格を接続
 * Ver.01.06.00 Shunji Ogawa  2026/11/16  選択storageの原全作用・私有資格と通常導入経路を接続
 * Ver.01.07.00 Shunji Ogawa  2026/11/20  収集原本とWindows同梱INFの選択依存検査を追加
 * Ver.01.08.00 Shunji Ogawa  2026/11/21  元SYSを持つHDCを収集の全選択検査に追加
 * Ver.01.09.00 Shunji Ogawa  2026/11/21  Windows標準シリアルページの固定証拠を共有
 * Ver.01.10.00 Shunji Ogawa  2026/11/22  仮想Wi-Fiバスの端末フィルター置換を非実行観測へ保持
 * Ver.01.11.00 Shunji Ogawa  2026/11/22  公式Net選択の同梱仮想Wi-Fiバスを収集から検査
 * Ver.01.12.00 Shunji Ogawa  2026/11/22  公式Netの同梱依存の比較用証拠を追加
 * Ver.01.13.00 Shunji Ogawa  2026/11/23  自動起動ストレージの現用機器読取りを接続
 * Ver.01.14.00 Shunji Ogawa  2026/11/23  現用署名元と現在構成の再観測結果を比較
 * Ver.01.15.00 Shunji Ogawa  2026/11/24  公式USB Bluetoothの元選択と収集依存の検査入口を追加
 * Ver.01.16.00 Shunji Ogawa  2026/11/24  混在シリアルの二選択を同じ同梱観測へ結ぶ
 * </pre>
 *
 * @note Workerで同期借用し、実device、実行command、導入許可を扱わない
 * @see docs/adr/0270-read-only-inf-dependency-native-adapter.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/inf_dependency_plan.h"
#include "platform/official_file_verifier.h"
#include "platform/system_inf_effects_internal.h"
#include "platform/storage_inf_effects_internal.h"
#include <functional>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
class OfficialDownloadWorkspace ;
class OfficialAcquisitionSession ;
class OfficialInfArchiveBinding ;
struct CommonInfInspection ;
struct OfficialDriverClosure ;
struct OfficialInfInstallInventory ;
struct OfficialInfPackage ;
struct OfficialZipEntry ;

/** @brief 元作用の検査後に同じ選択機器の現用登録・現在構成を保持する同期操作 */
using StorageRegisteredDeviceRead = std::function<NativeError( const SelectedStorageServiceFacts &,
															  StorageAutomaticDeviceSnapshot &)> ;
class RequiredDriverComponentPlan ;
struct RequiredInfBindingDiagnostic ;

//------------------------------------------------------------------------------
/**
 * @brief 現Windowsの標準シリアルページDLLをロードせず検査する
 * @param[in] workspace 元配布物を所有する保護領域
 * @param[out] proof 固定DLLとWindows署名、保護の全証拠。失敗時は空
 * @return 正規System32、Windows署名、同じバイトのAMD64 exportが成立すれば0
 * @note 固定DLLだけを検査する。元INFの選択や導入可否は呼び出し元で確認する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectWindowsSerialPropertyPage(
	const OfficialDownloadWorkspace &workspace, WindowsSystemFileTrust &proof) ;

/** @brief Needs/AddRegの最初の拒否地点です。既binding stageへだけ投影します */
enum class NeedsAddRegDiagnosticStage : std::uint32_t {
	/// 未到達又は未対応の設置文脈です。observedは元context bitです
	CONTEXT = 12100U,
	/// 参照数が0又は64超です。observedは65で飽和した件数です
	REFERENCE_COUNT = 12101U,
	/// 呼出し前の累積行数が過大です。observedは4097で飽和します
	INITIAL_ROW_BUDGET = 12102U,
	/// 参照節名の読取失敗です。observedは1始まりの参照位置です
	SECTION_NAME_READ = 12103U,
	/// 読めた参照節名が不正です。observedは1始まりの参照位置です
	SECTION_NAME = 12104U,
	/// 未採用security節があります。observedは4097で飽和した行数です
	SECURITY_DECLARATION = 12105U,
	/// security節の不在照会が元API errorで失敗しました。observedは0です
	SECURITY_READ = 12106U,
	/// 参照節行数が読めず、元方針でSECTION_NOT_FOUNDを返します。observedは0です
	SECTION_ROWS = 12107U,
	/// 全参照節の累積行数が過大です。observedは4097で飽和した予定行数です
	ROW_BUDGET = 12108U,
	/// 一つの設定行の読取失敗です。observedは1始まりの行位置です
	ROW_READ = 12109U,
	/// 設定field数がHKRの3～5又は検証済みSYSTEMの3～20を外れました。observedは元契約の6で飽和します
	FIELD_COUNT = 12110U,
	/// 設定fieldの読取失敗です。observedは元位置で最大20です
	FIELD_READ = 12111U,
	/// 検証済みSYSTEM例外を持たないHKR以外のrootです。root文字列は保持せずobservedは0です
	ROOT = 12112U,
	/// 相対subkeyのcomponentが不正です。文字列は保持せずobservedは0です
	SUBKEY_COMPONENT = 12113U,
	/// subkey末尾separatorを拒否しました。observedは0です
	SUBKEY_TRAILING_SEPARATOR = 12114U,
	/// 別作用の組込み特殊値です。observedは元固定配列の1～9です
	SPECIAL_VALUE = 12115U,
	/// 元flags数値parserが失敗しました。元E_INVALIDARGとobserved0を保持します
	FLAGS_PARSE = 12116U,
	/// 未採用flagsです。observedは元SDK flag bitmaskです
	FLAGS = 12117U,
	/// DWORDのfield不足又は元数値parser失敗です。データを出さずobservedはfield数です
	DWORD_VALUE = 12118U,
	/// 未照合program参照です。observedはexe1/dll2/sys3/com4の固定区分です
	PROGRAM_REFERENCE = 12119U,
	/// SYSTEM媒体登録のroot下scopeが未採用です。observedは0です
	SYSTEM_SCOPE = 12120U,
	/// SYSTEM媒体データの値種類/型/byte数が不正です。observedはfield数です
	SYSTEM_TYPE = 12121U,
	/// 固定Windows登録の完全な文法/引数が不正です。observedは0です
	SYSTEM_REGISTRATION = 12122U,
	/// 同原SYSTEM documentのinterface作用が未充足です。observedは0です
	SYSTEM_INTERFACE = 12123U,
	/// 固定Windows helperの元trust/権限/不変tupleが不成立です。observedは0です
	SYSTEM_HELPER = 12124U,
} ;

/** @brief 抽出済みpackage INFの固定member。公式取得由来の証明ではない */
struct InfDependencyPackageMember {
	/// 保護workspace内の有限ASCII相対INF位置
	std::wstring  relativePath ;
	/// 抽出器で固定した小文字SHA-256
	std::wstring  sha256 ;
	/// 1～4 MiBの実INF size
	std::uint64_t byteCount{} ;
} ;

/** @brief 一documentの署名／由来に付いた元診断。包括的不適合ではない */
struct InfDependencyNativeFinding {
	/// 共通graph内の一意document identity
	std::uint64_t identity{} ;
	/// 署名不足の元HRESULT。検査合格の場合0
	NativeError	  signatureError{} ;
	/// system由来照合の元HRESULT。未検査または合格では0の場合がある
	NativeError	  provenanceError{} ;
} ;

/** @brief 到達INFの具体的file用途。payload位置・byte・署名は未検査 */
struct InfDependencyNativeFileUse {
	/// 同runの原document identity
	std::uint64_t identity{} ;
	/// 原明示節名。worker内だけに保持する
	std::wstring  section ;
	/// 元file用途または未解釈宣言名
	std::wstring  directive ;
	/// 展開後の原参照値。位置を推測せず、UI／logへ渡さない
	std::wstring  target ;
} ;

/** @brief 依存検査で保持した原fileの私有不変tupleです */
struct InfDependencyFixedFile {
	/// 同同期で固定した完全位置です。一般logへ出しません
	std::wstring	   path ;
	/// 保持した原fileの完全SHA-256です
	std::wstring	   sha256 ;
	/// 原fileの有限byte数です
	std::uint64_t	   bytes{} ;
	/**
	 * @brief 元計画と再検証の原file tupleを全fieldで比較します
	 * @param[in] other 同選択から再構築した独立tupleです
	 * @return 完全一致ならtrueです
	 */
	[[nodiscard]] bool operator==( const InfDependencyFixedFile &other) const = default ;
} ;

/** @brief 実byteへ結合した非実行観測。型は導入用計画と互換でない */
struct InfDependencyNativeResult {
	/// appの同原storage全作用だけです。内容/通常DTOから資格には変換しません
	std::optional<StorageInfEffects>		storageEffects ;
	/// 同OS・同runへ結合した共通依存graph
	InfDependencyResult						dependency ;
	/// 全発見documentの署名／由来診断
	std::vector<InfDependencyNativeFinding> findings ;
	/// 到達節・Version／sourceの最大4,096用途。空でも全payload検査の証明ではない
	std::vector<InfDependencyNativeFileUse> fileUses ;
	/// 一runで固定したINF／CAT／Store file数。最大256、全体失敗時0
	std::size_t								fixedFileCount{} ;
	/// 同じ固定fileの累積byte。最大128 MiB、全体失敗時0
	std::uint64_t							fixedByteCount{} ;
	/// 元INF/Store/CAT/追加固定fileの全tupleです。権限の代用にはしません
	std::vector<InfDependencyFixedFile>		fixedFiles ;
	/// 標準Windows登録を要する場合だけの原helper/CAT/権限tupleです
	std::vector<WindowsSystemFileTrust>		systemFiles ;
	/// 同原文の型/文脈/所有者/全fieldを導入直前まで完全比較します
	std::vector<SystemInfEffect>			systemEffects ;
	/// 必要だった既存serviceの安定config/元SDです
	std::vector<SystemServiceEvidence>		systemServices ;
	/// 元選択が端末の上位フィルターを単一の仮想Wi-Fiバスへ置換する場合trueです
	bool									replacesWifiBusUpperFilters{} ;
	/// 固定SWENUM登録が実際に成立した場合だけtrueです
	bool									delayedRegistration{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 相対member位置と絶対local DOS位置の構文を検査する
 * @param[in] path 原位置。正規化やfilesystem探索を行わない
 * @param[in] absolute trueの場合は通常のdrive絶対path、falseの場合はASCII相対path
 * @return 構文合格の場合true。実path認証ではない
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool		  validInfDependencyPath( std::wstring_view path, bool absolute) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 保護packageと現在WindowsのINFを共通核へ非実行接続する
 * @param[in] workspace 全package memberを呼出し終了まで所有する保護領域
 * @param[in] members 全抽出INFの閉じた固定一覧。1～64件、重複を禁止する
 * @param[in] rootIndex members内の開始INF位置
 * @param[in] seeds 同じroot内の明示節群。作用完全性を認定しない
 * @param[in] observationId 非零のworker内観測世代
 * @param[out] result 全再確認成功時だけ保持し、全体失敗では空
 * @return 観測完了0、不正入力・path・改変・OS差・容量・例外のHRESULT
 * @pre 入力と出力の所有storageはaliasしない。同期workerで呼び、再入しない
 * @note Packageの公式由来は未検査に固定する。署名成功を由来・導入許可へ流用しない。OS trustがrevocation照会する場合がある。scan・staging・device導入
 *       は行わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectNativeInfDependencies(
	const OfficialDownloadWorkspace &workspace, std::span<const InfDependencyPackageMember> members,
	std::size_t rootIndex, std::span<const std::wstring> seeds, std::uint64_t observationId,
	InfDependencyNativeResult &result) ;

//------------------------------------------------------------------------------
/**
 * @brief 収集原本の選択節からWindows同梱の依存またはHDCの元SYSと全作用を検査する
 * @param[in] workspace 収集した原閉包の実ファイルを同期呼出し中所有する領域
 * @param[in] closure 元アーカイブから抽出し、各INFと宣言CATの内容検査を終えた閉包
 * @param[in] archiveEntries 抽出前に確認した同じアーカイブ階層の全通常ファイル一覧
 * @param[in] seeds AMD64 Modelsで選択した実基本節と実在する同名のHW・Services節
 * @param[in] selectedBase 元選択の実基本節名。seedsの先頭と一致する
 * @param[in] observationId 原収集の非零scan session ID
 * @return 全参照の所有元、署名、作用と同OSでの終了再検査が成立すれば0、失敗はHRESULT
 * @note 同期結果は収集内容だけに適用し、端末の選択や導入許可を発行しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectCollectorInfDependencies(
	const OfficialDownloadWorkspace &workspace, const OfficialDriverClosure &closure,
	std::span<const OfficialZipEntry> archiveEntries, std::span<const std::wstring> seeds,
	std::wstring_view selectedBase, std::uint64_t observationId) ;

//------------------------------------------------------------------------------
/**
 * @brief 混在シリアル媒体の二つの元選択で、同じ同梱ファイルとサービスの成立を確認する
 * @param[in] workspace 元INF、CAT、SYSとDLLを保持する現在userの私有検査領域
 * @param[in] closure 元媒体の全構造と署名、元DLLのexportを確認した一基本INFの閉包
 * @param[in] archiveEntries 審査済み元書庫の同じ四項目とそれぞれのSHA-256
 * @param[in] observationId 原収集の非零scan session ID
 * @return 両選択で元配布と同じ同梱根拠が成立した場合0、読取りや途中変化はHRESULT
 * @note Windows側の読取り専用検査。現在のデバイス選択や導入許可は扱わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectCollectorSerialEnumeratorDependencies(
	const OfficialDownloadWorkspace &workspace, const OfficialDriverClosure &closure,
	std::span<const OfficialZipEntry> archiveEntries, std::uint64_t observationId) ;

//------------------------------------------------------------------------------
/**
 * @brief 同じ元CABで確認した公式USB Bluetoothの選択を全参照と終端再検査へ結ぶ
 * @param[in] workspace 同期中に元CABの展開データを所有する領域
 * @param[in] closure 元INFとCATを検査済みの一つのBluetooth閉包
 * @param[in] archiveEntries 同じ元CABの全通常ファイル
 * @param[in] selected 元INFから同じ公式Models範囲を読んだ一つの選択棚卸し
 * @param[in] observationId 収集処理の非零の観測世代
 * @return 元選択とすべての参照・作用が終端まで一致して0、読取や不一致はHRESULT
 * @note 同じCABから得た署名証拠を前提に、収集内容だけを検査する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectScopedBluetoothUsbDependencies(
	const OfficialDownloadWorkspace &workspace, const OfficialDriverClosure &closure,
	std::span<const OfficialZipEntry> archiveEntries, const OfficialInfInstallInventory &selected,
	std::uint64_t observationId) ;

/** @brief 公式Netの一選択で確認した仮想Wi-Fiバスの比較用証拠 */
struct ScopedWifiBusDependencyEvidence {
	/// 同じ元INF・CAT・Storeに固定した全ファイルの位置と元バイト
	std::vector<InfDependencyFixedFile> fixedFiles ;
	/// 正規Windowsファイルと元署名・保護の一致証拠
	std::vector<WindowsSystemFileTrust> systemFiles ;
	/// 同梱文書から到達した元作用の文脈と全フィールド
	std::vector<SystemInfEffect>		systemEffects ;
	/// 現在の同梱サービスの全設定とアクセス制御
	std::vector<SystemServiceEvidence>	systemServices ;
	/**
	 * @brief 同じ公式選択の同梱ファイル・作用・現サービスを全値で比較する
	 * @param[in] other 独立に取得し直した同梱依存の証拠
	 * @return 全値が一致する場合true
	 */
	[[nodiscard]] bool operator==( const ScopedWifiBusDependencyEvidence &other) const = default ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 一つの公式Net選択から実解決した全仮想Wi-Fiバス参照と現状態を確認する
 * @param[in] workspace 同じ原アーカイブから展開した保護閉包の領域
 * @param[in] closure 原CATと全参照を確認した一つの公式Net基本INF
 * @param[in] archiveEntries 元CABの同じ容器内の全通常ファイル。部分展開一覧は不可
 * @param[in] selected 同じ元INFバイトから読んだ実導入節と付随節の棚卸し
 * @param[in] observationId 現workerの非零の観測世代
 * @param[out] evidence 非nullの場合、全確認後だけ元観測を返す。失敗時は空
 * @return 全元参照、同梱署名・Storeと現サービスが一致すれば0、失敗はHRESULT
 * @pre 端末側では呼出し側が公式レコードと現在の実選択を確定する
 * @note 読取り専用。元端末と導入資格は発行しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectScopedWifiBusDependencies(
	const OfficialDownloadWorkspace &workspace, const OfficialDriverClosure &closure,
	std::span<const OfficialZipEntry> archiveEntries, const OfficialInfInstallInventory &selected,
	std::uint64_t observationId, ScopedWifiBusDependencyEvidence *evidence = nullptr) ;

/** @brief 封印所有者だけが呼べるnative接続。公開boolや任意callbackを認証にしない */
class AcquiredInfNativeAccess final {
private:
	friend class OfficialInfArchiveBinding ;
	/**
	 * @brief 使用中固定した封印集合を同じnative loaderへ渡す
	 * @param[in] binding 同期使用中固定を所有する封印結果
	 * @param[in] session 元証拠の生存issuer
	 * @param[in] archiveWorkspace 元取得領域
	 * @param[in] rootIndex 全INF内の開始位置
	 * @param[in] seeds 明示節群
	 * @param[in] observationId 非零の観測世代
	 * @param[out] result 全成功時だけの非実行結果
	 * @return 完了0、最初の検証／API／例外のHRESULT
	 * @pre 呼出し元が元／派生全fileを呼出し終了まで固定する
	 */
	[[nodiscard]] static NativeError inspect( const OfficialInfArchiveBinding  &binding,
											 const OfficialAcquisitionSession &session,
											 const OfficialDownloadWorkspace  &archiveWorkspace,
											 std::size_t					   rootIndex,
											 std::span<const std::wstring>	   seeds,
											 std::uint64_t					   observationId,
											 InfDependencyNativeResult		  &result) ;
} ;
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
namespace test {
struct InfDependencyNativeTestApi ;
//------------------------------------------------------------------------------
/**
 * @brief 専用compileの架空APIで実Common私有入口を一同期検査します
 * @param[in] api 既存の必須五callbackです
 * @param[in] inspected このfixtureだけの原内容です
 * @param[in] selected 実readerが再解析する元選択です
 * @param[out] result 成功時だけの元graphです
 * @param[out] diagnostic 元数値の任意出力です
 * @return Common入口の未変更HRESULTです
 * @note 通常製品にはこの宣言/入口を含めません
 */
//------------------------------------------------------------------------------
NativeError inspectCommonInfDependenciesWithTestApi( const InfDependencyNativeTestApi &api,
													const CommonInfInspection		 &inspected,
													const OfficialInfPackage		 &selected,
													InfDependencyNativeResult		 &result,
													RequiredInfBindingDiagnostic	 *diagnostic) ;
}
#endif

/** @brief 実内容factoryだけが呼べる選択節依存と効果の検査です */
class CommonInfNativeAccess final {
private:
#ifdef DRIVERCRATE_INF_DEPENDENCY_TESTING
	/**
	 * @brief 専用compileの架空APIで実Common私有入口を一同期検査します
	 * @note 第1引数（const test :: InfDependencyNativeTestApi &、in）はこの宣言では無名です。既存の必須五callbackです
	 * @note 第2引数（const CommonInfInspection &、in）はこの宣言では無名です。このfixtureだけの原内容です
	 * @note 第3引数（const OfficialInfPackage &、in）はこの宣言では無名です。実readerが再解析する元選択です
	 * @note 第4引数（InfDependencyNativeResult &、out）はこの宣言では無名です。成功時だけの元graphです
	 * @note 第5引数（RequiredInfBindingDiagnostic *、out）はこの宣言では無名です。元数値の任意出力です
	 * @return Common入口の未変更HRESULTです
	 * @note 通常製品にはこの宣言/入口を含めません
	 */
	friend NativeError test::inspectCommonInfDependenciesWithTestApi(
		const test::InfDependencyNativeTestApi &, const CommonInfInspection &,
		const OfficialInfPackage &, InfDependencyNativeResult &, RequiredInfBindingDiagnostic *) ;
#endif
	/**
	 * @brief 実検査した元基本INF閉包から必要役割の関係を構築します
	 * @note 第1引数（const CommonInfInspection &、in）はこの宣言では無名です。元保護byteと全署名を保持する同workerの内容検査です
	 * @note 第2引数（std :: span < const OfficialInfPackage >、in）はこの宣言では無名です。baseと全importの元順copyです。選択機能
	 *       関係は私有native nodeから解析します
	 * @note 第3引数（std :: shared_ptr < const RequiredDriverComponentPlan > &、out）はこの宣言では無名です。成功時だけ元閉包
	 *       へ結合した不変計画です。失敗時は空です
	 * @note 第4引数（RequiredInfBindingDiagnostic *、out）はこの宣言では無名です。任意の数値診断です。nullなら採取せず合否へ使用しません
	 * @note 第5引数（const StorageRegisteredDeviceRead *、in）はこの宣言では無名です。nullまたは同じ選択機器の読取操作です
	 * @return 内容と関係の一意な確認0、未対応・欠損・曖昧・循環は元HRESULTです
	 * @note 計画は内容関係だけで、同意・復旧・PnP・私有install bindingを代替しません
	 */
	friend NativeError makeRequiredDriverComponentPlan(
		const CommonInfInspection &, std::span<const OfficialInfPackage>,
		std::shared_ptr<const RequiredDriverComponentPlan> &, RequiredInfBindingDiagnostic *,
		const StorageRegisteredDeviceRead *) ;
	/**
	 * @brief 元内容を前後確認し、選択節の全Needs効果を検査します
	 * @param[in] inspected 元保護byteと全署名を所有する内容です
	 * @param[in] selected 同元packageの私有node選択copyです
	 * @param[out] result 非実行graphです。効果は独立に検査します
	 * @param[out] diagnostic 任意の非機密数値です。合否を変更する入力ではありません
	 * @param[in] registeredDeviceRead 同じ選択機器の現用登録を読取する同期操作。指定しない場合はnull
	 * @return 全依存と有限効果の充足0、未観測・未知・不合格のHRESULTです
	 */
	[[nodiscard]] static NativeError inspect(
		const CommonInfInspection &inspected, const OfficialInfPackage &selected,
		InfDependencyNativeResult &result, RequiredInfBindingDiagnostic *diagnostic,
		const StorageRegisteredDeviceRead *registeredDeviceRead = nullptr) ;
} ;
} // namespace drivercrate
