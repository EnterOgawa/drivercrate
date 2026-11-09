//------------------------------------------------------------------------------
/**
 * @file local_diagnostic_log.cpp
 * @brief 匿名診断を非reparseのEXE隣へ有界保存します。
 * @version 01.04.02
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
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  固定2slotと有界queueで自動local診断を保存。
 * Ver.01.01.00 Shunji Ogawa  2026/11/03  取得前の版比較分類件数を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/11/08  匿名導入診断と保存状態・元数値の有限確認を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/11/08  準備不成立後の元表示保持と段階別匿名診断を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/11/08  元checkbox意図の表示保持とbinding拒否の固定診断を接続。
 * Ver.01.04.01 Shunji Ogawa  2026/11/09  開始時pauseと元wakeによる一方向再開・停止解除を接続。
 * Ver.01.04.02 Shunji Ogawa  2026/11/09  最終pathの同容量bufferをheapへ移しstack使用を抑制。
 * </pre>
 * @note I/Oは専用workerだけです。未知file・linkを置換せず保存不能は診断だけを停止します。
 * @see docs/adr/0427-local-anonymous-scan-diagnostics.md
 */
//------------------------------------------------------------------------------
#include "platform/local_diagnostic_log.h"
#include "core/provider_registry.h"
#include "platform/inf_dependency_native.h"
#include "drivercrate_version.h"
#include <Windows.h>
#include <algorithm>
#include <atomic>
#include <charconv>
#include <string>
#include <thread>
#include <vector>

namespace drivercrate {
namespace {
// 既知fileだけを再利用する所有markerとwire版です。
constexpr std::string_view HEADER =
	"# DriverCrate anonymous diagnostics v1 app=" DRIVERCRATE_VERSION_STRING "\n" ;
constexpr std::size_t FILE_LIMIT  = 256U * 1024U ;	// 固定slot一つのbyte上限です。
constexpr std::size_t QUEUE_LIMIT = 256U ;			// UIが保持する記録数の上限です。
constexpr std::size_t LINE_LIMIT  = 2048U ;			// 一snapshotのUTF-8 byte上限です。
constexpr std::array  EVENT_NAMES{					// 記録地点の閉じた文字列です。
								  "startup",
								  "operation_started",
								  "scan_completed",
								  "provider_scan",
								  "index_refresh",
								  "index_store",
								  "index_scan",
								  "index_lookup",
								  "preparation_plan",
								  "candidate_display",
								  "candidate_reasons",
								  "operation_completed",
								  "queue_dropped",
								  "provider_configuration",
								  "install_requested",
								  "install_started",
								  "preparation_operation",
								  "install_item",
								  "install_role",
								  "post_install",
								  "install_protection",
								  "preparation_target",
								  "preparation_resolution",
								  "preparation_continuation"} ;
constexpr std::array  FIELD_NAMES{	// 任意本文を受けない閉じた列名です。
								  "elevationKnown",
								  "elevated",
								  "state",
								  "succeeded",
								  "outcome",
								  "known",
								  "enabled",
								  "total",
								  "processed",
								  "remaining",
								  "httpStatus",
								  "sends",
								  "receivedBytes",
								  "httpError",
								  "manifestStatus",
								  "assetStatus",
								  "recordsStatus",
								  "attemptedGeneration",
								  "persistedGeneration",
								  "generationKnown",
								  "commit",
								  "usableSnapshot",
								  "usedCache",
								  "cacheGeneration",
								  "cacheGenerationKnown",
								  "storeStatus",
								  "lookupStatus",
								  "relations",
								  "relatedDevices",
								  "matched",
								  "nonUnique",
								  "undetermined",
								  "partialPositive",
								  "resolverCalls",
								  "planPresent",
								  "targets",
								  "indexTargets",
								  "unavailable",
								  "capacityRejected",
								  "current",
								  "installable",
								  "recommended",
								  "initialReferences",
								  "pendingReferences",
								  "nonInitialReferences",
								  "recommendedFilter",
								  "visibleDevices",
								  "updates",
								  "reinstalls",
								  "downgrades",
								  "initialInstalls",
								  "applicabilityPending",
								  "applicabilityRejected",
								  "osRejected",
								  "eligible",
								  "assessed",
								  "measurementAccepted",
								  "registeredReferences",
								  "unknownPresenceReferences",
								  "recommendedInstallable",
								  "newerReferences",
								  "sameReferences",
								  "olderReferences",
								  "unknownVersionReferences",
								  "ordinal",
								  "stage",
								  "action",
								  "downloadOutcome",
								  "downloadError",
								  "installOutcome",
								  "installError",
								  "handoff",
								  "handoffOutcome",
								  "handoffError",
								  "rebootRequired",
								  "reflection",
								  "diagnosticMissing",
								  "bound",
								  "presence",
								  "nodeRead",
								  "driverKeyRead",
								  "versionRead",
								  "problemKnown",
								  "problemCode",
								  "requestVersionRelation",
								  "beforeVersionRelation",
								  "intentCount",
								  "readyCount",
								  "codeKnown",
								  "selectedCount",
								  "omitted",
								  "parsedCount",
								  "signatureRejectedCount",
								  "bindingPath",
								  "bindingRejection",
								  "bindingObserved",
								  "bindingStage",
								  "bindingFlags",
								  "dependencyReason",
								  "rootSignatureError",
								  "dependencySignatureError",
								  "dependencyProvenanceError"} ;
static_assert( FIELD_NAMES.size() ==
			  static_cast<std::size_t>( DiagnosticField::DEPENDENCY_PROVENANCE_ERROR) + 1U) ;
static_assert( EVENT_NAMES.size() ==
			  static_cast<std::size_t>( DiagnosticEvent::PREPARATION_CONTINUATION) + 1U) ;

/** @brief 無効値を除く単一Windows handleを閉じます。 */
struct HandleCloser {
	/** @brief 所有handleだけを解放します。
     * @param[in] handle 所有値または無効値。
     */
	void operator()( void *handle) const noexcept
	{
		// 未取得値にCloseHandleを呼びません。
		if( handle && handle != INVALID_HANDLE_VALUE) {
			CloseHandle( handle) ;
		}
	}
} ;
/** @brief 保存worker内の単独handle所有。 */
using Handle = std::unique_ptr<void, HandleCloser> ;
LocalDiagnosticLog processLog ;	// 通常Mainの開始後だけ投入されるprocess所有loggerです。

/** @brief 任意入力でなくcanonical static IDだけをASCIIへ変換します。
 * @param[in] provider Registry発行token。
 * @return ASCIIの固定Provider ID。
 */
std::string		   providerName( const DiagnosticProvider &provider)
{
	std::string name ;	// Static IDの有限copyだけです。
	// Registryのstable IDはASCII小文字/数字/hyphenに限定されています。
	for( const wchar_t character : provider.id()) {
		name.push_back( static_cast<char>( character)) ;
	}

	return name ;
}

/** @brief Provider列が固定literalまたはcanonical registryのIDか確認します。
 * @param[in] value 保存済みfileの有限token。
 * @return 任意文字列でない場合true。
 */
bool validProviderName( const std::string_view value)
{
	// Application/unknownはloggerの固定tokenです。
	if( value == "application" || value == "unknown") {
		return true ;
	}

	// 任意長文字列を確保・registry照合しません。
	if( value.empty() || value.size() > 96U) {
		return false ;
	}

	const std::wstring wide( value.begin(), value.end()) ;	// 有限のASCII候補だけです。
	return findProviderDescriptor( wide) != nullptr ;
}

/** @brief 完全な整数tokenだけを受けます。
 * @param[in] value 終端を除く一token。
 * @param[in] signedValue HRESULTだけ符号を許します。
 * @return Overflowやsuffixのない整数の場合true。
 */
bool validNumber( const std::string_view value, const bool signedValue)
{
	// 空tokenを0へ補いません。
	if( value.empty()) {
		return false ;
	}

	const char *last = value.data() + value.size() ;	// From_charsの有限終端です。
	// HRESULTの符号だけは元値を保持します。
	if( signedValue) {
		std::int32_t number{} ;													// 検証だけの受信値です。
		const auto	 result = std::from_chars( value.data(), last, number) ;	// 全token解析結果です。
		return result.ec == std::errc{} && result.ptr == last ;
	}

	std::uint64_t number{} ;												// Count/enum/UTCの受信値です。
	const auto	  result = std::from_chars( value.data(), last, number) ;	// 全token解析結果です。
	return result.ec == std::errc{} && result.ptr == last ;
}

/** @brief 所有markerだけでなく全行の閉じた形式を確認します。
 * @param[in] bytes 256KiB以内の元file。
 * @return 全行がloggerの型付き形式である場合true。
 */
bool validOwnedBytes( std::string_view bytes)
{
	// 不明・旧版・途中headerを上書きしません。
	if( !bytes.starts_with( HEADER)) {
		return false ;
	}

	bytes.remove_prefix( HEADER.size()) ;
	// 全保存行を有限に検証し、部分writeも未知fileとして保持します。
	while( !bytes.empty()) {
		const auto end = bytes.find( '\n') ;	// 一行終端です。
		// 切詰め行や過大行を所有へ変換しません。
		if( end == std::string_view::npos || end > LINE_LIMIT) {
			return false ;
		}

		std::string_view line = bytes.substr( 0U, end) ;	// 当該行だけの借用です。
		bytes.remove_prefix( end + 1U) ;
		std::size_t count{} ;	// 必須6列と最大16個の数値列です。
		// 空白区切りの列名/値を既知表と整数文法へ照合します。
		while( !line.empty()) {
			const auto space = line.find( ' ') ;			// 当該tokenの終端です。
			const auto token = line.substr( 0U, space) ;	// 終端なしtokenです。
			const auto equal = token.find( '=') ;			// 固定名と整数の境界です。
			// 名前のない任意本文を認めません。
			if( equal == std::string_view::npos || ++count > 22U) {
				return false ;
			}

			const auto			 key   = token.substr( 0U, equal) ;		// 照合専用の列名です。
			const auto			 value = token.substr( equal + 1U) ;	// 有限値です。
			constexpr std::array PREFIX{"utcMs",	 "event",  "provider",
										"operation", "status", "error"} ;	// 必須列順です。
			// 任意のprefixや列順から所有を推定しません。
			if( count <= PREFIX.size() && key != PREFIX[count - 1U]) {
				return false ;
			}

			// Eventは固定表だけです。
			if( key == "event") {
				// 未知event名を所有fileの根拠へ使いません。
				if( std::ranges::find( EVENT_NAMES, value) == EVENT_NAMES.end()) {
					return false ;
				}
			}
			// Providerはcanonical表からだけです。
			else if( key == "provider") {
				// Registry由来でない本文をProvider名として再利用しません。
				if( !validProviderName( value)) {
					return false ;
				}
			}
			// 数値以外の本文を受けず、追加列名も閉じた表へ照合します。
			else if( !validNumber( value, key == "error" || key == "status") ||
					(count > PREFIX.size() &&
					 std::ranges::find( FIELD_NAMES, key) == FIELD_NAMES.end())) {
				return false ;
			}

			// 最後のtokenでは同じlineを再解析しません。
			if( space == std::string_view::npos) {
				break ;
			}

			line.remove_prefix( space + 1U) ;
		}

		// Headerだけの不明行を所有へ取り込みません。
		if( count < 6U) {
			return false ;
		}
	}

	return true ;
}

/** @brief 実通常位置を固定してlinkとrenameを拒否します。
 * @param[in] path 検証済み絶対DOS位置。
 * @param[in] directory Directoryまたは通常fileの期待。
 * @param[in] access 必要最小のaccess mask。
 * @param[in] creation CREATE_NEWまたはOPEN_EXISTING。
 * @param[out] error 元API失敗のcode、policy拒否は0です。
 * @param[out] errorKnown 元API直後のcodeを取得した場合trueです。
 * @return 同最終位置の所有handle。拒否時は無効handleです。
 * @throws std::bad_alloc 実位置bufferを確保できない場合。既workerのRESOURCE捕捉へ渡します。
 */
Handle openPinned( const std::wstring &path, const bool directory, const DWORD access,
				  const DWORD creation = OPEN_EXISTING, DWORD *error = nullptr,
				  bool *errorKnown = nullptr)
{
	// 0はpolicy拒否であり、古いLastErrorを元API失敗へ補完しません。
	if( error) {
		*error = 0U ;
	}

	// Policy拒否とAPIの診断欠落0を区別します。
	if( errorKnown) {
		*errorKnown = false ;
	}

	Handle					   handle( CreateFileW(
		path.c_str(), access, directory ? FILE_SHARE_READ | FILE_SHARE_WRITE : FILE_SHARE_READ,
		nullptr, creation,
		FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0U),
		nullptr)) ;						// Rename/writeを共有しません。
	BY_HANDLE_FILE_INFORMATION info{} ;	// 実種別とhardlink数です。
	// 共通file固定と同じ実handle規則を使用します。
	if( handle.get() == INVALID_HANDLE_VALUE) {
		// CreateFile失敗直後の元codeだけを保持します。
		if( error) {
			*error = GetLastError() ;
		}

		// API失敗直後の0も実取得した値です。
		if( errorKnown) {
			*errorKnown = true ;
		}

		return {} ;
	}

	// 取得した通常handleの属性照会失敗を元codeで区別します。
	if( !GetFileInformationByHandle( handle.get(), &info)) {
		// 属性照会失敗直後の元codeです。
		if( error) {
			*error = GetLastError() ;
		}

		// API直後の観測を保持します。
		if( errorKnown) {
			*errorKnown = true ;
		}

		return {} ;
	}

	// 非disk/reparse/種別/link差はpolicy拒否です。
	if( GetFileType( handle.get()) != FILE_TYPE_DISK ||
	   (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U ||
	   ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) != directory ||
	   (!directory && info.nNumberOfLinks != 1U)) {
		return {} ;
	}

	std::wstring actual( 32768U, L'\0') ;	// 同容量をheapで零初期化し実位置の有限上限を保ちます。
	const DWORD	 length =
		GetFinalPathNameByHandleW( handle.get(), actual.data(), static_cast<DWORD>( actual.size()),
								  FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) ;	// 正規実位置です。
	// 元path照会失敗だけにcodeを付けます。
	if( length == 0U && error) {
		*error = GetLastError() ;
		// 長さ0のAPI失敗だけをknownにします。
		if( errorKnown) {
			*errorKnown = true ;
		}
	}

	// 別名やreparse経由の成功を元絶対位置への成功にしません。
	if( length < 4U || length >= actual.size() ||
	   std::wstring_view( actual.data(), 4U) != L"\\\\?\\" ||
	   CompareStringOrdinal( actual.data() + 4U, static_cast<int>( length - 4U), path.data(),
							static_cast<int>( path.size()), TRUE) != CSTR_EQUAL) {
		return {} ;
	}

	return handle ;
}

/** @brief 固定2slotだけを扱うworker専用の保存所有。 */
struct FileSink {
	/// 最初の保存不能段階です。成功slotがあれば非致命拒否は破棄します。
	DiagnosticStorageStage failure{DiagnosticStorageStage::NONE} ;
	/// 元API code。policy拒否は0です。
	DWORD				   error{} ;
	/// 元API直後のcodeを取得しました。
	bool				   errorKnown{} ;
	/** @brief 最初の失敗だけを保持します。
	 * @param[in] stage 固定段階。
	 * @param[in] code 元API code、またはpolicy拒否の0。
	 * @param[in] known 元API直後のcodeを取得した事実です。
	 * @return 常にfalseです。
	 */
	bool reject( const DiagnosticStorageStage stage, const DWORD code = 0U, const bool known = false)
	{
		// 最初の失敗を後続の照会で上書きしません。
		if( failure == DiagnosticStorageStage::NONE) {
			failure	   = stage ;
			error	   = code ;
			errorKnown = known ;
		}

		return false ;
	}
	/// EXE祖先とlogをrename不可のまま保持します。
	std::vector<Handle>			   pins ;
	/// 固定2fileの通常handleだけです。
	std::array<Handle, 2U>		   slots ;
	/// 作成/更新時刻の比較値です。
	std::array<ULARGE_INTEGER, 2U> modified{} ;
	/// 現slotの実保持byte数です。
	std::size_t					   size{} ;
	/// 0/1または無効値2です。
	std::size_t					   active{2U} ;

	/** @brief EXE祖先とlogを固定し、所有形式のslotだけを開きます。
     * @param[in] folder 実EXEの絶対directory。
     * @return 一つ以上の安全slotを確保できた場合true。
     */
	bool						   initialize( const std::wstring &folder)
	{
		// 共通の絶対DOS path文法を使いcwdやdevice namespaceへ逃げません。
		if( !validInfDependencyPath( folder, true)) {
			return reject( DiagnosticStorageStage::PATH) ;
		}

		// 共通file固定と同じ順序で祖先rename/reparseを拒否します。
		for( std::size_t end = 3U; end <= folder.size(); ++end) {
			// Component境界以外で祖先を開きません。
			if( end != 3U && end != folder.size() && folder[end] != L'\\') {
				continue ;
			}

			DWORD openError{} ;	// 元open失敗codeだけです。
			bool  openKnown{} ;	// Policy拒否と診断0を分けます。
			auto  handle =
				// 当該祖先です。
				openPinned( folder.substr( 0U, end), true, FILE_READ_ATTRIBUTES, OPEN_EXISTING,
						   &openError, &openKnown) ;
			// 祖先を一つでも固定できなければ保存を省きます。
			if( !handle) {
				return reject( DiagnosticStorageStage::ANCESTOR, openError, openKnown) ;
			}

			pins.push_back( std::move( handle)) ;
		}

		const auto logFolder = folder + L"\\log" ;	// 製品ではEXE隣以外を使いません。
		// 既存folderでも実handleの非reparse検査を省きません。
		if( !CreateDirectoryW( logFolder.c_str(), nullptr) &&
		   GetLastError() != ERROR_ALREADY_EXISTS) {
			return reject( DiagnosticStorageStage::FOLDER, GetLastError(), true) ;
		}

		DWORD openError{} ;	// log/slot openの元codeです。
		bool  openKnown{} ;	// 元codeの実取得有無です。
		auto  directory =
			// 固定された通常log folderです。
			openPinned( logFolder, true, FILE_READ_ATTRIBUTES, OPEN_EXISTING, &openError,
					   &openKnown) ;
		// Junction等のlogへfallbackして書き込みません。
		if( !directory) {
			return reject( DiagnosticStorageStage::FOLDER, openError, openKnown) ;
		}

		pins.push_back( std::move( directory)) ;
		// 固定2file以外は列挙も削除もしません。
		for( std::size_t index{}; index < slots.size(); ++index) {
			const auto path =
				logFolder + L"\\scan-" + std::to_wstring( index) + L".log" ;	// 固定basenameです。
			const DWORD attributes = GetFileAttributesW( path.c_str()) ;		// 新規作成との区別だけです。
			auto		file =
				openPinned( path, false, GENERIC_READ | GENERIC_WRITE,
						   attributes == INVALID_FILE_ATTRIBUTES ? CREATE_NEW : OPEN_EXISTING,
						   &openError, &openKnown) ;	// 不明fileをtruncateしません。
			// 当該slotが安全でなければもう一方だけを検査します。
			if( !file) {
				static_cast<void>( reject( DiagnosticStorageStage::SLOT, openError, openKnown)) ;
				continue ;
			}

			// CREATE_NEWしたslotは両方とも所有headerを保存してから再利用対象にします。
			if( attributes == INVALID_FILE_ATTRIBUTES) {
				DWORD		  written{} ;	// 新規所有headerの実write数です。
				LARGE_INTEGER begin{} ;		// 検証読取りへ戻す先頭です。
				// 不完全な新規headerを所有file成功へ換算しません。
				if( !WriteFile( file.get(), HEADER.data(), static_cast<DWORD>( HEADER.size()),
							  &written, nullptr)) {
					static_cast<void>( reject( DiagnosticStorageStage::HEADER, GetLastError(), true)) ;
					continue ;
				}

				// Short-writeへ古いLastErrorを付けません。
				if( written != HEADER.size()) {
					static_cast<void>( reject( DiagnosticStorageStage::HEADER)) ;
					continue ;
				}

				// 元のpointer照会失敗を保持します。
				if( !SetFilePointerEx( file.get(), begin, nullptr, FILE_BEGIN)) {
					static_cast<void>( reject( DiagnosticStorageStage::HEADER, GetLastError(), true)) ;
					continue ;
				}
			}

			LARGE_INTEGER length{} ;	// 所有確認前の実byte数です。
			// 過大fileを読まず、既存byteも変更しません。
			if( !GetFileSizeEx( file.get(), &length)) {
				static_cast<void>( reject( DiagnosticStorageStage::READ, GetLastError(), true)) ;
				continue ;
			}

			// 過大/不正な長さは元API errorではありません。
			if( length.QuadPart < 0 || static_cast<std::uint64_t>( length.QuadPart) > FILE_LIMIT) {
				static_cast<void>( reject( DiagnosticStorageStage::READ)) ;
				continue ;
			}

			std::string bytes( static_cast<std::size_t>( length.QuadPart),
							  '\0') ;	// 有限読取だけです。
			DWORD		read{} ;		// 実読取数です。
			// 全byteと所有文法の確認前にはtruncateしません。
			if( !ReadFile( file.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &read,
						 nullptr)) {
				static_cast<void>( reject( DiagnosticStorageStage::READ, GetLastError(), true)) ;
				continue ;
			}

			// 閉文法の拒否へ元API codeを捏造しません。
			if( read != bytes.size() || !validOwnedBytes( bytes)) {
				static_cast<void>( reject( DiagnosticStorageStage::READ)) ;
				continue ;
			}

			FILETIME written{} ;	// 古い所有slotを先に再利用します。
			// 時刻不明のfileを古いslotと仮定しません。
			if( !GetFileTime( file.get(), nullptr, nullptr, &written)) {
				static_cast<void>( reject( DiagnosticStorageStage::READ, GetLastError(), true)) ;
				continue ;
			}

			modified[index].LowPart	 = written.dwLowDateTime ;
			modified[index].HighPart = written.dwHighDateTime ;
			slots[index]			 = std::move( file) ;
		}

		// 古い一方を今回の開始slotにし、直前sessionをもう一方へ保持します。
		active = !slots[0]										? 1U
				 : !slots[1]									? 0U
				 : modified[0].QuadPart <= modified[1].QuadPart ? 0U
																: 1U ;
		// 一つも安全slotがなければ最初の拒否を保持します。
		if( active >= slots.size() || !slots[active]) {
			return reject( DiagnosticStorageStage::SLOT) ;
		}

		failure	   = DiagnosticStorageStage::NONE ;
		error	   = 0U ;
		errorKnown = false ;
		return reset() ;
	}

	/** @brief 検証済み所有slotだけを固定headerへ戻します。
     * @return Headerの完全writeが成立した場合true。
     */
	bool reset()
	{
		LARGE_INTEGER begin{} ;		// 所有handleの先頭だけです。
		DWORD		  written{} ;	// Headerの実write数です。
		size = HEADER.size() ;
		// 元API失敗とshort-writeを分け、架空のcodeを付けません。
		if( !SetFilePointerEx( slots[active].get(), begin, nullptr, FILE_BEGIN) ||
		   !SetEndOfFile( slots[active].get()) ||
		   !WriteFile( slots[active].get(), HEADER.data(), static_cast<DWORD>( HEADER.size()),
					  &written, nullptr)) {
			return reject( DiagnosticStorageStage::HEADER, GetLastError(), true) ;
		}

		return written == HEADER.size() || reject( DiagnosticStorageStage::HEADER) ;
	}

	/** @brief 一行を有界writeし、必要時もう一方の所有slotだけを再利用します。
     * @param[in] line 2048byte以内の閉じた形式。
     * @return 全write/flushが成立した場合true。
     */
	bool write( const std::string_view line)
	{
		// 一記録を切り詰めて保存しません。
		if( line.size() > LINE_LIMIT) {
			return reject( DiagnosticStorageStage::WRITE) ;
		}

		// 容量上限を越す前に所有するもう一slotへ切り替えます。
		if( size + line.size() > FILE_LIMIT) {
			active = 1U - active ;
			// 不明なもう一slotを置換せず、この診断だけを停止します。
			if( !slots[active] || !reset()) {
				return reject( DiagnosticStorageStage::SLOT) ;
			}
		}

		DWORD written{} ;	// 当該一行の実write数です。
		// Write失敗直後のcodeだけを保持します。
		if( !WriteFile( slots[active].get(), line.data(), static_cast<DWORD>( line.size()), &written,
					  nullptr)) {
			return reject( DiagnosticStorageStage::WRITE, GetLastError(), true) ;
		}

		size += written ;
		// Short-writeに無関係のLastErrorを付けません。
		if( written != line.size()) {
			return reject( DiagnosticStorageStage::WRITE) ;
		}

		// Workerだけでflushし、成功確認前には保存済みへ加算しません。
		if( !FlushFileBuffers( slots[active].get())) {
			return reject( DiagnosticStorageStage::FLUSH, GetLastError(), true) ;
		}

		return true ;
	}
} ;

/** @brief 閉enum/整数だけをUTF-8の一行へserializeします。
 * @param[in] record Queueへ投入済みの固定snapshot。
 * @return 固定名と数値だけのUTF-8行。不正enumは空です。
 */
std::string serialize( const DiagnosticRecord &record)
{
	const auto event = static_cast<std::size_t>( record.event) ;	// 閉じた表の位置です。
	// Enum不正やfield超過を配列外参照しません。
	if( event >= EVENT_NAMES.size() || record.fieldCount > record.fields.size()) {
		return {} ;
	}

	FILETIME utc{} ;	// Raw inventoryとは独立のWindows UTCです。
	GetSystemTimeAsFileTime( &utc) ;
	ULARGE_INTEGER ticks{} ;	// FILETIMEの100ns単位です。
	ticks.LowPart  = utc.dwLowDateTime ;
	ticks.HighPart = utc.dwHighDateTime ;
	const auto milliseconds =
		(ticks.QuadPart - 116444736000000000ULL) / 10000ULL ;	// Unix UTC msです。
	std::string line = "utcMs=" + std::to_string( milliseconds) + " event=" + EVENT_NAMES[event] +
					   " provider=" + providerName( record.provider) +
					   " operation=" + std::to_string( record.operation) +
					   " status=" + std::to_string( record.status) +
					   " error=" + std::to_string( record.error) ;	// 本文を持たない必須列です。
	// 最大16個の閉じた列だけを追加します。
	for( std::size_t index{}; index < record.fieldCount; ++index) {
		const auto field =
			// 閉じた列位置です。
			static_cast<std::size_t>( record.fields[index].first) ;
		// 型を迂回した不正enumをserializeしません。
		if( field >= FIELD_NAMES.size()) {
			return {} ;
		}

		line += " " + std::string( FIELD_NAMES[field]) + "=" +
				std::to_string( record.fields[index].second) ;
	}

	line.push_back( '\n') ;
	return line ;
}
}

/** @brief Worker終了後まで共有所有される固定容量state。 */
struct LocalDiagnosticLog::State {
	/// I/Oを保持中に取得しないqueue lockです。
	SRWLOCK									  lock = SRWLOCK_INIT ;
	/// 固定capacityの値queueです。
	std::array<DiagnosticRecord, QUEUE_LIMIT> queue ;
	/// 先頭位置です。lock下だけで更新します。
	std::size_t								  head{} ;
	/// Queue件数です。lock下だけで更新します。
	std::size_t								  count{} ;
	/// Auto-reset通知eventです。
	Handle									  wake ;
	/// Worker終了eventです。
	Handle									  done ;
	/// Queueを排出して終了する要求です。
	std::atomic<bool>						  stopping{} ;
	/// 保存不能後は新規投入を省きます。
	std::atomic<bool>						  failed{} ;
	/// 最初の保存停止段階です。
	std::atomic<DiagnosticStorageStage>		  failureStage{DiagnosticStorageStage::NONE} ;
	/// 最初の元Win32 codeです。0は未取得です。
	std::atomic<DWORD>						  failureCode{} ;
	/// 元API codeを0も含めて取得しました。
	std::atomic<bool>						  failureCodeKnown{} ;
	/// Queueへ受理したrecord件数です。
	std::atomic<std::uint64_t>				  accepted{} ;
	/// Flushまで成功したrecord件数です。
	std::atomic<std::uint64_t>				  saved{} ;
	/// 全期間の投入欠落です。通知済みでも減らしません。
	std::atomic<std::uint64_t>				  droppedTotal{} ;
	/// 起動recordを実flushした事実です。
	std::atomic<bool>						  startupFlushed{} ;
	/// 保存先初期化が終わりました。
	std::atomic<bool>						  initialized{} ;
	/// 有界stopが終端を確認できませんでした。
	std::atomic<bool>						  stopTimeout{} ;
	/// 内部fixtureだけの局所writer失敗です。
	std::atomic<DiagnosticStorageStage>		  testFailure{DiagnosticStorageStage::NONE} ;
	/// 内部fixtureの開始時だけtrueです。通常開始はfalseで、再pauseしません。
	std::atomic<bool>						  testPaused{} ;
	/// 非待機投入で落とした件数です。
	std::atomic<std::uint64_t>				  dropped{} ;
	/// 試験の有限drainだけが読む保存中flagです。
	std::atomic<bool>						  writing{} ;
	/// Workerが保存する唯一の絶対folderです。
	std::wstring							  folder ;

	/** @brief UIから独立してqueueを排出し全例外を診断停止へ変換します。 */
	void									  run() noexcept
	{
		try {
			FileSink sink ;	// Worker寿命中だけ祖先と固定fileを所有します。
			// 保存を確保できなくても通常処理へ失敗を返しません。
			if( !sink.initialize( folder)) {
				failureStage	 = sink.failure ;
				failureCode		 = sink.error ;
				failureCodeKnown = sink.errorKnown ;
				failed			 = true ;
			}

			initialized = true ;

			// 保存停止か停止要求後のqueue空までだけ待機します。
			while( !failed) {
				// 制御されたfixtureだけが排出を保留し、queue lockや追加eventを保持しません。
				while( testPaused && !stopping) {
					static_cast<void>( WaitForSingleObject( wake.get(), INFINITE)) ;
				}

				DiagnosticRecord record ;	// lock外I/Oへ移す固定snapshotです。
				AcquireSRWLockExclusive( &lock) ;
				const bool present = count != 0U ;	// Queue空を0件と誤認しません。
				// I/O前に一記録だけをqueueから移し、lockを解放します。
				if( present) {
					record = queue[head] ;
					head   = (head + 1U) % queue.size() ;
					--count ;
					writing = true ;
				}

				ReleaseSRWLockExclusive( &lock) ;
				// 実記録がある場合だけlock外で保存します。
				if( present) {
					const auto lost = dropped.exchange( 0U) ;	// 欠落を成功記録数へ換算しません。
					// Queue競合や容量超過があったときだけ固定件数を補います。
					if( lost != 0U) {
						DiagnosticRecord missing ;	// 欠落件数以外を持ちません。
						missing.event = DiagnosticEvent::QUEUE_DROPPED ;
						missing.add( DiagnosticField::TOTAL, lost) ;
						// 欠落通知も保存不能ならloggerだけを停止します。
						if( !sink.write( serialize( missing))) {
							failureStage	 = sink.failure ;
							failureCode		 = sink.error ;
							failureCodeKnown = sink.errorKnown ;
							failed			 = true ;
						}
					}

					const auto line		= serialize( record) ;	// 本文なしの型付きserializeです。
					const auto injected = testFailure.load() ;	// 製品では常にNONEです。
					// 自己所有fixtureだけがwrite/flush失敗を固定入力で与えます。
					if( injected == DiagnosticStorageStage::WRITE ||
					   injected == DiagnosticStorageStage::FLUSH) {
						static_cast<void>( sink.reject( injected,
													  injected == DiagnosticStorageStage::WRITE
														  ? ERROR_WRITE_FAULT
														  : ERROR_GEN_FAILURE,
													  true)) ;
						failureStage	 = sink.failure ;
						failureCode		 = sink.error ;
						failureCodeKnown = sink.errorKnown ;
						failed			 = true ;
					}

					// 保存失敗を通常scan成功/失敗へ混ぜません。
					if( !failed && !line.empty() && !sink.write( line)) {
						failureStage	 = sink.failure ;
						failureCode		 = sink.error ;
						failureCodeKnown = sink.errorKnown ;
						failed			 = true ;
					}
					// 実write/flushが全て成功した記録だけを数えます。
					else if( !failed && !line.empty()) {
						++saved ;
						// Startup記録の実write/flushだけを別に保持します。
						if( record.event == DiagnosticEvent::STARTUP) {
							startupFlushed = true ;
						}
					}

					writing = false ;
					continue ;
				}

				// 停止要求後はqueueを排出した時点で終了します。
				if( stopping) {
					// 内部fixture以外では待機を増やしません。
					if( testFailure == DiagnosticStorageStage::STOP) {
						Sleep( 300U) ;
					}

					break ;
				}

				static_cast<void>( WaitForSingleObject( wake.get(), INFINITE)) ;
			}
		} catch( ...) {
			// 保存不能は通常scan/installへ返さず、このloggerだけを停止します。
			failureStage = DiagnosticStorageStage::RESOURCE ;
			failed		 = true ;
		}

		writing = false ;
		SetEvent( done.get()) ;
	}
} ;

/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
DiagnosticProvider DiagnosticProvider::fromId( const std::wstring_view id) noexcept
{
	DiagnosticProvider result ;								// Registry以外は固定unknownへ縮退します。
	const auto *descriptor = findProviderDescriptor( id) ;	// Process lifetimeのcanonical entryです。
	// Conditional式で一時std::wstringを作らず、static registryの寿命だけを借用します。
	if( descriptor) {
		result.id_ = descriptor->id ;
	} else {
		result.id_ = L"unknown" ;
	}

	return result ;
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
std::wstring_view DiagnosticProvider::id() const noexcept
{
	return id_ ;
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
DiagnosticRecord &DiagnosticRecord::add( const DiagnosticField field,
										const std::uint64_t	  value) noexcept
{
	// 超過を動的確保へ逃がしません。
	if( fieldCount < fields.size()) {
		fields[fieldCount++] = {field, value} ;
	}

	return *this ;
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
LocalDiagnosticLog::~LocalDiagnosticLog()
{
	stop() ;
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
void LocalDiagnosticLog::start() noexcept
{
	try {
		std::wstring path( 32768U, L'\0') ;	// 実module位置の有限受信領域です。
		const DWORD	 length = GetModuleFileNameW(
			 nullptr, path.data(), static_cast<DWORD>( path.size())) ;	// Cwdを参照しません。
		// Module位置が不明なら別folderへ保存しません。
		if( length == 0U || length >= path.size()) {
			startFailure_ = {DiagnosticStorageState::FAILED, DiagnosticStorageStage::MODULE_PATH,
							 length == 0U ? GetLastError() : 0U, length == 0U} ;
			return ;
		}

		path.resize( length) ;
		const auto separator = path.find_last_of( L'\\') ;	// 実EXEのfolder境界です。
		// 絶対folderを得られない値をcwd基準へ補いません。
		if( separator == std::wstring::npos) {
			startFailure_ = {DiagnosticStorageState::FAILED, DiagnosticStorageStage::MODULE_PATH} ;
			return ;
		}

		path.resize( separator) ;
		startInFolder( path) ;
	} catch( ...) {
		// Path確保不能も診断だけを省きます。通常起動に失敗を返しません。
		startFailure_ = {DiagnosticStorageState::FAILED, DiagnosticStorageStage::RESOURCE} ;
	}
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
void LocalDiagnosticLog::startInFolder( const std::wstring_view folder, const bool paused) noexcept
{
	// Process中の別保存先への再初期化を許しません。
	if( state_) {
		return ;
	}

	try {
		auto state	  = std::make_shared<State>() ;	// Workerにも同じ寿命を渡します。
		state->folder = folder ;
		// Thread開始後にpauseへ切り替えない一方向のfixture制御です。
		state->testPaused = paused ;
		state->wake.reset( CreateEventW( nullptr, FALSE, FALSE, nullptr)) ;
		// 通知資源が不足している場合も通常起動を続けます。
		if( !state->wake) {
			startFailure_ = {DiagnosticStorageState::FAILED, DiagnosticStorageStage::RESOURCE,
							 GetLastError(), true} ;
			return ;
		}

		state->done.reset( CreateEventW( nullptr, TRUE, FALSE, nullptr)) ;
		// 後続APIが失敗codeを上書きする前に取得します。
		if( !state->done) {
			startFailure_ = {DiagnosticStorageState::FAILED, DiagnosticStorageStage::RESOURCE,
							 GetLastError(), true} ;
			return ;
		}

		std::thread worker( [state] { state->run() ; }) ;	// I/O中も共有stateが生存します。
		worker.detach() ;
		state_ = std::move( state) ;
	} catch( ...) {
		// Thread/queue確保不能も起動・操作へ伝播させません。
		startFailure_ = {DiagnosticStorageState::FAILED, DiagnosticStorageStage::RESOURCE} ;
	}
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
void LocalDiagnosticLog::append( const DiagnosticRecord &record) noexcept
{
	// 開始不能・保存不能・停止後は通常処理へ即時復帰します。
	if( !state_) {
		return ;
	}

	// 保存停止後の投入も成功に数えません。
	if( state_->failed || state_->stopping) {
		++state_->droppedTotal ;
		return ;
	}

	// UI/workerをqueue lock待機させません。
	if( !TryAcquireSRWLockExclusive( &state_->lock)) {
		++state_->droppedTotal ;
		++state_->dropped ;
		return ;
	}

	// 有限枠を越した診断だけを落とします。
	if( state_->count == state_->queue.size()) {
		++state_->droppedTotal ;
		++state_->dropped ;
	} else {
		state_->queue[(state_->head + state_->count) % state_->queue.size()] = record ;
		++state_->count ;
		++state_->accepted ;
	}

	ReleaseSRWLockExclusive( &state_->lock) ;
	SetEvent( state_->wake.get()) ;
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
void LocalDiagnosticLog::stop() noexcept
{
	// 既に停止済みなら二回待機しません。
	if( !state_ || state_->stopping.exchange( true)) {
		return ;
	}

	SetEvent( state_->wake.get()) ;
	const DWORD waited = WaitForSingleObject( state_->done.get(), 200U) ;	// 有界終了の元結果です。
	// Timeoutをqueue保存済みへ読み替えません。
	if( waited != WAIT_OBJECT_0) {
		state_->stopTimeout = true ;
		// 元待機失敗だけにWin32 codeを付けます。
		if( waited == WAIT_FAILED && !state_->failed) {
			state_->failureCode		 = GetLastError() ;
			state_->failureCodeKnown = true ;
			state_->failureStage	 = DiagnosticStorageStage::STOP ;
			state_->failed			 = true ;
		}
	}
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
DiagnosticStorageStatus LocalDiagnosticLog::status() const noexcept
{
	// Worker開始前の元失敗も隠しません。
	if( !state_) {
		return startFailure_ ;
	}

	const bool failed = state_->failed.load() ;	// 原停止理由のpublish後だけFAILEDを返します。
	DiagnosticStorageStatus value ;				// 文字列やpathを持たない所有snapshotです。
	value.stage			 = state_->failureStage.load() ;
	value.code			 = state_->failureCode.load() ;
	value.codeKnown		 = state_->failureCodeKnown.load() ;
	value.startupFlushed = state_->startupFlushed.load() ;
	value.saved			 = state_->saved.load() ;
	const auto accepted	 = state_->accepted.load() ;	// 保存確認を先に読み過大差分を作りません。
	value.pending		 = accepted >= value.saved ? accepted - value.saved : 0U ;
	value.dropped		 = state_->droppedTotal.load() ;
	value.state			 = failed				 ? DiagnosticStorageState::FAILED
						   : state_->stopTimeout ? DiagnosticStorageState::STOP_TIMEOUT
						   : state_->stopping && WaitForSingleObject( state_->done.get(), 0U) == WAIT_OBJECT_0
							   ? DiagnosticStorageState::STOPPED
						   : state_->initialized ? DiagnosticStorageState::ACTIVE
												 : DiagnosticStorageState::STARTING ;
	// Timeoutの固定段階は元I/O失敗がない場合だけ使います。
	if( value.state == DiagnosticStorageState::STOP_TIMEOUT) {
		value.stage = DiagnosticStorageStage::STOP ;
	}

	return value ;
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
void startLocalDiagnostics() noexcept
{
	processLog.start() ;
	DiagnosticRecord record ;		// Token値やSIDではなく照会結果だけです。
	TOKEN_ELEVATION	 elevation{} ;	// OSが返すboolだけを使用します。
	DWORD			 size{} ;		// 返却byte数です。
	HANDLE			 raw{} ;		// OpenProcessToken直後だけの受信所有値です。
	const bool		 opened = OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &raw) !=
						FALSE ;											// 名前やSIDは照会しません。
	const DWORD openError = opened ? ERROR_SUCCESS : GetLastError() ;	// 元失敗を保持します。
	Handle		token( raw) ;											// Query後に自動closeします。
	const bool	known =
		opened && GetTokenInformation( token.get(), TokenElevation, &elevation, sizeof( elevation),
									  &size) != FALSE ;	// TokenElevationだけです。
	record.error = static_cast<std::int32_t>( known	  ? ERROR_SUCCESS
											 : opened ? GetLastError()
													  : openError) ;
	record.add( DiagnosticField::ELEVATION_KNOWN, known)
		.add( DiagnosticField::ELEVATED, known && elevation.TokenIsElevated != 0U) ;
	processLog.append( record) ;
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
void recordLocalDiagnostic( const DiagnosticRecord &record) noexcept
{
	processLog.append( record) ;
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
void stopLocalDiagnostics() noexcept
{
	processLog.stop() ;
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
DiagnosticStorageStatus localDiagnosticStatus() noexcept
{
	return processLog.status() ;
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
void local_diagnostic_detail::Access::start( LocalDiagnosticLog	   &log,
											const std::wstring_view folder) noexcept
{
	log.startInFolder( folder) ;
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
void local_diagnostic_detail::Access::startPaused( LocalDiagnosticLog	 &log,
												  const std::wstring_view folder) noexcept
{
	log.startInFolder( folder, true) ;
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
void local_diagnostic_detail::Access::resume( LocalDiagnosticLog &log) noexcept
{
	// 未開始/再開済み/停止済みを再初期化したり、pauseへ戻したりしません。
	if( !log.state_ || log.state_->stopping || !log.state_->testPaused.exchange( false)) {
		return ;
	}

	SetEvent( log.state_->wake.get()) ;
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
bool local_diagnostic_detail::Access::drain( const LocalDiagnosticLog &log) noexcept
{
	// 未開始も非阻害の結果として扱います。
	if( !log.state_) {
		return true ;
	}

	// 内部file試験だけは最大5秒、処理済み観測を待ちます。
	for( unsigned attempt{}; attempt < 1000U; ++attempt) {
		AcquireSRWLockExclusive( &log.state_->lock) ;
		const bool empty =
			// Pop直後のI/Oも含めます。
			log.state_->count == 0U && !log.state_->writing ;
		ReleaseSRWLockExclusive( &log.state_->lock) ;
		// 保存済みか診断停止ならfixtureの有限待機を終えます。
		if( (empty || log.state_->failed) &&
		   (!log.state_->stopping ||
			WaitForSingleObject( log.state_->done.get(), 0U) == WAIT_OBJECT_0)) {
			return true ;
		}

		Sleep( 5U) ;
	}

	return false ;
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
void local_diagnostic_detail::Access::fail( LocalDiagnosticLog		   &log,
										   const DiagnosticStorageStage stage) noexcept
{
	// 既自己所有fixtureのwriterだけに限定します。
	if( log.state_ &&
	   (stage == DiagnosticStorageStage::WRITE || stage == DiagnosticStorageStage::FLUSH ||
		stage == DiagnosticStorageStage::STOP)) {
		log.state_->testFailure = stage ;
	}
}
/** @see local_diagnostic_log.h 宣言側の契約を正本とします。 */
void local_diagnostic_detail::Access::failProcess( const DiagnosticStorageStage stage) noexcept
{
	fail( processLog, stage) ;
}
}
