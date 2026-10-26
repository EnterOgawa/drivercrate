//------------------------------------------------------------------------------
/**
 * @file local_driver_collector_main.cpp
 * @brief 開発用ローカル公式metadata collectorの一回実行入口です。
 * @version 01.14.00
 * @date 2026/09/24
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/24  明示manifestの単発収集入口を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/25  台帳権限拒否の数値診断を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/25  日跨ぎ再開の非機密表示を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/25  保留件数と未昇格commit回収を表示。
 * Ver.01.04.00 Shunji Ogawa  2026/10/03  非通信の旧待機export入口を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/14  明示一対象の原本文evidence新規保存を追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/15  非対話の日次receiptとdue前HOLD入口を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/10/15  日次だけのProgramData保護出力と実ACL検査を追加。
 * Ver.01.08.00 Shunji Ogawa  2026/10/17  原予約の明示非変更照合CLIを追加。
 * Ver.01.08.01 Shunji Ogawa  2026/10/17  全CLI modeの引数配置と予約照合の終了値説明を補完。
 * Ver.01.09.00 Shunji Ogawa  2026/10/20  保護原二fileの閉匿名readback modeを追加。
 * Ver.01.10.00 Shunji Ogawa  2026/10/23  外部registry jobの非通信検証と通信未接続拒否を追加。
 * Ver.01.11.00 Shunji Ogawa  2026/10/25  原terms pin付き日次本体取得と保護非置換保存を追加。
 * Ver.01.12.00 Shunji Ogawa  2026/10/25  明示取得stdoutへ呼出し内拒否段階を追加。
 * Ver.01.13.00 Shunji Ogawa  2026/10/25  同HTTP失敗本文を固定派生の保護診断へ保存。
 * Ver.01.14.00 Shunji Ogawa  2026/10/26 共通承認readerとSHA-512-only取得保存を接続。
 * </pre>
 *
 * @note 通常DriverCrate.exeと独立し、URL、製品名、pathを標準出力へ出しません。
 */
//------------------------------------------------------------------------------

#include "platform/local_driver_collector.h"
#include "platform/local_collector_legacy.h"
#include "platform/public_index_readback.h"
#include "platform/collector_registry_job.h"
#include "platform/official_acquisition.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"

#include <Windows.h>
#include <AclAPI.h>
#include <ShlObj.h>
#include <sddl.h>
#include <wincrypt.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#include <chrono>
#include <charconv>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <stdexcept>
#include <utility>
#include <vector>

namespace {

/** @brief 出力fileと固定directoryのOS handleをscope終了時に回収します。 */
struct HandleCloser {
	/** @brief 有効な非owning引数のOS handleを解放します。
	 * @param[in] handle このdeleterだけが解放する有効handle。
	 * @note Destructorから例外を送出せず、flushと正常終了の確認はcallerが行います。
	 */
	void operator()( void *handle) const noexcept
	{
		(void)CloseHandle( handle) ;
	}
} ;

/** @brief OSのProgramData起点から日次専用operationsを得ます。
 * @return 成功時の固定絶対path。OS照会失敗時は空です。
 * @note 環境変数や作業directoryを信頼起点にしません。
 */
[[nodiscard]] std::filesystem::path dailyOperationsRoot()
{
	PWSTR		  raw{} ;	// OSがCoTaskMemで所有権を渡す既知folder。
	const HRESULT result = SHGetKnownFolderPath( FOLDERID_ProgramData, KF_FLAG_DONT_VERIFY, nullptr,
												&raw) ;	// 非作成照会。
	std::filesystem::path root ;						// 成功時だけの固定出力先。
	// 欠損値を環境変数へfallbackしません。
	if( SUCCEEDED( result) && raw != nullptr) {
		root = std::filesystem::path( raw) / L"DriverCrate" / L"PrivateIndex229" / L"operations" ;
	}

	CoTaskMemFree( raw) ;
	return root ;
}

/** @brief 既知のOS保守主体だけをowner/書込み主体へ許可します。
 * @param[in] sid OS security descriptor内の有効な借用SID。
 * @return SYSTEM、Administrators、既知TrustedInstallerの場合true。
 */
[[nodiscard]] bool dailyTrustedSid( PSID sid)
{
	// 不正SIDはOS照会へ渡しません。
	if( sid == nullptr || !IsValidSid( sid)) {
		return false ;
	}

	// 固定した二つのwell-known管理主体を許可します。
	if( IsWellKnownSid( sid, WinLocalSystemSid) || IsWellKnownSid( sid, WinBuiltinAdministratorsSid)) {
		return true ;
	}

	PSID installer{} ;	// LocalFreeで解放する既知service SID。
	// Windows volume rootの保守ownerを任意serviceへ広げません。
	if( !ConvertStringSidToSidW( L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
							   &installer)) {
		return false ;
	}

	const bool trusted = EqualSid( sid, installer) != FALSE ;	// 完全一致だけ。
	LocalFree( installer) ;
	return trusted ;
}

/** @brief 日次出力の実handleに管理者ownerと非書換DACLを要求します。
 * @param[in] handle READ_CONTROLを持つ検査対象のborrowed handle。
 * @param[in] ancestor trueでは既存保護子を置換しない新規作成権だけを許容します。
 * @param[in] requireProtected trueではDACLの継承停止も要求します。
 * @return 不明owner、null DACL、許可外書込み、照会失敗ではfalse。
 */
[[nodiscard]] bool dailyProtectedHandle( HANDLE handle, bool ancestor, bool requireProtected)
{
	PSECURITY_DESCRIPTOR descriptor{} ;	// LocalFreeで解放するOS結果。
	PSID				 owner{} ;		// descriptor存続中だけのowner借用。
	PACL				 acl{} ;		// descriptor存続中だけのDACL借用。
	const DWORD			 result = GetSecurityInfo( handle, SE_FILE_OBJECT,
												  OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
												  &owner, nullptr, &acl, nullptr,
												  &descriptor) ;	// 実際に固定したhandleから照会する。
	bool allowed = result == ERROR_SUCCESS && dailyTrustedSid( owner) && acl != nullptr &&
				   // ownerも権限変更主体へ含める。
				   IsValidAcl( acl) ;
	SECURITY_DESCRIPTOR_CONTROL control{} ;		// DACL保護bitを確認する。
	DWORD						revision{} ;	// APIの必須出力。
	// 専用rootの継承を無効化し、親から弱い許可を持ち込ませません。
	if( allowed && requireProtected) {
		allowed = GetSecurityDescriptorControl( descriptor, &control, &revision) &&
				  (control & SE_DACL_PROTECTED) != 0U ;
	}

	const DWORD mask = ancestor ? 0x000D0040U : 0x000D0156U ;	// 削除・ACLと実内容書込みを区別する。
	// 全ACEを有限に確認し、未知allow型を許容しません。
	for( DWORD index = 0U; allowed && index < acl->AceCount; ++index) {
		void *raw{} ;	// ACL内だけのborrowed ACE。
		// 不明なACEを無視しません。
		if( !GetAce( acl, index, &raw)) {
			allowed = false ;
			break ;
		}

		const auto *ace = static_cast<const ACCESS_ALLOWED_ACE *>( raw) ;	// Win32 ACLの固定境界。
		// inherit-only許可は既存対象を置換する権限ではありません。
		if( (ace->Header.AceFlags & INHERIT_ONLY_ACE) != 0U ||
		   ace->Header.AceType == ACCESS_DENIED_ACE_TYPE) {
			continue ;
		}

		// 通常allow以外の複雑な権限はfail-closedにします。
		if( ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
		   ace->Header.AceSize < sizeof( ACCESS_ALLOWED_ACE)) {
			allowed = false ;
			break ;
		}

		PSID sid = const_cast<DWORD *>( &ace->SidStart) ;	// 可変長SIDはACL内を借用する。
		allowed	 = IsValidSid( sid) && ((ace->Mask & (mask | GENERIC_WRITE | GENERIC_ALL)) == 0U ||
									   dailyTrustedSid( sid)) ;
	}

	LocalFree( descriptor) ;
	return allowed ;
}

/** @brief 日次だけの固定operations一job階層と有限ASCII名を検査します。
 * @param[in] output 保護job内の絶対path。
 * @param[in] allowGzip 閉readback modeだけでgzip拡張子を許す場合true。
 * @return OS起点の通常固定drive上にある有限pathの場合true。
 */
[[nodiscard]] bool dailyOutputPath( const std::filesystem::path &output,
								   const bool					allowGzip = false)
{
	const auto root = dailyOperationsRoot() ;						// OSが返した信頼起点。
	const auto job	= output.parent_path().filename().native() ;	// 一階層だけのjob名。
	const auto name = output.filename().native() ;					// 有限のASCII出力名。
	// UNC、ADS、別root、相対成分、過長名を拒否します。
	if( root.empty() || !output.is_absolute() || output != output.lexically_normal() ||
	   output.parent_path().parent_path() != root ||
	   (output.extension() != L".json" && !(allowGzip && output.extension() == L".gz")) ||
	   output.native().find( L':', 2U) != std::wstring::npos || job.empty() || job.size() > 80U ||
	   job.front() == L'.' || name.empty() || name.size() > 160U || name.front() == L'.' ||
	   GetDriveTypeW( output.root_path().c_str()) != DRIVE_FIXED) {
		return false ;
	}

	return std::all_of( job.begin(), job.end(),
					   []( wchar_t letter) {
						   return (letter >= L'a' && letter <= L'z') ||
								  (letter >= L'0' && letter <= L'9') || letter == L'-' ;
					   }) &&
		   std::all_of( name.begin(), name.end(), []( wchar_t letter) {
			   return (letter >= L'a' && letter <= L'z') || (letter >= L'0' && letter <= L'9') ||
					  letter == L'-' || letter == L'.' ;
		   }) ;
}

/** @brief 非通信snapshotを新規fileだけへ保存し、祖先の入替えをhandleで止めます。
 * @param[in] output 旧分析先、または日次専用operations一job内の絶対JSON path。
 * @param[in] bytes 完全検証済みの通常1MiB以下、失敗診断だけ3MiB以下のsnapshot。
 * @param[in] daily trueではProgramData日次専用先と実ACLを要求します。
 * @param[in] failedPageDiagnostic trueではdailyの固定失敗診断suffixだけ3MiBを許可します。
 * @return 保存・flush成功0、それ以外は元Win32 code。
 * @note 既存fileは上書きせず、失敗途中のfileも削除しません。
 */
DWORD writeLegacyExport( const std::filesystem::path &output, const std::string &bytes,
						bool daily = false, bool failedPageDiagnostic = false)
{
	using OwnedHandle = std::unique_ptr<void, HandleCloser> ;
	const auto base =
		// 許可する公開作業領域。
		std::filesystem::current_path() / L"work" / L"analysis" ;
	const auto maximumBytes =
		failedPageDiagnostic ? 3U * 1024U * 1024U : 1024U * 1024U ;	// 用途別上限です。
	// 任意path・volume・suffixへの出力を拒否する。
	if( !output.is_absolute() || output != output.lexically_normal() ||
	   (daily ? !dailyOutputPath( output) : output.parent_path().parent_path() != base) ||
	   output.extension() != L".json" || output.native().find( L':', 2U) != std::wstring::npos ||
	   (failedPageDiagnostic &&
		(!daily || !output.filename().native().ends_with( L".failed-page.json"))) ||
	   bytes.empty() || bytes.size() > maximumBytes ||
	   GetDriveTypeW( output.root_path().c_str()) != DRIVE_FIXED) {
		return ERROR_INVALID_PARAMETER ;
	}

	std::vector<OwnedHandle> directories ;	// 全祖先を保存完了まで非削除shareで固定する。
	auto path = output.parent_path() ;		// 子からdrive rootまで有限に検査するcursor。
	// 全祖先の同じhandleで通常directoryと非reparseを確認する。
	while( !path.empty()) {
		const HANDLE raw =
			CreateFileW( path.c_str(), FILE_READ_ATTRIBUTES | (daily ? READ_CONTROL : 0U),
						FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
						FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
						nullptr) ;	// 既存祖先だけ。
		// 欠損祖先を作成せず元errorを返す。
		if( raw == INVALID_HANDLE_VALUE) {
			return GetLastError() ;
		}

		OwnedHandle				   handle( raw) ;	// 検査失敗でもOS資源を回収する。
		BY_HANDLE_FILE_INFORMATION information{} ;	// 同じ実handleの属性。
		// 属性照会失敗を正常directoryへ読み替えない。
		if( !GetFileInformationByHandle( handle.get(), &information)) {
			return GetLastError() ;
		}

		// Junction・mount point・通常fileの祖先を拒否する。
		if( (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U ||
		   (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) {
			return ERROR_INVALID_DATA ;
		}

		// 日次祖先を固定した同handleから検査し、一般userによる署名入力の差替えを止めます。
		if( daily && !dailyProtectedHandle( handle.get(),
										  path.native().size() <
											  dailyOperationsRoot().parent_path().native().size(),
										  path == dailyOperationsRoot().parent_path())) {
			return ERROR_ACCESS_DENIED ;
		}

		directories.push_back( std::move( handle)) ;
		const auto parent = path.parent_path() ;	// 一つ上の祖先。
		// drive rootで終了し、同じpathを無限に反復しない。
		if( parent == path) {
			break ;
		}

		path = parent ;
	}

	const HANDLE raw =
		CreateFileW( output.c_str(), GENERIC_WRITE | (daily ? READ_CONTROL : 0U), 0U, nullptr,
					CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
					nullptr) ;	// 上書きしない一回作成。
	// 既存file・directoryとアクセス拒否を成功へ変換しない。
	if( raw == INVALID_HANDLE_VALUE) {
		return GetLastError() ;
	}

	OwnedHandle file( raw) ;	// 部分出力を残し、handleだけを解放する。
	// 継承後の実fileもowner/DACLを再検査し、不成立時は本文を書きません。
	if( daily && !dailyProtectedHandle( file.get(), false, false)) {
		return ERROR_ACCESS_DENIED ;
	}

	DWORD written{} ;	// 実APIが確認したbyte数。
	// 全byteの書込みとflushを確認するまで出力成功を表示しない。
	if( !WriteFile( file.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &written, nullptr)) {
		return GetLastError() ;
	}

	// 短い成功書込みを完全snapshotとして扱わない。
	if( written != bytes.size()) {
		return ERROR_WRITE_FAULT ;
	}

	// 内容を保存装置へ送れない場合は成功を返さない。
	if( !FlushFileBuffers( file.get())) {
		return GetLastError() ;
	}

	// 通常終了のclose失敗も出力成功へ変換しない。
	if( !CloseHandle( file.release())) {
		return GetLastError() ;
	}

	return ERROR_SUCCESS ;
}

/** @brief 実HTTP前に明示evidence出力の有限pathと新規性を確認します。
 * @param[in] output 旧分析先、または日次専用operations一job内の絶対JSON path。
 * @param[in] daily trueでは日次専用先と実ACLを通信前に要求します。
 * @return 既存通常祖先と欠損出力だけの場合true。保存時にも同handleで再検査します。
 * @note 状態や出力fileを作成せず、任意pathへ原本文を送信しません。
 */
[[nodiscard]] bool validEvidenceOutput( const std::filesystem::path &output, bool daily = false)
{
	const auto base = std::filesystem::current_path() / L"work" / L"analysis" ;	// 固定公開作業領域。
	// 任意directory、ADS、既存fileへの出力をHTTPより先に拒否します。
	if( !output.is_absolute() || output != output.lexically_normal() ||
	   (daily ? !dailyOutputPath( output) : output.parent_path().parent_path() != base) ||
	   output.extension() != L".json" || output.native().find( L':', 2U) != std::wstring::npos ||
	   std::filesystem::exists( output)) {
		return false ;
	}

	auto parent = output.parent_path() ;	// drive rootまで有限に確認するcursor。
	// 欠損・非directory・reparse祖先を通信前に拒否します。
	while( !parent.empty()) {
		const DWORD attributes = GetFileAttributesW( parent.c_str()) ;	// 非変更属性照会。
		// 未確認祖先を通常directoryへ読み替えません。
		if( attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0U ||
		   (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) {
			return false ;
		}

		// 日次だけは通信前にも既存祖先の実ACLを要求します。
		if( daily) {
			const HANDLE raw = CreateFileW(
				parent.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES,
				FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
				FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;	// 非作成照会。
			// 開けない祖先で収集を開始しません。
			if( raw == INVALID_HANDLE_VALUE) {
				return false ;
			}

			const std::unique_ptr<void, HandleCloser> handle( raw) ;	// 一階層の検査handle。
			// 保護rootとその下は内容書込みも拒否します。
			if( !dailyProtectedHandle( handle.get(),
									 parent.native().size() <
										 dailyOperationsRoot().parent_path().native().size(),
									 parent == dailyOperationsRoot().parent_path())) {
				return false ;
			}
		}

		const auto next = parent.parent_path() ;	// 一階層だけ上がる。
		// drive rootで終了します。
		if( next == parent) {
			break ;
		}

		parent = next ;
	}

	return true ;
}

/** @brief 元receiptと同HTTP失敗本文だけを別保護診断へ保存します。
 * @param[in] output 元receiptから固定派生した同job内の診断先です。
 * @param[in] run 今回の失敗結果です。成功checkpointを変更しません。
 * @param[in] receiptBytes 先に保存できた元receiptの完全byteです。
 * @param[in] collectorCode 元collector部分失敗1です。
 * @return 保存成功0、生成拒否/例外13、保存失敗は元Win32 errorです。
 * @note 例外や保存失敗を元collectorのstdout/終了値へ伝播しません。
 */
[[nodiscard]] DWORD saveFailedPageDiagnostic( const std::filesystem::path		  &output,
											 const drivercrate::LocalCollectorRun &run,
											 const std::string_view				   receiptBytes,
											 const int collectorCode) noexcept
{
	try {
		std::string bytes ;	// 本文は専用保護出力だけへ渡します。
		// 欠測/部分/304や別receiptを診断本文で補完しません。
		if( !drivercrate::makeLocalCollectorFailedPageDiagnostic( run, receiptBytes, collectorCode,
																bytes)) {
			return ERROR_INVALID_DATA ;
		}

		return writeLegacyExport( output, bytes, true, true) ;
	} catch( ...) {
		return ERROR_INVALID_DATA ;
	}
}

/** @brief 一つの新200原本文と検証済みmetadataを原byte保持のJSONへ包みます。
 * @param[in] run 完了した固定一対象の実収集結果。
 * @return 最大1MiBのevidence JSON。不成立時は例外で保存しません。
 * @throws std::runtime_error 新200、対象数、原byte上限、base64 APIが不成立の場合。
 * @note 保存本文は通常stdout/logへ渡さず、署名・取得許可・端末適合を発行しません。
 */
[[nodiscard]] std::string collectorEvidenceBytes( const drivercrate::LocalCollectorRun &run)
{
	using winrt::Windows::Data::Json::JsonArray ;
	using winrt::Windows::Data::Json::JsonObject ;
	using winrt::Windows::Data::Json::JsonValue ;
	// 旧成功再利用、失敗、304または複数対象を新原本文へ昇格しません。
	if( !run.complete || run.targets.size() != 1U) {
		throw std::runtime_error( "collector evidence target rejected") ;
	}

	const auto &target = run.targets.front() ;	// 同runの固定一対象。
	// 実200で全metadata検証済みの新原byteだけを保存します。
	if( target.source != L"INTEL_ETHERNET_WINDOWS11" || target.lastHttpStatus != 200U ||
	   target.error != 0U || target.rawMetadataBytes.empty() ||
	   target.rawMetadataBytes.size() > 512U * 1024U ||
	   (target.state != drivercrate::LocalCollectorTargetState::UPDATED &&
		target.state != drivercrate::LocalCollectorTargetState::UNCHANGED)) {
		throw std::runtime_error( "collector evidence body rejected") ;
	}

	DWORD			size{} ;	// 終端を含むbase64容量。
	// SDK byte境界だけで、既に有限な原文字byteを非owningで借用します。
	const auto	   *raw = reinterpret_cast<const BYTE *>( target.rawMetadataBytes.data()) ;
	constexpr DWORD FLAGS =
		CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF ;	// 原byteを改行なしで保持する。
	// 容量確認に失敗した場合は部分出力を作りません。
	if( !CryptBinaryToStringA( raw, static_cast<DWORD>( target.rawMetadataBytes.size()), FLAGS,
							 nullptr, &size)) {
		throw std::runtime_error( "collector evidence encoding failed") ;
	}

	std::string encoded( size, '\0') ;	// 有限なbase64保存buffer。
	// 実変換失敗を空原本文へ置き換えません。
	if( !CryptBinaryToStringA( raw, static_cast<DWORD>( target.rawMetadataBytes.size()), FLAGS,
							 encoded.data(), &size)) {
		throw std::runtime_error( "collector evidence encoding failed") ;
	}

	encoded.resize( size) ;
	// SDKが数える末尾NULだけをJSON文字列から除きます。
	if( !encoded.empty() && encoded.back() == '\0') {
		encoded.pop_back() ;
	}

	JsonObject value ;	// URL、header、端末inventoryを追加しない一回の証拠。
	value.Insert( L"schema", JsonValue::CreateStringValue( L"dc-collector-evidence-v1")) ;
	value.Insert( L"manifestSha256", JsonValue::CreateStringValue( run.manifestSha256)) ;
	value.Insert( L"contractSha256", JsonValue::CreateStringValue( run.contractSha256)) ;
	value.Insert( L"source", JsonValue::CreateStringValue( target.source)) ;
	value.Insert( L"httpStatus", JsonValue::CreateNumberValue( target.lastHttpStatus)) ;
	value.Insert( L"lastSuccessfulValidationAt", JsonValue::CreateNumberValue( static_cast<double>(
													target.lastSuccessfulValidationAt))) ;
	value.Insert( L"bodySha256", JsonValue::CreateStringValue( target.bodySha256)) ;
	value.Insert( L"bodyBytesBase64", JsonValue::CreateStringValue( winrt::to_hstring( encoded))) ;
	JsonArray rows ;	// 同じ原本文を検証したmetadata fieldだけ。
	// 全有限recordの公開値とfingerprintを順序通りに保持します。
	for( const auto &record : target.records) {
		JsonObject row ;	// 一つの検証済みmetadata射影。
		row.Insert( L"fingerprint", JsonValue::CreateStringValue( record.fingerprint)) ;
		row.Insert( L"displayTitle", JsonValue::CreateStringValue( record.displayTitle)) ;
		row.Insert( L"driverCategory", JsonValue::CreateStringValue( record.driverCategory)) ;
		row.Insert( L"operatingSystem", JsonValue::CreateStringValue( record.operatingSystem)) ;
		row.Insert( L"packageVersion", JsonValue::CreateStringValue( record.packageVersion)) ;
		row.Insert( L"publishedDate", JsonValue::CreateStringValue( record.publishedDate)) ;
		rows.Append( row) ;
	}

	value.Insert( L"records", rows) ;
	return winrt::to_string( value.Stringify()) ;
}

/** @brief 原日次入力を保護した同handleから有限に読みます。
 * @param[in] path 固定ProgramData operations一job内の既存file。
 * @param[out] bytes 成功時だけ原byte。失敗時は空。
 * @param[in] maximumBytes 用途が固定する正の上限byte数。
 * @param[in] allowGzip 閉readbackだけのgzip許可です。
 * @return ACL・属性・全byte読取が成立した場合true。
 * @note 祖先とfileを非削除shareで固定し、新規作成・修復を行いません。
 */
[[nodiscard]] bool readDailyReservationReceipt( const std::filesystem::path &path,
											   std::string				   &bytes,
											   const std::uint32_t maximumBytes = 1024U * 1024U,
											   const bool		   allowGzip	= false)
{
	bytes.clear() ;
	// 通常の保護operations以外を原予約証明へ渡さない。
	if( maximumBytes == 0U || maximumBytes > 16U * 1024U * 1024U ||
	   !dailyOutputPath( path, allowGzip)) {
		return false ;
	}

	using OwnedHandle = std::unique_ptr<void, HandleCloser> ;
	std::vector<OwnedHandle> ancestors ;					// 読取完了まで全祖先を固定する。
	auto					 parent = path.parent_path() ;	// drive rootまでの有限cursor。
	// 全祖先のreparseとowner/DACLを同じhandleで検査する。
	while( !parent.empty()) {
		const HANDLE raw = CreateFileW( parent.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
									   FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
									   FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
									   nullptr) ;	// 既存だけ。
		// 欠損を作成して証拠にしない。
		if( raw == INVALID_HANDLE_VALUE) {
			return false ;
		}

		OwnedHandle				   handle( raw) ;	// scope終了時に解放する。
		BY_HANDLE_FILE_INFORMATION info{} ;			// 属性を同handleへ結ぶ。
		// 保護祖先以外から本文を取り込まない。
		if( !GetFileInformationByHandle( raw, &info) ||
		   (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U ||
		   (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U ||
		   !dailyProtectedHandle(
			   raw, parent.native().size() < dailyOperationsRoot().parent_path().native().size(),
			   parent == dailyOperationsRoot().parent_path())) {
			return false ;
		}

		ancestors.push_back( std::move( handle)) ;
		const auto next = parent.parent_path() ;	// 上位の一階層。
		// drive rootで有限走査を終える。
		if( next == parent) {
			break ;
		}

		parent = next ;
	}

	const HANDLE raw =
		CreateFileW( path.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr,
					OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;	// 原fileを固定する。
	// file欠損は初回化しない。
	if( raw == INVALID_HANDLE_VALUE) {
		return false ;
	}

	OwnedHandle				   handle( raw) ;	// 原fileの所有handle。
	BY_HANDLE_FILE_INFORMATION info{} ;			// 同handleのsizeと属性。
	// 用途別byte上限超過、reparse、通常file以外、弱いACLを拒否する。
	if( !GetFileInformationByHandle( raw, &info) ||
	   (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0U ||
	   info.nNumberOfLinks != 1U || info.nFileSizeHigh != 0U || info.nFileSizeLow == 0U ||
	   info.nFileSizeLow > maximumBytes || !dailyProtectedHandle( raw, false, false)) {
		return false ;
	}

	std::string result( info.nFileSizeLow, '\0') ;	// 事前上限内の原byte。
	DWORD		readBytes{} ;						// 一回の有限同期読取量。
	// 短い読取を完全な原receiptへ読み替えない。
	if( !ReadFile( raw, result.data(), info.nFileSizeLow, &readBytes, nullptr) ||
	   readBytes != info.nFileSizeLow) {
		return false ;
	}

	bytes = std::move( result) ;
	return true ;
}

/** @brief 日次の同じ保護jobだけへ新archiveをcommitする同期sinkです。
 * @note 全祖先のpinを本体HTTPより前から保持し、部分fileも既存archiveも削除しません。
 */
class DailyPayloadOutput final {
public:
	/** @brief 新receiptに一意なfinal/partial名と全保護祖先を通信前に固定します。
	 * @param[in] receipt 既存daily writerが受理する新規JSON名です。
	 * @return 全祖先/ACL/新規名を固定できた場合trueです。
	 */
	[[nodiscard]] bool initialize( const std::filesystem::path &receipt)
	{
		// 既存receiptや別jobへ本体を保存しません。
		if( !validEvidenceOutput( receipt, true)) {
			return false ;
		}

		final_ = receipt ;
		final_.replace_extension( L".payload.zip") ;
		partial_ = receipt ;
		partial_.replace_extension( L".payload.partial.zip") ;
		// 途中/完了の原byteを新しい試行で上書きしません。
		if( std::filesystem::exists( final_) || std::filesystem::exists( partial_)) {
			return false ;
		}

		auto parent = receipt.parent_path() ;	// drive rootまでの有限cursorです。
		// 同じ既存daily保護規則で全祖先を非削除shareにpinします。
		while( !parent.empty()) {
			const HANDLE raw = CreateFileW(
				parent.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
				FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
				FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;	// 非作成です。
			// 不明な祖先や権限ではHTTPを開始しません。
			if( raw == INVALID_HANDLE_VALUE) {
				return false ;
			}

			std::unique_ptr<void, HandleCloser> owner( raw) ;	// 終端まで保持します。
			BY_HANDLE_FILE_INFORMATION			info{} ;		// 同handleの原属性です。
			// 既存owner/DACL/reparse規則を緩めません。
			if( !GetFileInformationByHandle( raw, &info) ||
			   (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U ||
			   (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U ||
			   !dailyProtectedHandle( raw,
									 parent.native().size() <
										 dailyOperationsRoot().parent_path().native().size(),
									 parent == dailyOperationsRoot().parent_path())) {
				return false ;
			}

			parents_.push_back( std::move( owner)) ;
			const auto next = parent.parent_path() ;	// 一階層ずつ遡ります。
			// drive rootで有限走査を終了します。
			if( next == parent) {
				break ;
			}

			parent = next ;
		}

		return !parents_.empty() ;
	}

	/** @brief 同sessionの封印/原byteを再照合し、flush後に新final名へ非置換commitします。
	 * @param[in] session 同native runが所有する生存取得sessionです。
	 * @param[in] workspace 同sessionの取得原byteを所有する保護workspaceです。
	 * @param[in] acquired 同sessionが返した一回取得の結果です。
	 * @return 全保存/再hash/atomic rename成功0、元HRESULTです。
	 */
	[[nodiscard]] drivercrate::NativeError commit(
		const drivercrate::OfficialAcquisitionSession &session,
		const drivercrate::OfficialDownloadWorkspace  &workspace,
		const drivercrate::OfficialAcquisitionResult  &acquired)
	{
		drivercrate::OfficialAcquiredFileEvidence evidence ;	// JSONから構築しない私有封印です。
		auto error = session.bindAcquiredFile( workspace, acquired.acquisitionId,
											  evidence) ;	// 原byte再検査です。
		// 生存issuerと同workspaceを要求します。
		if( error == 0) {
			error = session.verifyAcquiredFile( evidence, workspace) ;
		}

		// 失敗結果/無hash/既存名を保存成功へ補完しません。
		if( error != 0 || committed_ || parents_.empty() ||
		   acquired.state != drivercrate::OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
		   !acquired.delegatedRecord ||
		   (!acquired.publishedSha256Verified && !acquired.publishedSha512Verified) ||
		   acquired.byteCount == 0U || acquired.byteCount > 128U * 1024U * 1024U) {
			return error != 0 ? error : static_cast<drivercrate::NativeError>( E_INVALIDARG) ;
		}

		// CopyFileのfailIfExistsでCREATE_NEWと同じ非置換を要求します。
		if( !CopyFileW( acquired.inspectionPath.c_str(), partial_.c_str(), TRUE)) {
			return static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
		}

		const HANDLE raw = CreateFileW(
			partial_.c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL, 0U, nullptr,
			OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;	// 同partialだけを固定します。
		// Copy後のfileを固定できない場合も原partialを保持します。
		if( raw == INVALID_HANDLE_VALUE) {
			return static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
		}

		std::unique_ptr<void, HandleCloser> file( raw) ;	// flushの失敗でもhandleだけを回収します。
		BY_HANDLE_FILE_INFORMATION			info{} ;		// 実size/属性/link数です。
		// コピー先の保護/size/通常fileを再確認します。
		if( !GetFileInformationByHandle( raw, &info) ||
		   (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
			   0U ||
		   info.nNumberOfLinks != 1U || info.nFileSizeHigh != 0U ||
		   info.nFileSizeLow != acquired.byteCount || !dailyProtectedHandle( raw, false, false)) {
			return static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
		}

		// durableにできないpartialをfinalへ昇格しません。
		if( !FlushFileBuffers( raw)) {
			return static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
		}

		// close失敗もcommit成功へ変換しません。
		if( !CloseHandle( file.release())) {
			return static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
		}

		std::wstring actual ;	// 同copy先の実hashです。
		error = drivercrate::computeFileSha256( partial_.native(), actual) ;
		// 元hashから変わったcopyを既存内容検査へ渡しません。
		if( error != 0 || actual != acquired.sha256) {
			return error != 0
					   ? error
					   : static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( ERROR_CRC)) ;
		}

		// 同じ固定親のrenameだけです。REPLACE_EXISTING/COPY_ALLOWEDは使用しません。
		if( !MoveFileExW( partial_.c_str(), final_.c_str(), MOVEFILE_WRITE_THROUGH)) {
			return static_cast<drivercrate::NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
		}

		committed_ = true ;
		return 0 ;
	}

private:
	/// 原byteを上書きしない新final名です。
	std::filesystem::path							 final_ ;
	/// 不確定/失敗時も保持する新partial名です。
	std::filesystem::path							 partial_ ;
	/// HTTP開始前からcommit終了まで固定する全祖先です。
	std::vector<std::unique_ptr<void, HandleCloser>> parents_ ;
	/// 一回の非置換commitだけを許します。
	bool											 committed_{} ;
} ;

/** @brief 明示取得の原同意pinを読み、同run用の期待値だけへ変換します。
 * @param[in] args 正確な十argvです。原releaseは既存保護operations内です。
 * @param[out] request 原terms/hash/今回予算だけです。公式authorityは作りません。
 * @return 明示同意・全byte pin・原releaseの最小条件を満たす場合trueです。
 */
[[nodiscard]] bool readPayloadApproval( wchar_t *const							  args[],
									   drivercrate::LocalCollectorPayloadRequest &request)
{
	// 同意switchを省略または置換した呼出しを受理しません。
	if( std::wstring_view( args[9]) != L"--accept-pinned-terms") {
		return false ;
	}

	std::string	 raw ;	// 同handleの保護原release byteです。
	std::wstring hash ;	// 呼出しが明示pinした全byteの実hashです。
	// 原terms inputをprivate authorityへ変換せず、全byte期待値だけを確認します。
	if( !readDailyReservationReceipt( args[5], raw) ||
	   drivercrate::computeBytesSha256( raw, hash) != 0 || hash != args[6]) {
		return false ;
	}

	// 全algorithmとmetadataの共通readerを同runの期待値だけへ使用します。
	if( !drivercrate::decodeLocalCollectorPayloadApproval( raw, request)) {
		return false ;
	}

	// 予算と同意期限を有限十進整数としてだけ受理します。
	for( unsigned index = 7U; index <= 8U; ++index) {
		const std::string literal =
			// 元引数のASCII検査です。
			winrt::to_string( winrt::hstring{args[index]}) ;
		std::uint64_t value{} ;	// overflow時に部分値を使いません。
		const auto	  parsed = std::from_chars( literal.data(), literal.data() + literal.size(),
											   value) ;	// 非locale整数です。
		// 空/符号/先頭0/余剰文字を受理しません。
		if( literal.empty() || literal.front() < '1' || literal.front() > '9' ||
		   parsed.ec != std::errc{} || parsed.ptr != literal.data() + literal.size()) {
			return false ;
		}

		// 位置を固定し、予算と時刻を取り違えません。
		if( index == 7U) {
			request.maximumBytes = value ;
		} else {
			request.consentNotAfter = value ;
		}
	}

	request.termsAccepted = true ;
	return true ;
}

/** @brief 閉readback modeだけを有限readerと非保存nativeへ接続します。
 * @param[in] count 実行file名込みの引数数です。
 * @param[in] args 全引数を呼出し中借用します。
 * @return canonical stdoutの全検証成功0、UNKNOWNまたは出力失敗2です。
 * @note URL、path、例外文を標準出力または標準errorへ出しません。
 */
[[nodiscard]] int runPublicIndexReadback( const int count, wchar_t *const args[])
{
	drivercrate::PublicIndexReadbackReport report ;					// 引数拒否時も同じ閉wireです。
	const auto started		= std::chrono::steady_clock::now() ;	// reader待機を含む一つの開始です。
	const auto startedAtUtc = std::chrono::floor<std::chrono::seconds>(
		// 入口の元UTCです。
		std::chrono::system_clock::now()) ;
	report.startedAtUtc	   = startedAtUtc ;
	bool		  executed = false ;	// nativeが所有した終了観測を入口で上書きしません。
	std::uint32_t milliseconds{} ;		// 正確な五argvでだけ設定します。
	try {
		// 余剰URLや任意trustの指定では保護fileも読取りません。
		if( drivercrate::publicIndexReadbackArguments( count, args, milliseconds)) {
			report.failureStage = drivercrate::PublicIndexFailureStage::INPUT ;
			const std::filesystem::path envelopePath{args[2]} ;	// 元保護jobのenvelopeです。
			const std::filesystem::path gzipPath{args[3]} ;		// 同prefixのgzipです。
			const auto					envelopeName =
				// 有限ASCII名だけを検査します。
				envelopePath.filename().native() ;
			const std::wstring suffix =
				L".acquisition.manifest.json" ;	// 元public orchestrationの固定suffixです。
			std::string envelope ;				// 同handle readerだけが設定する原byteです。
			std::string gzip ;					// 同じ保護job内の原gzipです。
			// 正確なJST day prefixと固定二fileの組だけを許可します。
			if( envelopeName.size() == 8U + suffix.size() && envelopeName.ends_with( suffix) &&
			   std::all_of( envelopeName.begin(), envelopeName.begin() + 8U,
						   []( const wchar_t c) { return c >= L'0' && c <= L'9' ; }) &&
			   gzipPath.parent_path() == envelopePath.parent_path() &&
			   gzipPath.filename() == envelopeName.substr( 0U, 8U) + L".acquisition.index.json.gz" &&
			   readDailyReservationReceipt( envelopePath, envelope, 98304U) &&
			   readDailyReservationReceipt( gzipPath, gzip, 16U * 1024U * 1024U, true)) {
				const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
										 std::chrono::steady_clock::now() - started)
										 .count() ;	// 読取時間を再起点化しません。
				// readerが親の残枠を使い切った場合、HTTPを開始しません。
				if( elapsed >= 0 && elapsed < milliseconds) {
					report	 = drivercrate::readbackFixedPublicIndex( envelope, gzip, milliseconds,
																	 started, startedAtUtc) ;
					executed = true ;
				} else {
					report.failureStage = drivercrate::PublicIndexFailureStage::TIME ;
					report.nativeError	= HRESULT_FROM_WIN32( ERROR_TIMEOUT) ;
				}
			}
		}
	} catch( ...) {
		report.verified	   = false ;
		report.nativeError = E_UNEXPECTED ;
	}

	// 引数・保護読取拒否も実際に取得できた入口と終了の時計を残します。
	if( !executed) {
		report.completedAtUtc =
			std::chrono::floor<std::chrono::seconds>( std::chrono::system_clock::now()) ;
		report.elapsedMilliseconds =
			static_cast<std::uint64_t>( std::chrono::duration_cast<std::chrono::milliseconds>(
										   std::chrono::steady_clock::now() - started)
										   .count()) ;
	}

	try {
		const auto output =
			// 任意textを含まない閉writerです。
			drivercrate::publicIndexReadbackJson( report) ;
		// 出力の切断とflush失敗を成功にしません。
		if( output.empty() || output.size() > 65536U ||
		   std::fwrite( output.data(), 1U, output.size(), stdout) != output.size() ||
		   std::fflush( stdout) != 0) {
			return 2 ;
		}

		return report.verified ? 0 : 2 ;
	} catch( ...) {
		// writerの確保・閉wire拒否をprocess境界へ漏らしません。
		return 2 ;
	}
}

/** @brief 明示local jobを同handleと固定祖先から有限読取りします。
 * @param[in] path 明示した絶対通常固定driveのJSONです。
 * @param[out] bytes 成功時だけ最大1MiBの原byteです。失敗時空です。
 * @return 全属性・祖先・原sizeが成立した場合trueです。
 * @note 非通信validate専用です。ACL修復、state初期化、予約、出力保存を行いません。
 */
[[nodiscard]] bool readRegistryJobFile( const std::filesystem::path &path, std::string &bytes)
{
	using OwnedHandle = std::unique_ptr<void, HandleCloser> ;	// 同じ既存deleterのscope所有です。
	bytes.clear() ;
	// UNC・ADS・相対成分・reparse経由を明示入力でも受理しません。
	if( !path.is_absolute() || path != path.lexically_normal() || path.extension() != L".json" ||
	   path.native().size() > 240U || path.native().find( L':', 2U) != std::wstring::npos ||
	   GetDriveTypeW( path.root_path().c_str()) != DRIVE_FIXED) {
		return false ;
	}

	std::vector<OwnedHandle> parents ;						// 祖先を非削除shareで固定します。
	auto					 parent = path.root_path() ;	// 検証済み固定drive起点です。
	// 起点から親までを順にpinし、後からjunctionへ置き換えさせません。
	for( const auto &component : path.parent_path().relative_path()) {
		parent /= component ;
		OwnedHandle				   pinned( CreateFileW( parent.c_str(), FILE_READ_ATTRIBUTES,
													  FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
													  FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
													  nullptr)) ;	// 同祖先の所有handleです。
		BY_HANDLE_FILE_INFORMATION info{} ;							// 変更を解決しない元属性です。
		// 存在しない祖先、通常file、reparseを拒否します。
		if( pinned.get() == INVALID_HANDLE_VALUE ||
		   !GetFileInformationByHandle( pinned.get(), &info) ||
		   (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U ||
		   (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U) {
			return false ;
		}

		parents.push_back( std::move( pinned)) ;
	}

	OwnedHandle				   handle( CreateFileW(
		   path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		   FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)) ;	// 原fileを固定します。
	BY_HANDLE_FILE_INFORMATION info{} ;												// 同handleの原size/通常属性です。
	// Hardlinkと過大fileを通常jobへ取り込みません。
	if( handle.get() == INVALID_HANDLE_VALUE || !GetFileInformationByHandle( handle.get(), &info) ||
	   (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0U ||
	   info.nNumberOfLinks != 1U || info.nFileSizeHigh != 0U || info.nFileSizeLow == 0U ||
	   info.nFileSizeLow > drivercrate::COLLECTOR_REGISTRY_JOB_MAX_BYTES) {
		return false ;
	}

	std::string raw( info.nFileSizeLow, '\0') ;	// 検証済み上限内だけを確保します。
	DWORD		received{} ;					// 同file原byteの全読取数です。
	// 部分読取を成功JSONへ補完しません。
	if( !ReadFile( handle.get(), raw.data(), info.nFileSizeLow, &received, nullptr) ||
	   received != info.nFileSizeLow) {
		return false ;
	}

	bytes = std::move( raw) ;
	return true ;
}

/** @brief 非通信registry job modeだけを実行します。
 * @param[in] count 実行file名込みの引数数です。
 * @param[in] args 同呼出し中に借用する全引数です。
 * @return 厳密検証成功0、引数・file・schema拒否2です。
 */
[[nodiscard]] int validateRegistryJob( const int count, wchar_t *const args[])
{
	try {
		std::string						  bytes ;	// 同handleの有限原byteだけです。
		drivercrate::CollectorRegistryJob job ;		// 許可や成功証拠を持たない検証結果です。
		winrt::init_apartment(
			winrt::apartment_type::multi_threaded) ;	// JSONの同thread apartmentです。
		// 余剰引数を未知の実行条件へ流しません。
		if( count == 3 && args[2] != nullptr && readRegistryJobFile( args[2], bytes) &&
		   drivercrate::parseCollectorRegistryJob( bytes, job) == 0) {
			std::printf( "COLLECTOR_REGISTRY_JOB valid=1 products=%zu network=0 inspection=0\n",
						job.productCount()) ;
			return 0 ;
		}
	} catch( ...) {
		// OS/JSON例外をcode付き固定拒否へ閉じます。
	}

	std::printf( "COLLECTOR_REGISTRY_JOB valid=0 error=87 network=0 inspection=0\n") ;
	return 2 ;
}
} // namespace

/**
 * @brief 一manifestのmetadata、または明示同意した同record一fileを有限に収集します。
 * @param[in] count 実行file名を含む引数数。registry非通信検証は3、通常と旧待機exportは4、
 *                 evidenceとreadbackは5、予約照合は6、明示本体取得は10です。
 * @param[in] args count個のNULL終端wide文字列を本呼出し中だけ借用します。args[0]は実行file名です。
 *                 `--once manifest stateRoot`と`--validate manifest stateRoot`は収集と非通信検証です。
 *                 `--export-legacy-waits protectedRoot newFile`は旧待機を検証して新規fileへ出力します。
 *                 `--once-evidence manifest stateRoot newFile`は一回収集の原byteを新規fileへ保存します。
 *                 `--daily-evidence manifest stateRoot receipt`は日次の保護されたreceipt出力先を取ります。
 *                 `--daily-acquire manifest stateRoot receipt approvedRelease releaseSha256 maximumBytes
 *                 consentNotAfter --accept-pinned-terms`は同runの一fileだけを新規保存します。
 *                 失敗時の完全200だけをreceiptと同jobの固定派生.failed-page.jsonへ診断保存します。
 *                 診断保存の数値結果はstderrだけへ渡し、元stdout/終了値を維持します。
 *                 `--verify-daily-reservation manifest stateRoot receipt FRESH_INPUT|LEGACY_FENCE`は
 *                 保存済み予約と保護receiptを明示用途で非変更照合します。欠損引数は拒否します。
 *                 `--public-index-readback envelope gzip remainingMilliseconds`は固定三URLを匿名照合します。
 *                 `--validate-registry-job absoluteJob.json`は外部jobの非通信検証です。
 *                 `--registry-job`は保護予約caller未接続のため引数にかかわらず拒否します。
 * @return 選択したmodeの終了codeです。
 * @retval 0 全件確認、registryを含む非通信検証、旧待機export、予約照合、または匿名三resource確認の成功です。
 * @retval 1 収集runの部分失敗です。
 * @retval 2 入力・状態・保存の拒否、例外、または予約照合APIの非0結果です。
 * @retval 3 日次due前のHOLDです。
 */
int wmain( const int count, wchar_t *args[])
{
	// 新しい明示取得modeを通常metadataや旧onceへfallbackさせません。
	if( count >= 2 && args != nullptr && args[1] != nullptr &&
	   std::wstring_view( args[1]) == L"--daily-acquire") {
		try {
			// 全固定argvと明示同意を揃えない場合、保護fileも読みません。
			if( count != 10 || std::any_of( args + 2, args + count,
										  []( const wchar_t *value) { return value == nullptr ; })) {
				std::printf( "COLLECTOR_PAYLOAD error=87 stage=0 acquired=0 installed=0\n") ;
				return 2 ;
			}

			winrt::init_apartment(
				winrt::apartment_type::multi_threaded) ;				// 同threadのJSON/OS costです。
			std::vector<drivercrate::LocalCollectorTarget> targets ;	// 既存一対象manifestです。
			std::wstring								   manifest ;	// 元manifest全byteです。
			drivercrate::LocalCollectorPayloadRequest	   payload ;	// 同意と期待値だけです。
			DailyPayloadOutput	  output ;								// HTTP前から全保護親をpinします。
			std::filesystem::path failedPageOutput{args[4]} ;			// 元receiptと同jobの固定派生先です。
			failedPageOutput.replace_extension( L".failed-page.json") ;
			// 不正inputや保存先を新PAGEの試行前に拒否します。
			if( !drivercrate::loadLocalCollectorManifest( args[2], targets, manifest) ||
			   targets.size() != 1U || targets.front().source != L"INTEL_ETHERNET_WINDOWS11" ||
			   !readPayloadApproval( args, payload) || !output.initialize( args[4]) ||
			   !validEvidenceOutput( failedPageOutput, true)) {
				std::printf( "COLLECTOR_PAYLOAD error=13 stage=0 acquired=0 installed=0\n") ;
				return 2 ;
			}

			payload.commitArchive = [&output]( const auto &session, const auto &workspace,
											  const auto &acquired) {
				return output.commit( session, workspace, acquired) ;
			} ; // 同呼出しだけのsinkです。
			drivercrate::LocalCollectorRun run ;	// 元writer/待機/世代を共用します。
			const int					   code = drivercrate::runLocalDriverCollector(
				 args[3], targets, manifest, false, run, false, true,
				 &payload) ;					// 同runのtyped recordだけで取得します。
			DWORD		saved = ERROR_SUCCESS ;	// HOLD/FAILも元daily receiptへ分離します。
			std::string receiptBytes ;			// 診断は実保存した元receipt全byteへだけ結びます。
			// 状態拒否を保存成功で隠さず、元writer完了後だけreceiptを新規保存します。
			if( code != 2) {
				saved = drivercrate::makeLocalCollectorDailyReceipt( run, receiptBytes)
							? writeLegacyExport( args[4], receiptBytes, true)
							: ERROR_INVALID_DATA ;
			}

			// 診断生成/保存失敗で元収集失敗や元receipt保存結果を隠しません。
			if( code == 1) {
				const DWORD diagnosticSaved =
					saved == ERROR_SUCCESS
						? saveFailedPageDiagnostic( failedPageOutput, run, receiptBytes, code)
						: saved ;	// 元receiptが未保存なら本文診断も保存しません。
				std::fprintf( stderr, "COLLECTOR_FAILED_PAGE save_error=%u captured=%d\n",
							 static_cast<unsigned>( diagnosticSaved),
							 diagnosticSaved == ERROR_SUCCESS ? 1 : 0) ;
			}

			const bool acquired = code == 0 && saved == 0U && run.targets.size() == 1U &&
								  // 今回の実保存だけです。
								  run.targets.front().payloadAcquiredThisInvocation ;
			std::printf(
				"COLLECTOR_PAYLOAD save_error=%u held=%d not_before=%llu stage=%u acquired=%d installed=0\n",
				static_cast<unsigned>( saved), run.dailyHeld ? 1 : 0,
				static_cast<unsigned long long>( run.dailyNotBefore),
				run.targets.size() == 1U
					? static_cast<unsigned>( run.targets.front().failureStageThisInvocation)
					: 0U,
				acquired ? 1 : 0) ;
			return saved != 0U ? 2 : (code == 0 && !acquired ? 3 : code) ;
		} catch( ...) {
			std::printf( "COLLECTOR_PAYLOAD error=13 stage=0 acquired=0 installed=0\n") ;
			return 2 ;
		}
	}

	// 新modeは既存予約や旧onceの入口へfallbackさせません。
	if( count >= 2 && args != nullptr && args[1] != nullptr &&
	   std::wstring_view( args[1]) == L"--validate-registry-job") {
		return validateRegistryJob( count, args) ;
	}

	// 後続lock/admission・PAGE/payload予約が未接続の間は任意JSONによる通信を拒否します。
	if( count >= 2 && args != nullptr && args[1] != nullptr &&
	   std::wstring_view( args[1]) == L"--registry-job") {
		std::printf(
			"COLLECTOR_REGISTRY_JOB error=NATIVE_ADMISSION_NOT_CONNECTED network=0 inspection=0\n") ;
		return 2 ;
	}

	// 明示readbackの誤引数を旧modeへfallbackさせません。
	if( count >= 2 && args != nullptr && args[1] != nullptr &&
	   std::wstring_view( args[1]) == L"--public-index-readback") {
		return runPublicIndexReadback( count, args) ;
	}

	// 明示した六引数だけを非変更照合へ渡し、旧実行modeへfallbackしない。
	if( count == 6 && args != nullptr && args[1] != nullptr &&
	   std::wstring_view( args[1]) == L"--verify-daily-reservation") {
		try {
			// 欠損modeや未定義modeでは保護fileも読まない。
			if( args[2] == nullptr || args[3] == nullptr || args[4] == nullptr ||
			   args[5] == nullptr ||
			   (std::wstring_view( args[5]) != L"FRESH_INPUT" &&
				std::wstring_view( args[5]) != L"LEGACY_FENCE")) {
				std::printf( "COLLECTOR_RESERVATION error=87\n") ;
				return 2 ;
			}

			std::vector<drivercrate::LocalCollectorTarget> targets ;	// manifestの固定公開target。
			std::wstring								   hash ;		// manifest全byteのhash。
			std::string									   bytes ;		// 保護readerが固定した原receipt。
			// 既存Intel一対象と保護原byteだけをAPIへ接続する。
			if( !drivercrate::loadLocalCollectorManifest( args[2], targets, hash) ||
			   targets.size() != 1U || targets.front().source != L"INTEL_ETHERNET_WINDOWS11" ||
			   !readDailyReservationReceipt( args[4], bytes)) {
				std::printf( "COLLECTOR_RESERVATION error=13\n") ;
				return 2 ;
			}

			const auto mode =
				std::wstring_view( args[5]) == L"FRESH_INPUT"
					? drivercrate::LocalCollectorReservationMode::FRESH_INPUT
					: drivercrate::LocalCollectorReservationMode::LEGACY_FENCE ;	// 明示用途。
			drivercrate::LocalCollectorReservationFacts facts ;						// 非秘密factsだけ。
			const auto code = drivercrate::verifyLocalCollectorDailyReservation(
				args[3], hash, bytes, mode, facts) ;	// 非変更。
			std::printf(
				"COLLECTOR_RESERVATION error=%u mode=%ls generation=%llu receipt_sha256=%ls\n",
				static_cast<unsigned>( code), args[5],
				static_cast<unsigned long long>( facts.generation), facts.receiptSha256.c_str()) ;
			return code == 0U ? 0 : 2 ;
		} catch( ...) {
			std::printf( "COLLECTOR_RESERVATION error=13\n") ;
			return 2 ;
		}
	}

	// 入力と出力を有限上限内へ制限する。
	if( args == nullptr || (count != 4 && count != 5) || args[1] == nullptr || args[2] == nullptr ||
	   args[3] == nullptr) {
		std::printf( "COLLECTOR_REJECTED stage=arguments\n") ;
		return 2 ;
	}

	// 明示された一回実行modeを保持する。
	const std::wstring_view command( args[1]) ;
	// この段階の入力条件を満たさない値を採用しない。
	if( (count == 5 && ((command != L"--once-evidence" && command != L"--daily-evidence") ||
					   args[4] == nullptr)) ||
	   (count == 4 && command != L"--once" && command != L"--validate" &&
		command != L"--export-legacy-waits")) {
		std::printf( "COLLECTOR_REJECTED stage=arguments\n") ;
		return 2 ;
	}

	try {
		const bool evidenceMode = command == L"--once-evidence" ;	// 明示modeだけの原byte保存。
		const bool dailyMode = command == L"--daily-evidence" ;		// 新200と実304を区別する日次入口。
		// 不正または既存出力へ原本文を取得しません。
		if( (evidenceMode || dailyMode) && !validEvidenceOutput( args[4], dailyMode)) {
			std::printf( "COLLECTOR_REJECTED stage=evidence-output\n") ;
			return 2 ;
		}

		// 旧待機の出力だけではmetadata取得やrun開始へ進めない。
		if( command == L"--export-legacy-waits") {
			drivercrate::CollectorLegacySnapshot snapshot ;	// 完全検証後だけの旧待機。
			std::string							 bytes ;	// URL・pathを含めない持出しJSON。
			const auto epoch = std::chrono::duration_cast<std::chrono::milliseconds>(
								   std::chrono::system_clock::now().time_since_epoch())
								   .count() ;	// CLI内部のOS時計。
			DWORD code = epoch > 0
							 ? drivercrate::prepareLocalCollectorLegacyExport(
								   args[2], static_cast<std::uint64_t>( epoch), snapshot, bytes)
							 : ERROR_INVALID_DATA ;	// 非変更検査。
			// 旧検証成功後だけ新規fileを作成する。
			if( code == ERROR_SUCCESS) {
				code = writeLegacyExport( args[3], bytes) ;
			}

			std::printf(
				"COLLECTOR_LEGACY_EXPORT state_error=%u files=%u waits=%zu network=0 acquired=0 installed=0\n",
				static_cast<unsigned>( code), snapshot.fileCount, snapshot.waits.size()) ;
			return code == ERROR_SUCCESS ? 0 : 2 ;
		}

		// 検証済みmanifestの公開target集合を保持する。
		std::vector<drivercrate::LocalCollectorTarget> targets ;
		// 実byte SHA-256。
		std::wstring								   hash ;
		// 実byteの指紋と保存済みの結合を確認する。
		if( !drivercrate::loadLocalCollectorManifest( args[2], targets, hash)) {
			std::printf( "COLLECTOR_REJECTED stage=manifest\n") ;
			return 2 ;
		}

		// 初回evidence seamは同じ登録済みIntel一対象だけに限定します。
		if( (evidenceMode || dailyMode) &&
		   (targets.size() != 1U || targets.front().source != L"INTEL_ETHERNET_WINDOWS11")) {
			std::printf( "COLLECTOR_REJECTED stage=evidence-target\n") ;
			return 2 ;
		}

		drivercrate::LocalCollectorRun run ;
		// 今回のtarget別保存結果。
		const int					   result = drivercrate::runLocalDriverCollector(
			 std::filesystem::path( args[3]), targets, hash, command == L"--validate", run,
			 evidenceMode, dailyMode) ;
		// 日次receiptはHOLDと未通信も保存し、投影側が新観測だけを選別します。
		if( dailyMode && result != 2) {
			std::string bytes ;	// 有限な明示出力。通常logへ渡しません。
			const DWORD saved = drivercrate::makeLocalCollectorDailyReceipt( run, bytes)
									? writeLegacyExport( args[4], bytes, true)
									: ERROR_INVALID_DATA ;	// 本文欠測は拒否。
			std::printf(
				"COLLECTOR_DAILY save_error=%u held=%d not_before=%llu acquired=0 installed=0\n",
				static_cast<unsigned>( saved), run.dailyHeld ? 1 : 0,
				static_cast<unsigned long long>( run.dailyNotBefore)) ;
			// 部分書込みも新しい索引の根拠にしません。
			if( saved != ERROR_SUCCESS) {
				return 2 ;
			}
		}

		// 実収集成功でも保存／原byte欠測を索引投影成功へ読み替えません。
		if( evidenceMode && result == 0) {
			const DWORD saved =
				// CREATE_NEWだけ。
				writeLegacyExport( args[4], collectorEvidenceBytes( run)) ;
			std::printf( "COLLECTOR_EVIDENCE save_error=%u acquired=0 installed=0\n",
						static_cast<unsigned>( saved)) ;
			// 部分保存や既存出力拒否は全体失敗へ残します。
			if( saved != ERROR_SUCCESS) {
				return 2 ;
			}
		}

		// 今回更新された公開targetの件数を数える。
		std::size_t updated{} ;
		// 前回と同じだった公開targetの件数を数える。
		std::size_t unchanged{} ;
		// 部分失敗の集計状態。
		std::size_t failed{} ;
		// 空・減少・待機不明を成功と分離する。
		std::size_t held{} ;
		// 期限または予算で延期したtargetの件数を数える。
		std::size_t deferred{} ;
		// 今回の有限公式record集合。
		std::size_t records{} ;
		// 有限集合の各要素を順に検証し、件数と順序を保持する。
		for( const auto &target : run.targets) {
			updated += target.state == drivercrate::LocalCollectorTargetState::UPDATED ? 1U : 0U ;
			unchanged +=
				target.state == drivercrate::LocalCollectorTargetState::UNCHANGED ? 1U : 0U ;
			failed += target.state == drivercrate::LocalCollectorTargetState::FAILED ? 1U : 0U ;
			held += target.state == drivercrate::LocalCollectorTargetState::HELD ? 1U : 0U ;
			deferred += target.state == drivercrate::LocalCollectorTargetState::DEFERRED ? 1U : 0U ;
			records += target.records.size() ;
		}

		std::printf(
			"COLLECTOR_RESULT code=%d state_error=%u reused=%d resumed_earlier_day=%d recovered_commit=%d targets=%zu updated=%zu unchanged=%zu errors=%zu held=%zu deferred=%zu records=%zu acquired=0 installed=0\n",
			result, run.stateError, run.reusedCheckpoint ? 1 : 0, run.resumedEarlierDay ? 1 : 0,
			run.recoveredCommit ? 1 : 0, run.targets.size(), updated, unchanged, failed, held,
			deferred, records) ;
		return result ;
	} catch( ...) {
		std::printf( "COLLECTOR_FAILURE stage=exception acquired=0 installed=0\n") ;
		return 2 ;
	}
}
