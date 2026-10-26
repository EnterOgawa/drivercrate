//------------------------------------------------------------------------------
/**
 * @file collector_registry_job_tests.cpp
 * @brief 厳密外部jobと同取得・検査結果の結合を完全fakeで検証します。
 * @version 01.04.00
 * @date 2026/10/24
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/23  外部job・完全HTTP fake・通常検査seam回帰を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/23  未記載台帳URLと確認済みlocatorの分離回帰を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/23  実転送/同run PAGE/私有capの完全fake回帰を追加。
 * Ver.01.01.01 Shunji Ogawa  2026/10/23  再開時の失敗行診断と収集cap超過読取り上限の回帰を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/23  同結果の投影と複数INF/表現限界専用metadata seamを追加。
 * Ver.01.02.01 Shunji Ogawa  2026/10/23  実parser正例も使うmode12の検査境界説明を更新。
 * Ver.01.03.00 Shunji Ogawa  2026/10/24  現行nested member identityと原record完全tupleへ整合。
 * Ver.01.03.01 Shunji Ogawa  2026/10/24  必須解析に合わせ試験の所有・型・失敗制御を明示。
 * Ver.01.03.02 Shunji Ogawa  2026/10/25  各手動確認時刻の順序/未来拒否と原PAGE保持を回帰。
 * Ver.01.04.00 Shunji Ogawa  2026/10/25  現行v2の独立content digestとraw bindingを固定。
 * </pre>
 *
 * @note 全HTTP／DNSをfixtureへ置換し、実network・導入・Taskを使用しない。
 * @see docs/adr/0280-collector-scoped-inspection-acquisition.md
 */
//------------------------------------------------------------------------------
#include "platform/collector_registry_job.h"
#include "platform/official_file_verifier.h"
#include "platform/signed_index_json_internal.h"
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#include <string>
#include <cstdint>
#include "platform/official_download_workspace.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <vector>
#include <utility>
#include <chrono>
#include <limits>
#include <memory>
#include <type_traits>
#include <source_location>
#include <array>
#include <Windows.h>
#include <winhttp.h>

namespace {
/** @brief 一hopの架空応答。 */
struct Response {
	/// HTML起点または検査payloadの本文。
	std::string					body ;
	/// 受信headerのstatus。
	DWORD						status{200U} ;
	/// HTMLのMIMEとUTF-8。
	std::wstring				mime{L"text/html; charset=utf-8"} ;
	/// 同一origin内redirect fixture。
	std::optional<std::wstring> location ;
	/// 明示した場合だけ宣言長を実本文から独立させます。
	std::optional<std::wstring> contentLength ;
} ;
/** @brief 同期HTTP表を全部置換する一fixture。 */
struct Fixture {
	/// 送信順の二応答。
	std::vector<Response>					responses ;
	/// 完了した送信回数。未送信0。
	std::size_t								sends{} ;
	/// 現本文の読取byte位置。
	std::size_t								offset{} ;
	/// 作成したfake handle数。
	std::size_t								opened{} ;
	/// 全fake handleの解放数。
	std::size_t								closed{} ;
	/// 全resolver呼出し数。
	std::size_t								dns{} ;
	/// trueなら一宛先をprivateにする。
	bool									privateAddress{} ;
	/// trueなら二回目以降のpayload DNSだけprivateにする。
	bool									privatePayload{} ;
	/// trueなら本文途中でReadDataを失敗させる。
	bool									failRead{} ;
	/// 実send呼出しの試行数です。失敗sendも数えます。
	std::size_t								attempts{} ;
	/// Handle作成失敗でsend前停止を再現します。
	bool									failOpen{} ;
	/// 実send失敗を再現します。
	bool									failSend{} ;
	/// 読取り済み本文量がこの値へ達した後のreadを失敗します。
	std::optional<std::size_t>				failAfterBytes ;
	/// 有限chunkへ分けて途中故障を注入します。
	std::size_t								chunkBytes{64U * 1024U} ;
	/// 1始まりの故障対象responseです。0は全responseです。
	std::size_t								faultResponse{} ;
	/// Payloadの保存終端だけを失敗します。
	bool									failFlush{} ;
	/// ReadData完了後の取消しを再現します。
	bool									cancelAfterRead{} ;
	/// 同期待機中の取消しを親callbackへ返します。
	bool									cancelled{} ;
	/// 次のDataAvailableで例外を送出する故障です。
	bool									throwAfterRead{} ;
	/// Fake通常検査に到達したsessionを記録します。
	std::vector<drivercrate::ScanSessionId> sessions ;
	/// 各jobの新しい保護workspaceから渡された実archive pathです。出力しません。
	std::vector<std::wstring>				inspectionPaths ;
	/// 安全なtimeout・cookie・credential条件が維持された場合true。
	bool									safe{true} ;
} ;
thread_local Fixture *fixture{} ;	// 同期試験scopeだけの非所有参照。
std::size_t			  checks{} ;	// 独立した有限assertion数。

/** @brief 失敗時は固定診断だけで終了する。
 * @param[in] condition 個別の期待条件。
 * @param[in] location 固定試験の失敗行です。絶対pathや入力内容は表示しません。
 */
void check( bool condition, const std::source_location location = std::source_location::current())
{
	++checks ;
	// 元入力やURLを診断へ含めない。
	if( !condition) {
		std::printf( "Collector registry job failed at source line: %u\n", location.line()) ;
		throw std::runtime_error( "COLLECTOR_INSPECTION_CHECK") ;
	}
}

/** @brief 全WinHTTP／DNS関数を架空表へ置換する。
 * @return Native呼出しへfallbackしない完全表。
 */
drivercrate::OfficialHttpTransport transport()
{
	drivercrate::OfficialHttpTransport api ;	// 下の全関数で上書きする所有表。
	api.open = []( LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) -> HINTERNET {
		// 未送信のhandle故障をURL検証済み要求へ数えません。
		if( fixture->failOpen) {
			SetLastError( ERROR_NOT_ENOUGH_MEMORY) ;
			return nullptr ;
		}

		++fixture->opened ;
		return fixture ;
	} ;
	api.connect = []( HINTERNET, LPCWSTR, INTERNET_PORT, DWORD) -> HINTERNET {
		++fixture->opened ;
		return fixture ;
	} ;
	api.openRequest = []( HINTERNET, LPCWSTR verb, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *,
						 DWORD) -> HINTERNET {
		fixture->safe &= std::wstring_view( verb) == L"GET" ;
		++fixture->opened ;
		return fixture ;
	} ;
	api.setTimeouts = []( HINTERNET, int resolve, int connect, int send, int receive) -> BOOL {
		fixture->safe &= resolve > 0 && connect > 0 && send > 0 && receive > 0 ;
		return TRUE ;
	} ;
	api.setOption = []( HINTERNET, DWORD option, LPVOID value, DWORD size) -> BOOL {
		// 誤ったoption bufferは試験失敗として記録し、無効なDWORDを参照しない。
		if( value == nullptr || size != sizeof( DWORD)) {
			fixture->safe = false ;
			SetLastError( ERROR_INVALID_PARAMETER) ;
			return FALSE ;
		}

		const auto setting = *static_cast<DWORD *>( value) ;	// 架空optionの有限DWORD。
		// 既定資格情報を送る設定を試験でも拒否する。
		if( option == WINHTTP_OPTION_AUTOLOGON_POLICY) {
			fixture->safe &= setting == WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH ;
		}

		// Cookieの自動処理を両HTTPで無効化する。
		if( option == WINHTTP_OPTION_DISABLE_FEATURE) {
			fixture->safe &= (setting & WINHTTP_DISABLE_COOKIES) != 0U ;
		}

		return TRUE ;
	} ;
	api.addHeaders = []( HINTERNET, LPCWSTR text, DWORD size, DWORD) -> BOOL {
		const std::wstring_view value( text, size) ;	// 共通HTTPが設定する非秘密headerだけ。
		fixture->safe &= value.starts_with( L"Accept: ") || value == L"Cache-Control: no-cache\r\n" ;
		return TRUE ;
	} ;
	api.sendRequest = []( HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR) -> BOOL {
		++fixture->attempts ;
		// 実send失敗も試行実数へ残します。
		if( fixture->failSend) {
			SetLastError( ERROR_WINHTTP_CONNECTION_ERROR) ;
			return FALSE ;
		}

		// 用意した二応答を超える再送を拒否する。
		if( fixture->sends >= fixture->responses.size()) {
			SetLastError( ERROR_WINHTTP_INVALID_SERVER_RESPONSE) ;
			return FALSE ;
		}

		++fixture->sends ;
		fixture->offset = 0U ;
		return TRUE ;
	} ;
	api.receiveResponse = []( HINTERNET, LPVOID) -> BOOL { return TRUE ; } ;
	api.queryHeaders	= []( HINTERNET, DWORD info, LPCWSTR, LPVOID output, LPDWORD size,
							 LPDWORD) -> BOOL {
		   const auto &response = fixture->responses.at( fixture->sends - 1U) ;	// 現hopの不変応答。
		   // Statusだけは数値として返す。
		   if( info == (WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER)) {
			   *static_cast<DWORD *>( output) = response.status ;
			   *size						 = sizeof( DWORD) ;
			   return TRUE ;
		   }

		   std::wstring text ;	// 元fixture以外のheaderを合成しない。
		   // HTML MIMEの二段照会を再現する。
		   if( info == WINHTTP_QUERY_CONTENT_TYPE) {
			   text = response.mime ;
		   }
		   // 同じ本文の完全な実byte数だけを宣言する。
		   else if( info == WINHTTP_QUERY_CONTENT_LENGTH) {
			   text = response.contentLength.value_or( std::to_wstring( response.body.size())) ;
		   }
		   // 明示redirect以外にLocationを付与しない。
		   else if( info == WINHTTP_QUERY_LOCATION && response.location) {
			   text = *response.location ;
		   } else {
			   SetLastError( ERROR_WINHTTP_HEADER_NOT_FOUND) ;
			   return FALSE ;
		   }

		   const auto required =
			   // 有限header量。
			   static_cast<DWORD>( (text.size() + 1U) * sizeof( wchar_t)) ;
		   // WinHTTPの第一段または容量不足を同じerrorで再現する。
		   if( output == nullptr || *size < required) {
			   *size = required ;
			   SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			   return FALSE ;
		   }

		   std::memcpy( output, text.c_str(), required) ;
		   *size = required - sizeof( wchar_t) ;
		   return TRUE ;
	} ;
	api.queryAvailable = []( HINTERNET, LPDWORD size) -> BOOL {
		// API例外後も先行read実数を破棄しません。
		if( fixture->throwAfterRead && fixture->offset > 0U &&
		   (fixture->faultResponse == 0U || fixture->faultResponse == fixture->sends)) {
			throw std::runtime_error( "FAKE_READ_EXCEPTION") ;
		}

		*size = static_cast<DWORD>( fixture->responses.at( fixture->sends - 1U).body.size() -
								   fixture->offset) ;
		return TRUE ;
	} ;
	api.readData = []( HINTERNET, LPVOID output, DWORD requested, LPDWORD size) -> BOOL {
		// 途中故障を完全取得へ昇格させない。
		if( (fixture->faultResponse == 0U || fixture->faultResponse == fixture->sends) &&
		   (fixture->failRead ||
			(fixture->failAfterBytes && fixture->offset >= *fixture->failAfterBytes))) {
			SetLastError( ERROR_WINHTTP_CONNECTION_ERROR) ;
			return FALSE ;
		}

		const auto &body  = fixture->responses.at( fixture->sends - 1U).body ;	// 現本文。
		const auto	bytes = std::min<std::size_t>(
			 {requested, body.size() - fixture->offset, fixture->chunkBytes}) ;	// 上限内copy量。
		std::memcpy( output, body.data() + fixture->offset, bytes) ;
		fixture->offset += bytes ;
		*size = static_cast<DWORD>( bytes) ;
		// 同期read中に到着した取消しを次の保存前確認へ渡します。
		if( fixture->cancelAfterRead &&
		   (fixture->faultResponse == 0U || fixture->faultResponse == fixture->sends)) {
			fixture->cancelled = true ;
		}

		return TRUE ;
	} ;
	api.closeHandle = []( HINTERNET) -> BOOL {
		++fixture->closed ;
		return TRUE ;
	} ;
	api.resolveDestination =
		[]( std::wstring_view, std::vector<drivercrate::OfficialResolvedNetworkAddress> &addresses) {
			++fixture->dns ;
			drivercrate::OfficialResolvedNetworkAddress address ;	// 架空IPv4一件。
			address.bytes[0] =
				(fixture->privateAddress || (fixture->privatePayload && fixture->dns >= 2U))
					? std::byte{10U}
					: std::byte{8U} ;
			address.bytes[1] = std::byte{8U} ;
			address.bytes[2] = std::byte{8U} ;
			address.bytes[3] = std::byte{8U} ;
			addresses		 = {address} ;
			return drivercrate::NativeError{} ;
		} ;
	api.utcNow = []() { return std::uint64_t{1000U} ; } ;
	return api ;
}

/** @brief 実回線APIを使用しない試験cost。 */
class Cost final : public drivercrate::IOfficialNetworkCostReader {
public:
	/// 今回のfixture区分。
	drivercrate::OfficialNetworkCostKind value{drivercrate::OfficialNetworkCostKind::UNRESTRICTED} ;
	/** @brief 不変区分を返す。
	 * @param[out] output 試験区分。
	 * @return 成功0。
	 */
	drivercrate::NativeError read( drivercrate::OfficialNetworkCostKind &output) noexcept override
	{
		output = value ;
		return 0 ;
	}
} ;

} // namespace

namespace drivercrate {
/** @brief Test targetだけがprivate I/O seamを接続します。通常jobに設定入口はありません。 */
class CollectorRegistryJobTestAccess final {
public:
	/** @brief 同じ実runnerの私有結果だけを候補へ渡します。
	 * @param[in] result 同じ通常runの結果です。公開JSONを読みません。
	 * @param[in] now 検査時刻です。観測時刻は変更しません。
	 * @param[out] candidate 全投影と拒否分母です。
	 * @return 観測がない場合E_INVALIDARG、ほかは元投影診断です。
	 */
	static NativeError project( const CollectorRegistryJobResult &result,
							   std::chrono::sys_seconds			 now,
							   CollectorDistributionCandidate	&candidate)
	{
		// 未実行/公開JSON由来の空結果を証拠へ昇格させません。
		if( !result.observation_) {
			return E_INVALIDARG ;
		}

		return makeCollectorDistributionRecords( *result.observation_, now, candidate) ;
	}
	/** @brief 完全fake HTTPと限定検査seamで一回実行します。
	 * @param[in] job 非通信検証した元jobです。
	 * @param[in] other 別jobの再使用拒否に使う元jobです。
	 * @param[in] mode 固定した故障fixture番号です。
	 * @param[out] result 元一回結果を保持します。
	 * @param[in,out] scope 任意の同run PAGE所有者です。
	 * @param[in] proof 任意の同run PAGE借用です。
	 * @param[in] cap 今回だけのprivate payload上限です。
	 * @param[in] sessionId 今回だけの0でないsessionです。
	 * @param[in] deadline 元実行の固定期限です。
	 * @return 元runの結果です。
	 */
	static NativeError execute( const CollectorRegistryJob &job, const CollectorRegistryJob &other,
							   const unsigned mode, CollectorRegistryJobResult &result,
							   CollectorRunPageScope	   *scope = nullptr,
							   const CollectorRunPageProof *proof = nullptr,
							   std::uint64_t cap	   = COLLECTOR_INSPECTION_MAXIMUM_BYTES,
							   ScanSessionId sessionId = 25353U,
							   std::chrono::steady_clock::time_point deadline =
								   std::chrono::steady_clock::time_point::max())
	{
		CollectorRegistryJobRunner runner( transport()) ;	// HTTP/DNSは全てfixtureです。
		Cost					   cost ;					// 実回線APIを呼びません。
		// 不明/制限回線は同意を補完せず停止します。
		if( mode == 11U) {
			cost.value = OfficialNetworkCostKind::RESTRICTED ;
		}

		// mode12だけは検査/identity両probeを使わず、通常archive/INF parserへ渡します。
		if( mode != 12U) {
			// Lambdaは故障番号だけを値captureし、実取得の元identityへ結果を結合します。
			runner.inspectionProbe_ = [mode]( const DriverArchiveInput &input,
											 OfficialDriverArchiveFormat,
											 CommonDriverPackageInspection &inspection) {
				inspection.scanSessionId = input.scanSessionId ;
				inspection.archiveSha256 = input.sha256 ;
				inspection.archiveBytes	 = input.byteCount ;
				fixture->sessions.push_back( input.scanSessionId) ;
				fixture->inspectionPaths.push_back( input.inspectionPath) ;
				// 全体破損を個別失敗や部分成功に変換しません。
				if( mode == 9U) {
					inspection.error = E_FAIL ;
					return static_cast<NativeError>( E_FAIL) ;
				}

				// 別archiveの過去検査結果を借用できません。
				if( mode == 10U) {
					inspection.archiveSha256.assign( 64U, L'0') ;
				}

				CommonInfInspection first ;	// 新しい架空INF名です。
				first.scanSessionId	  = input.scanSessionId ;
				first.infRelativePath = L"brand-new-network.inf" ;
				first.state			  = CommonInfInspectionState::VERIFIED ;
				OfficialInfPackage package ;	// 同fake検査が返す公開内容です。
				package.infRelativePath		= first.infRelativePath ;
				package.catalogRelativePath = L"brand-new-network.cat" ;
				package.className			= L"Net" ;
				package.classGuid			= L"{4d36e972-e325-11ce-bfc1-08002be10318}" ;
				package.providerName		= L"Fixture Manufacturer" ;
				package.driverDate			= L"10/22/2026" ;
				package.driverVersion		= L"2.3.4.5" ;
				// 候補専用fixtureの更新は旧研究versionと独立した実INF観測です。
				if( mode == 26U) {
					package.driverVersion = L"3.4.5.6" ;
				}

				// 一段nestedの元identityを現行selectorへ投影します。
				if( mode == 23U) {
					first.nestedArchivePath = L"nested.zip" ;
				}

				first.closure.packages.push_back( package) ;
				// CAT失敗は通常検査の個別拒否として保持します。
				if( mode == 7U) {
					first.state = CommonInfInspectionState::SIGNATURE_REJECTED ;
					first.error = TRUST_E_BAD_DIGEST ;
				}

				inspection.infs.push_back( std::move( first)) ;
				// 同INF hash/節でもflat/nested A/Bと別INF memberを独立した元観測へ保ちます。
				if( mode == 30U || mode == 31U || mode == 32U) {
					// 別memberまたは意図した重複を有限な元INF観測へ追加します。
					for( unsigned ordinal = 0U; ordinal < (mode == 32U ? 1U : 2U); ++ordinal) {
						CommonInfInspection another ;	// 元byte/節が同じでもmemberは別です。
						another.scanSessionId	  = input.scanSessionId ;
						another.infRelativePath	  = mode == 32U ? L"other\\brand-new-network.inf"
																: L"brand-new-network.inf" ;
						another.nestedArchivePath = mode == 32U ? L""
													: mode == 31U || ordinal == 0U
														? L"release+a.zip"
														: L"release+b.zip" ;
						another.state			  = CommonInfInspectionState::VERIFIED ;
						package.infRelativePath	  = another.infRelativePath ;
						another.closure.packages.push_back( package) ;
						inspection.infs.push_back( std::move( another)) ;
					}
				}

				// 同package内の別INFも同じ通常検査結果から返します。
				if( mode == 21U || mode == 22U) {
					CommonInfInspection second ;	// 新規名/別Modelsを持つ元個別INFです。
					second.scanSessionId		= input.scanSessionId ;
					second.infRelativePath		= L"sub\\another-new.inf" ;
					second.state				= CommonInfInspectionState::VERIFIED ;
					package.infRelativePath		= second.infRelativePath ;
					package.catalogRelativePath = L"sub\\another-new.cat" ;
					second.closure.packages.push_back( package) ;
					inspection.infs.push_back( std::move( second)) ;
				}

				// 二つ目の明示INFが全job拒否した場合、最初の合格を救済しません。
				if( mode == 24U && fixture->sessions.size() >= 2U) {
					inspection.error = E_FAIL ;
					return static_cast<NativeError>( E_FAIL) ;
				}

				// 部分失敗の未知class/OS/構文は元の個別拒否から消しません。
				if( mode == 8U) {
					CommonInfInspection rejected ;	// 明示失敗の別INFです。
					rejected.scanSessionId	 = input.scanSessionId ;
					rejected.infRelativePath = L"unsupported-other.inf" ;
					rejected.error			 = HRESULT_FROM_WIN32( ERROR_NOT_SUPPORTED) ;
					inspection.infs.push_back( std::move( rejected)) ;
				}

				return NativeError{} ;
			} ;
			// 公開IDはfixture内容からだけ供給し、jobや保存成功JSONからは読みません。
			runner.identityProbe_ = [mode]( const CommonInfInspection	&inf,
										   OfficialInfPublishedIdentity &identity,
										   std::wstring					&publisher) {
				identity.infSha256.assign( 64U, L'c') ;
				identity.classGuid = L"{4d36e972-e325-11ce-bfc1-08002be10318}" ;
				identity.models.push_back( {L"NewModels.NTamd64.10.0",
										   {L"PCI\\VEN_FA01&DEV_0021"},
										   {L"PCI\\VEN_FA01&CC_0200"}}) ;
				publisher = mode == 13U ? L"" : L"Fixture Windows Publisher" ;
				// 原一節の129 IDを全保持し、v2への切捨て拒否を検査します。
				if( mode == 20U || mode == 25U) {
					identity.models.front().hardwareIds.clear() ;
					identity.models.front().compatibleIds.clear() ;
					// 件数超過または64KiB表現超過の元公開ID集合を作ります。
					for( std::size_t index = 0U; index < (mode == 20U ? 129U : 128U); ++index) {
						std::wstring id =
							L"PCI\\VEN_FA01&DEV_" + std::to_wstring( index) ;	// 架空IDだけです。
						// 一ID文法上限の512byteを保ったままrecord全体枠を越えさせます。
						if( mode == 25U) {
							id.append( 512U - id.size(), L'A') ;
						}

						identity.models.front().hardwareIds.push_back( std::move( id)) ;
					}
				}

				// 同packageの新INF/節をcode登録なしで別recordへ進めます。
				if( (mode == 21U || mode == 22U) && inf.infRelativePath.starts_with( L"sub\\")) {
					identity.infSha256.assign( 64U, L'd') ;
					identity.models.front().modelSection = L"UnexpectedSecond.NTamd64.10.0" ;
					identity.models.front().hardwareIds	 = {L"PCI\\VEN_FB01&DEV_0032"} ;
					// 署名者が複数なら一つのpackage descriptorへ推測集約しません。
					if( mode == 22U) {
						publisher = L"Other Fixture Publisher" ;
					}
				}

				return NativeError{} ;
			} ;
		}

		CollectorRegistryExecutionLimits limits( cap, deadline) ;	// 保存jobとは独立した実行枠です。
		OfficialHttpClient::collectorFlushProbe_ = fixture->failFlush ? +[]( HANDLE) -> BOOL {
			SetLastError( ERROR_WRITE_FAULT) ;
			return FALSE ;
		}
		: nullptr ;
		const auto error =
			// 元一回の実保護file/hashを使います。
			runner.run(
				job, sessionId, cost, []() { return fixture->cancelled ; }, limits, result, scope,
				proof) ;
		OfficialHttpClient::collectorFlushProbe_ = nullptr ;
		const auto				   sends		 = fixture->sends ;	// 二度目の送信禁止確認です。
		CollectorRegistryJobResult replay ;							// 元結果を上書きしません。
		check( runner.run( other, 25354U, cost, {}, limits, replay) != 0 && replay.json().empty() &&
			  fixture->sends == sends) ;
		return error ;
	}
	/** @brief 私有parent contextを完全fakeの固定値から作ります。
	 * @param[in] now 元runのfake単調時計です。
	 * @param[in] runId 元runの識別子です。
	 * @return 公開constructorを持たない有限scopeです。
	 */
	static CollectorRunPageScope makeScope( std::chrono::steady_clock::time_point &now,
										   std::wstring runId = L"fixture-run")
	{
		return CollectorRunPageScope(
			std::move( runId), 9U, 17U,
			{std::wstring( 64U, L'a'), std::wstring( 64U, L'b'), std::wstring( 64U, L'c')},
			std::wstring( 64U, L'd'), now + std::chrono::minutes( 10),
			[]() { return fixture->cancelled ; }, [&now]() { return now ; }) ;
	}
	/** @brief 次jobの先行予約前に同起点のproofを検索します。
	 * @param[in,out] scope 元runです。
	 * @param[in] source 次jobの原exact起点です。
	 * @return 同runの完全証拠、未取得/停止時nullです。
	 */
	static std::shared_ptr<const CollectorRunPageProof> page(
		CollectorRunPageScope &scope, const CollectorInspectionSource &source)
	{
		return scope.find( source) ;
	}
	/** @brief 明示終了後の借用拒否を検証します。
	 * @param[in,out] scope 終了する元runです。
	 */
	static void finish( CollectorRunPageScope &scope)
	{
		scope.finish() ;
	}
	/** @brief 原本文所有と実byte観測の一致を確認します。
	 * @param[in] proof 実HTTPだけが作った証拠です。
	 * @return 同じ原本文/hash/UTC/完了が保存された場合trueです。
	 */
	static bool hasRaw( const CollectorRunPageProof &proof)
	{
		return proof.raw_.size() == proof.observation_.bodyBytes && !proof.html_.empty() &&
			   proof.observation_.observedAtUtc.time_since_epoch().count() > 0 &&
			   proof.transfer_.completion() == CollectorHttpTransferCompletion::COMPLETE ;
	}
	/** @brief 有限cacheの容量だけを専用fixtureから検証します。
	 * @param[in,out] scope 実fake HTTPで最初のPAGEを保持したscopeです。
	 * @param[in] proof 同scopeの元raw/復号/hash/転送観測です。
	 * @param[in] ordinal 重複しない試験用cache key番号です。
	 * @return 有限cacheへ保持できた場合trueです。
	 * @note 実取得経路の代用ではなく、32entry/32MiB境界だけを私有seamで確認します。
	 */
	static bool retainBoundaryPage( CollectorRunPageScope &scope, const CollectorRunPageProof &proof,
								   std::size_t ordinal)
	{
		const CollectorInspectionSource source{L"https://maker-a.example.org/cache/" +
												   std::to_wstring( ordinal),
											   proof.rootHost_} ;	// 容量を分離確認する一意keyです。
		return scope.retain( source, proof.raw_, proof.html_, proof.observation_, proof.transfer_) !=
			   nullptr ;
	}
	/** @brief 保持中に観測した停止を未取得へ読み替えてnonnullを返しません。
	 * @param[in] proof 実fake HTTPの完全PAGEです。新scopeの容量試験へだけ借用します。
	 */
	static void retainCancellationTest( const CollectorRunPageProof &proof)
	{
		unsigned			  polls{} ;									// 同scopeが停止確認した回数です。
		bool				  stopped{} ;								// 同じcallbackが停止を返した事実です。
		const auto			  now = std::chrono::steady_clock::now() ;	// 有限な新scopeの起点です。
		// 二回目以降の停止を記録し、保持関数がそれを無視した場合を検出します。
		CollectorRunPageScope scope( L"retain-cancel", 9U, 17U, {std::wstring( 64U, L'a')},
									std::wstring( 64U, L'd'), now + std::chrono::minutes( 10),
									[&polls, &stopped]() {
										stopped = ++polls >= 2U ;
										return stopped ;
									}) ;
		const CollectorInspectionSource source{proof.rootUrl_,
											   proof.rootHost_} ;	// 同exact keyです。
		const auto retained = scope.retain( source, proof.raw_, proof.html_, proof.observation_,
										   proof.transfer_) ;	// 公開入力の復元ではありません。
		check( !stopped || !retained) ;
		check( !scope.find( source)) ;
	}
	/** @brief uint64最大上限でもcollector読取量計算がoverflowしないことを確認します。 */
	static void maximumCapTest()
	{
		Fixture state{{Response{"abc"}}} ;	// 一payloadだけの低位HTTP fixtureです。
		fixture = &state ;
		OfficialDownloadWorkspace workspace ;	// 通常運用storeと独立した自作一時領域です。
		check( workspace.initialize( COLLECTOR_INSPECTION_PROVIDER_ID, 34000U) == 0) ;
		HANDLE created = INVALID_HANDLE_VALUE ;	// 成功時だけ次のRAIIへ所有権を移します。
		check( workspace.createFile( L"boundary.bin", created) == 0) ;
		const std::unique_ptr<void, decltype( &CloseHandle)> file(
			created, &CloseHandle) ;			// 同handleの所有者です。
		OfficialHttpClient http( transport()) ;	// 全低位I/Oをfixtureへ固定します。
		const std::array<std::wstring_view, 1U> hosts{
			L"maker-a.example.org"} ;					// Exact一hostだけです。
		std::vector<std::uint32_t>		 origins ;		// 検証回数を実送信数へ代用しません。
		CollectorHttpTransferObservation observation ;	// 同じ私有recorderの終端です。
		check( http.downloadToFile(
				  L"https://maker-a.example.org/boundary.bin", hosts, 2U,
				  std::numeric_limits<std::uint64_t>::max(), file.get(),
				  []( std::uint64_t, std::uint64_t) {}, {}, origins, true, &observation) == 0) ;
		check( observation.completion() == CollectorHttpTransferCompletion::COMPLETE &&
			  observation.bodyBytesRead() == 3U && observation.attemptedRequests() == 1U &&
			  state.attempts == 1U && state.safe && state.opened == state.closed) ;
		fixture = nullptr ;
	}
} ;
} // namespace drivercrate

namespace {
using JsonObject = winrt::Windows::Data::Json::JsonObject ;	// 固定fixture編集だけのDOMです。
using JsonArray	 = winrt::Windows::Data::Json::JsonArray ;	// 元製品参照です。
using JsonValue	 = winrt::Windows::Data::Json::JsonValue ;	// 型付きfixture値です。

// B1の正例jobです。全URL/製品/IDは架空です。
constexpr std::string_view JOB_EXAMPLE = R"JOB({
  "container": "ZIP",
  "infSelection": {
    "mode": "ALL",
    "paths": []
  },
  "jobId": "profile-000",
  "locators": {
    "asOf": "2026-10-23T00:00:00Z",
    "revision": "locators-01",
    "schema": "dc-public-driver-locators-v1",
    "sha256": "fedba94903effd720be2fe1aff6c4fdc4c9f5a889bb7535e2443f78c5d8c2835"
  },
  "maximumBytes": 33554432,
  "pageObservation": {
    "bodyBytes": 1200,
    "bodySha256": "2ac9a6746aca543af8dff39894cfe8173afba21eb01c6fae33d52947222855ef",
    "checkedAt": "2026-10-22T00:00:00Z",
    "httpStatus": 200,
    "method": "LOCAL_HTTP"
  },
  "products": [
    {
      "driverCategory": "LAN",
      "id": "product-000",
      "manufacturer": "Maker A",
      "model": "Device product-000",
      "reason": "NONE",
      "recordIds": [
        "record-000"
      ],
      "researchState": "METADATA_SAVED",
      "sourceIds": [
        "source-000"
      ]
    },
    {
      "driverCategory": "LAN",
      "id": "product-shared",
      "manufacturer": "Maker A",
      "model": "Device product-shared",
      "reason": "NONE",
      "recordIds": [
        "record-000"
      ],
      "researchState": "METADATA_SAVED",
      "sourceIds": [
        "source-000"
      ]
    }
  ],
  "profileRevision": "profile-01",
  "record": {
    "contentState": "NOT_DOWNLOADED",
    "downloadUrl": "https://maker-a.example.org/download/000/driver.zip",
    "driverCategory": "LAN",
    "driverVersion": null,
    "id": "record-000",
    "linkState": "OFFICIAL_LINK",
    "operatingSystems": [
      "WINDOWS_11_X64"
    ],
    "packageVersion": "1.0",
    "publishedDate": null,
    "publishedSha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "sourceId": "source-000",
    "title": "Network driver 000"
  },
  "recordId": "record-000",
  "referenceSha256": "53f758a3950c78fef9326a1f78f7059f8e3dae14060867a3b6788c50270b3561",
  "registry": {
    "asOf": "2026-10-23T00:00:00Z",
    "revision": "fixture-01",
    "schema": "dc-public-driver-registry-v1",
    "sha256": "60d395458a4b8aaf58c5dd69a18edc6170c1ecb6ba59ab4ab777beaa3376b308"
  },
  "review": {
    "official": {
      "evidence": {
        "bodySha256": "2ac9a6746aca543af8dff39894cfe8173afba21eb01c6fae33d52947222855ef",
        "contentSha256": "2ac9a6746aca543af8dff39894cfe8173afba21eb01c6fae33d52947222855ef",
        "checkedAt": "2026-10-22T00:00:00Z",
        "locatorId": "page-000",
        "scope": "official"
      },
      "state": "CONFIRMED"
    },
    "preDownload": {
      "evidence": {
        "bodySha256": "2ac9a6746aca543af8dff39894cfe8173afba21eb01c6fae33d52947222855ef",
        "contentSha256": "2ac9a6746aca543af8dff39894cfe8173afba21eb01c6fae33d52947222855ef",
        "checkedAt": "2026-10-22T00:00:00Z",
        "locatorId": "page-000",
        "scope": "preDownload"
      },
      "state": "NO_EXTRA_PROMPT"
    },
    "prerequisites": {
      "evidence": {
        "bodySha256": "2ac9a6746aca543af8dff39894cfe8173afba21eb01c6fae33d52947222855ef",
        "contentSha256": "2ac9a6746aca543af8dff39894cfe8173afba21eb01c6fae33d52947222855ef",
        "checkedAt": "2026-10-22T00:00:00Z",
        "locatorId": "page-000",
        "scope": "prerequisites"
      },
      "items": [],
      "state": "NONE_REQUIRED"
    },
    "terms": {
      "evidence": {
        "bodySha256": "2ac9a6746aca543af8dff39894cfe8173afba21eb01c6fae33d52947222855ef",
        "contentSha256": "2ac9a6746aca543af8dff39894cfe8173afba21eb01c6fae33d52947222855ef",
        "checkedAt": "2026-10-22T00:00:00Z",
        "locatorId": "page-000",
        "scope": "terms"
      },
      "state": "NO_ADDITIONAL_TERMS"
    }
  },
  "schema": "dc-collector-registry-job-v2",
  "source": {
    "href": "driver.zip",
    "payloadHost": "maker-a.example.org",
    "payloadUrl": "https://maker-a.example.org/download/000/driver.zip",
    "rootHost": "maker-a.example.org",
    "rootUrl": "https://maker-a.example.org/download/000/"
  },
  "sourceFormat": "STATIC_HTML_ANCHOR_V1",
  "sourceId": "source-000"
})JOB" ;

/** @brief Fixture objectへ元文字列を設定します。
 * @param[in,out] object 変更するfixtureだけです。
 * @param[in] key 固定fieldです。
 * @param[in] value 新しい架空値です。
 */
void setText( JsonObject &object, const wchar_t *key, const std::wstring_view value)
{
	object.Insert( key, JsonValue::CreateStringValue( value)) ;
}

/** @brief 同じfixture本文hashを全独立手動確認へ結合します。
 * @param[in,out] job 元fixture jobです。
 * @param[in] html 原HTTP fixture byteです。
 */
void bindPage( JsonObject &job, const std::string_view html)
{
	std::wstring digest ;	// 同じ原byteの実CNG hashです。
	check( drivercrate::computeCollectorMetadataSha256( html, digest) == 0) ;
	std::wstring content ;	// 原SHAと区別した同本文の比較値です。
	check( drivercrate::computeCollectorPageContentSha256( html, content) == 0) ;
	auto page = job.GetNamedObject( L"pageObservation") ;	// 元page観測です。
	setText( page, L"bodySha256", digest) ;
	page.Insert( L"bodyBytes", JsonValue::CreateNumberValue( static_cast<double>( html.size()))) ;
	auto review = job.GetNamedObject( L"review") ;	// 各元scopeです。
	// 全scopeの元根拠本文を同じ起点へ固定します。
	for( const auto name : {L"official", L"preDownload", L"terms", L"prerequisites"}) {
		auto evidence = review.GetNamedObject( name).GetNamedObject( L"evidence") ;	// 同page根拠です。
		setText( evidence, L"bodySha256", digest) ;
		setText( evidence, L"contentSha256", content) ;
	}
}

/** @brief 架空A二製品またはB一製品のjobを作ります。
 * @param[in] second B社一製品を使う場合trueです。
 * @return 原B1 schemaを保持したfixtureです。
 */
JsonObject jobFixture( const bool second = false)
{
	auto job	= JsonObject::Parse( winrt::to_hstring( JOB_EXAMPLE)) ;	// 原正例です。
	auto record = job.GetNamedObject( L"record") ;						// 実fake byte abcへ固定します。
	setText( record, L"publishedSha256",
			L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") ;
	bindPage( job, "<a href=\"driver.zip\">driver</a>") ;
	// B社は別recordの独立一jobで、Aの共有関係を変更しません。
	if( second) {
		setText( job, L"jobId", L"profile-b") ;
		setText( job, L"sourceId", L"source-b") ;
		setText( job, L"recordId", L"record-b") ;
		setText( record, L"id", L"record-b") ;
		setText( record, L"sourceId", L"source-b") ;
		setText( record, L"downloadUrl", L"https://maker-b.example.org/download/driver.zip") ;
		auto source = job.GetNamedObject( L"source") ;	// Bのexact導線です。
		setText( source, L"rootUrl", L"https://maker-b.example.org/download/driver.html") ;
		setText( source, L"rootHost", L"maker-b.example.org") ;
		setText( source, L"payloadUrl", L"https://maker-b.example.org/download/driver.zip") ;
		setText( source, L"payloadHost", L"maker-b.example.org") ;
		auto product = job.GetNamedArray( L"products").GetAt( 0U).GetObject() ;	// Bの一製品です。
		setText( product, L"id", L"product-b") ;
		setText( product, L"manufacturer", L"Maker B") ;
		setText( product, L"model", L"New Device B") ;
		JsonArray sources ;	// Bのsourceだけです。
		sources.Append( JsonValue::CreateStringValue( L"source-b")) ;
		product.Insert( L"sourceIds", sources) ;
		JsonArray records ;	// Bのrecordだけです。
		records.Append( JsonValue::CreateStringValue( L"record-b")) ;
		product.Insert( L"recordIds", records) ;
		JsonArray products ;	// Aは二、Bは一です。
		products.Append( product) ;
		job.Insert( L"products", products) ;
	}

	return job ;
}

/** @brief 全schema/参照拒否と同取得・検査を有限fixtureで検証します。 */
void registryTests()
{
	{
		Fixture state ;	// Backendの誤buffer拒否を元通信fixtureから独立させる。
		fixture			 = &state ;
		const auto api	 = transport() ;							// 実WinHTTPへ接続しない完全表。
		DWORD	   value = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH ;	// 有効なDWORDの借用領域。
		check( api.setOption( nullptr, WINHTTP_OPTION_AUTOLOGON_POLICY, nullptr, sizeof( value)) ==
				  FALSE &&
			  GetLastError() == ERROR_INVALID_PARAMETER && !state.safe) ;
		state.safe = true ;
		check( api.setOption( nullptr, WINHTTP_OPTION_AUTOLOGON_POLICY, &value, 0U) == FALSE &&
			  GetLastError() == ERROR_INVALID_PARAMETER && !state.safe) ;
		state.safe = true ;
		check( api.setOption( nullptr, WINHTTP_OPTION_AUTOLOGON_POLICY, &value, sizeof( value)) !=
				  FALSE &&
			  state.safe) ;
		fixture = nullptr ;
	}

	drivercrate::CollectorRegistryJob b ;	// 別メーカーの一jobです。
	check( drivercrate::parseCollectorRegistryJob( winrt::to_string( jobFixture( true).Stringify()),
												 b) == 0 &&
		  b.productCount() == 1U) ;
	// 全field型/参照/条件の一条件だけを変更して通信前拒否を確認します。
	for( unsigned mode = 0U; mode < 20U; ++mode) {
		auto fixtureJob = jobFixture() ;							// 正例を各caseで独立所有します。
		auto record		= fixtureJob.GetNamedObject( L"record") ;	// 一recordです。
		auto source		= fixtureJob.GetNamedObject( L"source") ;	// Exact導線です。
		// 拒否境界ごとに原データを一箇所だけ変えます。
		switch( mode) {
			case 0U: /* そのままのA共有二製品です。 */
				break ;

			case 1U: /* 未知fieldを拒否します。 */
				setText( fixtureJob, L"publisher", L"Claimed Publisher") ;
				break ;

			case 2U: /* 成功schemaの借用を拒否します。 */
				setText( fixtureJob, L"schema", L"dc-collector-registry-native-result-v1") ;
				break ;

			case 3U: /* Query経路は未対応です。 */
				setText( source, L"payloadUrl", L"https://maker-a.example.org/x.zip?token=x") ;
				break ;

			case 4U: /* Private literalを拒否します。 */
				setText( source, L"rootHost", L"127.0.0.1") ;
				break ;

			case 5U: /* 許可hostの転用を拒否します。 */
				setText( source, L"payloadHost", L"other.example.org") ;
				break ;

			case 6U: /* Recordの参照先を変更できません。 */
				setText( record, L"id", L"other-record") ;
				break ;

			case 7U: /* Inputの内容成功値を受理しません。 */
				setText( record, L"contentState", L"CONTENT_INSPECTED") ;
				break ;

			case 8U: /* 不正hashを拒否します。 */
				setText( record, L"publishedSha256", L"bad") ;
				break ;

			case 9U: /* 容量超過を拒否します。 */
				fixtureJob.Insert( L"maximumBytes", JsonValue::CreateNumberValue( 33554433.0)) ;
				break ;

			case 10U: /* 未知termsを許可へ補完しません。 */ {
				auto item = fixtureJob.GetNamedObject( L"review").GetNamedObject(
					L"terms") ;	// 未知規約の元scopeです。
				setText( item, L"state", L"UNKNOWN") ;
				break ;
			}
			case 11U: /* 同意gateを自動承認しません。 */ {
				auto item = fixtureJob.GetNamedObject( L"review").GetNamedObject(
					L"preDownload") ;	// 同意gateの元scopeです。
				setText( item, L"state", L"CONSENT_REQUIRED") ;
				break ;
			}
			case 12U: /* 必須条件ありを受理しません。 */ {
				auto item = fixtureJob.GetNamedObject( L"review").GetNamedObject(
					L"prerequisites") ;	// 必須条件の元scopeです。
				setText( item, L"state", L"REQUIRED") ;
				break ;
			}
			case 13U: /* 空製品を全成功にしません。 */
				fixtureJob.Insert( L"products", JsonArray{}) ;
				break ;

			case 14U: /* 欠損fieldを拒否します。 */
				fixtureJob.Remove( L"sourceId") ;
				break ;

			case 15U: /* 原pageの根拠借用を拒否します。 */ {
				auto page = fixtureJob.GetNamedObject( L"pageObservation") ;	// 根拠借用の原pageです。
				setText( page, L"bodySha256", std::wstring( 64U, L'0')) ;
				break ;
			}
			case 16U: /* Firmwareを通常driverにしません。 */
				setText( record, L"driverCategory", L"FIRMWARE") ;
				break ;

			case 17U: /* 不正暦日を拒否します。 */
				setText( record, L"publishedDate", L"2026-02-30") ;
				break ;

			case 18U: /* 未知OSを成功にしません。 */ {
				JsonArray os ;	// 未知OSだけの負例配列です。
				os.Append( JsonValue::CreateStringValue( L"UNKNOWN")) ;
				record.Insert( L"operatingSystems", os) ;
				break ;
			}
			default: /* 過去成功boolは入力権限ではありません。 */
				fixtureJob.Insert( L"sourceVerified", JsonValue::CreateBooleanValue( true)) ;
				break ;
		}

		drivercrate::CollectorRegistryJob job ;	// 拒否時は必ず無効です。
		const auto						  error = drivercrate::parseCollectorRegistryJob(
			   // 実native parserです。
			   winrt::to_string( fixtureJob.Stringify()), job) ;
		check( (error == 0) == (mode == 0U)) ;
		check( job.productCount() == (mode == 0U ? 2U : 0U)) ;
	}

	const auto original = winrt::to_string( jobFixture().Stringify()) ;	// 最終正例原byteです。
	drivercrate::CollectorRegistryJob invalid ;							// 重複/余剰拒否用です。
	check( drivercrate::parseCollectorRegistryJob( original + "{}", invalid) != 0) ;
	check( drivercrate::parseCollectorRegistryJob( "{\"schema\":\"x\"," + original.substr( 1U),
												 invalid) != 0) ;
	check( drivercrate::parseCollectorRegistryJob(
			  std::string( drivercrate::COLLECTOR_REGISTRY_JOB_MAX_BYTES + 1U, ' '), invalid) != 0) ;
	// 実HTML/byte/保護取得を通し、検査I/Oだけは明示seamへ固定します。
	for( unsigned mode = 0U; mode < 15U; ++mode) {
		Fixture state{
			{Response{"<a href=\"driver.zip\">driver</a>"}, Response{"abc"}}} ;	// 二GETだけです。
		fixture			= &state ;
		auto fixtureJob = jobFixture( mode == 0U) ;	// B一製品も実runへ渡します。
		// 元pageと実取得の異常を独立に注入します。
		if( mode == 1U) {
			state.responses[0].body = "<a href=\"other.zip\">other</a>" ;
			bindPage( fixtureJob, state.responses[0].body) ;
		}

		// 曖昧anchorを本文hash一致だけで受理しません。
		if( mode == 2U) {
			state.responses[0].body += state.responses[0].body ;
			bindPage( fixtureJob, state.responses[0].body) ;
		}

		// 起点privateは初回send前に拒否します。
		if( mode == 3U) {
			state.privateAddress = true ;
		}

		// Payload privateを起点のpublic成功で補いません。
		if( mode == 4U) {
			state.privatePayload = true ;
		}

		// 公開hashは実payload byteへ比較します。
		if( mode == 5U) {
			state.responses[1].body = "xyz" ;
		}

		// 手動確認本文と異なるfresh本文ではpayloadを取得しません。
		if( mode == 6U) {
			state.responses[0].body += "changed" ;
		}

		drivercrate::CollectorRegistryJob job ;	// 同fixtureの元jobです。
		check( drivercrate::parseCollectorRegistryJob( winrt::to_string( fixtureJob.Stringify()),
													 job) == 0) ;
		drivercrate::CollectorRegistryJobResult result ;	// 明示結果を通常logへ出しません。
		const auto error = drivercrate::CollectorRegistryJobTestAccess::execute(
			job, b, mode, result) ;	// 実module呼出しです。
		check( !result.json().empty() && state.safe && state.closed == state.opened) ;
		const auto output =
			// 実module出力だけです。
			JsonObject::Parse( winrt::to_hstring( result.json())) ;
		check( output.GetNamedObject( L"job").GetNamedArray( L"products").Size() ==
			  (mode == 0U ? 1U : 2U)) ;
		check( output.GetNamedNumber( L"verifiedInfs") ==
			  (mode == 0U || mode == 8U || mode == 14U ? 1.0 : 0.0)) ;
		check( (error == 0) == (mode == 0U || mode == 14U)) ;
		// 正例と部分失敗は新INF/原公開ID/Models/publisherを保持します。
		if( mode == 0U || mode == 8U || mode == 14U) {
			const auto row = output.GetNamedArray( L"infs").GetAt( 0U).GetObject() ;	// 元成功行です。
			check( row.GetNamedString( L"infIdentity") == L"brand-new-network.inf" &&
				  row.GetNamedArray( L"models").Size() == 1U &&
				  row.GetNamedString( L"verifiedPublisher") == L"Fixture Windows Publisher") ;
			check( state.sends == 2U) ;
		}

		// 部分失敗の元行は分母と独立診断へ残します。
		if( mode == 8U) {
			check( error == S_FALSE && output.GetNamedString( L"status") == L"PARTIAL_FAILURE" &&
				  output.GetNamedArray( L"infs").Size() == 2U &&
				  output.GetNamedNumber( L"rejectedInfs") == 1.0) ;
		}

		// 起点だけで停止した試行はpayload GETを増やしません。
		if( mode == 1U || mode == 2U || mode == 4U || mode == 6U) {
			check( state.sends == 1U) ;
		}

		// 回線または非public拒否は送信ゼロです。
		if( mode == 3U || mode == 11U) {
			check( state.sends == 0U) ;
		}

		// 原観測は同取得のhashとUTCだけを保持します。
		if( mode == 0U) {
			const auto observed = output.GetNamedObject( L"pageObservation") ;	// 成功実GETです。
			check( observed.GetNamedString( L"bodySha256") ==
					  fixtureJob.GetNamedObject( L"pageObservation").GetNamedString( L"bodySha256") &&
				  observed.GetNamedNumber( L"bodyBytes") == state.responses[0].body.size() &&
				  observed.GetNamedNumber( L"observedUtcSeconds") > 0.0) ;
		}

		check( drivercrate::parseCollectorRegistryJob( result.json(), invalid) != 0) ;
	}

	fixture = nullptr ;
}

/** @brief 四範囲の実手動確認時刻と原本文への結合を独立に検証します。 */
void manualReviewTimeTests()
{
	// 各scopeに同じ境界を適用し、一つの確認で他scopeの欠損を補完しません。
	for( const auto scope : {L"official", L"preDownload", L"terms", L"prerequisites"}) {
		// 等日時/後刻/小数秒を正例とし、他の変更は一条件で拒否します。
		for( unsigned mode = 0U; mode < 9U; ++mode) {
			auto	   job = jobFixture() ;	// 旧PAGE時刻と旧locator世代を保持します。
			const auto page =
				// 原観測byteです。
				job.GetNamedObject( L"pageObservation").Stringify() ;
			auto review	  = job.GetNamedObject( L"review") ;	// 独立四scopeです。
			auto evidence = review.GetNamedObject( scope).GetNamedObject(
				L"evidence") ;	// 今回変更する一範囲だけです。
			// 正例以外は時刻/本文/locator/scopeの一境界だけを変更します。
			switch( mode) {
				case 0U:	// 旧等日時の正例です。
					break ;

				case 1U:	// locator世代より後の実手動確認を受理します。
					setText( evidence, L"checkedAt", L"2026-10-24T00:00:00Z") ;
					break ;

				case 2U:	// 原PAGE観測以前を拒否します。
					setText( evidence, L"checkedAt", L"2026-10-21T23:59:59Z") ;
					break ;

				case 3U:	// locator世代ではなく実現在を上限にします。
					setText( evidence, L"checkedAt", L"9999-12-31T00:00:00Z") ;
					break ;

				case 4U:	// 別本文の根拠借用を拒否します。
					setText( evidence, L"bodySha256", std::wstring( 64U, L'0')) ;
					break ;

				case 5U:	// 別locatorを混在させません。
					setText( evidence, L"locatorId", L"other-page") ;
					break ;

				case 6U:	// 別scopeの確認を借用しません。
					setText( evidence, L"scope", L"unrelated") ;
					break ;

				case 7U:	// 欠scopeを成功へ補完しません。
					review.Remove( scope) ;
					break ;

				default:	// 既存の小数秒入力も原精度を保持して受理します。
					setText( evidence, L"checkedAt", L"2026-10-24T00:00:00.999999Z") ;
					break ;
			}

			drivercrate::CollectorRegistryJob parsed ;	// 拒否時は空です。
			const auto						  error = drivercrate::parseCollectorRegistryJob(
				   // 製品の同じvalidatorです。
				   winrt::to_string( job.Stringify()), parsed) ;
			const bool accepted = mode == 0U || mode == 1U || mode == 8U ;	// 固定した正例三つです。
			check( (error == 0) == accepted && parsed.productCount() == (accepted ? 2U : 0U)) ;
			check( job.GetNamedObject( L"pageObservation").Stringify() == page) ;
		}
	}
}

/** @brief 台帳URL未記載と確認済みlocatorを分離し、既存の取得検査を省略しません。 */
void nullableLinkTests()
{
	drivercrate::CollectorRegistryJob baseline ;	// 原B1正例をそのまま再確認します。
	check( drivercrate::parseCollectorRegistryJob( JOB_EXAMPLE, baseline) == 0 &&
		  baseline.productCount() == 2U) ;
	// 合法null/MISSINGと、状態矛盾・既知URL不一致・未確認規約を有限に比較します。
	for( unsigned mode = 0U; mode < 5U; ++mode) {
		auto job	= jobFixture() ;					// 元正例の研究状態だけを変更します。
		auto record = job.GetNamedObject( L"record") ;	// 上書きせず結果へ残す元recordです。
		record.Insert( L"downloadUrl", JsonValue::CreateNullValue()) ;
		setText( record, L"linkState", L"MISSING") ;
		// Nullと既知リンク状態の矛盾を拒否します。
		if( mode == 1U) {
			setText( record, L"linkState", L"OFFICIAL_LINK") ;
		}

		// 非nullとMISSINGの矛盾を拒否します。
		if( mode == 2U) {
			setText( record, L"downloadUrl",
					job.GetNamedObject( L"source").GetNamedString( L"payloadUrl")) ;
		}

		// 既知台帳URLとlocator取得URLの不一致を救済しません。
		if( mode == 3U) {
			setText( record, L"downloadUrl", L"https://maker-a.example.org/other.zip") ;
			setText( record, L"linkState", L"OFFICIAL_LINK") ;
		}

		// URL未記載の受理を未知規約の自動承認へ広げません。
		if( mode == 4U) {
			auto terms =
				// 未確認の独立scopeです。
				job.GetNamedObject( L"review").GetNamedObject( L"terms") ;
			setText( terms, L"state", L"UNKNOWN") ;
		}

		drivercrate::CollectorRegistryJob parsed ;	// 拒否時は空のままです。
		check( (drivercrate::parseCollectorRegistryJob( winrt::to_string( job.Stringify()), parsed) ==
			   0) == (mode == 0U)) ;
		check( parsed.productCount() == (mode == 0U ? 2U : 0U)) ;
	}

	drivercrate::CollectorRegistryJob other ;	// One-shotの別job拒否を維持します。
	check( drivercrate::parseCollectorRegistryJob( winrt::to_string( jobFixture( true).Stringify()),
												 other) == 0) ;
	// Null/MISSINGでも同じ実取得・通常検査へ進み、anchor欠落はpayload前で拒否します。
	for( const bool missingAnchor : {false, true}) {
		Fixture state{{Response{missingAnchor ? "<a href=\"other.zip\">other</a>"
											  : "<a href=\"driver.zip\">driver</a>"},
					   Response{"abc"}}} ;	// 完全fake HTTPだけです。
		fixture		= &state ;
		auto job	= jobFixture() ;					// URL未記載の共有二製品jobです。
		auto record = job.GetNamedObject( L"record") ;	// 元研究状態です。
		record.Insert( L"downloadUrl", JsonValue::CreateNullValue()) ;
		setText( record, L"linkState", L"MISSING") ;
		bindPage( job, state.responses[0].body) ;
		const auto original = winrt::to_string( job.Stringify()) ;	// 実行前の原jobを比較します。
		drivercrate::CollectorRegistryJob parsed ;					// 同じ元jobへ結合した非通信結果です。
		check( drivercrate::parseCollectorRegistryJob( original, parsed) == 0) ;
		drivercrate::CollectorRegistryJobResult result ;	// 元状態と新しい観測を分けた実結果です。
		const auto error = drivercrate::CollectorRegistryJobTestAccess::execute(
			parsed, other, 14U, result) ;	// 既存の通常検査I/O seamを使います。
		check( (error == 0) == !missingAnchor && !result.json().empty()) ;
		const auto output =
			// 同nativeだけの出力です。
			JsonObject::Parse( winrt::to_hstring( result.json())) ;
		const auto retained =
			// 上書きしない元recordです。
			output.GetNamedObject( L"job").GetNamedObject( L"record") ;
		check( retained.GetNamedValue( L"downloadUrl").ValueType() ==
				  winrt::Windows::Data::Json::JsonValueType::Null &&
			  retained.GetNamedString( L"linkState") == L"MISSING") ;
		check( winrt::to_string( job.Stringify()) == original &&
			  state.sends == (missingAnchor ? 1U : 2U) && state.safe &&
			  state.closed == state.opened) ;
		check( output.GetNamedNumber( L"verifiedInfs") == (missingAnchor ? 0.0 : 1.0)) ;
		// 正例は元公開ID・INFと実取得archive hashを従来どおり保持します。
		if( !missingAnchor) {
			const auto inf =
				// 同じ通常検査の成功行です。
				output.GetNamedArray( L"infs").GetAt( 0U).GetObject() ;
			check( output.GetNamedString( L"archiveSha256") ==
					  L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" &&
				  inf.GetNamedString( L"infIdentity") == L"brand-new-network.inf" &&
				  inf.GetNamedArray( L"models").Size() == 1U) ;
		}
	}

	fixture = nullptr ;
}

/** @brief 同PAGEの独立record二件を作ります。
 * @param[in] second 二番目のrecord/anchor/payloadを使う場合trueです。
 * @param[in] html 共通の原HTTP本文です。
 * @return 製品/record参照と原本文を保持した合法jobです。
 */
JsonObject samePageJob( bool second, std::string_view html)
{
	auto job = jobFixture( second) ;	// 元A共有製品とB独立recordを維持します。
	// 二番目だけを同じPAGEの別anchorと別実payloadへ向けます。
	if( second) {
		auto source = job.GetNamedObject( L"source") ;	// 同起点・別payloadです。
		setText( source, L"rootUrl", L"https://maker-a.example.org/download/000/") ;
		setText( source, L"rootHost", L"maker-a.example.org") ;
		setText( source, L"payloadHost", L"maker-a.example.org") ;
		setText( source, L"payloadUrl", L"https://maker-a.example.org/download/000/second.zip") ;
		setText( source, L"href", L"second.zip") ;
		auto record = job.GetNamedObject( L"record") ;	// 別recordの実bytehashです。
		setText( record, L"downloadUrl", source.GetNamedString( L"payloadUrl")) ;
		std::wstring digest ;	// 二番目の完全fake本文です。
		check( drivercrate::computeBytesSha256( "def", digest) == 0) ;
		setText( record, L"publishedSha256", digest) ;
	}

	bindPage( job, html) ;
	return job ;
}

/** @brief fixture DOMを本物の非通信parserへ渡します。
 * @param[in] value 合法fixtureです。
 * @return 原byteに結合したjobです。
 */
drivercrate::CollectorRegistryJob parseFixture( const JsonObject &value)
{
	drivercrate::CollectorRegistryJob job ;	// 本物parserの結果です。
	check( drivercrate::parseCollectorRegistryJob( winrt::to_string( value.Stringify()), job) == 0) ;
	return job ;
}

/** @brief 同run共有/原観測/別anchorと新sessionを完全fakeで確認します。 */
void sharedPageTests()
{
	using Access	 = drivercrate::CollectorRegistryJobTestAccess ;	// 専用targetの私有入口です。
	using Completion = drivercrate::CollectorHttpTransferCompletion ;	// 実転送の独立区分です。
	constexpr std::string_view HTML =
		"<a href=\"driver.zip\">first</a><a href=\"second.zip\">second</a>" ;	// 二つの独立anchorです。
	const drivercrate::CollectorInspectionSource root{
		L"https://maker-a.example.org/download/000/",
		L"maker-a.example.org"} ;	// 検索keyだけを使います。
	// 後段CAT拒否でも、完全PAGEは別recordの独立確認へ再利用できます。
	for( const bool catRejected : {false, true}) {
		Fixture state{{Response{std::string( HTML)}, Response{"abc"},
					   Response{"def"}}} ;	// PAGE1+payload2です。
		fixture			 = &state ;
		auto	   now	 = std::chrono::steady_clock::now() ;				// 同runの単調fixture時計です。
		auto	   scope = Access::makeScope( now) ;						// Parent/lease/child/hash/planを不変保持します。
		auto	   firstDom	 = samePageJob( false, HTML) ;					// 元共有二製品のrecordです。
		auto	   secondDom = samePageJob( true, HTML) ;					// 同PAGEの別recordです。
		const auto original	 = winrt::to_string( firstDom.Stringify()) ;	// 原job不変の比較値です。
		auto	   first	 = parseFixture( firstDom) ;					// 本物の厳格jobです。
		auto	   second	 = parseFixture( secondDom) ;					// 別payloadの厳格jobです。
		const auto firstCap =
			30ULL * 1024ULL * 1024ULL - 2U ;		// PAGE/payloadの検出用各1byteを控除します。
		drivercrate::CollectorRegistryJobResult a ;	// 第一jobの原観測です。
		check( Access::execute( first, second, catRejected ? 7U : 0U, a, &scope, nullptr, firstCap,
							  31001U) == (catRejected
											  ? static_cast<drivercrate::NativeError>( S_FALSE)
											  : drivercrate::NativeError{})) ;
		auto proof = Access::page( scope, root) ;	// 予約前に親が検索する同run証拠です。
		check( proof && Access::hasRaw( *proof) &&
			  a.pageTransfer().completion() == Completion::COMPLETE &&
			  a.payloadTransfer().completion() == Completion::COMPLETE && !a.pageReusedInRun()) ;
		const auto firstOut =
			// 同nativeだけのJSONです。
			JsonObject::Parse( winrt::to_hstring( a.json())) ;
		check( firstOut.GetNamedNumber( L"originalMaximumBytes") == 33554432.0 &&
			  firstOut.GetNamedNumber( L"effectiveMaximumBytes") == firstCap &&
			  winrt::to_string( firstOut.GetNamedObject( L"job").Stringify()) == original) ;
		const auto remaining = drivercrate::COLLECTOR_INSPECTION_MAXIMUM_BYTES -
							   a.pageTransfer().bodyBytesRead() -
							   // 実数精算後の残枠fixtureです。
							   // 次payloadの検出用余裕です。
							   a.payloadTransfer().bodyBytesRead() - 1U ;
		drivercrate::CollectorRegistryJobResult b ;	// 第二jobに別grant/検査を発行します。
		check( Access::execute( second, first, 0U, b, &scope, proof.get(), remaining, 31002U) == 0) ;
		check( state.sends == 3U && state.attempts == 3U &&
			  state.sessions == std::vector<drivercrate::ScanSessionId>{31001U, 31002U} &&
			  state.inspectionPaths.size() == 2U && !state.inspectionPaths[0].empty() &&
			  state.inspectionPaths[0] != state.inspectionPaths[1] && state.safe &&
			  state.opened == state.closed) ;
		const auto secondOut =
			// 元PAGEと増分0を別保持します。
			JsonObject::Parse( winrt::to_hstring( b.json())) ;
		check( b.pageReusedInRun() && b.pageTransfer().attemptedRequests() == 1U &&
			  b.pageTransfer().bodyBytesRead() == HTML.size() &&
			  b.payloadTransfer().bodyBytesRead() == 3U &&
			  secondOut.GetNamedNumber( L"incrementalPageRequests") == 0.0 &&
			  secondOut.GetNamedNumber( L"incrementalPageBodyBytes") == 0.0 &&
			  secondOut.GetNamedNumber( L"effectiveMaximumBytes") == remaining &&
			  secondOut.GetNamedObject( L"job").GetNamedNumber( L"maximumBytes") == 33554432.0) ;
		check( firstOut.GetNamedNumber( L"verifiedInfs") == (catRejected ? 0.0 : 1.0) &&
			  secondOut.GetNamedNumber( L"verifiedInfs") == 1.0) ;
	}

	fixture = nullptr ;
}

/** @brief 無効proof・別run・期限・取消し・anchorを新GETなしで拒否します。 */
void proofRejectionTests()
{
	using Access = drivercrate::CollectorRegistryJobTestAccess ;	// 私有scopeだけを操作します。
	const drivercrate::CollectorInspectionSource root{
		L"https://maker-a.example.org/download/000/",
		L"maker-a.example.org"} ;	// 同起点のexact keyです。
	// 各負例は一条件だけを変え、第一PAGE取得成功を共通前提にします。
	for( unsigned mode = 0U; mode < 9U; ++mode) {
		std::string html =
			"<a href=\"driver.zip\">first</a><a href=\"second.zip\">second</a>" ;	// 元本文です。
		// 第二anchorだけを曖昧にし、第一jobは完全に取得できます。
		if( mode == 1U) {
			html += "<a href=\"second.zip\">duplicate</a>" ;
		}

		// 第二anchor欠落を未取得の正常0件へしません。
		if( mode == 2U) {
			html = "<a href=\"driver.zip\">first</a>" ;
		}

		Fixture state{{Response{html}, Response{"abc"}}} ;	// 第二payloadは送信させません。
		fixture			= &state ;
		auto now		= std::chrono::steady_clock::now() ;			// 元固定時計です。
		auto scope		= Access::makeScope( now) ;						// 第一runです。
		auto otherScope = Access::makeScope( now, L"other-run") ;		// 別runの同じ起点です。
		auto first		= parseFixture( samePageJob( false, html)) ;	// 第一jobは全例成功します。
		auto secondDom	= samePageJob( true, html) ;					// 別anchorの元jobです。
		// 原手動確認hash不一致は借用でも毎job再検証します。
		if( mode == 0U) {
			bindPage( secondDom, html + "changed") ;
		}

		auto second = parseFixture( secondDom) ;	// 未変更schemaの第二jobです。
		drivercrate::CollectorRegistryJobResult a ;	// 実原PAGEを生成する結果です。
		check( Access::execute( first, second, 0U, a, &scope, nullptr, 1024U, 32001U) == 0) ;
		auto proof = Access::page( scope, root) ;	// 元完全本文です。
		check( proof != nullptr) ;
		// 期限到達で全proofを一方向に失効します。
		if( mode == 4U) {
			now += std::chrono::minutes( 10) ;
		}

		// 明示終了も借用を永久に無効にします。
		if( mode == 5U) {
			Access::finish( scope) ;
		}

		// 子停止のcallbackは全scopeを失効します。
		if( mode == 6U) {
			state.cancelled = true ;
		}

		// 単調時計後退を別の有効期間へ読み替えません。
		if( mode == 7U) {
			now -= std::chrono::seconds( 1) ;
		}

		drivercrate::CollectorRegistryJobResult rejected ;	// 新しいrunner/sessionで借用を試します。
		check( Access::execute( second, first, 0U, rejected, mode == 3U ? &otherScope : &scope,
							  mode == 8U ? nullptr : proof.get(), 1024U, 32002U) != 0) ;
		check( state.sends == 2U && state.attempts == 2U && state.sessions.size() == 1U) ;
		// 取消し解除や時計修正でも停止したscopeを復活させません。
		if( mode >= 4U && mode <= 7U) {
			state.cancelled = false ;
			now				= std::chrono::steady_clock::now() ;
			check( !Access::page( scope, root)) ;
		}
	}

	std::shared_ptr<const drivercrate::CollectorRunPageProof>
			old ;	// 元scope破棄後も保持する不変借用です。
	Fixture state{
		{Response{"<a href=\"driver.zip\">first</a>"}, Response{"abc"}}} ;	// 破棄負例です。
	fixture	   = &state ;
	auto now   = std::chrono::steady_clock::now() ;								// 新旧scopeのfake時計です。
	auto first = parseFixture( samePageJob( false, state.responses[0].body)) ;	// 元jobです。
	{
		auto scope = Access::makeScope( now) ;				// Block終了でlifetimeを失効します。
		drivercrate::CollectorRegistryJobResult result ;	// 同原HTTPを生成します。
		check( Access::execute( first, first, 0U, result, &scope, nullptr, 1024U, 32003U) == 0) ;
		old = Access::page( scope, root) ;
	}
	auto scope = Access::makeScope( now) ;				// 同名run/同bindingでも別scopeです。
	drivercrate::CollectorRegistryJobResult rejected ;	// 元scope破棄後の借用です。
	check( old &&
		  Access::execute( first, first, 0U, rejected, &scope, old.get(), 1024U, 32004U) != 0 &&
		  state.sends == 2U) ;
	fixture = nullptr ;
}

/** @brief 各2redirect/実send/原本文量とUNKNOWNを有限故障で確認します。 */
void transferTests()
{
	using Access = drivercrate::CollectorRegistryJobTestAccess ;	// 私有runnerの専用試験です。
	using Completion =
		drivercrate::CollectorHttpTransferCompletion ;	// 全保存と後段検査を分離します。
	// 完全終端と途中故障を同じ低位send/read表で比較します。
	for( unsigned mode = 0U; mode < 18U; ++mode) {
		Fixture state{
			{Response{"<a href=\"driver.zip\">driver</a>"}, Response{"abc"}}} ;	// 基準二GETです。
		fixture			  = &state ;
		auto		  dom = jobFixture() ;	// 原maximum32MiBを保持します。
		std::uint64_t cap = 1024U ;			// 実行枠だけを小さくします。
		// 起点だけを実送信前に拒否します。
		if( mode == 1U) {
			state.failOpen = true ;
		}

		// 実send呼出し失敗を試行数1へ計上します。
		if( mode == 2U) {
			state.failSend = true ;
		}

		// Payloadの一部読取り後失敗を実量2byte/UNKNOWNへ残します。
		if( mode == 3U) {
			state.chunkBytes	 = 2U ;
			state.failAfterBytes = 2U ;
			state.faultResponse	 = 2U ;
		}

		// 最後の保存失敗をHTTP完了へしません。
		if( mode == 4U) {
			state.failFlush = true ;
		}

		// 宣言長不足・超過とも完全終端にしません。
		if( mode == 5U) {
			state.responses[1].contentLength = L"4" ;
		}

		// Cap超過probeも実readした3byteを丸めず保持します。
		if( mode == 6U) {
			cap								 = 2U ;
			state.responses[1].contentLength = L"2" ;
		}

		// 宣言長だけでcap超過と分かれば本文を読みません。
		if( mode == 7U) {
			cap = 2U ;
		}

		// Read復帰後取消しでも同じ実量3byteを保持します。
		if( mode == 8U) {
			state.cancelAfterRead = true ;
			state.faultResponse	  = 2U ;
		}

		// Read後の例外は共通取得境界の明示失敗とtyped UNKNOWNへ残します。
		if( mode == 9U) {
			state.throwAfterRead = true ;
			state.faultResponse	 = 2U ;
		}

		// PAGE/PAYLOADの各二redirectは正確に合計6sendです。
		if( mode >= 10U && mode <= 12U) {
			Response pageRedirect{"", 302U} ;	// 同じorigin内の有限中間応答です。
			pageRedirect.location = L"https://maker-a.example.org/download/000/step" ;
			Response pageRedirect2{"", 302U} ;	// 二番目の同origin redirectです。
			pageRedirect2.location = L"https://maker-a.example.org/download/000/index.html" ;
			Response payloadRedirect{"", 302U} ;	// Payloadも別に最大二回です。
			payloadRedirect.location = L"https://maker-a.example.org/download/000/middle.zip" ;
			Response payloadRedirect2{"", 302U} ;	// 二番目のpayload redirectです。
			payloadRedirect2.location = L"https://maker-a.example.org/download/000/final.zip" ;
			state.responses			  = {pageRedirect,	  pageRedirect2,	state.responses[0],
										 payloadRedirect, payloadRedirect2, Response{"abc"}} ;
			// 起点の第三redirectは第四sendを作りません。
			if( mode == 11U) {
				state.responses[2] = pageRedirect ;
			}

			// Payloadの第三redirectも第七sendを作りません。
			if( mode == 12U) {
				state.responses[5] = payloadRedirect ;
			}
		}

		// PAGE途中失敗はproofを作らず、payload段階を未実行へ残します。
		if( mode == 13U) {
			state.chunkBytes	 = 2U ;
			state.failAfterBytes = 2U ;
			state.faultResponse	 = 1U ;
		}

		// URL検証済みでも二hop目のprivate DNS拒否は送信数へ加えません。
		if( mode == 14U) {
			state.responses[0].status	= 302U ;
			state.responses[0].location = L"https://maker-a.example.org/download/000/index.html" ;
			state.privatePayload		= true ;
		}

		// HTTP拒否statusも実転送診断へ残します。
		if( mode == 15U) {
			state.responses[1].status = 503U ;
		}

		// 大きいavailableでもpayloadの残capと検出用1byteを超えて読みません。
		if( mode == 16U) {
			cap = 2U ;
			state.responses[1].body.assign( 192U * 1024U, 'x') ;
			state.responses[1].contentLength = L"2" ;
		}

		// PAGEの2MiB上限も同じ検出用1byteで止め、余分な本文をproofへ渡しません。
		if( mode == 17U) {
			state.responses[0].body.resize( 2U * 1024U * 1024U + 64U * 1024U, 'x') ;
			state.responses[0].contentLength = L"2097152" ;
		}

		auto									job = parseFixture( dom) ;	// 実parserを省略しません。
		drivercrate::CollectorRegistryJobResult result ;					// 同native観測です。
		const auto								error =
			// 一回実行です。
			Access::execute( job, job, 0U, result, nullptr, nullptr, cap) ;
		check( (error == 0) == (mode == 0U || mode == 10U) && state.safe &&
			  state.opened == state.closed) ;
		check( result.pageTransfer().attemptedRequests() +
				  result.payloadTransfer().attemptedRequests() ==
			  state.attempts) ;
		// 完全取得または後段失敗前のPAGE観測は独立にCOMPLETEです。
		if( mode == 0U || mode == 10U) {
			check( result.pageTransfer().completion() == Completion::COMPLETE &&
				  result.payloadTransfer().completion() == Completion::COMPLETE &&
				  result.payloadTransfer().bodyBytesRead() == 3U &&
				  state.attempts == (mode == 10U ? 6U : 2U)) ;
		}
		// 起点失敗はpayload未実行のままにし、URL検証済みの数を送信数へ加算しません。
		else if( mode == 1U || mode == 2U || mode == 11U || mode == 13U || mode == 14U ||
				mode == 17U) {
			// PAGE失敗時は後段payloadを送らず、未送信open故障だけを0要求にします。
			check( result.pageTransfer().completion() == Completion::UNKNOWN &&
				  result.payloadTransfer().attemptedRequests() == 0U &&
				  state.attempts == (mode == 1U	   ? 0U
									 : mode == 11U ? 3U
												   : 1U)) ;
		} else {
			check( result.pageTransfer().completion() == Completion::COMPLETE &&
				  result.payloadTransfer().completion() == Completion::UNKNOWN) ;
		}

		// 正常redirectはURL検証indexではなく各三実sendを保持します。
		if( mode == 10U) {
			check( result.pageTransfer().attemptedRequests() == 3U &&
				  result.payloadTransfer().attemptedRequests() == 3U) ;
		}

		// 途中readの実量と例外欠損を隠しません。
		if( mode == 3U || mode == 13U) {
			check( (mode == 3U ? result.payloadTransfer() : result.pageTransfer()).bodyBytesRead() ==
				  2U) ;
		}

		// 保存・cap・取消し・例外は実read量をcapへ丸めません。
		if( mode == 4U || mode == 5U || mode == 6U || mode == 8U || mode == 9U) {
			check( result.payloadTransfer().bodyBytesRead() == 3U) ;
		}

		// 宣言長拒否は本文readなしのUNKNOWNです。
		if( mode == 7U || mode == 15U) {
			check( result.payloadTransfer().bodyBytesRead() == 0U) ;
		}

		// 共通取得が例外を数値失敗へ変換した場合も、成功状態は発行しません。
		if( mode == 9U) {
			check( JsonObject::Parse( winrt::to_hstring( result.json())).GetNamedString( L"status") ==
				  L"FAILED") ;
		}

		// 超過本文は上限へ丸めず、予約対象となる検出用1byteを実量へ残します。
		if( mode == 16U || mode == 17U) {
			const auto &transfer =
				// 同失敗段階です。
				mode == 16U ? result.payloadTransfer() : result.pageTransfer() ;
			const auto allowed =
				// 元許可本文上限です。
				mode == 16U ? cap : 2ULL * 1024ULL * 1024ULL ;
			check( transfer.completion() == Completion::UNKNOWN &&
				  transfer.bodyBytesRead() == allowed + 1U && state.sessions.empty()) ;
		}

		// 最後に受信したstatusは拒否時も維持します。
		if( mode == 15U) {
			check( result.payloadTransfer().terminalStatus() == 503U) ;
		}
	}

	// ゼロ・原上限超過・整数最大・期限切れは最初のDNSより前に止めます。
	for( unsigned mode = 0U; mode < 4U; ++mode) {
		Fixture state ;	// 通信しないため応答も不要です。
		fixture	 = &state ;
		auto job = parseFixture( jobFixture()) ;			// 原job上限は32MiBです。
		drivercrate::CollectorRegistryJobResult result ;	// 無効枠は空です。
		const auto								cap = mode == 0U ? 0U
													  : mode == 1U ? drivercrate::COLLECTOR_INSPECTION_MAXIMUM_BYTES + 1U
													  : mode == 2U ? std::numeric_limits<std::uint64_t>::max()
																   : 1U ;	// 各境界の値です。
		check( Access::execute( job, job, 0U, result, nullptr, nullptr, cap, 33000U,
							  mode == 3U ? std::chrono::steady_clock::now()
										 : std::chrono::steady_clock::time_point::max()) != 0 &&
			  state.attempts == 0U && state.dns == 0U && result.json().empty()) ;
	}

	check( !std::is_default_constructible_v<drivercrate::CollectorRunPageScope> &&
		  !std::is_default_constructible_v<drivercrate::CollectorRunPageProof> &&
		  !std::is_default_constructible_v<drivercrate::CollectorRegistryExecutionLimits>) ;
	Access::maximumCapTest() ;
	fixture = nullptr ;
}

/** @brief 実fake PAGEを元に私有cacheのentry/raw合計境界を分離確認します。 */
void pageCacheLimitTests()
{
	using Access = drivercrate::CollectorRegistryJobTestAccess ;	// 専用targetだけの私有seamです。
	const drivercrate::CollectorInspectionSource root{
		L"https://maker-a.example.org/download/000/",
		L"maker-a.example.org"} ;	// 元完全PAGEのkeyです。
	// 小本文32entryと大本文raw32MiBの上限を、それぞれ一つずつ超えて確認します。
	for( const bool large : {false, true}) {
		std::string html = "<a href=\"driver.zip\">driver</a>" ;	// 有効anchorとUTF-8本文です。
		// 最大2MiBのPAGEで、entry数上限より先にraw合計上限へ到達させます。
		if( large) {
			html.resize( 2U * 1024U * 1024U, 'x') ;
		}

		Fixture state{
			{Response{html}, Response{"abc"}}} ;	// 最初のPAGEだけを実fake I/Oで取得します。
		fixture	   = &state ;
		auto now   = std::chrono::steady_clock::now() ;			// 同runの固定単調時計です。
		auto scope = Access::makeScope( now) ;					// 原証拠と容量fixtureの所有境界です。
		auto job   = parseFixture( samePageJob( false, html)) ;	// 原hashを含む実jobです。
		drivercrate::CollectorRegistryJobResult result ;		// 原PAGE/PAYLOADの実観測です。
		check( Access::execute( job, job, 0U, result, &scope, nullptr, 1024U, 35000U) == 0) ;
		auto proof = Access::page( scope, root) ;	// 同じ実I/Oでのみ生成した元証拠です。
		check( proof != nullptr) ;
		// 同保持呼出し中に観測済みの停止を、cache未取得として処理しません。
		if( !large) {
			Access::retainCancellationTest( *proof) ;
		}

		const std::size_t maximumPages = large ? 16U : 32U ;	// 同run上限から導く完全保有数です。
		// 元一件を含め上限まで保持し、退避・古いproof削除で枠を再発行しません。
		for( std::size_t ordinal = 1U; ordinal < maximumPages; ++ordinal) {
			check( Access::retainBoundaryPage( scope, *proof, ordinal)) ;
		}

		check( !Access::retainBoundaryPage( scope, *proof, maximumPages) &&
			  Access::page( scope, root) == proof && state.attempts == 2U &&
			  state.opened == state.closed) ;
	}

	fixture = nullptr ;
}
} // namespace

/** @brief 人工PAGEの限定比較と偽末尾/本文変更の拒否を確認します。 */
void terminalPageComparisonTests()
{
	const std::string prefix =
		"<html><body><a href=\"driver.zip\">terms/prerequisites</a></body>\n</html>" ;	// 人工内容です。
	const std::string old =
		"<!-- WP Fastest Cache file was created in 0.51081204414368 seconds, on 24-10-26 10:12:44 -->" ;	// 旧診断です。
	const std::string fresh =
		"<!-- WP Fastest Cache file was created in 0.59633994102478 seconds, on 25-10-26 11:22:05 -->" ;	// 新診断です。
	// 元内容の比較値です。
	std::wstring expected ;
	// 各入力の計算結果です。
	std::wstring actual ;
	check( drivercrate::computeCollectorMetadataSha256( prefix, expected) == 0) ;
	check( drivercrate::computeCollectorPageContentSha256( prefix + old, actual) == 0 &&
		  actual == expected) ;
	check( drivercrate::computeCollectorPageContentSha256( prefix + fresh, actual) == 0 &&
		  actual == expected) ;
	// 不正/重複/非末尾とscript/属性/comment内の偽終端は全rawで比較します。
	for( const auto &raw :
		{prefix + old + fresh, prefix + fresh + "\n", prefix + fresh + "visible",
		 std::string( "<html><script>\"") + prefix + fresh,
		 std::string( "<html><div title=\"") + prefix + fresh,
		 std::string( "<html><!--") + prefix + fresh,
		 std::string( "<html><template>") + prefix + fresh,
		 std::string( "<html><svg>") + prefix + fresh,
		 prefix +
			 "<!-- WP Fastest Cache file was created in 1.59633994102478 seconds, on 25-10-26 11:22:05 -->",
		 prefix +
			 "<!-- WP Fastest Cache file was created in 0.59633994102478 seconds, on 32-10-26 11:22:05 -->"}) {
		std::wstring original ;	// 正規化しない原SHAです。
		check( drivercrate::computeCollectorMetadataSha256( raw, original) == 0) ;
		check( drivercrate::computeCollectorPageContentSha256( raw, actual) == 0 &&
			  actual == original && actual != expected) ;
	}

	check( drivercrate::computeCollectorPageContentSha256( "changed" + prefix + fresh, actual) == 0 &&
		  actual != expected) ;
	check( drivercrate::computeCollectorPageContentSha256( {}, actual) == E_INVALIDARG &&
		  actual.empty()) ;
}

/** @brief 外部引数を受けず完全fakeの固定集合を実行します。
 * @return 全合格0、固定assertion不一致1です。
 */
int main()
{
	try {
		winrt::init_apartment( winrt::apartment_type::multi_threaded) ;
		terminalPageComparisonTests() ;
		registryTests() ;
		manualReviewTimeTests() ;
		nullableLinkTests() ;
		sharedPageTests() ;
		proofRejectionTests() ;
		transferTests() ;
		pageCacheLimitTests() ;
		std::printf( "Collector registry job checks: %zu\n", checks) ;
		return 0 ;
	} catch( ...) {
		std::printf( "Collector registry job failed at check: %zu\n", checks) ;
		return 1 ;
	}
}
