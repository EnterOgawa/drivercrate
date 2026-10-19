//------------------------------------------------------------------------------
/**
 * @file intel_ethernet_windows11_record_smoke.cpp
 * @brief Intel Windows 11公式recordから共通内容検査までの読取り専用live検証。
 * @version 01.00.01
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  Record限定取得・共通検査・候補集計のlive入口を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/09/15  Compositeと同じ固定root typed resolverへ統一。
 * </pre>
 *
 * @note 明示optionでだけ固定Intel rootを取得します。Full modeはEULA同意済みの一回だけpayloadを
 *       保護workspaceへ取得します。URL、path、hash、端末IDを出力せず、導入・staging・実行を行いません。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 * @see docs/adr/0153-intel-ethernet-windows11-provider-integration.md
 */
//------------------------------------------------------------------------------

#include "core/candidate_assessment.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "platform/com_raii.h"
#include "platform/composite_update_provider.h"
#include "platform/intel_ethernet_windows11_record_adapter.h"
#include "platform/official_acquisition.h"
#include "platform/official_delegated_package_inspection.h"
#include "platform/official_download_grant.h"
#include "platform/official_download_workspace.h"
#include "platform/official_file_verifier.h"
#include "platform/official_http_client.h"
#include "platform/official_record_resolution.h"
#include "platform/official_release_metadata.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace {

//------------------------------------------------------------------------------
// Live検証の固定条件。
//------------------------------------------------------------------------------

constexpr drivercrate::ScanSessionId RECORD_SCAN_SESSION_ID	   = 51U ;				// 公式record取得session。
constexpr drivercrate::ScanSessionId CANDIDATE_SCAN_SESSION_ID = 52U ;				// Local候補集計session。
constexpr drivercrate::OperationId	 RECORD_OPERATION_ID	   = 1U ;				// Record解決operation。
constexpr std::uint64_t				 GRANT_ID				   = 1U ;				// 一回使用grant ID。
constexpr std::uint64_t				 MEBIBYTE				   = 1'048'576U ;		// Byte予算単位。
constexpr std::uint64_t				 MAXIMUM_PAYLOAD_BYTES	   = 128U * MEBIBYTE ;	// Intel ZIP上限。
constexpr std::uint64_t				 MINIMUM_FREE_BYTES = 512U * MEBIBYTE ;			// 取得後の空き容量。
constexpr std::size_t				 EXPECTED_INVENTORY_FILES	 = 467U ;			// 試験Aの通常file数。
constexpr std::size_t				 EXPECTED_VERIFIED_INFS		 = 57U ;			// 試験Aの署名合格INF数。
constexpr std::size_t				 EXPECTED_CLOSURE_REJECTIONS = 15U ;			// 試験Aの構文未対応INF数。
constexpr std::size_t				 EXPECTED_CANDIDATES		 = 11U ;			// 同一PCの試験A候補数。

/** @brief 共通内容検査の個別終端件数です。 */
struct InfStateCounts {
	/// 署名と参照閉包に合格したINF数です。
	std::size_t verified{} ;
	/// 静的閉包を構築できなかったINF数です。
	std::size_t closureRejected{} ;
	/// 閉包後のWindows署名またはCAT memberを拒否したINF数です。
	std::size_t signatureRejected{} ;
} ;

/**
 * @brief 現在UTCをUnix epoch秒へ変換します。
 * @return 0ではない現在UTC秒。Clockがepoch以前の場合は0です。
 */
[[nodiscard]] std::uint64_t currentUtcSeconds() noexcept
{
	const auto now = std::chrono::system_clock::now().time_since_epoch() ;	// 現在のepoch差。
	const auto seconds =
		std::chrono::duration_cast<std::chrono::seconds>( now).count() ;	// 秒単位の符号付き値。
	// 異常な負時刻をgrant発行時刻へ変換しない。
	if( seconds <= 0) {
		return 0U ;
	}

	return static_cast<std::uint64_t>( seconds) ;
}

/**
 * @brief 参照archiveの通常file sizeを取得します。
 * @param[in] path NUL終端の読取り対象pathです。
 * @param[out] size 成功時の正のbyte数、失敗時は0です。
 * @return 再解析点でない通常fileのsizeを取得できた場合は`true`です。
 */
[[nodiscard]] bool readRegularFileSize( const wchar_t *const path, std::uint64_t &size) noexcept
{
	size = 0U ;
	WIN32_FILE_ATTRIBUTE_DATA attributes{} ;	// Windowsが返すfile属性と64-bit sizeです。
	// Null、属性失敗、directory、再解析点を参照archiveとして使用しない。
	if( path == nullptr || path[0] == L'\0' ||
	   GetFileAttributesExW( path, GetFileExInfoStandard, &attributes) == FALSE ||
	   (attributes.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
		   0U) {
		return false ;
	}

	ULARGE_INTEGER combined{} ;	// 上下DWORDを結合したsizeです。
	combined.LowPart  = attributes.nFileSizeLow ;
	combined.HighPart = attributes.nFileSizeHigh ;
	size			  = combined.QuadPart ;
	return size != 0U ;
}

/**
 * @brief 大文字小文字だけを無視して二つのSHA-256表記を比較します。
 * @param[in] left 一つ目の64桁hexです。
 * @param[in] right 二つ目の64桁hexです。
 * @return 両方が64桁でcase-insensitive一致する場合は`true`です。
 */
[[nodiscard]] bool sameSha256( const std::wstring_view left, const std::wstring_view right) noexcept
{
	// 長さを固定してからWindowsのordinal比較へ渡す。
	if( left.size() != 64U || right.size() != 64U) {
		return false ;
	}

	return CompareStringOrdinal( left.data(), static_cast<int>( left.size()), right.data(),
								static_cast<int>( right.size()), TRUE) == CSTR_EQUAL ;
}

/**
 * @brief 共通検査の全INFを有限状態別に数えます。
 * @param[in] inspection 全体検査成功後の所有結果です。
 * @return 三つの既知終端の件数です。
 */
[[nodiscard]] InfStateCounts countInfStates(
	const drivercrate::CommonDriverPackageInspection &inspection) noexcept
{
	InfStateCounts counts ;	// 全INFを一度ずつ数えた結果です。
	// 個別INFを登録順に数え、未知状態を既知の成功へ含めない。
	for( const drivercrate::CommonInfInspection &inf : inspection.infs) {
		// 既知の三終端を個別に集計する。
		switch( inf.state) {
			// 署名と参照閉包を検証済みのINFを成功件数へ加える。
			case drivercrate::CommonInfInspectionState::VERIFIED:
				++counts.verified ;
				break ;

			// 静的参照閉包を安全に構築できなかったINFを個別拒否へ加える。
			case drivercrate::CommonInfInspectionState::CLOSURE_REJECTED:
				++counts.closureRejected ;
				break ;

			// 閉包後のWindows署名またはCAT member拒否を個別拒否へ加える。
			case drivercrate::CommonInfInspectionState::SIGNATURE_REJECTED:
				++counts.signatureRejected ;
				break ;
		}
	}

	return counts ;
}

/**
 * @brief Production HTTPとWindows 11 parserで固定rootを型付きrecordへ変換します。
 * @param[in] scanSessionId 現在のrecord sessionです。
 * @param[in] recordEvidenceId Sessionが割り当てたopaque証拠IDです。
 * @param[in] providerId Registryで検証済みのProvider IDです。
 * @param[in] rootResourceId 固定landing resource IDです。
 * @param[in] builtInRootUrl Registryから解決した組み込みrootです。
 * @param[in] maximumRecordBytes Commandが許可したroot本文上限です。
 * @param[in] fetchMode Cacheを許可しないrecord取得modeです。
 * @param[in,out] client Rootと後続payloadを同一sessionで処理するHTTP clientです。
 * @param[out] record 成功時の秘密URL所有recordです。
 * @return Root、取得証拠、parser、record adapterの成功時は0です。
 */
[[nodiscard]] drivercrate::NativeError resolveIntelWindows11Record(
	const drivercrate::ScanSessionId scanSessionId, const std::uint64_t recordEvidenceId,
	const std::wstring_view providerId, const std::wstring_view rootResourceId,
	const std::wstring_view builtInRootUrl, const std::uint64_t maximumRecordBytes,
	const drivercrate::OfficialRecordFetchMode fetchMode, drivercrate::OfficialHttpClient &client,
	drivercrate::OfficialDistributionRecord &record)
{
	const drivercrate::OfficialDiscoveryFixedRootResult result =
		drivercrate::resolveIntelEthernetWindows11OfficialDiscoveryRecord(
			scanSessionId, recordEvidenceId, providerId, rootResourceId, builtInRootUrl,
			maximumRecordBytes, fetchMode, client,
			record) ;	// Compositeと同じtyped resolver結果です。
	// 旧live sessionの成功契約へ、解決済み状態だけを0として変換する。
	if( result.state == drivercrate::OfficialDiscoveryFixedRootState::RESOLVED) {
		return 0 ;
	}

	return result.error != 0 ? result.error : static_cast<drivercrate::NativeError>( E_UNEXPECTED) ;
}

/**
 * @brief Download済みarchiveを既存Compositeの汎用表示専用候補へ集計します。
 * @param[in] archivePath 保護workspace内の取得済みZIP pathです。
 * @param[out] candidateCount Generic Providerが返した候補行数です。
 * @param[out] providerDiagnostic 個別INF拒否を含むProvider診断値です。
 * @return Driver Store列挙、再内容検査、Windows適合と候補安全状態が整合する場合は0です。
 */
[[nodiscard]] drivercrate::NativeError scanDownloadedArchive(
	const std::wstring_view archivePath, std::size_t &candidateCount,
	drivercrate::NativeError &providerDiagnostic)
{
	candidateCount	   = 0U ;
	providerDiagnostic = 0 ;
	drivercrate::ScanOptions options ;	// Driver Storeと汎用local内容経路だけの設定です。
	options.useDefaultProviders = false ;
	options.enabledProviderIds	= {
		 std::wstring( drivercrate::DRIVER_STORE_PROVIDER_ID),
		 std::wstring( drivercrate::GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID)} ;
	options.userSelectedFiles.push_back(
		{.providerId = std::wstring( drivercrate::GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID),
		 .path		 = std::wstring( archivePath)}) ;

	drivercrate::ProviderProgress				lastProgress{} ;	// 最後に確定したComposite進捗です。
	const drivercrate::ProviderProgressCallback progress =
		[&lastProgress]( const drivercrate::ProviderProgress &current) {
			lastProgress = current ;
		} ; // 非機密の件数進捗だけを保持します。
	drivercrate::CompositeUpdateProvider provider ;	// 製品と同じProvider集約です。
	const drivercrate::ScanResult		 result =
		// OS変更なしの通常scanです。
		provider.scan( CANDIDATE_SCAN_SESSION_ID, options, progress) ;
	// Aggregate失敗を候補なしとして扱わない。
	if( !result.succeeded) {
		return result.error != 0 ? result.error : static_cast<drivercrate::NativeError>( E_FAIL) ;
	}

	const auto report = std::find_if( result.providerReports.begin(), result.providerReports.end(),
									 []( const drivercrate::ProviderScanReport &entry) {
										 return entry.descriptor.id ==
												drivercrate::GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID ;
									 }) ; // 汎用Providerの一報告です。
	// 内容拒否を伴う候補あり、または正常な候補なしだけを受理する。
	if( report == result.providerReports.end() ||
	   (report->state != drivercrate::ProviderScanState::CANDIDATES_AVAILABLE &&
		report->state != drivercrate::ProviderScanState::NO_CANDIDATES)) {
		return static_cast<drivercrate::NativeError>( E_UNEXPECTED) ;
	}

	providerDiagnostic = report->error ;
	// 汎用Provider候補だけを数え、取得済みfileを導入可能へ昇格していないことを確認する。
	for( const drivercrate::UpdateCandidate &candidate : result.candidates) {
		// 別Providerの候補は今回の内容経路へ含めない。
		if( candidate.providerId != drivercrate::GENERIC_SIGNED_INF_PACKAGE_PROVIDER_ID) {
			continue ;
		}

		// 実内容とWindows適合があっても表示専用・取得元未証明の状態を維持する。
		if( candidate.installable || candidate.recommended || !candidate.assessment ||
		   candidate.discoveryBasis !=
			   drivercrate::CandidateDiscoveryBasis::USER_IMPORTED_PACKAGE ||
		   candidate.assessment->signature.state != drivercrate::CandidateAssessmentState::PASSED ||
		   candidate.assessment->applicability.state !=
			   drivercrate::CandidateAssessmentState::PASSED) {
			return static_cast<drivercrate::NativeError>( E_ACCESSDENIED) ;
		}

		++candidateCount ;
	}

	// Provider report、候補行、完了進捗の不一致を受理しない。
	if( candidateCount != report->candidateCount || lastProgress.percentComplete != 100U) {
		return static_cast<drivercrate::NativeError>( E_UNEXPECTED) ;
	}

	return 0 ;
}

/**
 * @brief 固定rootからrecordだけ、または明示同意後の取得・検査までを実行します。
 * @param[in] acquirePayload `true`の場合だけ一回使用grantでpayloadを取得します。
 * @param[in] referenceArchive 取得時に比較する試験Aのarchive pathです。
 * @return 全境界が成立した場合は0、通信・内容・候補差があれば1です。
 */
[[nodiscard]] int runLiveRoute( const bool acquirePayload, const wchar_t *const referenceArchive)
{
	const drivercrate::ComApartment apartment( COINIT_MULTITHREADED) ;	// Worker相当のCOM MTAです。
	// COM初期化に失敗したthreadでnetworkやWindows適合を開始しない。
	if( FAILED( apartment.result())) {
		std::wprintf( L"COM initialization failed: 0x%08X.\n",
					 static_cast<unsigned int>( apartment.result())) ;
		return 1 ;
	}

	const drivercrate::OfficialSourceDefinition *const definition =
		drivercrate::officialSourceDefinition(
			drivercrate::OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11) ;	// 固定727998系列です。
	// 組み込み定義が欠落したbuildではresolverを作らない。
	if( definition == nullptr || definition->maximumMetadataBytes == 0U ||
	   definition->maximumMetadataBytes > 4U * MEBIBYTE) {
		std::wprintf( L"Windows 11 record definition is invalid.\n") ;
		return 1 ;
	}

	drivercrate::OfficialHttpClient client(
		false) ;	// Cacheを読書きしないproduction HTTP clientです。
	const drivercrate::OfficialRecordRootResolver resolver =
		[&client]( const drivercrate::ScanSessionId scanSessionId,
				  const std::uint64_t recordEvidenceId, const std::wstring_view providerId,
				  const std::wstring_view rootResourceId, const std::wstring_view builtInRootUrl,
				  const std::uint64_t						 maximumRecordBytes,
				  const drivercrate::OfficialRecordFetchMode fetchMode,
				  drivercrate::OfficialDistributionRecord	&record) {
			return resolveIntelWindows11Record( scanSessionId, recordEvidenceId, providerId,
											   rootResourceId, builtInRootUrl, maximumRecordBytes,
											   fetchMode, client, record) ;
		} ; // Registryが渡した固定rootだけをproduction parserへ渡します。
	const std::array registrations{drivercrate::OfficialRecordResolverRegistration{
		.providerId		= drivercrate::INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID,
		.rootResourceId = drivercrate::OFFICIAL_LANDING_RESOURCE_ID,
		.resolver		= resolver}} ;	// 一系列だけのlive resolver registryです。

	drivercrate::OfficialRecordResolutionSession
							 resolutionSession ;	// 秘密recordのsession所有者です。
	drivercrate::NativeError error =
		// 一回限りのsession開始結果です。
		resolutionSession.beginSession( RECORD_SCAN_SESSION_ID) ;
	// Session開始失敗時はrootへ通信しない。
	if( error != 0) {
		std::wprintf( L"Record session initialization failed: 0x%08X.\n",
					 static_cast<unsigned int>( error)) ;
		return 1 ;
	}

	drivercrate::OfficialRecordResolutionCommand command{
		.operationId		= RECORD_OPERATION_ID,
		.scanSessionId		= RECORD_SCAN_SESSION_ID,
		.providerId			= std::wstring( definition->providerId),
		.rootResourceId		= std::wstring( drivercrate::OFFICIAL_LANDING_RESOURCE_ID),
		.maximumRecordBytes = definition->maximumMetadataBytes,
		.submittedUrl = drivercrate::SecretOfficialUrl{	// 選択文字列はresolver前に消去されます。
													   std::wstring( definition->landingUrl)}} ;
	const drivercrate::OfficialRecordResolutionResult resolution = resolutionSession.resolve(
		// 取消しなしの明示実行です。
		std::move( command), registrations, []() { return false ; }) ;
	// 非機密結果が一つの保持recordを示さなければ後続へ進まない。
	if( resolution.state != drivercrate::OfficialRecordResolutionState::RESOLVED ||
	   resolution.error != 0 || resolution.recordEvidenceId == 0U ||
	   resolution.retainedRecordCount != 1U) {
		std::wprintf( L"Record resolution failed: 0x%08X.\n",
					 static_cast<unsigned int>( resolution.error)) ;
		return 1 ;
	}

	drivercrate::ResolvedOfficialDistributionRecord resolved ;	// 一回claimする秘密recordです。
	error = resolutionSession.claimResolvedRecord( RECORD_SCAN_SESSION_ID,
												  resolution.recordEvidenceId, resolved) ;
	// Recordの方式・EULA・上限を取得権限発行前に確認する。
	if( error != 0 || resolved.record.recordKey != L"727998" ||
	   resolved.record.terms != drivercrate::OfficialDistributionTerms::ACCEPTANCE_REQUIRED ||
	   resolved.record.eulaRevision.empty() || resolved.record.eulaText.empty() ||
	   resolved.record.payloads.size() != 1U ||
	   resolved.record.payloads.front().kind !=
		   drivercrate::OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE ||
	   resolved.record.payloads.front().maximumBytes != MAXIMUM_PAYLOAD_BYTES ||
	   resolved.record.payloads.front().publishedSha256.size() != 64U) {
		std::wprintf( L"Record schema or EULA validation failed: 0x%08X.\n",
					 static_cast<unsigned int>( error)) ;
		return 1 ;
	}

	// Record-only modeではpayload grantを発行せず、非機密件数だけを表示する。
	if( !acquirePayload) {
		std::wprintf(
			L"Intel Windows 11 record route succeeded: records 1, payloads 1, EULA required, "
			L"maximum bytes %llu.\n",
			static_cast<unsigned long long>( resolved.record.payloads.front().maximumBytes)) ;
		return 0 ;
	}

	std::uint64_t referenceSize{} ;	// 試験A archiveの実byte数です。
	std::wstring  referenceSha256 ;	// 試験A archiveの小文字SHA-256です。
	// 明示された参照archiveが通常fileで、公開hashと一致する場合だけ再取得へ進む。
	if( !readRegularFileSize( referenceArchive, referenceSize) ||
	   drivercrate::computeFileSha256( referenceArchive, referenceSha256) != 0 ||
	   !sameSha256( referenceSha256, resolved.record.payloads.front().publishedSha256)) {
		std::wprintf( L"Reference archive validation failed.\n") ;
		return 1 ;
	}

	const std::uint64_t issuedUtcSeconds = currentUtcSeconds() ;	// 明示操作後のgrant発行時刻です。
	drivercrate::RecordScopedDownloadGrant grant ;					// Payload URLを一回だけ所有するgrantです。
	error = grant.issue( resolved.record, resolved.evidence, 0U, GRANT_ID, issuedUtcSeconds, 0U) ;
	// EULA同意optionがあるこの分岐だけでgrantを発行する。
	if( error != 0 ||
	   grant.metadata().state != drivercrate::OfficialDownloadGrantState::GRANT_ISSUED) {
		std::wprintf( L"Download grant issuance failed: 0x%08X.\n",
					 static_cast<unsigned int>( error)) ;
		return 1 ;
	}

	drivercrate::OfficialDownloadWorkspace workspace ;	// 取得物と展開閉包をscope終了まで所有します。
	error = workspace.initialize( L"intel-win11-record", RECORD_SCAN_SESSION_ID) ;
	// 保護DACL付きworkspaceを作れない場合はnetwork取得を始めない。
	if( error != 0) {
		std::wprintf( L"Protected workspace initialization failed: 0x%08X.\n",
					 static_cast<unsigned int>( error)) ;
		return 1 ;
	}

	const drivercrate::OfficialAcquisitionLimits limits{
		.maximumFileBytes	  = MAXIMUM_PAYLOAD_BYTES,
		.maximumProviderBytes = MAXIMUM_PAYLOAD_BYTES,
		.maximumSessionBytes  = MAXIMUM_PAYLOAD_BYTES,
		.minimumFreeBytes	  = MINIMUM_FREE_BYTES,
		.maximumProviderFiles = 1U,
		.maximumSessionFiles  = 1U} ;	// 一file・一Provider・一sessionの固定予算です。
	drivercrate::OfficialAcquisitionSession
		acquisitionSession ;	// 成功fileだけを数える取得ledgerです。
	error = acquisitionSession.initialize( RECORD_SCAN_SESSION_ID, limits) ;
	// 不正な予算では取得要求を作らない。
	if( error != 0) {
		std::wprintf( L"Acquisition session initialization failed: 0x%08X.\n",
					 static_cast<unsigned int>( error)) ;
		return 1 ;
	}

	drivercrate::OfficialHttpAcquisitionTransport transport(
		client) ;	// Production delegated GET adapterです。
	drivercrate::WindowsOfficialNetworkCostReader
				  costReader ;			// 現在のmachine-wide回線区分readerです。
	std::uint64_t downloadedBytes{} ;	// 最後に通知された確定受信byte数です。
	std::uint64_t announcedBytes{} ;	// 応答が明示した総byte数です。
	const drivercrate::HttpDownloadProgressCallback progress =
		[&downloadedBytes, &announcedBytes]( const std::uint64_t completed,
											const std::uint64_t total) {
			downloadedBytes = completed ;
			announcedBytes	= total ;
		} ; // URLや端末情報を持たない進捗です。
	const drivercrate::OfficialAcquisitionRequest request{
		.workspaceFileName		   = L"record-payload.zip",
		.restrictedNetworkApproved = false,
		.delegatedGrant			   = &grant,
		.delegatedGrantId		   = GRANT_ID,
		.delegatedUtcNow		   = currentUtcSeconds} ;	// EULA同意と回線同意を混同しない要求です。
	drivercrate::OfficialAcquisitionResult acquisition ;	// URL非保持の取得終端です。
	error = acquisitionSession.acquire(
		request, workspace, transport, costReader, progress, []() { return false ; }, acquisition) ;
	// Restricted／Unknown回線では別同意なしに続行せず、専用終了値で示す。
	if( acquisition.state == drivercrate::OfficialAcquisitionState::AWAITING_NETWORK_CONSENT) {
		std::wprintf( L"Acquisition requires separate restricted-network consent.\n") ;
		return 3 ;
	}

	// 取得、grant消費、公開hash、試験A identity、進捗を全て一致させる。
	if( error != 0 ||
	   acquisition.state != drivercrate::OfficialAcquisitionState::ACQUIRED_FOR_INSPECTION ||
	   grant.metadata().state != drivercrate::OfficialDownloadGrantState::CONSUMED ||
	   grant.metadata().outcome !=
		   drivercrate::OfficialDownloadGrantState::ACQUIRED_FOR_INSPECTION ||
	   !acquisition.delegatedRecord || !acquisition.publishedSha256Verified ||
	   !acquisition.destinationLocallyResolved ||
	   acquisition.validatedDestinationAddressCount == 0U ||
	   acquisition.byteCount != referenceSize || !sameSha256( acquisition.sha256, referenceSha256) ||
	   downloadedBytes != acquisition.byteCount ||
	   (announcedBytes != 0U && announcedBytes != acquisition.byteCount)) {
		std::wprintf( L"Delegated acquisition validation failed: 0x%08X.\n",
					 static_cast<unsigned int>( error)) ;
		return 1 ;
	}

	drivercrate::DelegatedOfficialPackageInput packageInput ;	// URL非保持の共通検査入力です。
	error = drivercrate::makeDelegatedOfficialPackageInput( acquisition, grant, packageInput) ;
	// 取得identityとgrantが一致しないfileを共通内容検査へ渡さない。
	if( error != 0 || !sameSha256( packageInput.archive.sha256, referenceSha256)) {
		std::wprintf( L"Delegated package input validation failed: 0x%08X.\n",
					 static_cast<unsigned int>( error)) ;
		return 1 ;
	}

	drivercrate::CommonDriverPackageInspection inspection ;	// 由来と独立した全INF検査結果です。
	error = drivercrate::inspectDelegatedOfficialDriverPackage( RECORD_SCAN_SESSION_ID, packageInput,
															   inspection) ;
	const InfStateCounts infCounts = countInfStates( inspection) ;	// 三終端の実測件数です。
	// 試験Aと同じ通常file・INF終端へ到達しなければ内容差として拒否する。
	if( error != 0 || inspection.inventoryFileCount != EXPECTED_INVENTORY_FILES ||
	   infCounts.verified != EXPECTED_VERIFIED_INFS ||
	   infCounts.closureRejected != EXPECTED_CLOSURE_REJECTIONS ||
	   infCounts.signatureRejected != 0U) {
		std::wprintf( L"Common package inspection differs from test A: 0x%08X.\n",
					 static_cast<unsigned int>( error)) ;
		return 1 ;
	}

	std::size_t reverified{} ;	// 成功閉包を現在内容へ再照合した件数です。
	// 全署名合格INFを同じscope内で再検証し、取得後差替えを見逃さない。
	for( const drivercrate::CommonInfInspection &inf : inspection.infs) {
		// 個別拒否行は再検証対象にせず、成功閉包だけを確認する。
		if( inf.state != drivercrate::CommonInfInspectionState::VERIFIED) {
			continue ;
		}

		error = drivercrate::reverifyCommonDriverInf( inf) ;
		// 一件でも再検証に失敗したら後続のWindows適合へ進まない。
		if( error != 0) {
			std::wprintf( L"Common INF revalidation failed: 0x%08X.\n",
						 static_cast<unsigned int>( error)) ;
			return 1 ;
		}

		++reverified ;
	}

	std::size_t				 candidateCount{} ;		// 現在PCでの表示専用候補行数です。
	drivercrate::NativeError providerDiagnostic{} ;	// 個別拒否を保持する汎用Provider診断です。
	error = scanDownloadedArchive( acquisition.inspectionPath, candidateCount, providerDiagnostic) ;
	// 同一PCの試験Aと候補数が異なる場合はOS状態差として合格にしない。
	if( error != 0 || candidateCount != EXPECTED_CANDIDATES ||
	   reverified != EXPECTED_VERIFIED_INFS) {
		std::wprintf( L"Read-only candidate aggregation differs from test A: 0x%08X.\n",
					 static_cast<unsigned int>( error)) ;
		return 1 ;
	}

	std::wprintf(
		L"Intel Windows 11 record acquisition succeeded: bytes %llu, verified INF %zu, "
		L"closure rejected %zu, candidates %zu, destination addresses %u, diagnostic 0x%08X.\n",
		static_cast<unsigned long long>( acquisition.byteCount), infCounts.verified,
		infCounts.closureRejected, candidateCount, acquisition.validatedDestinationAddressCount,
		static_cast<unsigned int>( providerDiagnostic)) ;
	return 0 ;
}

} // namespace

/**
 * @brief 明示option時だけIntel Windows 11 recordの読取り専用live試験を実行します。
 * @param[in] argumentCount Process開始時のargument数です。
 * @param[in] arguments `--record-only`、または`--accept-eula`と試験A archive pathです。
 * @return 成功0、入力拒否2、別の制限回線同意待ち3、その他失敗1です。
 */
int wmain( const int argumentCount, wchar_t *arguments[])
{
	// Record-onlyはpayload取得、grant発行、local参照を行わない。
	if( argumentCount == 2 && arguments != nullptr && arguments[1] != nullptr &&
	   std::wstring_view( arguments[1]) == L"--record-only") {
		try {
			return runLiveRoute( false, nullptr) ;
		} catch( const std::exception &error) {
			static_cast<void>( error) ;
			std::wcerr << L"Record-only live test raised an exception.\n" ;
			return 1 ;
		} catch( ...) {
			std::wcerr << L"Record-only live test raised an unknown exception.\n" ;
			return 1 ;
		}
	}

	// Full modeは明示EULA optionと試験A archive一件を必須にする。
	if( argumentCount == 3 && arguments != nullptr && arguments[1] != nullptr &&
	   arguments[2] != nullptr && std::wstring_view( arguments[1]) == L"--accept-eula" &&
	   arguments[2][0] != L'\0') {
		try {
			return runLiveRoute( true, arguments[2]) ;
		} catch( const std::exception &error) {
			static_cast<void>( error) ;
			std::wcerr << L"Record acquisition live test raised an exception.\n" ;
			return 1 ;
		} catch( ...) {
			std::wcerr << L"Record acquisition live test raised an unknown exception.\n" ;
			return 1 ;
		}
	}

	std::wprintf( L"Usage: intel_ethernet_windows11_record_smoke --record-only | "
				 L"--accept-eula <test-a-archive>.\n") ;
	return 2 ;
}
