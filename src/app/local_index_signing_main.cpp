//------------------------------------------------------------------------------
/**
 * @file local_index_signing_main.cpp
 * @brief 開発用の明示ローカル鍵操作と原manifest署名のnative入口です。
 * @version 01.08.00
 * @date 2026/10/13
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/13  非export鍵と新規公開fileだけの明示CLIを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/14  用途別取得索引署名と明示固定store importを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/14  共通HTML全文検査と監視側の一意なscript取得証跡を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/15  明示配布profileと鍵store非照会の公開検証を追加。
 * Ver.01.03.01 Shunji Ogawa  2026/10/16  配布取得用途の公開検証と固定鍵署名modeを追加。
 * Ver.01.03.02 Shunji Ogawa  2026/10/17  公開byteだけの全検証modeで未照会の鍵属性表示を除去。
 * Ver.01.04.00 Shunji Ogawa  2026/10/17  署名発行秒に限定した配布取得履歴の明示入口を追加。
 * Ver.01.05.00 Shunji Ogawa  2026/10/23  鍵非照会の未署名候補検査modeを追加。
 * Ver.01.06.00 Shunji Ogawa  2026/10/24  公開履歴の世代下限だけを認証する明示入口を追加。
 * Ver.01.07.00 Shunji Ogawa  2026/10/26  非通信release解析へ公開SHA-512の私有保持を追加。
 * Ver.01.08.00 Shunji Ogawa  2026/10/26 公表exact sizeと実archive SHA-512の検査artifactを追加。
 * </pre>
 *
 * @note 秘密鍵・SID・path・manifest内容を標準出力へ出しません。既存fileを上書きしません。
 * @see docs/adr/0337-local-index-signing-and-build-pins.md
 */
//------------------------------------------------------------------------------
#include "platform/local_index_signing.h"
#include "platform/signed_index_store.h"
#include "platform/unsigned_index_candidate.h"
#include "platform/official_file_verifier.h"
#include "platform/official_release_metadata.h"
#include "platform/common_driver_package.h"
#include "platform/official_driver_closure.h"
#include "platform/official_download_workspace.h"
#include "platform/official_html_terms.h"
#include "platform/official_http_client.h"
#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "local_index_acceptance.h"
#include <charconv>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <windows.h>
#include <wincrypt.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>

namespace {

/** @brief CLIが所有するfile/directory handleだけを回収します。 */
struct HandleCloser {
	/** @brief 有効handleを全終了経路で閉じます。
	 * @param[in] handle 単独ownerのOS handleです。
	 */
	void operator()( void *handle) const noexcept
	{
		static_cast<void>( CloseHandle( handle)) ;
	}
} ;

/** @brief 元Win32拒否codeをmainへ渡す非秘密値です。 */
struct Failure {
	/// 元OS codeです。秘密内容を持ちません。
	DWORD code{} ;
} ;

/** @brief OS handleを単独所有する型です。 */
using OwnedHandle = std::unique_ptr<void, HandleCloser> ;

/** @brief 通常fixed-drive祖先をpinし、file入替えとreparseを拒否します。
 * @param[in] file 明示された絶対file pathです。
 * @return 保存/読取り完了まで祖先を保持するowner集合です。
 */
[[nodiscard]] std::vector<OwnedHandle> pinParents( const std::filesystem::path &file)
{
	// ADS、相対path、network drive、dot componentへの出力を拒否します。
	if( !file.is_absolute() || file != file.lexically_normal() || file.filename().empty() ||
	   file.native().find( L':', 2U) != std::wstring::npos ||
	   GetDriveTypeW( file.root_path().c_str()) != DRIVE_FIXED) {
		throw Failure{ERROR_INVALID_PARAMETER} ;
	}

	std::vector<OwnedHandle> owners ;						// 同operation完了まで祖先を非delete-shareで保持します。
	auto					 path = file.parent_path() ;	// 全祖先を有限に遡るcursorです。
	// Drive rootまで各祖先の同handle属性を確認し、junctionを経由しません。
	while( !path.empty()) {
		const HANDLE raw = CreateFileW( path.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
									   FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
									   FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
									   nullptr) ;	// 既存祖先だけです。
		// 欠損directoryを暗黙作成せず、実codeで中断します。
		if( raw == INVALID_HANDLE_VALUE) {
			throw Failure{GetLastError()} ;
		}

		OwnedHandle				   handle( raw) ;	// 検査途中の失敗でも回収するownerです。
		BY_HANDLE_FILE_INFORMATION information{} ;	// 同実handleの属性です。
		// 属性照会の失敗は成功directoryへ読み替えません。
		if( !GetFileInformationByHandle( handle.get(), &information)) {
			throw Failure{GetLastError()} ;
		}

		// Reparseまたは通常fileの祖先を拒否します。
		if( (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U ||
		   (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) {
			throw Failure{ERROR_INVALID_DATA} ;
		}

		owners.push_back( std::move( handle)) ;
		const auto parent = path.parent_path() ;	// 一つ上の祖先です。
		// Drive rootで終了して同pathを反復しません。
		if( parent == path) {
			break ;
		}

		path = parent ;
	}

	return owners ;
}

/** @brief 明示した上限内の原入力を同handleで有限に読み取ります。
 * @param[in] input 明示された既存の通常fileです。
 * @param[in] maximum 同用途だけへ許可した最大byte数です。
 * @return 再serializationしない原byteです。
 */
[[nodiscard]] std::string readInput( const std::filesystem::path &input, const std::size_t maximum)
{
	const auto	 parents = pinParents( input) ;	// 読取り完了まで全祖先を固定します。
	const HANDLE raw	 = CreateFileW(
		input.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;	// 既存入力だけです。
	// Missing inputを空manifestへ補完しません。
	if( raw == INVALID_HANDLE_VALUE) {
		throw Failure{GetLastError()} ;
	}

	const OwnedHandle		   handle( raw) ;	// 同fileを容量確認から読取りまで固定します。
	BY_HANDLE_FILE_INFORMATION information{} ;	// 同handleの実属性です。
	LARGE_INTEGER			   size{} ;			// Narrowing前に検査する実byte数です。
	// 属性またはsize取得失敗を保持します。
	if( !GetFileInformationByHandle( handle.get(), &information) ||
	   !GetFileSizeEx( handle.get(), &size)) {
		throw Failure{GetLastError()} ;
	}

	// 通常fileの有限原byteだけを受理します。
	if( (information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
		   0U ||
	   size.QuadPart <= 0 || size.QuadPart > static_cast<LONGLONG>( maximum)) {
		throw Failure{ERROR_INVALID_DATA} ;
	}

	std::string bytes( static_cast<std::size_t>( size.QuadPart), '\0') ;	// 正確な原入力容量です。
	DWORD		read{} ;													// 実APIが確認したbyte数です。
	// Short readを完全manifestとして署名しません。
	if( !ReadFile( handle.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &read, nullptr)) {
		throw Failure{GetLastError()} ;
	}

	// 実容量と一致しない入力を拒否します。
	if( read != bytes.size()) {
		throw Failure{ERROR_READ_FAULT} ;
	}

	return bytes ;
}

/** @brief Build固定local pinがある開発profileだけで固定storeへ原索引をimportします。
 * @param[in] envelopeFile 明示した原署名envelopeの絶対pathです。
 * @param[in] assetFile 同manifestへ結合した原GZipの絶対pathです。
 * @return Commitと再認証の全成立時0、元拒否時2です。
 * @note 任意store/key、highwater削除、network、scan、導入を扱いません。
 */
[[nodiscard]] int importIndex( const std::filesystem::path &envelopeFile,
							  const std::filesystem::path &assetFile)
{
	// 通常OFFでは入力fileとProgramDataへ触れる前に拒否します。
	if( drivercrate::local_index_profile::TRUST_KEYS.empty()) {
		throw Failure{ERROR_ACCESS_DENIED} ;
	}

	const auto now =
		std::chrono::floor<std::chrono::seconds>( std::chrono::system_clock::now()) ;	// 実OS UTC。
	const auto envelope =
		// 原署名だけです。
		readInput( envelopeFile, drivercrate::INDEX_ENVELOPE_MAX_BYTES) ;
	const auto packed =
		// 原GZipだけです。
		readInput( assetFile, drivercrate::INDEX_ASSET_MAX_BYTES) ;
	const auto manifest =
		// Build固定pin。
		drivercrate::authenticateSignedIndexManifest( envelope, now, std::nullopt) ;
	// 署名/期限の失敗から後続storeを作りません。
	if( !manifest.manifest) {
		std::printf( "LOCAL_INDEX_IMPORT manifest=%u code=0x%08lx\n",
					static_cast<unsigned>( manifest.status),
					static_cast<unsigned long>( manifest.error)) ;
		return 2 ;
	}

	const auto bytes = std::as_bytes(
		std::span<const char>{packed.data(), packed.size()}) ;	// 呼出し中だけの原byte view。
	const auto asset = drivercrate::authenticateIndexAssetBytes( *manifest.manifest, bytes,
																now) ;	// 実hash/size/GZip。
	// 実byteの拒否を署名成功だけで補いません。
	if( !asset.receipt) {
		std::printf( "LOCAL_INDEX_IMPORT asset=%u code=0x%08lx\n",
					static_cast<unsigned>( asset.status), static_cast<unsigned long>( asset.error)) ;
		return 2 ;
	}

	const auto records = drivercrate::readSignedIndexRecords( *asset.receipt, now) ;	// 原v2/quality。
	// Metadata型の拒否時も保存operationを始めません。
	if( !records.receipt) {
		std::printf( "LOCAL_INDEX_IMPORT records=%u code=0x%08lx\n",
					static_cast<unsigned>( records.status),
					static_cast<unsigned long>( records.error)) ;
		return 2 ;
	}

	auto opened =
		// 既存保護initializerだけです。
		drivercrate::SignedIndexStore::openFixedProtectedStore() ;
	// 不適合既存rootをrepairせず元codeで中止します。
	if( !opened.store) {
		std::printf( "LOCAL_INDEX_IMPORT open=0 code=0x%08lx\n",
					static_cast<unsigned long>( opened.error)) ;
		return 2 ;
	}

	const auto committed =
		// 既存highwater/原子保存。
		opened.store->commit( *records.receipt, envelope, bytes, now) ;
	std::printf( "LOCAL_INDEX_IMPORT status=%u commit=%u code=0x%08lx\n",
				static_cast<unsigned>( committed.status), static_cast<unsigned>( committed.commit),
				static_cast<unsigned long>( committed.error)) ;
	// Commitの不確定や拒否を再認証成功で隠しません。
	if( !committed.snapshot) {
		return 2 ;
	}

	const auto reloaded = opened.store->reload( now) ;	// 元原byteを再認証して終了します。
	std::printf( "LOCAL_INDEX_IMPORT reloaded=%u code=0x%08lx\n",
				reloaded.snapshot.has_value() ? 1U : 0U,
				static_cast<unsigned long>( reloaded.error)) ;
	return reloaded.snapshot ? 0 : 2 ;
}

/** @brief 不正UTF-8を補完せず保存原byteを既存parserのUTF-16へ変換します。
 * @param[in] bytes 上限確認済みの原UTF-8です。
 * @return 全変換成功時だけ原textです。
 */
[[nodiscard]] std::wstring savedUtf8Text( const std::string_view bytes)
{
	const int units = MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(),
										  // 有限入力の実必要長。
										  static_cast<int>( bytes.size()), nullptr, 0) ;
	// 変換不能を空metadataへ補完しません。
	if( units <= 0) {
		throw Failure{GetLastError()} ;
	}

	std::wstring text( static_cast<std::size_t>( units), L'\0') ;	// Parserだけが借用します。
	// 同原byteの完全変換以外は拒否します。
	if( MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(),
						   static_cast<int>( bytes.size()), text.data(), units) != units) {
		throw Failure{ERROR_INVALID_DATA} ;
	}

	return text ;
}

/** @brief 元body hashと過去観測へ結び、監視側だけで保存releaseを再解析します。
 * @param[in] bodyFile 固定済み原UTF-8 bodyの絶対pathです。
 * @param[in] expectedHash 原evidenceへ事前結合した小文字SHA-256です。
 * @param[in] observed 原evidenceのUTC秒を表す十進literalです。
 * @return Metadataと原許諾の新JSONです。新HTTP証拠/grant/端末適用性ではありません。
 * @note 固定Intel parserは開発collector側toolだけへ接続し、通常appに増設しません。
 */
[[nodiscard]] std::string parseSavedRelease( const std::filesystem::path &bodyFile,
											const std::wstring_view		 expectedHash,
											const std::wstring_view		 observed)
{
	const auto	 raw = readInput( bodyFile, 512U * 1024U) ;					// 保存原byteだけです。
	std::wstring hash ;														// 共通SHA-256の原結果。
	const auto	 hashError = drivercrate::computeBytesSha256( raw, hash) ;	// 別暗号実装を足しません。
	// 不一致の原入力や非canonical digestはparserへ渡しません。
	if( hashError != 0 || expectedHash.size() != 64U || hash != expectedHash) {
		throw Failure{hashError != 0 ? static_cast<DWORD>( hashError) : ERROR_CRC} ;
	}

	std::string literal ;	// 十進秒だけを欠損なく借用変換します。
	// 原観測literalをUnicode/符号/空白の補正なしに確認します。
	for( const auto character : observed) {
		// 時刻の正規化や現在時刻への置換を許可しません。
		if( character < L'0' || character > L'9') {
			throw Failure{ERROR_INVALID_PARAMETER} ;
		}

		literal.push_back( static_cast<char>( character)) ;
	}

	std::uint64_t seconds{} ;	// 原過去観測の秒だけです。
	const auto	  parsed =
		// Overflow拒否。
		std::from_chars( literal.data(), literal.data() + literal.size(), seconds) ;
	const auto now = std::chrono::duration_cast<std::chrono::seconds>(
						 std::chrono::system_clock::now().time_since_epoch())
						 .count() ;	// 未来入力拒否だけへ使用します。
	// 欠損/未来/overflow観測をfresh evidenceへ読み替えません。
	if( literal.empty() || literal.size() > 20U || parsed.ec != std::errc{} ||
	   parsed.ptr != literal.data() + literal.size() || seconds == 0U || now <= 0 ||
	   seconds > static_cast<std::uint64_t>( now)) {
		throw Failure{ERROR_INVALID_PARAMETER} ;
	}

	const auto html = savedUtf8Text( raw) ;			// 原bodyからだけ生成するparser view。
	drivercrate::OfficialReleaseRecord release ;	// 既存metadata parserの所有出力。
	// 別page/familyや許諾欠測を取得可能なrecordへ補完しません。
	if( !drivercrate::parseOfficialReleaseRecord(
		   drivercrate::OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11, html, release) ||
	   release.family != drivercrate::OfficialReleaseFamily::INTEL_ETHERNET_WINDOWS11 ||
	   release.fileName.empty() || release.downloadUrl.empty() ||
	   (release.publishedSha256.empty() && release.publishedSha512.empty()) ||
	   release.license != drivercrate::OfficialReleaseLicense::ACCEPTANCE_BEFORE_DOWNLOAD ||
	   release.eulaText.empty() || release.eulaRevision.empty()) {
		throw Failure{ERROR_INVALID_DATA} ;
	}

	// JSON保存だけの開発threadです。
	winrt::init_apartment( winrt::apartment_type::multi_threaded) ;
	using winrt::Windows::Data::Json::JsonObject ;
	using winrt::Windows::Data::Json::JsonValue ;
	JsonObject value ;	// 新artifactだけに保存する非inventory証拠。
	// SHA-512を解釈しない旧readerが追加fieldを無視しないよう別schemaへ結合します。
	value.Insert( L"schema", JsonValue::CreateStringValue( release.publishedSha512.empty()
															 ? L"dc-saved-release-analysis-v1"
															 : L"dc-saved-release-analysis-v2")) ;
	value.Insert( L"source", JsonValue::CreateStringValue( L"INTEL_ETHERNET_WINDOWS11")) ;
	value.Insert( L"bodySha256", JsonValue::CreateStringValue( hash)) ;
	value.Insert( L"observedUtcSeconds", JsonValue::CreateStringValue( winrt::to_hstring( literal))) ;
	value.Insert( L"freshNetworkEvidence", JsonValue::CreateBooleanValue( false)) ;
	value.Insert( L"acquisitionAuthority", JsonValue::CreateBooleanValue( false)) ;
	value.Insert(
		L"distributionPage",
		JsonValue::CreateStringValue(
			L"https://www.intel.com/content/www/us/en/download/727998/intel-network-adapter-driver-for-microsoft-windows-11.html")) ;
	value.Insert( L"payloadUrl", JsonValue::CreateStringValue( release.downloadUrl)) ;
	value.Insert( L"fileName", JsonValue::CreateStringValue( release.fileName)) ;
	value.Insert( L"packageVersion", JsonValue::CreateStringValue( release.packageVersion)) ;
	value.Insert( L"publishedSha256", JsonValue::CreateStringValue( release.publishedSha256)) ;
	// 公表exact値だけを保存し、概算display sizeから値を合成しません。
	if( release.publishedSizeBytes) {
		value.Insert( L"publishedSizeBytes", JsonValue::CreateNumberValue(
												static_cast<double>( *release.publishedSizeBytes))) ;
	}

	// 未掲載SHA-512を新しい公開値として合成せず、掲載時だけ算法別に保存します。
	if( !release.publishedSha512.empty()) {
		value.Insert( L"publishedSha512", JsonValue::CreateStringValue( release.publishedSha512)) ;
	}

	value.Insert( L"parserRevision", JsonValue::CreateNumberValue( release.parserRevision)) ;
	value.Insert( L"termsRevision", JsonValue::CreateStringValue( release.eulaRevision)) ;
	value.Insert( L"termsText", JsonValue::CreateStringValue( release.eulaText)) ;
	const auto termsUtf8 =
		// 元parser全文のUTF-8だけです。
		winrt::to_string( winrt::hstring{release.eulaText}) ;
	std::wstring termsHash ;	// 出典bodyのhashとは別の全文hashです。
	const auto	 termsHashError =
		// 原全文hashの実結果です。
		drivercrate::computeBytesSha256( termsUtf8, termsHash) ;
	// 原全文hashを確認できない解析結果は保存しません。
	if( termsHashError != 0) {
		throw Failure{static_cast<DWORD>( termsHashError)} ;
	}

	value.Insert( L"termsTextSha256", JsonValue::CreateStringValue( termsHash)) ;
	value.Insert( L"termsTextUtf8Bytes",
				 JsonValue::CreateNumberValue( static_cast<double>( termsUtf8.size()))) ;
	drivercrate::IndexHtmlTermsExtraction extraction ;	// 監視側が実要素へ限定する公開selectorです。
	extraction.profile			 = "TEXTAREA_HTML_DOCUMENT_V1" ;
	extraction.selector			 = {"textarea", "id", "content-raw"} ;
	extraction.containerSelector = {"div", "id", "licenseModal"} ;
	extraction.linkSelector		 = {"button", "data-modal-id", "1"} ;
	extraction.payloadAttribute	 = "data-href" ;
	drivercrate::HtmlTermsTextObservation terms ;	// 新共通rendererの独立した原文書/全文です。
	const auto							  extractionError = drivercrate::extractStaticHtmlTerms(
		   html, extraction, winrt::to_string( winrt::hstring{release.downloadUrl}),
		   release.eulaRevision, terms) ;	// 元payloadへ結合します。
	// 同じ原bodyから既存parserと共通rendererの全文が一致しない場合は投影しません。
	if( extractionError != 0U || terms.text != release.eulaText) {
		std::printf( "LOCAL_INDEX_HTML stage=%u offset=%zu\n", terms.checkStage, terms.checkOffset) ;
		throw Failure{extractionError != 0U ? static_cast<DWORD>( extractionError) : ERROR_CRC} ;
	}

	const auto documentUtf8 =
		// 選択原文書の完全UTF-8です。
		winrt::to_string( winrt::hstring{terms.document}) ;
	std::wstring documentHash ;	// 原page/抽出全文とは別の選択raw文書hashです。
	const auto	 documentHashError =
		// 共通hashだけです。
		drivercrate::computeBytesSha256( documentUtf8, documentHash) ;
	// 選択文書の実hashが不明な結果をKNOWNへ補完しません。
	if( documentHashError != 0U) {
		throw Failure{static_cast<DWORD>( documentHashError)} ;
	}

	const auto selector = []( const drivercrate::IndexHtmlTermsSelector &source) {
		// 呼出し中だけ元selectorを借用して非秘密JSONへ写します。
		JsonObject result ;	// 三つの原属性だけを保持します。
		result.Insert( L"tag", JsonValue::CreateStringValue( winrt::to_hstring( source.tag))) ;
		result.Insert( L"attribute",
					  JsonValue::CreateStringValue( winrt::to_hstring( source.attribute))) ;
		result.Insert( L"value", JsonValue::CreateStringValue( winrt::to_hstring( source.value))) ;
		return result ;
	} ; // 元selectorを同期中だけ借用します。
	JsonObject projection ;	// 監視側の未認証抽出metadataです。
	projection.Insert( L"profile", JsonValue::CreateStringValue( L"TEXTAREA_HTML_DOCUMENT_V1")) ;
	projection.Insert( L"selector", selector( extraction.selector)) ;
	projection.Insert( L"containerSelector", selector( extraction.containerSelector)) ;
	projection.Insert( L"linkSelector", selector( extraction.linkSelector)) ;
	projection.Insert( L"payloadAttribute", JsonValue::CreateStringValue( L"data-href")) ;
	projection.Insert( L"documentSha256", JsonValue::CreateStringValue( documentHash)) ;
	projection.Insert( L"documentSizeBytes",
					  JsonValue::CreateNumberValue( static_cast<double>( documentUtf8.size()))) ;
	projection.Insert( L"textSha256", JsonValue::CreateStringValue( termsHash)) ;
	projection.Insert( L"textSizeBytes",
					  JsonValue::CreateNumberValue( static_cast<double>( termsUtf8.size()))) ;
	projection.Insert( L"bindingEvidenceUrl", JsonValue::CreateStringValue( L"")) ;
	projection.Insert( L"bindingEvidenceSha256", JsonValue::CreateStringValue( L"")) ;
	value.Insert( L"htmlExtraction", projection) ;
	value.Insert( L"bodyBytes", JsonValue::CreateNumberValue( static_cast<double>( raw.size()))) ;
	value.Insert( L"termsDocumentState",
				 JsonValue::CreateStringValue( L"HTML_EXTRACTED_BINDING_UNCONFIRMED")) ;
	return winrt::to_string( value.Stringify()) ;
}

/** @brief 同sourceの保存pageへ一意に結合する公式scriptを非実行で取得します。
 * @param[in] input 保存原bodyの絶対pathです。
 * @param[in] hash 同じ原bodyの完全hashです。
 * @param[in] observed 保存bodyの元観測秒です。現在時刻へ変更しません。
 * @param[in] url 保存pageの実srcに完全一致する同origin静的script URLです。
 * @return 原script byteとhash/実観測を保持する新規分析JSONです。
 * @note 最大64KiB、redirect0、retry0、120秒で停止を要求し、payload/JS実行は行いません。
 */
[[nodiscard]] std::string collectLinkedTermsScript( const std::filesystem::path &input,
												   const std::wstring_view		hash,
												   const std::wstring_view		observed,
												   const std::wstring_view		url)
{
	static_cast<void>(
		// 原page/family/hash/全文を先に検査します。
		parseSavedRelease( input, hash, observed)) ;
	const auto rawPage = readInput( input, 256U * 1024U) ;	// 元bodyだけを有限に再読します。
	const auto page	   = savedUtf8Text( rawPage) ;			// 厳密UTF-8からの原viewです。
	constexpr std::wstring_view PAGE =
		// 固定監視sourceです。
		L"https://www.intel.com/content/www/us/en/download/727998/intel-network-adapter-driver-for-microsoft-windows-11.html" ;
	// Cacheや別network実装を追加しません。
	drivercrate::OfficialHttpClient client( false) ;
	const auto						sessionError = client.beginSourceSession(
		 1U,
		 drivercrate::INTEL_ETHERNET_WINDOWS11_OFFICIAL_PROVIDER_ID) ;	// 元policyだけを使用します。
	// Source不一致を別sessionの許可へ変換しません。
	if( sessionError != 0U) {
		throw Failure{static_cast<DWORD>( sessionError)} ;
	}

	const auto deadline =
		// 停止上限です。
		std::chrono::steady_clock::now() + std::chrono::seconds{120} ;
	std::string script ;	// 成功した原scriptだけをRAMへ保持します。
	const auto	error = client.getCollectorLinkedScriptForSource(
		 PAGE, page, url, drivercrate::OFFICIAL_LANDING_RESOURCE_ID,
		 [deadline] { return std::chrono::steady_clock::now() >= deadline ; },
		 script) ;	// 元pageの実参照だけです。
	// 拒否/失敗を反復や成功根拠へ補完しません。
	if( error != 0U) {
		throw Failure{static_cast<DWORD>( error)} ;
	}

	std::wstring scriptHash ;														// 実取得した原byteの完全hashです。
	const auto	 hashError = drivercrate::computeBytesSha256( script, scriptHash) ;	// 共通hashです。
	// 原byte/hashが不明な取得証跡を発行しません。
	if( hashError != 0U || script.empty() || script.size() > 64U * 1024U) {
		throw Failure{hashError != 0U ? static_cast<DWORD>( hashError) : ERROR_INVALID_DATA} ;
	}

	DWORD encodedSize{} ;	// 改行なしbase64の必要容量です。
	// 完全原byteの必要容量を先に検査します。
	if( CryptBinaryToStringA(
		   reinterpret_cast<const BYTE *>( script.data()), static_cast<DWORD>( script.size()),
		   CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &encodedSize) == FALSE) {
		throw Failure{GetLastError()} ;
	}

	std::string encoded( encodedSize, '\0') ;	// 分析用原byteを損失なく保持する一時値です。
	// Base64失敗を原byte出力として扱いません。
	if( CryptBinaryToStringA(
		   reinterpret_cast<const BYTE *>( script.data()), static_cast<DWORD>( script.size()),
		   CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, encoded.data(), &encodedSize) == FALSE) {
		throw Failure{GetLastError()} ;
	}

	encoded.resize( encodedSize) ;
	// APIの任意終端NULはJSON本文へ入れません。
	if( !encoded.empty() && encoded.back() == '\0') {
		encoded.pop_back() ;
	}

	const auto now = std::chrono::floor<std::chrono::seconds>(
		// 実取得後UTCです。
		std::chrono::system_clock::now()) ;
	using winrt::Windows::Data::Json::JsonObject ;
	using winrt::Windows::Data::Json::JsonValue ;
	JsonObject result ;	// 原JS証跡だけの分析JSONです。
	result.Insert( L"schema", JsonValue::CreateStringValue( L"dc-collected-terms-script-v1")) ;
	result.Insert( L"source", JsonValue::CreateStringValue( L"INTEL_ETHERNET_WINDOWS11")) ;
	result.Insert( L"pageUrl", JsonValue::CreateStringValue( PAGE)) ;
	result.Insert( L"pageSha256", JsonValue::CreateStringValue( hash)) ;
	result.Insert( L"pageObservedUtcSeconds", JsonValue::CreateStringValue( observed)) ;
	result.Insert( L"scriptUrl", JsonValue::CreateStringValue( url)) ;
	result.Insert( L"scriptSha256", JsonValue::CreateStringValue( scriptHash)) ;
	result.Insert( L"scriptSizeBytes",
				  JsonValue::CreateNumberValue( static_cast<double>( script.size()))) ;
	result.Insert( L"scriptBytesBase64", JsonValue::CreateStringValue( winrt::to_hstring( encoded))) ;
	result.Insert( L"scriptObservedUtcSeconds",
				  JsonValue::CreateStringValue( winrt::to_hstring( now.time_since_epoch().count()))) ;
	result.Insert( L"httpStatus", JsonValue::CreateNumberValue( 200)) ;
	result.Insert( L"pageFreshNetworkEvidence", JsonValue::CreateBooleanValue( false)) ;
	result.Insert( L"scriptFreshNetworkEvidence", JsonValue::CreateBooleanValue( true)) ;
	result.Insert( L"scriptExecuted", JsonValue::CreateBooleanValue( false)) ;
	result.Insert( L"payloadGet", JsonValue::CreateNumberValue( 0)) ;
	return winrt::to_string( result.Stringify()) ;
}

/** @brief 非秘密public blobまたはenvelopeを新規fileへ保存します。
 * @param[in] output 明示された不存在の通常file pathです。
 * @param[in] bytes 同用途の上限内にある非秘密byteです。
 * @param[in] maximum 用途別の有限出力上限です。署名用途は既定96KiBを維持します。
 * @note 途中fileも削除せず、write/flush/closeの成功だけを返します。
 */
void writeNew( const std::filesystem::path &output, const std::span<const std::uint8_t> bytes,
			  const std::size_t maximum = drivercrate::INDEX_ENVELOPE_MAX_BYTES)
{
	const auto parents = pinParents( output) ;	// 完了まで祖先を固定します。
	// 有限な公開byte以外を出力しません。
	if( bytes.empty() || bytes.size() > maximum) {
		throw Failure{ERROR_INVALID_DATA} ;
	}

	const HANDLE raw = CreateFileW( output.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_NEW,
								   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
								   nullptr) ;	// 上書きを禁止します。
	// 既存fileやアクセス拒否を成功へ変換しません。
	if( raw == INVALID_HANDLE_VALUE) {
		throw Failure{GetLastError()} ;
	}

	OwnedHandle handle( raw) ;	// 部分出力を残してhandleだけ回収します。
	DWORD		written{} ;		// 実write byte数です。
	// 全writeとflushが完了するまで成功を返しません。
	if( !WriteFile( handle.get(), bytes.data(), static_cast<DWORD>( bytes.size()), &written,
				  nullptr)) {
		throw Failure{GetLastError()} ;
	}

	// Short writeは別の原失敗として保持します。
	if( written != bytes.size()) {
		throw Failure{ERROR_WRITE_FAULT} ;
	}

	// 保存装置へのflush失敗を出力成功としません。
	if( !FlushFileBuffers( handle.get())) {
		throw Failure{GetLastError()} ;
	}

	// 正常close失敗も結果へ保持します。
	if( !CloseHandle( handle.release())) {
		throw Failure{GetLastError()} ;
	}
}

/** @brief 同archive hashへ結合する通常検査と公開INF receiptを監視側へ出力します。
 * @param[in] archiveFile 明示した取得済み通常archiveの絶対pathです。
 * @param[in] expectedHash 対象配布物へ固定した小文字SHA-256です。
 * @param[in] selectedInf 固定した外側一INFの原相対pathです。
 * @return 通常検査の全行とVERIFIED INFだけの公開metadata JSONです。
 * @note 取得/公式性/端末適用性/導入を証明しません。元archiveを実行しません。
 */
[[nodiscard]] std::string inspectCollectedPackage( const std::filesystem::path &archiveFile,
												  const std::wstring_view	   expectedHash,
												  const std::wstring_view	   selectedInf)
{
	using namespace drivercrate ;
	constexpr ScanSessionId		SESSION = 20402U ;	// 取得済み入力だけの一回sessionです。
	OfficialDownloadWorkspace	workspace ;			// 元archiveの保護copyを所有します。
	DriverArchiveInput			input ;				// 実copy後の原size/hashです。
	OfficialDriverArchiveFormat format{} ;			// 推測せず共通copyが判別する形式です。
	const auto					copied =
		// 今回検査する保護copyの同size/hashだけを返す実結果です。
		copyLocalDriverArchive( archiveFile.native(), SESSION, workspace, input, format) ;
	// コピー失敗や別原archiveを検査証拠へ変換しません。
	if( copied != 0 || expectedHash.size() != 64U || input.sha256 != expectedHash) {
		throw Failure{copied != 0 ? static_cast<DWORD>( copied) : ERROR_CRC} ;
	}

	winrt::init_apartment(
		winrt::apartment_type::multi_threaded) ;	// 全Windows署名検査を同MTAで行います。
	CommonDriverPackageInspection inspection ;		// 通常policyの全成功/拒否行です。
	const auto					  inspected =
		// 実INF/CAT/全参照fileです。
		inspectSelectedCommonDriverPackage( input, format, selectedInf, inspection) ;
	using winrt::Windows::Data::Json::JsonArray ;
	using winrt::Windows::Data::Json::JsonObject ;
	using winrt::Windows::Data::Json::JsonValue ;
	JsonObject	 value ;			// 私有path/実端末情報を持たない新artifactです。
	std::wstring archiveSha512 ;	// 同じ保護copyの実SHA-512です。公開値を代用しません。
	const auto	 hashError =
		// 共通有限readerです。
		drivercrate::computeFileSha512( input.inspectionPath, archiveSha512) ;
	// 別算法を実copyへ結合できない検査artifactを発行しません。
	if( hashError != 0) {
		throw Failure{static_cast<DWORD>( hashError)} ;
	}

	value.Insert( L"schema", JsonValue::CreateStringValue( L"dc-inspected-public-identities-v3")) ;
	value.Insert( L"archiveSha256", JsonValue::CreateStringValue( input.sha256)) ;
	value.Insert( L"archiveSha512", JsonValue::CreateStringValue( archiveSha512)) ;
	value.Insert( L"archiveBytes",
				 JsonValue::CreateNumberValue( static_cast<double>( input.byteCount))) ;
	value.Insert( L"inspectionError", JsonValue::CreateNumberValue( inspected)) ;
	value.Insert( L"officialAuthority", JsonValue::CreateBooleanValue( false)) ;
	value.Insert( L"actualApplicabilityChecked", JsonValue::CreateBooleanValue( false)) ;
	value.Insert( L"selectedOnly", JsonValue::CreateBooleanValue( true)) ;
	value.Insert( L"selectedInf", JsonValue::CreateStringValue( selectedInf)) ;
	JsonArray	rows ;			// 失敗行も分母へ保持します。
	std::size_t verified{} ;	// 通常内容/CATと公開identityを両方確認したINF数です。
	// 有限な全INFの順序を保持し、署名失敗を成功行から省略しません。
	for( const auto &inf : inspection.infs) {
		JsonObject row ;	// 実端末のIDを入力しない一公開INFです。
		row.Insert( L"state", JsonValue::CreateNumberValue( static_cast<unsigned>( inf.state))) ;
		row.Insert( L"contentError", JsonValue::CreateNumberValue( inf.error)) ;
		row.Insert( L"publishedIdentityKnown", JsonValue::CreateBooleanValue( false)) ;
		// VERIFIED閉包以外へ公開identity成功を付与しません。
		if( inf.state == CommonInfInspectionState::VERIFIED && inf.workspace &&
		   inf.closure.packages.size() == 1U) {
			const auto &package = inf.closure.packages.front() ;	// 同通常検査が確認した元INFです。
			OfficialInfPublishedIdentity identity ;					// 同元HINFの非許可metadataです。
			auto						 error = readOfficialInfPublishedIdentity(
				*inf.workspace, package, identity) ;	// 原metadata読取りの実結果です。
			// 原metadata読取り後にも全CAT/memberを通常policyで確認します。
			if( error == 0) {
				error = verifyWindowsInfPackageIntegrity( *inf.workspace, package) ;
			}

			std::wstring publisher ;	// Providerとは別の実Windows signerです。
			// 新publisher metadataだけを同共通署名/全member検査へ結合します。
			if( error == 0U) {
				error = readWindowsInfPackagePublisher( *inf.workspace, package, publisher) ;
			}

			row.Insert( L"identityError", JsonValue::CreateNumberValue( error)) ;
			// 元ClassGUID/節/IDと実署名が両方成立したINFだけへmetadataを出力します。
			if( error == 0) {
				++verified ;
				std::wstring relative = inf.infRelativePath ;	// 公開相対INF名だけです。
				// Package相対表記だけを索引のslash規則へ表現します。
				for( auto &character : relative) {
					// 生端末IDやlocal絶対pathを作らず区切りだけを変えます。
					if( character == L'\\') {
						character = L'/' ;
					}
				}

				row.Insert( L"publishedIdentityKnown", JsonValue::CreateBooleanValue( true)) ;
				row.Insert( L"infIdentity", JsonValue::CreateStringValue( relative)) ;
				row.Insert( L"infSha256", JsonValue::CreateStringValue( identity.infSha256)) ;
				row.Insert( L"classGuid", JsonValue::CreateStringValue( identity.classGuid)) ;
				row.Insert( L"driverVersion", JsonValue::CreateStringValue( package.driverVersion)) ;
				row.Insert( L"driverDate", JsonValue::CreateStringValue( package.driverDate)) ;
				row.Insert( L"provider", JsonValue::CreateStringValue( package.providerName)) ;
				row.Insert( L"verifiedPublisher", JsonValue::CreateStringValue( publisher)) ;
				JsonArray models ;	// 各公開節へID種別を明示して保持します。
				// 全元Models節を同順で出力し、別節のIDを混入しません。
				for( const auto &section : identity.models) {
					JsonObject model ;	// 一節の元公開metadataです。
					model.Insert( L"modelSection",
								 JsonValue::CreateStringValue( section.modelSection)) ;
					JsonArray ids ;	// 元fieldのHardware/Compatible IDだけです。
					// 二つの元種別をそれぞれ元順で出力します。
					for( const bool compatible : {false, true}) {
						const auto &values = compatible ? section.compatibleIds
														: section.hardwareIds ;	// 元集合だけです。
						// 元公開IDを変更せず、端末側の値を付加しません。
						for( const auto &id : values) {
							JsonObject item ;	// 一つの原公開IDです。
							item.Insert( L"kind", JsonValue::CreateStringValue(
													 compatible ? L"COMPATIBLE" : L"HARDWARE")) ;
							item.Insert( L"value", JsonValue::CreateStringValue( id)) ;
							ids.Append( item) ;
						}
					}

					model.Insert( L"pnpIds", ids) ;
					models.Append( model) ;
				}

				row.Insert( L"models", models) ;
			}
		}

		rows.Append( row) ;
	}

	value.Insert( L"infs", rows) ;
	value.Insert( L"verifiedIdentityInfs",
				 JsonValue::CreateNumberValue( static_cast<double>( verified))) ;
	const auto contentChecked = std::chrono::floor<std::chrono::seconds>(
		// 実再検査終了のUTCで、元page観測を更新しません。
		std::chrono::system_clock::now()) ;
	value.Insert( L"contentCheckedUtcSeconds", JsonValue::CreateStringValue( winrt::to_hstring(
												  contentChecked.time_since_epoch().count()))) ;
	std::printf(
		"LOCAL_INDEX_PACKAGE inspected=%u infs=%zu verifiedIdentityInfs=%zu applicability=0 install=0\n",
		inspected == 0 ? 1U : 0U, inspection.infs.size(), verified) ;
	return winrt::to_string( value.Stringify()) ;
}

} // namespace

/**
 * @brief 明示create/public/inspect/signだけを実行する開発用入口です。
 * @param[in] count 引数数です。
 * @param[in] args 明示key操作、用途別署名、固定store import、保存bodyまたは一INF再検査の引数です。
 * @return 全確認成功0、OS/入力拒否2です。Driver導入/実HTTP収集は行いません。
 */
int wmain( const int count, wchar_t *args[])
{
	std::printf( "LOCAL_INDEX_SIGNER pid=%lu\n", GetCurrentProcessId()) ;
	try {
		// 不正argvを固定modeへ補完しません。
		if( args == nullptr || count < 2 || args[1] == nullptr) {
			throw Failure{ERROR_INVALID_PARAMETER} ;
		}

		const std::wstring_view mode{args[1]} ;	// 明示operation名です。
		// 未署名の値検査は鍵storeや既存署名操作へ進まず完結します。
		if( count == 4 && mode == L"--validate-unsigned-index-candidate") {
			const auto manifest =
				// 元manifestだけです。
				readInput( args[2], drivercrate::INDEX_MANIFEST_MAX_BYTES) ;
			const auto asset =
				// 元GZipだけです。
				readInput( args[3], drivercrate::INDEX_ASSET_MAX_BYTES) ;
			const auto checked = drivercrate::validateUnsignedIndexCandidate(
				manifest, std::as_bytes( std::span<const char>{asset.data(), asset.size()}),
				std::chrono::floor<std::chrono::seconds>(
					// 実UTCで再確認します。
					std::chrono::system_clock::now())) ;
			const auto manifestFailure =
				checked.manifestFailure
					? std::to_string( static_cast<unsigned>( *checked.manifestFailure))
					: "NONE" ;	// 認証成功値を出力しません。
			std::printf(
				"UNSIGNED_INDEX_CANDIDATE status=%u manifestFailure=%s asset=%u records=%u validated=%u authenticated=0 keyOperations=0\n",
				static_cast<unsigned>( checked.status), manifestFailure.c_str(),
				static_cast<unsigned>( checked.assetStatus),
				static_cast<unsigned>( checked.recordsStatus), checked.receipt ? 1U : 0U) ;
			return checked.receipt ? 0 : 2 ;
		}

		// 非実行script取得だけを元保存pageと有限な独立modeへ結合します。
		if( count == 7 && mode == L"--collect-terms-link-script") {
			const auto result = collectLinkedTermsScript( args[2], args[3], args[4],
														 args[5]) ;	// 元pageを先検査します。
			writeNew( args[6], {reinterpret_cast<const std::uint8_t *>( result.data()),
							   // 新分析JSONだけです。
							   result.size()}) ;
			std::printf(
				"LOCAL_INDEX_TERMS_SCRIPT metadataOperations=1 scriptExecuted=0 payloadGet=0\n") ;
			return 0 ;
		}

		// Importは鍵操作と別の明示modeで、固定pinを入力前に確認します。
		if( count == 4 && mode == L"--import-index") {
			return importIndex( args[2], args[3]) ;
		}

		// 保存body再解析は鍵/HTTP/製品storeを操作しない独立modeです。
		if( count == 6 && mode == L"--parse-collected-release") {
			const auto parsed =
				// 元hash/観測への限定結合。
				parseSavedRelease( args[2], args[3], args[4]) ;
			const auto bytes = std::as_bytes(
				std::span<const char>{parsed.data(), parsed.size()}) ;	// JSON原byte view。
			writeNew( args[5], {reinterpret_cast<const std::uint8_t *>( bytes.data()),
							   // 公開artifact境界。
							   bytes.size()}) ;
			std::printf( "LOCAL_INDEX_SAVED_RELEASE parsed=1 freshNetwork=0 authority=0\n") ;
			return 0 ;
		}

		// 監視側の取得済み原archive検査は署名/取得/実端末操作と別modeです。
		if( count == 6 && mode == L"--inspect-collected-package") {
			const auto parsed =
				// 同原hashの通常共通検査です。
				inspectCollectedPackage( args[2], args[3], args[5]) ;
			writeNew( args[4],
					 {reinterpret_cast<const std::uint8_t *>( parsed.data()), parsed.size()},
					 1024U * 1024U) ;	// 新公開artifactだけです。
			return 0 ;
		}

		// 下限専用はrecord readerや鍵storeへ進めず、数値診断だけで終了します。
		if( count == 7 && mode == L"--distribution-verify-floor-history") {
			const auto envelope =
				// 原署名です。
				readInput( args[2], drivercrate::INDEX_ENVELOPE_MAX_BYTES) ;
			const auto packed =
				// 原assetです。
				readInput( args[3], drivercrate::INDEX_ASSET_MAX_BYTES) ;
			const auto	  publicBytes = readInput( args[4], 411U) ;		// 公開blobだけです。
			const auto	  literal	  = winrt::to_string( args[6]) ;	// 原発行秒です。
			std::uint64_t seconds{} ;									// 補正しないUTC秒です。
			const auto	  parsed =
				// 原literal全体の整数解析結果です。
				std::from_chars( literal.data(), literal.data() + literal.size(), seconds) ;
			const auto now =
				// 過去へ変更しない現在UTCです。
				std::chrono::floor<std::chrono::seconds>( std::chrono::system_clock::now()) ;
			// 不明/overflow/未来を同じ下限専用拒否で保持します。
			if( literal.empty() || parsed.ec != std::errc{} ||
			   parsed.ptr != literal.data() + literal.size() || seconds == 0U ||
			   seconds > static_cast<std::uint64_t>( now.time_since_epoch().count())) {
				throw Failure{ERROR_INVALID_PARAMETER} ;
			}

			const auto floor = drivercrate::verifyDistributionIndexHistoryFloor(
				envelope, std::as_bytes( std::span<const char>{packed.data(), packed.size()}),
				{reinterpret_cast<const std::uint8_t *>( publicBytes.data()), publicBytes.size()},
				// 公開byteだけの型境界です。秘密materialを扱いません。
				winrt::to_string( args[5]), std::chrono::sys_seconds{std::chrono::seconds{seconds}},
				now) ;
			std::printf(
				"LOCAL_INDEX_HISTORY_FLOOR code=0x%08lx generation=%llu assetGeneration=%llu freshness=0 records=0 privateKeyQueried=0\n",
				static_cast<unsigned long>( floor.error),
				static_cast<unsigned long long>( floor.generation),
				static_cast<unsigned long long>( floor.assetGeneration)) ;
			return floor.error == 0 && floor.generation > 0U ? 0 : 2 ;
		}

		drivercrate::LocalIndexSigningResult result ;	// OS/codec結果を非秘密で保持します。
		// 四つの公開検証modeだけを受理し、鍵操作の枝へ流しません。
		if( (count == 6 &&
			(mode == L"--distribution-verify" || mode == L"--distribution-acquisition-verify")) ||
		   (count == 7 && (mode == L"--distribution-verify-history" ||
						   mode == L"--distribution-acquisition-verify-history"))) {
			const auto envelope =
				// 原envelopeです。
				readInput( args[2], drivercrate::INDEX_ENVELOPE_MAX_BYTES) ;
			const auto packed =
				// 原assetです。
				readInput( args[3], drivercrate::INDEX_ASSET_MAX_BYTES) ;
			const auto publicBytes = readInput( args[4], 411U) ;	// ローカル固定公開blobだけです。
			const auto fingerprint = winrt::to_string( args[5]) ;	// 非秘密pinを正規化せず渡します。
			auto	   checkedAt   = std::chrono::floor<std::chrono::seconds>(
				// 通常は実UTCだけです。
				std::chrono::system_clock::now()) ;
			const auto currentUtc = checkedAt ;	// 新historyでも現在に対する未来拒否を維持します。
			// 旧currentの署名高水位確認だけを明示し、freshな公開検査へ流用しません。
			if( mode == L"--distribution-verify-history" ||
			   mode == L"--distribution-acquisition-verify-history") {
				const auto literal = winrt::to_string( args[6]) ;	// 原manifestから読んだ発行秒です。
				std::uint64_t seconds{} ;							// 符号や補正なしの過去UTC秒です。
				const auto parsed = std::from_chars( literal.data(), literal.data() + literal.size(),
													seconds) ;	// Overflowも拒否します。
				// 未来や不正な時刻を歴史検証へ通しません。
				if( literal.empty() || parsed.ec != std::errc{} ||
				   parsed.ptr != literal.data() + literal.size() || seconds == 0U ||
				   seconds > static_cast<std::uint64_t>( checkedAt.time_since_epoch().count())) {
					throw Failure{ERROR_INVALID_PARAMETER} ;
				}

				checkedAt = std::chrono::sys_seconds{std::chrono::seconds{seconds}} ;
			}

			// 新historyは署名発行秒と現在UTCを別に渡し、現行取得の許可へ流しません。
			if( mode == L"--distribution-acquisition-verify-history") {
				result = drivercrate::verifyDistributionAcquisitionIndexHistory(
					envelope, std::as_bytes( std::span<const char>{packed.data(), packed.size()}),
					{reinterpret_cast<const std::uint8_t *>( publicBytes.data()),
					 publicBytes.size()},
					fingerprint, checkedAt, currentUtc) ;
			}
			// 現行取得は従来どおり現在UTCで全期限を検査します。
			else if( mode == L"--distribution-acquisition-verify") {
				result = drivercrate::verifyDistributionAcquisitionIndex(
					envelope, std::as_bytes( std::span<const char>{packed.data(), packed.size()}),
					{reinterpret_cast<const std::uint8_t *>( publicBytes.data()),
					 publicBytes.size()},
					fingerprint, checkedAt) ;
			} else {
				result = drivercrate::verifyDistributionIndex(
					envelope, std::as_bytes( std::span<const char>{packed.data(), packed.size()}),
					{reinterpret_cast<const std::uint8_t *>( publicBytes.data()),
					 publicBytes.size()},
					fingerprint, checkedAt, mode == L"--distribution-verify-history") ;
			}

			// 歴史検査成功は現在有効な索引の許可を発行しません。
			if( (mode == L"--distribution-verify-history" ||
				mode == L"--distribution-acquisition-verify-history") &&
			   result.error == 0) {
				std::printf( "LOCAL_INDEX_HISTORY_VERIFIED freshness=0\n") ;
			}
		}
		// 配布操作は別の明示modeだけへ結合します。
		else if( count == 3 &&
				(mode == L"--create-public" || mode == L"--public" ||
				 mode == L"--distribution-create-public" || mode == L"--distribution-public")) {
			const auto parents = pinParents( args[2]) ;	// 鍵作成前に出力祖先を確認します。
			// 明らかな既存出力への操作では鍵も作成しません。
			if( GetFileAttributesW( args[2]) != INVALID_FILE_ATTRIBUTES ||
			   GetLastError() != ERROR_FILE_NOT_FOUND) {
				throw Failure{ERROR_ALREADY_EXISTS} ;
			}

			result = mode.starts_with( L"--distribution-")
						 ? drivercrate::inspectDistributionIndexSigningKey(
							   mode == L"--distribution-create-public")
						 : drivercrate::inspectLocalIndexSigningKey( mode == L"--create-public") ;
		}
		// 非変更の既存鍵照会だけを明示受付けます。
		else if( count == 2 && (mode == L"--inspect" || mode == L"--distribution-inspect")) {
			// 非変更照会だけでkeyを作成しません。
			result = mode == L"--distribution-inspect"
						 ? drivercrate::inspectDistributionIndexSigningKey( false)
						 : drivercrate::inspectLocalIndexSigningKey( false) ;
		}
		// 明示fingerprintと原manifestだけを署名操作へ結合します。
		else if( (count == 5 && mode == L"--sign") ||
				(count == 6 && (mode == L"--sign-acquisition" || mode == L"--distribution-sign" ||
								mode == L"--distribution-acquisition-sign"))) {
			// Fingerprintは小文字ASCII64桁だけを欠損なく変換します。
			const std::wstring_view wide{args[count - 1]} ;	// 明示公開fingerprintです。
			std::string				fingerprint ;			// 秘密値を含まない比較入力です。
			// 全fingerprint文字を固定字句へ限定します。
			for( const auto character : wide) {
				// 曖昧なUnicodeやuppercaseを自動正規化しません。
				if( !((character >= L'0' && character <= L'9') ||
					 (character >= L'a' && character <= L'f'))) {
					throw Failure{ERROR_INVALID_PARAMETER} ;
				}

				fingerprint.push_back( static_cast<char>( character)) ;
			}

			// 無効pinでは鍵storeを開く前に中止します。
			if( fingerprint.size() != 64U) {
				throw Failure{ERROR_INVALID_PARAMETER} ;
			}

			const auto raw = readInput(
				args[2], drivercrate::INDEX_MANIFEST_MAX_BYTES) ;	// 原byteを再整形しません。
			const auto now = std::chrono::floor<std::chrono::seconds>(
				// 実OS UTCです。
				std::chrono::system_clock::now()) ;
			// 取得用途は同asset/v2全検査が終わるまで外側byteを返しません。
			if( mode == L"--sign-acquisition" || mode == L"--distribution-sign" ||
			   mode == L"--distribution-acquisition-sign") {
				const auto packed =
					// 同実GZipです。
					readInput( args[3], drivercrate::INDEX_ASSET_MAX_BYTES) ;
				// 新明示modeだけを既存固定配布containerの取得用途へ接続します。
				if( mode == L"--distribution-acquisition-sign") {
					result = drivercrate::signDistributionAcquisitionIndex(
						raw, std::as_bytes( std::span<const char>{packed.data(), packed.size()}),
						fingerprint, now) ;
				} else {
					result = mode == L"--distribution-sign"
								 ? drivercrate::signDistributionIndex(
									   raw,
									   std::as_bytes(
										   std::span<const char>{packed.data(), packed.size()}),
									   fingerprint, now)
								 : drivercrate::signLocalAcquisitionIndex(
									   raw,
									   std::as_bytes(
										   std::span<const char>{packed.data(), packed.size()}),
									   fingerprint, now) ;
				}
			} else {
				result = drivercrate::signLocalIndexManifest( raw, fingerprint, now) ;
			}
		} else {
			// 未知modeや引数集合は実行しません。
			throw Failure{ERROR_INVALID_PARAMETER} ;
		}

		std::printf(
			"LOCAL_INDEX_RESULT code=0x%08lx stage=%u observed=0x%08lx created=%u protected=%u\n",
			static_cast<unsigned long>( result.error), result.checkStage,
			static_cast<unsigned long>( result.observedValue), result.created ? 1U : 0U,
			result.publicKey && result.publicKey->protectionVerified ? 1U : 0U) ;
		// 途中作成の事実を表示した後に失敗codeで停止します。
		if( result.error != 0 || !result.publicKey) {
			return 2 ;
		}

		// 公開verifyは秘密鍵の存在/保護/export policyを確認したとは表示しません。
		if( mode == L"--distribution-verify" || mode == L"--distribution-verify-history" ||
		   mode == L"--distribution-acquisition-verify" ||
		   mode == L"--distribution-acquisition-verify-history") {
			std::printf(
				"LOCAL_INDEX_PUBLIC fingerprint=%s keyId=%s bytes=%zu publicOnly=1 privateKeyQueried=0\n",
				result.publicKey->fingerprint.c_str(), result.publicKey->keyId.c_str(),
				result.publicKey->publicBlob.size()) ;
		} else {
			std::printf(
				"LOCAL_INDEX_PUBLIC fingerprint=%s keyId=%s bytes=%zu rsaBits=3072 exportPolicy=0 usage=2 userKey=1\n",
				result.publicKey->fingerprint.c_str(), result.publicKey->keyId.c_str(),
				result.publicKey->publicBlob.size()) ;
		}

		// 非秘密public blobだけを新規fileへ出力します。
		if( mode == L"--create-public" || mode == L"--public" ||
		   mode == L"--distribution-create-public" || mode == L"--distribution-public") {
			writeNew( args[2], result.publicKey->publicBlob) ;
		}
		// 全manifest検証済みenvelopeだけを保存します。
		else if( mode == L"--sign" || mode == L"--sign-acquisition" ||
				mode == L"--distribution-sign" || mode == L"--distribution-acquisition-sign") {
			// 全codec成功後だけenvelopeを新規fileへ出力します。
			const auto bytes = std::span<const std::uint8_t>{
				reinterpret_cast<const std::uint8_t *>( result.envelope.data()),
				// 公開byte境界だけのviewです。
				result.envelope.size()} ;
			writeNew( args[mode == L"--sign" ? 3 : 4], bytes) ;
		}

		std::printf( "LOCAL_INDEX_COMPLETED\n") ;
		return 0 ;
	} catch( const Failure &failure) {
		std::printf( "LOCAL_INDEX_REJECTED code=0x%08lx\n",
					static_cast<unsigned long>( failure.code)) ;
	} catch( const winrt::hresult_error &failure) {
		std::printf( "LOCAL_INDEX_REJECTED code=0x%08lx\n",
					static_cast<unsigned long>( failure.code().value)) ;
	} catch( ...) {
		std::printf( "LOCAL_INDEX_REJECTED code=0x%08lx\n",
					static_cast<unsigned long>( E_UNEXPECTED)) ;
	}

	return 2 ;
}
