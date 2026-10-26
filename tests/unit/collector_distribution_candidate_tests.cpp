//------------------------------------------------------------------------------
/**
 * @file collector_distribution_candidate_tests.cpp
 * @brief 同じnative通常検査の私有観測から汎用v2投影を検証します。
 * @version 01.02.00
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/23  新INF/共有descriptor/全失敗/原期限/表現限界を固定。
 * Ver.01.01.00 Shunji Ogawa  2026/10/24  現行nested member identityと原record完全tupleへ整合。
 * Ver.01.01.01 Shunji Ogawa  2026/10/24  発行fresh24hと原8日期限の排他境界を確認。
 * Ver.01.01.02 Shunji Ogawa  2026/10/25  四範囲の実手動確認minと原PAGE保持/非自動延長を回帰。
 * Ver.01.02.00 Shunji Ogawa  2026/10/25  明示offline原PAGEを現行jobから同取得/候補へ接続。
 * </pre>
 * @note HTTP/DNS/WinTrust/INF metadata I/Oは既存専用seamです。実CAT合格を意味しません。
 * @see docs/adr/0396-collector-distribution-pipeline-connection.md
 */
//------------------------------------------------------------------------------
#define main registryPrimitiveMain
#include "collector_registry_job_tests.cpp"
#undef main
#include "platform/unsigned_index_candidate.h"
#include "platform/signed_index_json_internal.h"
#include <type_traits>
#include <set>
#include <filesystem>
#include <fstream>

namespace {
/** @brief 原jobへ公開OS三familyを追加します。適合を補完しません。
 * @param[in,out] job 検証前の架空入力だけです。
 */
void declareAllFamilies( JsonObject &job)
{
	JsonArray values ;	// 元公式申告の有限な三familyです。
	// 同じModelsから観測していない二familyも分母へ含めます。
	for( const auto value : {L"WINDOWS_10_X64", L"WINDOWS_11_X64", L"WINDOWS_SERVER_X64"}) {
		values.Append( JsonValue::CreateStringValue( value)) ;
	}

	job.GetNamedObject( L"record").Insert( L"operatingSystems", values) ;
}

/** @brief 一回の本物runnerと完全fake I/Oから投影の元結果を得ます。
 * @param[in] mode 元検査seamの固定故障番号です。
 * @param[in] allFamilies 現在以外のOSを未観測として検査します。
 * @param[out] candidate 同じ実結果objectから生成した候補です。
 * @return 全元metadataと失敗分母を持つ候補DOMです。
 */
JsonObject candidateFixture( const unsigned mode, const bool allFamilies,
							drivercrate::CollectorDistributionCandidate &candidate)
{
	Fixture state{
		{Response{"<a href=\"driver.zip\">A</a>"}, Response{"abc"}}} ;	// 実送信はありません。
	fixture	   = &state ;
	auto input = jobFixture() ;	// A社二製品の元共通recordです。
	bindPage( input, state.responses.front().body) ;
	auto originalRecord = input.GetNamedObject( L"record") ;	// 旧研究版を保持します。
	setText( originalRecord, L"driverVersion", L"0.9.0.0") ;
	// OS未観測fixtureだけが元公式申告を増やします。
	if( allFamilies) {
		declareAllFamilies( input) ;
	}

	// 先行合格後の全job失敗は二つの元明示INFを使用します。
	if( mode == 24U) {
		JsonObject selection ;	// 原jobの既存schemaだけです。
		setText( selection, L"mode", L"SELECTED") ;
		JsonArray paths ;	// 切捨てない元二INFです。
		paths.Append( JsonValue::CreateStringValue( L"brand-new-network.inf")) ;
		paths.Append( JsonValue::CreateStringValue( L"second.inf")) ;
		selection.Insert( L"paths", paths) ;
		input.Insert( L"infSelection", selection) ;
	}

	drivercrate::CollectorRegistryJob job ;	// 厳密な原入力解析だけを使います。
	check( drivercrate::parseCollectorRegistryJob( winrt::to_string( input.Stringify()), job) == 0) ;
	drivercrate::CollectorRegistryJobResult result ;	// 公開JSONから構築しません。
	const auto error = drivercrate::CollectorRegistryJobTestAccess::execute(
		job, job, mode, result) ;	// 通常runner一回です。
	check( !result.json().empty() && state.closed == state.opened && state.safe) ;
	const auto now = std::chrono::floor<std::chrono::seconds>(
		// 元実時計です。
		std::chrono::system_clock::now()) ;
	check( drivercrate::CollectorRegistryJobTestAccess::project( result, now, candidate) == 0 &&
		  !candidate.json().empty()) ;
	const auto projected =
		// 実producerの原byteです。
		JsonObject::Parse( winrt::to_hstring( candidate.json())) ;
	check( projected.GetNamedObject( L"job").GetNamedArray( L"products").Size() == 2U &&
		  projected.GetNamedObject( L"job").GetNamedObject( L"record").GetNamedString(
			  L"driverVersion") == L"0.9.0.0") ;
	check( projected.GetNamedObject( L"job").GetNamedObject( L"record").GetNamedString(
			  L"packageVersion") == L"1.0") ;
	// 原期限をbuild時刻へ延長しない再投影を比較します。
	if( candidate.recordCount() != 0U) {
		drivercrate::CollectorDistributionCandidate repeated ;	// 同じ元結果を後刻参照します。
		check( drivercrate::CollectorRegistryJobTestAccess::project(
				  result, now + std::chrono::seconds{1}, repeated) == 0 &&
			  repeated.json() == candidate.json()) ;
		drivercrate::CollectorDistributionCandidate expired ;	// 元観測自体を変更しません。
		check( drivercrate::CollectorRegistryJobTestAccess::project(
				  result, now + std::chrono::days{8}, expired) == 0 &&
			  expired.recordCount() == 0U) ;
		const auto old =
			// 元期限は変わりません。
			JsonObject::Parse( winrt::to_hstring( expired.json())) ;
		check( old.GetNamedString( L"validUntilUtc") == projected.GetNamedString( L"validUntilUtc")) ;
		const auto freshLimit =
			drivercrate::signed_index_json::utc(
				winrt::to_string( projected.GetNamedString( L"pageObservedAtUtc")), E_INVALIDARG) +
			std::chrono::hours{24} ;						// 実PAGE観測からの発行専用境界です。
		drivercrate::CollectorDistributionCandidate fresh ;	// 原8日期限を持つ同観測です。
		check( drivercrate::CollectorRegistryJobTestAccess::project(
				  result, freshLimit - std::chrono::seconds{1}, fresh) == 0 &&
			  fresh.json() == candidate.json()) ;
		drivercrate::CollectorDistributionCandidate stale ;	// 期限内でも24h観測を再発行しません。
		check( drivercrate::CollectorRegistryJobTestAccess::project( result, freshLimit, stale) ==
				  0 &&
			  stale.recordCount() == 0U) ;
		check( JsonObject::Parse( winrt::to_hstring( stale.json())).GetNamedString( L"validUntilUtc") ==
			  projected.GetNamedString( L"validUntilUtc")) ;
	}

	// 全job失敗は元HRESULTを保持して先行成功を投影しません。
	if( mode == 9U || mode == 24U) {
		check( error == E_FAIL && candidate.recordCount() == 0U &&
			  projected.GetNamedNumber( L"jobError") == E_FAIL) ;
	}

	return projected ;
}

/** @brief 四範囲の最も古い実手動確認を同run観測とは独立に期限へ残します。 */
void manualReviewExpiryTests()
{
	// 全scopeが最小時刻を制約できることを確認します。
	for( const auto oldest : {L"official", L"preDownload", L"terms", L"prerequisites"}) {
		auto	   input = jobFixture() ;	// 元PAGEは10月22日のままです。
		const auto originalPage =
			// 原観測を保持します。
			input.GetNamedObject( L"pageObservation").Stringify() ;
		auto review = input.GetNamedObject( L"review") ;	// 各scopeの実確認を独立に設定します。
		// 一範囲だけを他の三範囲より古くし、小数秒の切下げも確認します。
		for( const auto scope : {L"official", L"preDownload", L"terms", L"prerequisites"}) {
			auto evidence =
				// 当該範囲の根拠です。
				review.GetNamedObject( scope).GetNamedObject( L"evidence") ;
			setText( evidence, L"checkedAt",
					std::wstring_view{scope} == oldest ? L"2026-10-24T00:00:00.999999Z"
													   : L"2026-10-24T01:00:00Z") ;
		}

		const auto raw = winrt::to_string( input.Stringify()) ;	// 自動更新を許さない同じ原jobです。
		drivercrate::CollectorRegistryJob job ;					// 正規解析の同じ私有入力です。
		check( drivercrate::parseCollectorRegistryJob( raw, job) == 0) ;
		// 同jobの別fresh取得でも手動確認を自動延長しません。実通信は完全fakeです。
		for( unsigned run = 0U; run < 2U; ++run) {
			Fixture state{{Response{"<a href=\"driver.zip\">driver</a>"},
						   Response{"abc"}}} ;	// 元hashに一致する実fake応答です。
			fixture = &state ;
			drivercrate::CollectorRegistryJobResult result ;	// 旧成功JSONから復元しません。
			check( drivercrate::CollectorRegistryJobTestAccess::execute( job, job, 0U, result) == 0) ;
			const auto now = std::chrono::floor<std::chrono::seconds>(
				// 発行時の実現在です。
				std::chrono::system_clock::now()) ;
			drivercrate::CollectorDistributionCandidate
				candidate ;	// 同生存runの観測だけを使います。
			check( drivercrate::CollectorRegistryJobTestAccess::project( result, now, candidate) ==
					  0 &&
				  candidate.recordCount() == 1U) ;
			const auto projected =
				// 実投影出力です。
				JsonObject::Parse( winrt::to_hstring( candidate.json())) ;
			check( projected.GetNamedString( L"validUntilUtc") == L"2026-11-01T00:00:00Z" &&
				  winrt::to_string( projected.GetNamedObject( L"job").Stringify()) == raw &&
				  input.GetNamedObject( L"pageObservation").Stringify() == originalPage) ;
			const auto expiry = drivercrate::signed_index_json::utc(
				winrt::to_string( projected.GetNamedString( L"validUntilUtc")),
				E_INVALIDARG) ;	// 各元時刻の最小期限です。
			// 手動確認によって同run実内容/PAGEの8日上限を超えません。
			for( const auto field : {L"checkedAtUtc", L"pageObservedAtUtc"}) {
				check( expiry <=
					  drivercrate::signed_index_json::utc(
						  winrt::to_string( projected.GetNamedString( field)), E_INVALIDARG) +
						  std::chrono::days{8}) ;
			}

			check( state.sends == 2U && state.safe && state.opened == state.closed) ;
		}
	}

	fixture = nullptr ;
}
/** @brief 明示された有限offline fixtureだけを読みます。
 * @param[in] path 試験callerの端末内pathです。
 * @return 2 MiB以下の原byteです。実通信や通常logへ出しません。
 */
std::string readOfflineFixture( const char *path)
{
	const auto size = std::filesystem::file_size( path) ;	// 読取り前の有限長です。
	check( size > 0U && size <= 2U * 1024U * 1024U) ;
	std::string	  raw( static_cast<std::size_t>( size), '\0') ;	// 原byteだけを所有します。
	std::ifstream input( path, std::ios::binary) ;				// 同期test専用です。
	check( input.is_open()) ;
	input.read( raw.data(), static_cast<std::streamsize>( raw.size())) ;
	check( input.gcount() == static_cast<std::streamsize>( raw.size()) &&
		  input.peek() == std::char_traits<char>::eof()) ;
	return raw ;
}

/** @brief 共通producerの現行jobと原PAGEを本物runner/候補へ通します。
 * @param[in] argv 固定mode/job/PAGE/新規結果/成功期待の六要素です。
 * @note HTTP/DNS/検査は既存完全fakeで、原本文やpathを公開sourceへ埋め込みません。
 */
void offlinePageJobTest( char *argv[])
{
	const auto jobBytes = readOfflineFixture( argv[2]) ;			// 共通Python producerの原出力です。
	const auto raw		= readOfflineFixture( argv[3]) ;			// 実行しない端末内の原PAGEです。
	const auto accepted = std::string_view{argv[5]} == "ACCEPT" ;	// 固定分母の期待です。
	check( accepted || std::string_view{argv[5]} == "REJECT") ;
	Fixture state{{Response{raw}, Response{"abc"}}} ;	// 実送信をしません。
	fixture = &state ;
	drivercrate::CollectorRegistryJob job ;	// 通常の厳密v2解析です。
	check( drivercrate::parseCollectorRegistryJob( jobBytes, job) == 0) ;
	drivercrate::CollectorRegistryJobResult result ;	// 公開JSONから構築しません。
	const auto error = drivercrate::CollectorRegistryJobTestAccess::execute(
		job, job, 0U, result) ;	// 一回だけです。
	// 正例と拒否値を独立に比較し、NativeErrorとHRESULTの型境界を明示します。
	if( accepted) {
		check( error == 0) ;
	} else {
		const auto expected = static_cast<drivercrate::NativeError>(
			// 同じ型の原拒否値です。
			HRESULT_FROM_WIN32( ERROR_REVISION_MISMATCH)) ;
		check( error == expected) ;
	}

	check( state.sends == (accepted ? 2U : 1U) && state.safe && state.opened == state.closed) ;
	const auto native = JsonObject::Parse( winrt::to_hstring( result.json())) ;	// 同HTTPの原観測です。
	std::wstring liveHash ;														// 比較値と区別する原全体SHAです。
	check( drivercrate::computeCollectorMetadataSha256( raw, liveHash) == 0 &&
		  native.GetNamedObject( L"pageObservation").GetNamedString( L"bodySha256") == liveHash) ;
	check( native.GetNamedObject( L"pageObservation").GetNamedNumber( L"bodyBytes") ==
		  static_cast<double>( raw.size())) ;
	drivercrate::CollectorDistributionCandidate candidate ;	// 同runの私有観測だけを投影します。
	const auto									now =
		std::chrono::floor<std::chrono::seconds>( std::chrono::system_clock::now()) ;	// 実現在です。
	check( drivercrate::CollectorRegistryJobTestAccess::project( result, now, candidate) == 0 &&
		  candidate.recordCount() == (accepted ? 1U : 0U)) ;
	const auto projected =
		// 原job/時刻を保持します。
		JsonObject::Parse( winrt::to_hstring( candidate.json())) ;
	check( projected.GetNamedObject( L"job").Stringify() ==
		  JsonObject::Parse( winrt::to_hstring( jobBytes)).Stringify()) ;
	// 正例も手動確認の原期限をfresh取得によって延長しません。
	if( accepted) {
		check( projected.GetNamedString( L"validUntilUtc") == L"2026-11-02T02:43:22Z" &&
			  projected.GetNamedString( L"pageSha256") == liveHash) ;
	}

	JsonObject saved ;	// 本文やpathを含まない有限結果です。
	saved.Insert( L"native", native) ;
	saved.Insert( L"candidate", projected) ;
	check( !std::filesystem::exists( argv[4])) ;
	std::ofstream output( argv[4], std::ios::binary) ;				// 自己所有の新規結果だけです。
	const auto	  bytes = winrt::to_string( saved.Stringify()) ;	// 同producerの原metadataです。
	output.write( bytes.data(), static_cast<std::streamsize>( bytes.size())) ;
	output.flush() ;
	check( output.good()) ;
	fixture = nullptr ;
	std::printf( "Offline page job accepted: %u checks: %zu\n", accepted ? 1U : 0U, checks) ;
}
} // namespace

/** @brief 私有観測の生成不能性と全有限投影分母を確認します。
 * @param[in] argc 通常1、明示offline fixtureでは6の引数数です。
 * @param[in] argv 固定modeと端末内fixture pathです。通常処理では参照しません。
 * @return 全assertion成立0、元API/分母不一致1です。
 */
int main( const int argc, char *argv[])
{
	static_assert(
		!std::is_default_constructible_v<drivercrate::CollectorRegistryVerifiedObservation>) ;
	static_assert(
		!std::is_constructible_v<drivercrate::CollectorRegistryVerifiedObservation, bool>) ;
	static_assert(
		!std::is_constructible_v<drivercrate::CollectorRegistryVerifiedObservation, std::string>) ;
	static_assert( !std::is_convertible_v<drivercrate::UnsignedIndexCandidateReceipt,
										 drivercrate::AuthenticatedIndexManifest>) ;
	static_assert( !std::is_convertible_v<drivercrate::UnsignedIndexCandidateReceipt,
										 drivercrate::AuthenticatedIndexAssetBytes>) ;
	try {
		winrt::init_apartment() ;
		// 明示offline入力は通常unitと別の有限分母で実行します。
		if( argc != 1) {
			check( argc == 6 && std::string_view{argv[1]} == "--offline-page-job") ;
			offlinePageJobTest( argv) ;
			return 0 ;
		}

		manualReviewExpiryTests() ;
		// 新INF/節/架空IDはcodeの製品登録や研究版との一致条件なしで投影します。
		for( const unsigned mode : {0U, 8U, 9U, 20U, 21U, 22U, 23U, 24U, 25U, 26U, 30U, 31U, 32U}) {
			drivercrate::CollectorDistributionCandidate candidate ;				// 当該実結果だけを所有します。
			const auto output  = candidateFixture( mode, false, candidate) ;	// 実producerを呼びます。
			const auto records = output.GetNamedArray( L"records") ;			// 実v2投影です。
			const auto infs	   = output.GetNamedArray( L"infs") ;				// 全元分母です。
			const std::size_t expected =
				mode == 30U					 ? 3U
				: mode == 21U || mode == 32U ? 2U
				: mode == 0U || mode == 8U || mode == 23U || mode == 26U || mode == 31U
					? 1U
					: 0U ;	// 全分母を固定します。
			check( candidate.recordCount() == expected) ;
			// Fresh INF版は旧driverVersion/package版と別の値です。
			if( records.Size() != 0U) {
				check( records.GetAt( 0U)
						  .GetObject()
						  .GetNamedObject( L"version")
						  .GetNamedString( L"value") == (mode == 26U ? L"3.4.5.6" : L"2.3.4.5")) ;
				check( infs.GetAt( 0U).GetObject().GetNamedString( L"provider") ==
						  L"Fixture Manufacturer" &&
					  infs.GetAt( 0U).GetObject().GetNamedString( L"catalogIdentity") ==
						  L"brand-new-network.cat") ;
			}

			// 同packageの別INFで取得descriptorを変えず、INF/Modelsだけをidentityへ置きます。
			if( mode == 23U) {
				check( records.GetAt( 0U)
						  .GetObject()
						  .GetNamedObject( L"publishedIdentityEvidence")
						  .GetNamedString( L"nestedArchiveIdentity") == L"nested.zip") ;
			}

			// 同原hash/Modelsも別memberなら独立recordで、同payload descriptorだけを共有します。
			if( mode == 30U || mode == 32U) {
				std::set<std::wstring> identities ;	// 元memberが異なるrecordIdを数えます。
				std::set<std::wstring> selectors ;	// 空flatと各nestedを区別します。
				// 全投影recordを元member/原hashへ独立に確認します。
				for( const auto &value : records) {
					const auto record = value.GetObject() ;	// 実producerの元行です。
					const auto identity =
						// 現行10fieldです。
						record.GetNamedObject( L"publishedIdentityEvidence") ;
					identities.emplace( record.GetNamedString( L"recordId")) ;
					selectors.emplace( identity.GetNamedString( L"nestedArchiveIdentity")) ;
					check( record.GetNamedObject( L"acquisitionDescriptor").Stringify() ==
						  records.GetAt( 0U)
							  .GetObject()
							  .GetNamedObject( L"acquisitionDescriptor")
							  .Stringify()) ;
					check( identity.GetNamedString( L"evidenceSha256") == std::wstring( 64U, L'c')) ;
				}

				check( identities.size() == expected && selectors.size() == (mode == 30U ? 3U : 1U)) ;
			}

			// 同member/hash/節を二重観測したものだけを保留し、flatの元成功は保持します。
			if( mode == 31U) {
				std::size_t rejected{} ;	// 重複した二行だけの原保留数です。
				// 元失敗分母を走査し、重複した二行だけを数えます。
				for( const auto &value : output.GetNamedArray( L"outcomes")) {
					rejected +=
						value.GetObject().GetNamedString( L"reason") == L"V2_REPRESENTATION_LIMIT"
							? 1U
							: 0U ;
				}

				check( rejected == 2U && records.GetAt( 0U)
											.GetObject()
											.GetNamedObject( L"publishedIdentityEvidence")
											.GetNamedString( L"nestedArchiveIdentity")
											.empty()) ;
			}

			// 元二INFの共有descriptorと個別memberを確認します。
			if( mode == 21U) {
				const auto first  = records.GetAt( 0U).GetObject() ;	// 一つ目の新INFです。
				const auto second = records.GetAt( 1U).GetObject() ;	// 二つ目の新INFです。
				check( first.GetNamedObject( L"acquisitionDescriptor").Stringify() ==
					  second.GetNamedObject( L"acquisitionDescriptor").Stringify()) ;
				check( second.GetNamedObject( L"publishedIdentityEvidence")
							  .GetNamedString( L"infIdentity") == L"sub/another-new.inf" &&
					  first.GetNamedString( L"recordId") != second.GetNamedString( L"recordId")) ;
			}

			// 129 IDと128長IDは原全集合を保持して表現限界へ残します。
			if( mode == 20U || mode == 25U) {
				check( infs.GetAt( 0U)
						  .GetObject()
						  .GetNamedArray( L"models")
						  .GetAt( 0U)
						  .GetObject()
						  .GetNamedArray( L"pnpIds")
						  .Size() == (mode == 20U ? 129U : 128U)) ;
				check( output.GetNamedArray( L"outcomes")
						  .GetAt( 0U)
						  .GetObject()
						  .GetNamedString( L"reason") == L"V2_REPRESENTATION_LIMIT") ;
			}

			// 個別拒否は他の合格を残し、全体拒否は先行合格も破棄します。
			if( mode == 8U || mode == 24U) {
				check( output.GetNamedArray( L"outcomes").Size() == (mode == 8U ? 2U : 1U)) ;
			}
		}

		drivercrate::CollectorDistributionCandidate scoped ;		// 観測していない二familyを保留します。
		const auto output = candidateFixture( 0U, true, scoped) ;	// 現実OS選択は変更しません。
		check( scoped.recordCount() == 1U && output.GetNamedArray( L"outcomes").Size() == 3U) ;
		std::size_t unobserved{} ;	// 他OSの分母だけを数えます。
		// 全公式申告familyを確認し、未観測を成功へ含めません。
		for( const auto &value : output.GetNamedArray( L"outcomes")) {
			unobserved +=
				value.GetObject().GetNamedString( L"reason") == L"MODELS_OS_UNOBSERVED" ? 1U : 0U ;
		}

		check( unobserved == 2U) ;
		drivercrate::CollectorRegistryJobResult		empty ;		// 未実行の公開空結果です。
		drivercrate::CollectorDistributionCandidate rejected ;	// 観測型を作れません。
		check( drivercrate::CollectorRegistryJobTestAccess::project( empty, {}, rejected) ==
				  E_INVALIDARG &&
			  rejected.json().empty()) ;
		std::printf(
			"DISTRIBUTION_CANDIDATE_TEST assertions=%zu failures=0 network=0 actualCatAccepted=0\n",
			checks) ;
		return 0 ;
	} catch( const std::exception &error) {
		std::printf( "DISTRIBUTION_CANDIDATE_TEST_FAILED %s\n", error.what()) ;
	} catch( ...) {
		std::printf( "DISTRIBUTION_CANDIDATE_TEST_FAILED code=0x%08lx\n",
					static_cast<unsigned long>( E_UNEXPECTED)) ;
	}

	return 1 ;
}
