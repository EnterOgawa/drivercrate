//------------------------------------------------------------------------------
/**
 * @file official_release_observation_tests.cpp
 * @brief 公式release端末内観測単体試験実装。
 * @version 01.00.00
 * @date 2026/09/07
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  新規作成。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Local probe失効試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/07  Provider観測統合試験追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * </pre>
 *
 * @note Network、端末情報、driver導入を使用せず、架空fingerprintで比較します。
 */
//------------------------------------------------------------------------------

#include "official_release_observation_tests.h"

#include "core/official_release_observation.h"
#include "test_framework.h"

#include <array>
#include <string>
#include <vector>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 内部関数定義。
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
 * @brief 正常な架空観測を作成する。
 *
 * 実端末ID、URL、credentialを含まない共通fixtureを返す。
 * @return 公表SHA-256を持つ保存可能な架空観測。
 */
//------------------------------------------------------------------------------
[[nodiscard]] LocalOfficialReleaseObservation makeObservation()
{
	LocalOfficialReleaseObservation observation ;	// 各testで差分を加える基準観測。
	observation.binding.deviceBindingFingerprint		   = std::wstring( 64U, L'a') ;
	observation.binding.providerId						   = L"fictional-provider" ;
	observation.binding.sourceId						   = L"fictional-source" ;
	observation.binding.familyId						   = L"fictional-family" ;
	observation.binding.productKey						   = L"fictional-product" ;
	observation.binding.branch							   = L"windows-x64" ;
	observation.environment.operatingSystemFingerprint	   = std::wstring( 64U, L'b') ;
	observation.environment.deviceConfigurationFingerprint = std::wstring( 64U, L'c') ;
	observation.environment.policyRevision				   = 7U ;
	observation.environment.parserRevision				   = 3U ;
	observation.releaseKey								   = L"release-2026-09" ;
	observation.packageVersion							   = L"10.20.30.40" ;
	observation.publishedSha256							   = std::wstring( 64U, L'd') ;
	observation.observedFileTime						   = 1U ;
	return observation ;
}

//------------------------------------------------------------------------------
/**
 * @brief 保存契約の正常値と不正値を検証する。
 *
 * 欠落、上限、不正hash、未知enum、弱いrelease identityを確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testValidation( TestContext &context)
{
	const LocalOfficialReleaseObservation valid = makeObservation() ;	// 正常な強い観測。
	DRIVERCRATE_EXPECT( context, isLocalOfficialReleaseObservationValid( valid)) ;

	LocalOfficialReleaseObservation weak = valid ;	// Hashなしでも保存できる弱い観測。
	weak.releaseKey.clear() ;
	weak.publishedSha256.clear() ;
	DRIVERCRATE_EXPECT( context, isLocalOfficialReleaseObservationValid( weak)) ;

	LocalOfficialReleaseObservation missingRelease = weak ;	// Release識別情報が全てない観測。
	missingRelease.packageVersion.clear() ;
	DRIVERCRATE_EXPECT( context, !isLocalOfficialReleaseObservationValid( missingRelease)) ;

	LocalOfficialReleaseObservation rawSource = valid ;	// Stable IDにURL区切りを含む観測。
	rawSource.binding.sourceId				  = L"https://official.example.invalid/path" ;
	DRIVERCRATE_EXPECT( context, !isLocalOfficialReleaseObservationValid( rawSource)) ;

	LocalOfficialReleaseObservation uppercaseHash = valid ;	// Canonicalでない公表hash。
	uppercaseHash.publishedSha256[0]			  = L'D' ;
	DRIVERCRATE_EXPECT( context, !isLocalOfficialReleaseObservationValid( uppercaseHash)) ;

	LocalOfficialReleaseObservation oversized = valid ;	// Stable IDの有限上限を超える観測。
	oversized.binding.familyId				  = std::wstring( 129U, L'a') ;
	DRIVERCRATE_EXPECT( context, !isLocalOfficialReleaseObservationValid( oversized)) ;

	LocalOfficialReleaseObservation zeroRevision = valid ;	// Policy revisionが未定義の観測。
	zeroRevision.environment.policyRevision		 = 0U ;
	DRIVERCRATE_EXPECT( context, !isLocalOfficialReleaseObservationValid( zeroRevision)) ;

	LocalOfficialReleaseObservation unknownReason = valid ;	// 定義外の保留理由を持つ観測。
	unknownReason.pendingReason = static_cast<ReleaseObservationPendingReason>( 999) ;
	DRIVERCRATE_EXPECT( context, !isLocalOfficialReleaseObservationValid( unknownReason)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 初回とidentity一致を検証する。
 *
 * 初回、強いSHA-256一致、弱い表示metadata一致を区別する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testIdentityResults( TestContext &context)
{
	const LocalOfficialReleaseObservation strong = makeObservation() ;	// 公表hash付き観測。
	DRIVERCRATE_EXPECT( context, compareLocalOfficialReleaseObservation( nullptr, strong) ==
									ReleaseObservationDifference::FIRST_OBSERVATION) ;
	DRIVERCRATE_EXPECT( context, compareLocalOfficialReleaseObservation( &strong, strong) ==
									ReleaseObservationDifference::STRONG_IDENTITY_UNCHANGED) ;

	LocalOfficialReleaseObservation weak = strong ;	// 同一性を証明するhashがない観測。
	weak.publishedSha256.clear() ;
	DRIVERCRATE_EXPECT( context, compareLocalOfficialReleaseObservation( &weak, weak) ==
									ReleaseObservationDifference::METADATA_UNCHANGED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Bindingと環境の失効条件を検証する。
 *
 * Source、device、OS、構成、policy、parserの変更を個別に再評価へ分類する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testBindingAndEnvironmentChanges( TestContext &context)
{
	const LocalOfficialReleaseObservation previous = makeObservation() ;	// 前回観測。

	LocalOfficialReleaseObservation		  source = previous ;	// Source定義を変更した今回観測。
	source.binding.branch						 = L"windows-server-x64" ;
	DRIVERCRATE_EXPECT( context, compareLocalOfficialReleaseObservation( &previous, source) ==
									ReleaseObservationDifference::SOURCE_BINDING_CHANGED) ;

	LocalOfficialReleaseObservation device	= previous ;	// Local device対応を変更した観測。
	device.binding.deviceBindingFingerprint = std::wstring( 64U, L'e') ;
	DRIVERCRATE_EXPECT( context, compareLocalOfficialReleaseObservation( &previous, device) ==
									ReleaseObservationDifference::DEVICE_BINDING_CHANGED) ;

	LocalOfficialReleaseObservation operatingSystem		   = previous ;	// OS条件を変更した観測。
	operatingSystem.environment.operatingSystemFingerprint = std::wstring( 64U, L'f') ;
	DRIVERCRATE_EXPECT( context,
					   compareLocalOfficialReleaseObservation( &previous, operatingSystem) ==
						   ReleaseObservationDifference::OPERATING_SYSTEM_CHANGED) ;

	LocalOfficialReleaseObservation configuration = previous ;	// Device構成を変更した観測。
	configuration.environment.deviceConfigurationFingerprint = std::wstring( 64U, L'1') ;
	DRIVERCRATE_EXPECT( context, compareLocalOfficialReleaseObservation( &previous, configuration) ==
									ReleaseObservationDifference::DEVICE_CONFIGURATION_CHANGED) ;

	LocalOfficialReleaseObservation policy = previous ;	// 監査policyを更新した観測。
	policy.environment.policyRevision += 1U ;
	DRIVERCRATE_EXPECT( context, compareLocalOfficialReleaseObservation( &previous, policy) ==
									ReleaseObservationDifference::POLICY_CHANGED) ;

	LocalOfficialReleaseObservation parser = previous ;	// Parser契約を更新した観測。
	parser.environment.parserRevision += 1U ;
	DRIVERCRATE_EXPECT( context, compareLocalOfficialReleaseObservation( &previous, parser) ==
									ReleaseObservationDifference::PARSER_CHANGED) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Releaseと内容identity変更を検証する。
 *
 * 表示版が同じ場合も公表hash変更を内容差分として検出する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testReleaseChanges( TestContext &context)
{
	const LocalOfficialReleaseObservation previous = makeObservation() ;	// 前回観測。

	LocalOfficialReleaseObservation		  release = previous ;	// 新しいrelease keyの観測。
	release.releaseKey							  = L"release-2026-10" ;
	DRIVERCRATE_EXPECT( context, compareLocalOfficialReleaseObservation( &previous, release) ==
									ReleaseObservationDifference::RELEASE_CHANGED) ;

	LocalOfficialReleaseObservation content = previous ;	// 同じ表示版でhashだけ変わった観測。
	content.publishedSha256					= std::wstring( 64U, L'e') ;
	DRIVERCRATE_EXPECT( context, compareLocalOfficialReleaseObservation( &previous, content) ==
									ReleaseObservationDifference::CONTENT_IDENTITY_CHANGED) ;

	LocalOfficialReleaseObservation missingHash = previous ;	// 公表hashが消えた観測。
	missingHash.publishedSha256.clear() ;
	DRIVERCRATE_EXPECT( context, compareLocalOfficialReleaseObservation( &previous, missingHash) ==
									ReleaseObservationDifference::CONTENT_IDENTITY_CHANGED) ;

	LocalOfficialReleaseObservation pending = previous ;	// 未確認理由が発生した観測。
	pending.pendingReason = ReleaseObservationPendingReason::CONTENT_REVALIDATION_NEEDED ;
	DRIVERCRATE_EXPECT( context, compareLocalOfficialReleaseObservation( &previous, pending) ==
									ReleaseObservationDifference::PENDING_REASON_CHANGED) ;

	LocalOfficialReleaseObservation invalid = previous ;	// 不正fingerprintの今回観測。
	invalid.binding.deviceBindingFingerprint.clear() ;
	DRIVERCRATE_EXPECT( context, compareLocalOfficialReleaseObservation( &previous, invalid) ==
									ReleaseObservationDifference::INVALID) ;
}

//------------------------------------------------------------------------------
/**
 * @brief Local probeによる前回観測の失効分類を検証する。
 *
 * Binding、OS、device構成、policy、parser変更をnetworkなしでCurrentまたは失効理由へ分類する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testLocalProbeReuseClassification( TestContext &context)
{
	const LocalOfficialReleaseObservation observation = makeObservation() ;			// 保存済み観測。
	std::array							  bindings{observation.binding} ;			// 現在の一件binding集合。
	LocalOfficialObservationEnvironment	  environment = observation.environment ;	// 現在の基準環境。
	DRIVERCRATE_EXPECT( context,
					   classifyLocalOfficialObservationReuse( observation, bindings, environment) ==
						   LocalOfficialObservationReuse::CURRENT) ;

	bindings[0].deviceBindingFingerprint = std::wstring( 64U, L'e') ;
	DRIVERCRATE_EXPECT( context,
					   classifyLocalOfficialObservationReuse( observation, bindings, environment) ==
						   LocalOfficialObservationReuse::BINDING_UNAVAILABLE) ;
	bindings[0] = observation.binding ;

	environment.operatingSystemFingerprint = std::wstring( 64U, L'f') ;
	DRIVERCRATE_EXPECT( context,
					   classifyLocalOfficialObservationReuse( observation, bindings, environment) ==
						   LocalOfficialObservationReuse::OPERATING_SYSTEM_CHANGED) ;
	environment								   = observation.environment ;
	environment.deviceConfigurationFingerprint = std::wstring( 64U, L'1') ;
	DRIVERCRATE_EXPECT( context,
					   classifyLocalOfficialObservationReuse( observation, bindings, environment) ==
						   LocalOfficialObservationReuse::DEVICE_CONFIGURATION_CHANGED) ;
	environment = observation.environment ;
	++environment.policyRevision ;
	DRIVERCRATE_EXPECT( context,
					   classifyLocalOfficialObservationReuse( observation, bindings, environment) ==
						   LocalOfficialObservationReuse::POLICY_CHANGED) ;
	environment = observation.environment ;
	++environment.parserRevision ;
	DRIVERCRATE_EXPECT( context,
					   classifyLocalOfficialObservationReuse( observation, bindings, environment) ==
						   LocalOfficialObservationReuse::PARSER_CHANGED) ;

	environment = observation.environment ;
	bindings[0].deviceBindingFingerprint.clear() ;
	DRIVERCRATE_EXPECT( context,
					   classifyLocalOfficialObservationReuse( observation, bindings, environment) ==
						   LocalOfficialObservationReuse::INVALID) ;

	const std::array duplicateBindings{observation.binding,
									   observation.binding} ;	// 曖昧な重複集合。
	DRIVERCRATE_EXPECT( context, classifyLocalOfficialObservationReuse(
									observation, duplicateBindings, environment) ==
									LocalOfficialObservationReuse::INVALID) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 成立Providerだけの置換、対象外時の除去、失敗Provider保持、別Provider注入と重複の拒否を確認する。
 *
 * @param[in,out] context assertion集計先。
 */
//------------------------------------------------------------------------------
void testProviderObservationMerge( TestContext &context)
{
	LocalOfficialReleaseObservation first	   = makeObservation() ;	// 更新対象Providerの旧観測。
	LocalOfficialReleaseObservation preserved  = first ;				// 今回失敗した別Providerの旧観測。
	preserved.binding.deviceBindingFingerprint = std::wstring( 64U, L'e') ;
	preserved.binding.providerId			   = L"preserved-provider" ;
	preserved.binding.sourceId				   = L"preserved-source" ;
	preserved.binding.familyId				   = L"preserved-family" ;
	preserved.binding.productKey			   = L"preserved-product" ;
	const std::array				previous{first, preserved} ;	// 二Provider分の前回snapshot。

	LocalOfficialReleaseObservation refreshed = first ;	// 成立scanが返す今回観測。
	refreshed.packageVersion				  = L"10.20.30.41" ;
	refreshed.observedFileTime				  = 2U ;
	const std::array refreshedIds{std::wstring( L"fictional-provider")} ;	// 成立Provider集合。
	const std::array current{refreshed} ;									// 今回生成した一件の観測。
	std::vector<LocalOfficialReleaseObservation> merged ;					// 統合成功時の全snapshot。
	DRIVERCRATE_EXPECT(
		context, mergeLocalOfficialReleaseObservations( previous, refreshedIds, current, merged)) ;
	DRIVERCRATE_EXPECT( context, merged.size() == 2U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( merged.size() == 2U) {
		DRIVERCRATE_EXPECT( context, merged[0].binding.providerId == L"preserved-provider") ;
		DRIVERCRATE_EXPECT( context, merged[1].packageVersion == L"10.20.30.41") ;
	}

	std::vector<LocalOfficialReleaseObservation> removed ;	// 対象外Provider除去結果。
	DRIVERCRATE_EXPECT( context,
					   mergeLocalOfficialReleaseObservations( previous, refreshedIds, {}, removed)) ;
	DRIVERCRATE_EXPECT( context, removed.size() == 1U) ;
	// 結果の存在と参照範囲が確認できた場合にだけ内容を検証し、前提失敗を不正な参照へ波及させない。
	if( removed.size() == 1U) {
		DRIVERCRATE_EXPECT( context, removed[0].binding.providerId == L"preserved-provider") ;
	}

	LocalOfficialReleaseObservation injected = refreshed ;	// 更新集合外Providerの不正な今回観測。
	injected.binding.providerId				 = L"unexpected-provider" ;
	injected.binding.sourceId				 = L"unexpected-source" ;
	const std::array injectedCurrent{injected} ;						// 注入拒否を確認する入力。
	std::vector<LocalOfficialReleaseObservation> unchanged{preserved} ;	// 失敗時に保つ出力。
	DRIVERCRATE_EXPECT( context, !mergeLocalOfficialReleaseObservations( previous, refreshedIds,
																	   injectedCurrent, unchanged)) ;
	DRIVERCRATE_EXPECT( context, unchanged.size() == 1U &&
									unchanged[0].binding.providerId == L"preserved-provider") ;

	const std::array duplicateIds{std::wstring( L"fictional-provider"),
								  // 曖昧な更新集合。
								  std::wstring( L"fictional-provider")} ;
	DRIVERCRATE_EXPECT( context, !mergeLocalOfficialReleaseObservations( previous, duplicateIds,
																	   current, unchanged)) ;
	const std::array duplicateCurrent{refreshed, refreshed} ;	// 同じbindingの二重今回観測。
	DRIVERCRATE_EXPECT( context, !mergeLocalOfficialReleaseObservations(
									previous, refreshedIds, duplicateCurrent, unchanged)) ;
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @see tests/unit/official_release_observation_tests.h 宣言側の契約を正本とする。
 */
//------------------------------------------------------------------------------
void runOfficialReleaseObservationTests( TestContext &context)
{
	testValidation( context) ;
	testIdentityResults( context) ;
	testBindingAndEnvironmentChanges( context) ;
	testReleaseChanges( context) ;
	testLocalProbeReuseClassification( context) ;
	testProviderObservationMerge( context) ;
}

} // namespace drivercrate::test
