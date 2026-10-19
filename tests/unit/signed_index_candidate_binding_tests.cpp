//------------------------------------------------------------------------------
/**
 * @file signed_index_candidate_binding_tests.cpp
 * @brief 真署名索引から通常候補とfake指定導入へ接続する有限fixtureを検証します。
 * @version 01.18.00
 * @date 2026/10/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  同workerの索引候補と指定導入の内部境界を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/12  低位fixtureと通常候補試験の宣言・所有期間を説明。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  二device部分失敗と実UI共有の低位worker factoryを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  完全登録root・真初回・INF別拒否とdevice別callを固定。
 * Ver.01.02.01 Shunji Ogawa  2026/10/12  低位callbackとhelperの引数・返却・借用契約を補足。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  実CAT memberと低位署名期待hashの不一致を固定。
 * Ver.01.05.00 Shunji Ogawa  2026/10/13  元Class未確定と実INF/native Classの完全低位条件を固定。
 * Ver.01.06.00 Shunji Ogawa  2026/10/13  元親と必要SWC子の完全低位fixtureを追加。
 * Ver.01.07.00 Shunji Ogawa  2026/10/13  元native節と全import CAT/hash差を完全低位へ接続。
 * Ver.01.08.00 Shunji Ogawa  2026/10/13  必要Win32 service EXEを元INF ownerへ結ぶ完全低位条件を追加。
 * Ver.01.09.00 Shunji Ogawa  2026/10/13  固定subdir serviceの完全相対位置を同元INF CAT ownerへ結合。
 * Ver.01.10.00 Shunji Ogawa  2026/10/13  新媒体24条件の完全member位置と二CAT拒否を固定。
 * Ver.01.11.00 Shunji Ogawa  2026/10/13  完全五APIとSYSTEM元byte/効果とPACKAGE改変観測を接続。
 * Ver.01.12.00 Shunji Ogawa  2026/10/14  他node必要ID失敗と二node一致を低位propertyへ固定。
 * Ver.01.13.00 Shunji Ogawa  2026/10/15  R04で全present再列挙を指定node照会から独立観測。
 * Ver.01.14.00 Shunji Ogawa  2026/10/15  完全低位署名factoryから同期観測を登録。
 * Ver.01.15.00 Shunji Ogawa  2026/10/15  登録Extensionへの書換権限と全byte保持を実fileで確認。
 * Ver.01.16.00 Shunji Ogawa  2026/10/15  archive128/129境界にも全ownerの署名低位表を固定。
 * Ver.01.17.00 Shunji Ogawa  2026/10/15  fake復旧前同期とjoin後の非署名counter観測を追加。
 * Ver.01.17.01   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.18.00 Shunji Ogawa  2026/10/16  索引通信結果の可視導線と同版publicationの画面受入を追加。
 * </pre>
 *
 * @note Worker内だけで直列使用し、公開設定から取得権限を生成しません。
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#include "signed_index_candidate_binding_tests.h"
#include "platform/composite_update_provider.h"
#include "platform/official_file_verifier.h"
#include "platform/official_download_workspace.h"
#include "platform/inf_dependency_native_internal.h"
#include "core/restore_point_service.h"
#include "core/operation_controller.h"
#include "core/candidate_selection.h"
#include "core/provider_registry.h"
#include <Windows.h>
#include <Softpub.h>
#include <devpkey.h>
#include <devguid.h>
#include <cfg.h>
#include <miniz.h>
#include <array>
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <stdexcept>
#include <thread>
#include <vector>

namespace drivercrate::test {
namespace {
// 通常Ports内容とWindows nodeが完全一致する固定class。
constexpr GUID PORTS_CLASS{
	0x4d36e978, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}} ;
// Net一種へ処理を限定していないことを確認する別の通常class。
constexpr GUID NET_CLASS{
	0x4d36e972, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}} ;
// 必要SoftwareComponentの元Class/GUIDです。
constexpr GUID COMPONENT_CLASS{
	0x5c4c3332, 0x344d, 0x483c, {0x87, 0x39, 0x25, 0x9e, 0x93, 0x4c, 0x9c, 0xc8}} ;
// 必要Extensionの元Class/GUIDです。
constexpr GUID EXTENSION_CLASS{
	0xe2f84ce7, 0x8efa, 0x411c, {0xaa, 0x69, 0x97, 0x45, 0x4c, 0xa4, 0xcb, 0x57}} ;
/** @brief 同実INF byteのClassを返す低位fakeの宣言です。
 * @param[in] path 元INFの完全pathです。
 * @param[out] guid 元directiveのGUIDです。
 * @param[out] name 元Class名です。
 * @param[in] capacity nameの要素上限です。
 * @param[out] required NUL込み必要数です。
 * @return 全元byte/ABI一致TRUE、不正は原Windows診断のFALSEです。
 */
BOOL WINAPI infClass( PCWSTR path, LPGUID guid, PWSTR name, DWORD capacity, PDWORD required) ;
/** @brief 成功DTOでなく低位APIの状態だけを有限所有します。 */
struct NativeFixtureState {
	/// fake復旧直前に同workerだけが呼ぶ有限同期です。空は通常の元fixtureを維持します。
	std::function<void()>						   beforeRestore ;
	/// 同元登録Extensionへの変更権限probe回数です。
	std::uint32_t								   registeredExtensionProbes{} ;
	/// Windowsの実共有規則で拒否されたprobe回数です。
	std::uint32_t								   registeredExtensionBlocked{} ;
	/// 最後のprobeの元Windows診断です。
	DWORD										   registeredExtensionError{} ;
	/// 同登録INFのprobe前後全byte一致を保持します。
	bool										   registeredExtensionBytesUnchanged{true} ;
	/// 元ZIPの追加roleを持つ場合だけ親の指定API後のpropertyを変更します。
	bool										   requiredRoles{} ;
	/// 元AddComponentへ結合する人工SWCを含む場合trueです。
	bool										   componentChild{} ;
	/// 二つまでの必要SWC子の指定呼出し数です。
	std::array<std::uint32_t, 2U>				   childInstalls{} ;
	/// 実Windows INFを使わない保護された登録rootの所有です。
	OfficialDownloadWorkspace					   registration ;
	/// 完全root APIへ返す隔離Windows rootです。通常出力へ出しません。
	std::wstring								   windowsRoot ;
	/// 固定低位状態の拒否または初回条件です。
	SignedIndexBindingNativeCase				   nativeCase{SignedIndexBindingNativeCase::NORMAL} ;
	/// 公表後の原API状態だけを変更した場合trueです。
	bool										   changed{} ;
	/// 二番目deviceを失敗させる既存部分条件です。
	bool										   partialFailure{} ;
	/// INF検索で観測した元pathの有限集合です。
	std::vector<std::wstring>					   sourceInfs ;
	/// 各deviceの指定導入が一度だけであることを観測します。
	std::array<std::uint32_t, 2U>				   deviceInstalls{} ;
	/// 一handleの検索条件です。
	std::array<SP_DEVINSTALL_PARAMS_W, 32>		   parameters{} ;
	/// 生存handleです。
	std::array<bool, 32>						   used{} ;
	/// 本体へ通常propertyとして返す現在版です。
	std::wstring								   currentVersion{L"0.9.0.0"} ;
	/// 固定個別失敗または再起動条件です。
	unsigned									   mode{} ;
	/// 一般NetまたはPortsの固定fixtureです。
	bool										   network{} ;
	/// 二つの独立recordに対応する人工present deviceを列挙する場合trueです。
	bool										   multiple{} ;
	/// 復旧fakeの開始／終了回数です。
	std::uint32_t								   restoreBegins{} ;
	/// 復旧fake終了の実回数です。
	std::uint32_t								   restoreCompletes{} ;
	/// 復旧開始を元ERROR_ACCESS_DENIEDで拒否する場合trueです。
	bool										   restoreFailure{} ;
	/// 偽stageを元ERROR_ACCESS_DENIEDで拒否し指定導入を止める場合trueです。
	bool										   stagingFailure{} ;
	/// 最大二stageのexact INF pathを固定長bufferへ保持します。外部出力しません。
	std::array<std::array<wchar_t, MAX_PATH>, 32U> stagedPaths{} ;
	/// 指定導入のpath/node/版/provider/flags一致を全callで確認した場合trueです。
	bool										   specifiedBindingMatches{true} ;
	/// 実低位呼出し数です。
	std::uint32_t								   opens{} ;
	/// 実低位解放数です。
	std::uint32_t								   closes{} ;
	/// 実fake stage数です。
	std::uint32_t								   stages{} ;
	/// 実fake指定install数です。
	std::uint32_t								   installs{} ;
	/// 元Windows rank呼出しの実回数です。
	std::uint32_t								   rankCalls{} ;
	/// 空pathとinstalled-only flagsを照合済みの現在node照会回数です。
	std::uint32_t								   installedOnlyQueries{} ;
	/// 全present列挙開始だけを数え、指定device/node再確認を自動scanへ混ぜません。
	std::uint32_t								   allPresentInventoryOpens{} ;
	/// 同閉包PACKAGE必要INFへの署名照会回数です。
	std::uint32_t								   dependencyPackageObservations{} ;
	/// SYSTEM必要効果の全payload CAT照合回数です。
	std::uint32_t								   dependencySystemEffectChecks{} ;
	/// SYSTEM必要INFをstageしようとした実低位call数です。
	std::uint32_t								   dependencySystemStageCalls{} ;
	/// 完全低位表のOS version到達回数です。
	std::uint32_t								   dependencyVersionCalls{} ;
	/// 依存INF署名到達回数です。
	std::uint32_t								   dependencyInfCalls{} ;
	/// 依存CAT署名到達回数です。
	std::uint32_t								   dependencyCatalogCalls{} ;
	/// 同完全表の隔離Windows起点照会回数です。
	std::uint32_t								   dependencyWindowsDirectoryCalls{} ;
	/// 同完全表の対応Store独立照会回数です。
	std::uint32_t								   dependencyDriverStoreCalls{} ;
	/// 元署名応答の有限終端と非空条件の実観測です。
	bool										   dependencySignerResponsesValid{true} ;
	/// PACKAGE署名応答の四条件bitです。pathや署名本文を出力しません。
	std::uint32_t								   dependencySignerMask{} ;
	/// 同元root INFへの署名観測順です。終端応答だけの拒否に使います。
	std::uint32_t								   dependencyRootSignerCalls{} ;
} ;
thread_local NativeFixtureState *activeNative = nullptr ;	// 一workerの固定低位状態です。
/**
 * @brief 隔離登録Extensionだけへの変更権限と元全byteを実file APIで確認します。
 * @note 同workerのbase stageと指定API入口から同期使用し、実Windows INFへ触れません。
 *       書換条件は許可された場合に一byte追記し、DELETE条件は権限openだけで終了します。
 */
void							 probeRegisteredExtension()
{
	// 固定した二条件以外にはfile変更の試行を追加しません。
	if( !activeNative || (activeNative->nativeCase !=
							 SignedIndexBindingNativeCase::EXTENSION_REGISTERED_WRITE_PROBE &&
						 activeNative->nativeCase !=
							 SignedIndexBindingNativeCase::EXTENSION_REGISTERED_DELETE_PROBE)) {
		return ;
	}

	const auto	 path = activeNative->stagedPaths.front().data() ;		// 元隔離登録INFだけを借用します。
	std::wstring before ;												// 変更権限open前の全byte hashです。
	std::wstring after ;												// 変更権限open終端後の全byte hashです。
	const bool	 beforeRead = computeFileSha256( path, before) == 0 ;	// 欠測を一致へ補完しません。
	const bool	 write =
		activeNative->nativeCase ==
		SignedIndexBindingNativeCase::EXTENSION_REGISTERED_WRITE_PROBE ;	// 作用を固定します。
	++activeNative->registeredExtensionProbes ;
	const HANDLE opened					   = CreateFileW( path, write ? GENERIC_WRITE : DELETE,
														 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
														 nullptr, OPEN_EXISTING, 0U,
														 nullptr) ;	// 同期probeの所有handleです。
	activeNative->registeredExtensionError = opened == INVALID_HANDLE_VALUE ? GetLastError() : 0U ;
	// 拒否された変更権限だけをblockedへ数え、元診断を維持します。
	if( opened == INVALID_HANDLE_VALUE) {
		++activeNative->registeredExtensionBlocked ;
	} else {
		const std::unique_ptr<void, decltype( &CloseHandle)> handle{
			opened, &CloseHandle} ;	// 必ず解放します。
		// 修正前の実書換可否を、成功DTOへ触れず元登録fileだけで再現します。
		if( write) {
			DWORD	   written{} ;	// 意図した一byteの完了数です。
			const char byte = ';' ;	// 元INF hashを必ず変える追記です。
			const bool changed =
				SetFilePointer( handle.get(), 0L, nullptr, FILE_END) != INVALID_SET_FILE_POINTER &&
				WriteFile( handle.get(), &byte, 1U, &written, nullptr) &&
				// Windowsの実書込結果です。
				written == 1U ;
			activeNative->registeredExtensionBytesUnchanged &= !changed ;
		}
	}

	activeNative->registeredExtensionBytesUnchanged &=
		beforeRead && computeFileSha256( path, after) == 0 && before == after ;
}
/** @brief 原payloadと完全低位署名/起動表だけを所有する人工状態です。 */
struct InstallerFixtureState {
	/// 原payloadの全実byte hashです。
	std::wstring					hash ;
	/// Windows VERIFYへ渡された元保護pathです。外へ出しません。
	std::wstring					path ;
	/// 事前固定した署名/publisher/起動拒否条件です。
	SignedIndexBindingNativeCase	condition{} ;
	/// 非機密の原低位観測です。
	SignedIndexInstallerObservation observation ;
	/// 元query/findへ返す人工certificateです。
	CERT_CONTEXT					certificate{} ;
	/// 原processの終了codeです。driver導入済みではありません。
	DWORD							exitCode{} ;
} ;
// 同workerだけが完全表へ結ぶ人工状態です。
thread_local InstallerFixtureState *activeInstallerFixture{} ;
/** @brief 低位Windows境界でも実file全byteを元hashへ結合します。
 * @param[in] path 元保護fileです。
 * @return 全hash一致時trueです。実trustや起動を呼びません。
 */
[[nodiscard]] bool					installerBytes( const wchar_t *path)
{
	std::wstring hash ;	// 非公開の実検査値です。
	return activeInstallerFixture && path && computeFileSha256( path, hash) == 0 &&
		   hash == activeInstallerFixture->hash ;
}
/** @brief 原fileとWindows Authenticode policyの全設定を確認します。
 * @param[in] parent nullのABI親です。
 * @param[in] action Generic Verify V2です。
 * @param[in,out] value 元WINTRUST_DATAです。
 * @return 原正例0またはTRUST_E_BAD_DIGESTです。実trustを呼びません。
 */
LONG WINAPI installerVerify( HWND parent, GUID *action, LPVOID value)
{
	const GUID expected = WINTRUST_ACTION_GENERIC_VERIFY_V2 ;	// 製品と同policyです。
	// 欠損・別policyを成功へ補完しません。
	if( !activeInstallerFixture || parent || !action || !IsEqualGUID( *action, expected) || !value) {
		return TRUST_E_BAD_DIGEST ;
	}

	const auto &trust = *static_cast<WINTRUST_DATA *>( value) ;	// 同期ABIの同型値です。
	// 元実byte・完全Windows policy・ABIの全条件の照合値です。
	const bool	valid = trust.cbStruct == sizeof( trust) && trust.dwUIChoice == WTD_UI_NONE &&
					   trust.fdwRevocationChecks == WTD_REVOKE_WHOLECHAIN &&
					   trust.dwUnionChoice == WTD_CHOICE_FILE &&
					   trust.dwProvFlags == WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT &&
					   trust.pFile && installerBytes( trust.pFile->pcwszFilePath) &&
					   (trust.dwStateAction == WTD_STATEACTION_VERIFY ||
						trust.dwStateAction == WTD_STATEACTION_CLOSE) ;
	activeInstallerFixture->observation.valid &= valid ;
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません。
	if( !valid || activeInstallerFixture->condition ==
					 SignedIndexBindingNativeCase::INSTALLER_SIGNATURE_FAILURE) {
		return TRUST_E_BAD_DIGEST ;
	}

	activeInstallerFixture->path = trust.pFile->pcwszFilePath ;
	return ERROR_SUCCESS ;
}
/** @brief 同実fileのembedded signerだけを人工queryへ結合します。
 * @param[in] objectType FILEです。
 * @param[in] object 元完全pathです。
 * @param[in] content PKCS7 embeddedです。
 * @param[in] format BINARYです。
 * @param[in] flags 0です。
 * @param[out] encoding X509/PKCS7です。
 * @param[out] type Embeddedです。
 * @param[out] outputFormat BINARYです。
 * @param[out] store 人工storeです。
 * @param[out] message 人工messageです。
 * @param[out] context nullだけです。
 * @return 全byte/ABIが一致時TRUEです。実CryptQueryObjectは呼びません。
 */
BOOL WINAPI installerQuery( DWORD objectType, const void *object, DWORD content, DWORD format,
						   DWORD flags, DWORD *encoding, DWORD *type, DWORD *outputFormat,
						   HCERTSTORE *store, HCRYPTMSG *message, const void **context)
{
	// 別fileと不完全なqueryを拒否します。
	if( !activeInstallerFixture || objectType != CERT_QUERY_OBJECT_FILE ||
	   !installerBytes( static_cast<const wchar_t *>( object)) ||
	   content != CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED ||
	   format != CERT_QUERY_FORMAT_FLAG_BINARY || flags || !encoding || !type || !outputFormat ||
	   !store || !message || context) {
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	*encoding	  = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING ;
	*type		  = CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED ;
	*outputFormat = CERT_QUERY_FORMAT_BINARY ;
	*store		  = activeInstallerFixture ;
	*message	  = activeInstallerFixture ;
	return TRUE ;
}
/** @brief 同queryの原issuer/serialを二段階で返します。
 * @param[in] message 元人工messageです。
 * @param[in] type SIGNER_INFOです。
 * @param[in] index 0です。
 * @param[out] output Nullなら必要長です。
 * @param[in,out] bytes 終端出力長です。
 * @return 原ABI一致時TRUEです。実messageは使用しません。
 */
BOOL WINAPI installerMessage( HCRYPTMSG message, DWORD type, DWORD index, void *output, DWORD *bytes)
{
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません。
	if( !activeInstallerFixture || message != activeInstallerFixture ||
	   type != CMSG_SIGNER_INFO_PARAM || index || !bytes) {
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	// 元scopeだけで使用する有限な検査値です。未知を成功へ補完しません。
	CMSG_SIGNER_INFO signer{} ;
	static BYTE		 identity = 1U ;	// 人工issuer/serialの固定byteです。
	signer.Issuer			  = {1U, &identity} ;
	signer.SerialNumber		  = {1U, &identity} ;
	// 受信buffer未指定では必要長だけを返し、本文を発行しません。
	if( !output) {
		*bytes = sizeof( signer) ;
		return TRUE ;
	}

	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません。
	if( *bytes < sizeof( signer)) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	std::memcpy( output, &signer, sizeof( signer)) ;
	*bytes = sizeof( signer) ;
	return TRUE ;
}
/** @brief 原issuer/serialへ人工certificateを一意に結合します。
 * @param[in] store 元人工storeです。
 * @param[in] encoding X509/PKCS7です。
 * @param[in] flags 0です。
 * @param[in] type SUBJECT_CERTです。
 * @param[in] match 同issuer/serialのkeyです。
 * @param[in] previous nullです。
 * @return 人工certificateまたは空です。実storeへ触れません。
 */
PCCERT_CONTEXT WINAPI installerFind( HCERTSTORE store, DWORD encoding, DWORD flags, DWORD type,
									const void *match, PCCERT_CONTEXT previous)
{
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません。
	if( !activeInstallerFixture || store != activeInstallerFixture ||
	   encoding != (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING) || flags ||
	   type != CERT_FIND_SUBJECT_CERT || !match || previous) {
		SetLastError( ERROR_INVALID_DATA) ;
		return nullptr ;
	}

	const auto &key = *static_cast<const CERT_INFO *>( match) ;	// 同CAPI ABI keyです。
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません。
	if( key.Issuer.cbData != 1U || key.SerialNumber.cbData != 1U || !key.Issuer.pbData ||
	   !key.SerialNumber.pbData || key.Issuer.pbData[0] != 1U || key.SerialNumber.pbData[0] != 1U) {
		SetLastError( ERROR_INVALID_DATA) ;
		return nullptr ;
	}

	return &activeInstallerFixture->certificate ;
}
/** @brief 原signer名を二段階で返し期待publisher差を保存します。
 * @param[in] certificate 元人工certificateです。
 * @param[in] type SIMPLE_DISPLAYです。
 * @param[in] flags 0です。
 * @param[in] parameters nullです。
 * @param[out] output Nullなら必要長です。
 * @param[in] capacity wchar_t上限です。
 * @return 終端込み原名長です。実certificateを読みません。
 */
DWORD WINAPI installerName( PCCERT_CONTEXT certificate, DWORD type, DWORD flags, void *parameters,
						   LPWSTR output, DWORD capacity)
{
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません。
	if( !activeInstallerFixture || certificate != &activeInstallerFixture->certificate ||
	   type != CERT_NAME_SIMPLE_DISPLAY_TYPE || flags || parameters) {
		return 0U ;
	}

	// 原signer名です。期待publisherの差を正例へ置換しません。
	const std::wstring name = activeInstallerFixture->condition ==
									  SignedIndexBindingNativeCase::INSTALLER_PUBLISHER_FAILURE
								  ? L"Wrong publisher"
								  : L"Synthetic publisher" ;
	// 終端または元集合の有限必要数です。成功数を推測しません。
	const auto		   count = static_cast<DWORD>( name.size() + 1U) ;
	// 受信buffer未指定では必要長だけを返し、本文を発行しません。
	if( !output) {
		return count ;
	}

	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません。
	if( capacity < count) {
		return 0U ;
	}

	wcscpy_s( output, capacity, name.c_str()) ;
	return count ;
}
/** @brief 原人工certificateだけを返却します。
 * @param[in] certificate 元構造です。
 * @return 元構造ならTRUEです。実certificateを解放しません。
 */
BOOL WINAPI installerFree( PCCERT_CONTEXT certificate)
{
	return activeInstallerFixture && certificate == &activeInstallerFixture->certificate ;
}
/** @brief 原人工messageだけを返却します。
 * @param[in] message 元構造です。
 * @return 元構造ならTRUEです。実messageを解放しません。
 */
BOOL WINAPI installerCloseMessage( HCRYPTMSG message)
{
	return activeInstallerFixture && message == activeInstallerFixture ;
}
/** @brief 原人工storeだけを返却します。
 * @param[in] store 元構造です。
 * @param[in] flags 0です。
 * @return 元構造ならTRUEです。実storeを解放しません。
 */
BOOL WINAPI installerCloseStore( HCERTSTORE store, DWORD flags)
{
	return activeInstallerFixture && store == activeInstallerFixture && !flags ;
}
/** @brief 原全byteとexact非silent commandだけを受理します。
 * @param[in] application 原EXEまたは固定msiexecです。
 * @param[in,out] command 引用済み元commandです。
 * @param[in] processAttributes nullです。
 * @param[in] threadAttributes nullです。
 * @param[in] inherit FALSEです。
 * @param[in] flags 0です。
 * @param[in] environment nullです。
 * @param[in] directory 固定System32です。
 * @param[in] startup 非silent UI設定です。
 * @param[out] handles 人工二handleです。
 * @return 原正例TRUEまたは元ACCESS_DENIEDです。実processは作成しません。
 */
BOOL WINAPI installerCreate( LPCWSTR application, LPWSTR command,
							LPSECURITY_ATTRIBUTES processAttributes,
							LPSECURITY_ATTRIBUTES threadAttributes, BOOL inherit, DWORD flags,
							LPVOID environment, LPCWSTR directory, LPSTARTUPINFOW startup,
							LPPROCESS_INFORMATION handles)
{
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません。
	if( !activeInstallerFixture || !application || !command || !directory || !startup || !handles ||
	   !installerBytes( activeInstallerFixture->path.c_str())) {
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	// 固定Windows msiexecと原MSIだけに認める別方式です。
	const bool msi = std::wstring_view{application} == L"C:\\Windows\\System32\\msiexec.exe" ;
	// 元保護pathだけを含むexact非silent command期待です。
	const std::wstring expected = L"\"" + std::wstring{application} + L"\"" +
								  (msi ? L" /i \"" + activeInstallerFixture->path + L"\"" : L"") ;
	// 元実byte・完全Windows policy・ABIの全条件の照合値です。
	const bool valid = !processAttributes && !threadAttributes && !inherit && !flags &&
					   !environment && std::wstring_view{directory} == L"C:\\Windows\\System32" &&
					   startup->cb == sizeof( *startup) && !startup->dwFlags &&
					   std::wstring_view{command} == expected &&
					   (msi || std::wstring_view{application} == activeInstallerFixture->path) ;
	activeInstallerFixture->observation.valid &= valid ;
	++activeInstallerFixture->observation.launches ;
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません。
	if( !valid || activeInstallerFixture->condition ==
					 SignedIndexBindingNativeCase::INSTALLER_LAUNCH_FAILURE) {
		SetLastError( ERROR_ACCESS_DENIED) ;
		return FALSE ;
	}

	handles->hProcess				 = activeInstallerFixture ;
	handles->hThread				 = &activeInstallerFixture->certificate ;
	activeInstallerFixture->exitCode = msi ? ERROR_SUCCESS_REBOOT_REQUIRED : ERROR_SUCCESS ;
	return TRUE ;
}
/** @brief 人工processの終端だけを返します。
 * @param[in] process 元人工processです。
 * @param[in] timeout INFINITEです。
 * @return 原processならWAIT_OBJECT_0です。実待機は行いません。
 */
DWORD WINAPI installerWait( HANDLE process, DWORD timeout)
{
	return activeInstallerFixture && process == activeInstallerFixture && timeout == INFINITE
			   ? WAIT_OBJECT_0
			   : WAIT_FAILED ;
}
/** @brief 人工processの原終了codeだけを返します。
 * @param[in] process 元人工processです。
 * @param[out] code 原終了codeです。
 * @return 原processならTRUEです。driver導入を合成しません。
 */
BOOL WINAPI installerExit( HANDLE process, LPDWORD code)
{
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません。
	if( !activeInstallerFixture || process != activeInstallerFixture || !code) {
		return FALSE ;
	}

	*code = activeInstallerFixture->exitCode ;
	return TRUE ;
}
/** @brief 同起動の人工二handleだけを返却します。
 * @param[in] handle 元processまたはthreadです。
 * @return 原二handleならTRUEです。実handleを閉じません。
 */
BOOL WINAPI installerClose( HANDLE handle)
{
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません。
	if( !activeInstallerFixture ||
	   (handle != activeInstallerFixture && handle != &activeInstallerFixture->certificate)) {
		return FALSE ;
	}

	++activeInstallerFixture->observation.closes ;
	return TRUE ;
}
/** @brief 固定Windows標準directoryだけを返します。
 * @param[out] output 終端付き受信です。
 * @param[in] capacity wchar_t上限です。
 * @return 原directoryの長さです。実systemへ触れません。
 */
UINT WINAPI installerSystemDirectory( LPWSTR output, UINT capacity)
{
	const std::wstring path = L"C:\\Windows\\System32" ;	// 実起動へ渡さない架空固定値です。
	// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません。
	if( !output || capacity <= path.size()) {
		return 0U ;
	}

	wcscpy_s( output, capacity, path.c_str()) ;
	return static_cast<UINT>( path.size()) ;
}
/** @brief Class未確定初回の固定した追加低位条件か確認します。
 * @return 新しいClass条件の有限範囲に属する場合trueです。
 */
bool unknownClassScenario() noexcept
{
	return activeNative &&
		   activeNative->nativeCase >= SignedIndexBindingNativeCase::INITIAL_CLASS_MISSING &&
		   activeNative->nativeCase <= SignedIndexBindingNativeCase::INITIAL_CLASS_AFTER_STAGE ;
}

/** @brief 元deviceのClassが既知へ変わった固定条件を判定します。
 * @return 原低位状態の変更条件が成立した場合だけtrueです。
 */
bool observedClassChanged() noexcept
{
	return activeNative &&
		   ((activeNative->requiredRoles && activeNative->deviceInstalls[0] != 0U) ||
			(activeNative->changed &&
			 (activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_CLASS_CHANGED ||
			  activeNative->nativeCase == SignedIndexBindingNativeCase::KNOWN_CLASS_MISMATCH ||
			  activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_DRIVER_ADDED)) ||
			(activeNative->stages != 0U &&
			 activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_CLASS_AFTER_STAGE)) ;
}

/** @brief 同workerのnative現在状態が明示初回条件か確認します。
 * @return 属性欠損とCode28を返す固定状態の場合trueです。
 */
bool initialState() noexcept
{
	return activeNative &&
		   ((unknownClassScenario() &&
			 !(activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_DRIVER_ADDED &&
			   activeNative->changed)) ||
			activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL ||
			activeNative->nativeCase == SignedIndexBindingNativeCase::CONTRADICTORY_NODE ||
			activeNative->nativeCase == SignedIndexBindingNativeCase::DISAPPEARED ||
			activeNative->nativeCase == SignedIndexBindingNativeCase::PROPERTY_FAILURE ||
			activeNative->nativeCase == SignedIndexBindingNativeCase::MISSING_RANK ||
			(activeNative->nativeCase == SignedIndexBindingNativeCase::DRIVER_ADDED &&
			 !activeNative->changed)) ;
}
/** @brief Fake registrationの保護rootを一度だけ作ります。実OS登録先へ書込みません。
 * @param[in,out] state 一workerの隔離所有です。
 * @return 実fixture workspace生成が完了した場合trueです。
 */
bool initializeRegistration( NativeFixtureState &state)
{
	// 同workerへ重複したrootを作成しません。
	if( !state.windowsRoot.empty()) {
		return true ;
	}

	HANDLE marker = INVALID_HANDLE_VALUE ;	// 隔離INF directoryの生成fileです。
	// 既存rootを再利用せず本体と同じ保護workspaceへ固定します。
	if( state.registration.initialize( L"index-stage-fixture", 1U) != 0U ||
	   state.registration.createFile( L"INF\\marker.tmp", marker) != 0U) {
		return false ;
	}

	CloseHandle( marker) ;
	const auto path = state.registration.path( L"INF\\marker.tmp") ;	// 同workspace所有pathです。
	state.windowsRoot =
		path.substr( 0U, path.size() - std::wstring_view{L"\\INF\\marker.tmp"}.size()) ;
	return !state.windowsRoot.empty() ;
}
/** @brief 固定handleを有限indexへ戻します。WinAPI ABI境界だけのpointer表現です。
 * @param[in] set Fake生成handleです。
 * @return 有効なindex、または有限上限です。
 */
std::size_t setIndex( HDEVINFO set) noexcept
{
	const auto value = reinterpret_cast<std::uintptr_t>( set) ;	// 実pointerをdereferenceしません。
	return value >= 0x100U && value < 0x120U ? static_cast<std::size_t>( value - 0x100U) : 32U ;
}
/** @brief Nativeへfallbackせず固定handleを生成します。
 * @return 有限fake handleです。
 */
HDEVINFO createSet() noexcept
{
	// worker固定状態がなければnative handle生成へfallbackしません。
	if( !activeNative) {
		SetLastError( ERROR_INVALID_HANDLE) ;
		return INVALID_HANDLE_VALUE ;
	}

	// 有限handle枠を順番に探し、試験resourceを上限内へ保ちます。
	for( std::size_t i = 0U; i < activeNative->used.size(); ++i) {
		// 未使用の枠だけを生成し、同handleの二重所有を防ぎます。
		if( !activeNative->used[i]) {
			activeNative->used[i]			   = true ;
			activeNative->parameters[i]		   = {} ;
			activeNative->parameters[i].cbSize = sizeof( SP_DEVINSTALL_PARAMS_W) ;
			++activeNative->opens ;
			return reinterpret_cast<HDEVINFO>(
				// SDK opaque handleです。
				static_cast<std::uintptr_t>( 0x100U + i)) ;
		}
	}

	SetLastError( ERROR_TOO_MANY_OPEN_FILES) ;
	return INVALID_HANDLE_VALUE ;
}
/** @brief 同workerのpresent全class列挙に限って有限fake handleを発行します。
 * @param[in] classGuid ABIで借用するclass指定です。このfixtureは全classのflagsを検査します。
 * @param[in] enumerator ABIで借用する列挙名です。実端末を列挙しません。
 * @param[in] parent ABIで渡される親Windowです。画面を作成しません。
 * @param[in] flags present全classの完全一致を要求する検索条件です。
 * @return 有効なfake handle、条件不一致時はINVALID_HANDLE_VALUEと元errorです。
 * @note activeNativeを同worker threadでだけ借用し、closeInventoryで解放します。
 */
HDEVINFO WINAPI openInventory( [[maybe_unused]] const GUID *classGuid,
							  [[maybe_unused]] PCWSTR enumerator, [[maybe_unused]] HWND parent,
							  DWORD flags)
{
	// 本体のpresent全class列挙条件と異なる入力を拒否します。
	if( flags != (DIGCF_ALLCLASSES | DIGCF_PRESENT)) {
		SetLastError( ERROR_INVALID_FLAGS) ;
		return INVALID_HANDLE_VALUE ;
	}

	// 同workerの全present開始だけを数え、結果DTOや返却handleを変更しません。
	if( activeNative != nullptr) {
		++activeNative->allPresentInventoryOpens ;
	}

	return createSet() ;
}
/** @brief 指定INF照合用の有限fake device集合を生成します。
 * @param[in] classGuid ABIで借用するclass指定です。native集合は作成しません。
 * @param[in] parent ABIで渡される親Windowです。画面を作成しません。
 * @return 所有するfake handle、枠不足時はINVALID_HANDLE_VALUEと元errorです。
 * @note 同workerのactiveNativeを借用し、closeInventoryで解放します。
 */
HDEVINFO WINAPI createInventory( [[maybe_unused]] const GUID *classGuid,
								[[maybe_unused]] HWND		 parent)
{
	return createSet() ;
}
/** @brief 同workerで所有するfake handleを一度だけ解放します。
 * @param[in] set createSetで生成したopaque handleです。
 * @return 解放時TRUE、無効または二重解放時FALSEとERROR_INVALID_HANDLEです。
 */
BOOL WINAPI closeInventory( HDEVINFO set)
{
	// Fake handleを参照する前に確認する有限slot位置。
	const auto i = setIndex( set) ;
	// 無効または解放済みhandleの再解放を拒否します。
	if( !activeNative || i == 32U || !activeNative->used[i]) {
		SetLastError( ERROR_INVALID_HANDLE) ;
		return FALSE ;
	}

	activeNative->used[i] = false ;
	++activeNative->closes ;
	return TRUE ;
}
/** @brief 有限の人工deviceを列挙し、原Windows終端を返します。
 * @param[in] set ABIの集合handleです。このfixtureはactiveNativeの固定集合を使います。
 * @param[in] index 0から始まる人工device位置です。
 * @param[in,out] device 非nullかつSDK cbSizeを持つ借用出力です。成功時だけnodeを設定します。
 * @return 成功時TRUE、上限でERROR_NO_MORE_ITEMS、不正出力でERROR_INVALID_PARAMETERのFALSEです。
 */
BOOL WINAPI enumInventory( [[maybe_unused]] HDEVINFO set, DWORD index, PSP_DEVINFO_DATA device)
{
	// 固定一または二人工device以降は正式な列挙終端を返します。
	const auto parents = activeNative && activeNative->multiple ? 2U : 1U ;	// 元親数です。
	const bool children =
		activeNative && activeNative->componentChild && activeNative->installs != 0U &&
		activeNative->nativeCase !=
			SignedIndexBindingNativeCase::REQUIRED_CHILD_PENDING ;	// 生成待ちを分離します。
	// 親と実生成済みの必要子だけをpresent集合へ返します。
	const auto childCount =	// 同ID/同親の曖昧負例だけは二つの実present fake子です。
		children ? parents + (activeNative->nativeCase ==
									  SignedIndexBindingNativeCase::REQUIRED_CHILD_AMBIGUOUS
								  ? 1U
								  : 0U)
				 : 0U ;
	// 不在fixtureと親/実present子の完全な列挙終端を分けます。
	if( !activeNative || index >= parents + childCount) {
		SetLastError( ERROR_NO_MORE_ITEMS) ;
		return FALSE ;
	}

	// 欠損deviceとSDK cbSize不一致を拒否します。
	if( !device || device->cbSize != sizeof( SP_DEVINFO_DATA)) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	device->ClassGuid =
		unknownClassScenario() && !observedClassChanged()
			? (activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_CLASS_UNKNOWN
				   ? GUID_DEVCLASS_UNKNOWN
				   : GUID_NULL)
			: (activeNative->nativeCase == SignedIndexBindingNativeCase::KNOWN_CLASS_MISMATCH &&
					   activeNative->changed
				   ? NET_CLASS
			   : activeNative->network ? NET_CLASS
									   : PORTS_CLASS) ;
	// 親と必要SWCの役割を異なるnative Classで返します。
	if( index >= parents) {
		device->ClassGuid = COMPONENT_CLASS ;
		device->DevInst	  = 3U + index - parents ;
	} else {
		device->DevInst = index + 1U ;
	}

	return TRUE ;
}
/** @brief 固定人工instanceだけを同集合のdeviceへ解決します。
 * @param[in] set 有限集合handleです。
 * @param[in] instance 同期呼出し中借用する非null終端付き人工instanceです。
 * @param[in] parent ABIの親Windowです。画面を作成しません。
 * @param[in] flags 0だけを受理する開き方です。
 * @param[in,out] device SDK cbSizeを持つ借用出力です。成功時だけnodeを設定します。
 * @return 固定instance解決時TRUE、それ以外は元errorを持つFALSEです。
 */
BOOL WINAPI openDevice( HDEVINFO set, PCWSTR instance, [[maybe_unused]] HWND parent, DWORD flags,
					   PSP_DEVINFO_DATA device)
{
	// 元AddComponentの一意な人工子だけを完全tableで開きます。
	if( activeNative && activeNative->componentChild && instance && flags == 0U &&
	   (std::wstring_view{instance} == L"SWC\\SYNTH_COMPONENT\\CHILD1" ||
		std::wstring_view{instance} == L"SWC\\SYNTH_COMPONENT\\CHILD2")) {
		device->ClassGuid = COMPONENT_CLASS ;
		device->DevInst	  = std::wstring_view{instance}.ends_with( L"CHILD2") ? 4U : 3U ;
		return TRUE ;
	}

	// 固定instanceとflagsが完全一致する呼出しだけを受理します。
	if( !activeNative || !instance || flags != 0U ||
	   (std::wstring_view{instance} != L"TESTBUS\\SYNTH_0001\\FIXTURE" &&
		(!activeNative->multiple ||
		 std::wstring_view{instance} != L"TESTBUS\\SYNTH_0002\\FIXTURE"))) {
		std::cout << "Fixed openDevice rejected: flags " << flags << ", input length "
				  << (instance ? std::wcslen( instance) : 0U) << ", expected equality "
				  << (instance && std::wstring_view{instance} == L"TESTBUS\\SYNTH_0001\\FIXTURE")
				  << '\n' ;
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	return enumInventory(
		set, std::wstring_view{instance} == L"TESTBUS\\SYNTH_0002\\FIXTURE" ? 1U : 0U, device) ;
}
/** @brief 実端末IDを参照せず人工instanceの二段階照会を処理します。
 * @param[in] set ABIの集合handleです。このfixtureは固定device位置を参照します。
 * @param[in] device 同期中借用するdeviceです。nullは第一人工deviceを意味します。
 * @param[out] buffer 終端込み出力先です。nullまたは不足時は書込みません。
 * @param[in] capacity bufferのwchar_t要素数です。
 * @param[out] required null可の必要要素数です。終端を含みます。
 * @return 全値コピー時TRUE、buffer不足時FALSEとERROR_INSUFFICIENT_BUFFERです。
 */
BOOL WINAPI instanceId( [[maybe_unused]] HDEVINFO set, PSP_DEVINFO_DATA device, PWSTR buffer,
					   DWORD capacity, PDWORD required)
{
	// 実端末IDを参照しない人工instance。二段階照会で同じ値を返す。
	const std::wstring_view value =
		device && device->DevInst >= 3U ? (device->DevInst == 4U ? L"SWC\\SYNTH_COMPONENT\\CHILD2"
																 : L"SWC\\SYNTH_COMPONENT\\CHILD1")
		: device && device->DevInst == 2U
			? L"TESTBUS\\SYNTH_0002\\FIXTURE"
			: L"TESTBUS\\SYNTH_0001\\FIXTURE" ;	// 元deviceへ結ぶ人工instanceです。
	// 固定人工instanceの終端を含むwchar_t要素数。
	const auto length = static_cast<DWORD>( value.size() + 1U) ;
	// 必要長出力が指定された場合だけ終端込み長を返します。
	if( required) {
		*required = length ;
	}

	// 二段階照会の不足bufferへ元Windows errorを返します。
	if( !buffer || capacity < length) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	std::copy( value.begin(), value.end(), buffer) ;
	buffer[value.size()] = L'\0' ;
	return TRUE ;
}
/** @brief 同人工状態のCode28または既知driver状態を返します。
 * @param[out] status 非nullのnode状態出力です。成功時だけ更新します。
 * @param[out] problem 非nullの問題code出力です。成功時だけ更新します。
 * @param[in] instance ABIの人工nodeです。このfixtureは同workerの固定状態を使用します。
 * @param[in] flags 0だけを受理する条件です。
 * @return 成功時CR_SUCCESS、不正出力またはflags時CR_INVALID_FLAGです。
 */
CONFIGRET WINAPI nodeStatus( PULONG status, PULONG problem, [[maybe_unused]] DEVINST instance,
							ULONG flags)
{
	// 不完全なnode-status出力と未知flagsを拒否します。
	if( !status || !problem || flags != 0U) {
		return CR_INVALID_FLAG ;
	}

	const bool initial =
		initialState() && instance <= 2U &&
		!(activeNative && activeNative->requiredRoles && instance <= 2U &&
		  activeNative->deviceInstalls[instance - 1U] != 0U) ;	// 実fake API後だけです。
	*status	 = initial ? DN_HAS_PROBLEM : DN_STARTED | DN_DRIVER_LOADED ;
	*problem = initial ? CM_PROB_FAILED_INSTALL : 0U ;
	// 正常scanとbase指定後を分け、実fake API後の親startedだけを欠く負例です。
	if( activeNative && instance <= 2U && activeNative->deviceInstalls[instance - 1U] != 0U &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::REQUIRED_PARENT_NOT_STARTED) {
		*status = DN_DRIVER_LOADED ;
	}

	// Code28以外の問題を初回導入の証明へ流用しません。
	if( activeNative && activeNative->changed &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_NOT_CODE28) {
		*problem = CM_PROB_DISABLED ;
	}

	return CR_SUCCESS ;
}
/** @brief property keyのGUIDと番号を完全比較します。
 * @param[in] a 同期中借用する第一keyです。
 * @param[in] b 同期中借用する第二keyです。
 * @return 両要素が同じ場合trueです。
 */
bool sameKey( const DEVPROPKEY &a, const DEVPROPKEY &b) noexcept
{
	return a.pid == b.pid && IsEqualGUID( a.fmtid, b.fmtid) ;
}
/** @brief 現在nodeと候補nodeの固定日付をWindows表現へ変換します。
 * @param[in] candidate trueは候補日付、falseは現在日付を選びます。
 * @return 固定SYSTEMTIMEから変換した所有FILETIMEです。
 */
FILETIME date( bool candidate) noexcept
{
	// 現在版と候補版へ返す固定UTC日付。実時計を参照しない。
	SYSTEMTIME time{} ;
	time.wYear	= 2026 ;
	time.wMonth = 10 ;
	time.wDay	= candidate ? 11 : 1 ;
	// Windows表現へ変換した固定日付の所有出力。
	FILETIME result{} ;
	SystemTimeToFileTime( &time, &result) ;
	return result ;
}
/** @brief 固定人工propertyと明示NOT_FOUNDを型付きの二段階照会へ返します。
 * @param[in] set ABIの集合handleです。このfixtureはactiveNativeの状態を使います。
 * @param[in] device 同期中借用するdeviceです。nullは第一人工deviceを選びます。
 * @param[in] key 非nullの要求property keyです。
 * @param[out] type 非nullのWindows型出力です。対応propertyを照会した場合更新します。
 * @param[out] buffer 借用byte出力です。nullまたは容量不足時は書込みません。
 * @param[in] capacity bufferのbyte容量です。
 * @param[out] required null可の必要byte数です。既知propertyでは不足時にも返します。
 * @param[in] flags 0だけを受理します。
 * @return 成功時TRUE、欠損・不正・不足時は保持したWindows errorを持つFALSEです。
 * @note 同workerだけでactiveNativeを借用し、実Windows propertyへfallbackしません。
 */
BOOL WINAPI property( [[maybe_unused]] HDEVINFO set, PSP_DEVINFO_DATA device, const DEVPROPKEY *key,
					 DEVPROPTYPE *type, PBYTE buffer, DWORD capacity, PDWORD required, DWORD flags)
{
	// 固定状態・property・型出力・flagsの欠損を拒否します。
	if( !activeNative || !key || !type || flags != 0U) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	// Classの元読取失敗と上限を正式不存在へ置換しません。
	if( activeNative->changed &&
	   ((sameKey( *key, DEVPKEY_Device_Class) &&
		 activeNative->nativeCase == SignedIndexBindingNativeCase::CLASS_PROPERTY_FAILURE) ||
		(sameKey( *key, DEVPKEY_Device_ClassGuid) &&
		 activeNative->nativeCase == SignedIndexBindingNativeCase::CLASS_GUID_FAILURE))) {
		SetLastError( ERROR_ACCESS_DENIED) ;
		return FALSE ;
	}

	// 固定property上限超過を元Windowsの必要量応答として返します。
	if( activeNative->changed && sameKey( *key, DEVPKEY_Device_Class) &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::CLASS_PROPERTY_LIMIT) {
		*type = DEVPROP_TYPE_STRING ;
		// 元必要長出力を指定された場合だけ設定します。
		if( required) {
			*required = 64U * 1024U + 2U ;
		}

		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	// Classの不存在を空や型不正から分離し、後段の完全表へ同じ値を返します。
	if( unknownClassScenario() && !observedClassChanged() &&
	   (sameKey( *key, DEVPKEY_Device_Class) || sameKey( *key, DEVPKEY_Device_ClassGuid)) &&
	   activeNative->nativeCase != SignedIndexBindingNativeCase::INITIAL_CLASS_UNKNOWN &&
	   !(activeNative->changed &&
		 (activeNative->nativeCase == SignedIndexBindingNativeCase::CLASS_PROPERTY_INVALID ||
		  activeNative->nativeCase == SignedIndexBindingNativeCase::CLASS_PROPERTY_EMPTY ||
		  activeNative->nativeCase == SignedIndexBindingNativeCase::CLASS_CONTRADICTORY))) {
		SetLastError( ERROR_NOT_FOUND) ;
		return FALSE ;
	}

	// 元property failureを現在欠損や初回合格へ変換しません。
	if( sameKey( *key, DEVPKEY_Device_Driver) &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::PROPERTY_FAILURE &&
	   activeNative->changed) {
		SetLastError( ERROR_ACCESS_DENIED) ;
		return FALSE ;
	}

	// 初回の全現在属性は空文字でなく正式なNOT_FOUNDで返します。
	const bool child = device && device->DevInst >= 3U ;	// 元必要SWCです。
	const bool updated =
		activeNative->requiredRoles && !child && device &&
		activeNative->deviceInstalls[device->DevInst - 1U] != 0U ;	// 親個別API後だけです。
	// 初回の不存在とquery失敗を維持し、親API後とSWC子へ初回欠損を流用しません。
	if( (initialState() && !updated && !child &&
		((sameKey( *key, DEVPKEY_Device_Driver) &&
		  !(activeNative->changed &&
			activeNative->nativeCase ==
				SignedIndexBindingNativeCase::INITIAL_DRIVER_KEY_PRESENT)) ||
		 sameKey( *key, DEVPKEY_Device_DriverInfPath) ||
		 sameKey( *key, DEVPKEY_Device_DriverVersion) || sameKey( *key, DEVPKEY_Device_DriverDate) ||
		 sameKey( *key, DEVPKEY_Device_DriverProvider) ||
		 sameKey( *key, DEVPKEY_Device_MatchingDeviceId))) ||
	   (activeNative->nativeCase == SignedIndexBindingNativeCase::BLANK_CURRENT &&
		sameKey( *key, DEVPKEY_Device_DriverVersion)) ||
	   (initialState() &&
		(sameKey( *key, DEVPKEY_Device_FriendlyName) || sameKey( *key, DEVPKEY_Device_DeviceDesc)))) {
		SetLastError( ERROR_NOT_FOUND) ;
		return FALSE ;
	}

	std::wstring text ;	// 固定ASCII人工値だけです。
	const void	*data{} ;
	// 今回のpropertyが要求するbyte長。
	DWORD		 bytes{} ;
	// 現在driver日付。同期memcpyまで借用する所有値。
	FILETIME	 time = date( updated) ;
	// 同modeのNetまたはPortsの固定通常class。
	GUID		 guid =
		unknownClassScenario() && !observedClassChanged()
					? (activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_CLASS_UNKNOWN
						   ? GUID_DEVCLASS_UNKNOWN
						   : GUID_NULL)
					: (activeNative->nativeCase == SignedIndexBindingNativeCase::KNOWN_CLASS_MISMATCH &&
					   activeNative->changed
						   ? NET_CLASS
					   : activeNative->network ? NET_CLASS
											   : PORTS_CLASS) ;
	DEVPROP_BOOLEAN present =
		(activeNative->nativeCase == SignedIndexBindingNativeCase::DISAPPEARED ||
		 activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_DISAPPEARED) &&
				activeNative->changed
			? DEVPROP_FALSE
			: DEVPROP_TRUE ;	// 型付きの原present属性です。
	const std::wstring_view hardware =
		child ? L"SWC\\SYNTH_COMPONENT"
		: activeNative->changed &&
				activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_PNP_CHANGED
			? L"TESTBUS\\SYNTH_CHANGED"
		: device && device->DevInst == 2U &&
				activeNative->nativeCase != SignedIndexBindingNativeCase::INDEX_NON_UNIQUE
			? L"TESTBUS\\SYNTH_0002"
			: L"TESTBUS\\SYNTH_0001" ;	// 同deviceだけの人工公開IDです。
	// ClassGUID要求はSDK GUID型と実byte長で返します。
	// SoftwareComponentはbaseのClassへ偽装しません。
	if( child) {
		guid = COMPONENT_CLASS ;
	}

	// 元propertyごとに型と値を固定し、未照会属性を推測しません。
	if( sameKey( *key, DEVPKEY_Device_IsPresent)) {
		*type = DEVPROP_TYPE_BOOLEAN ;
		data  = &present ;
		bytes = sizeof( present) ;
	}
	// 原driver keyは既知状態と初回状態を区別する実propertyです。
	else if( sameKey( *key, DEVPKEY_Device_ClassGuid)) {
		*type = DEVPROP_TYPE_GUID ;
		data  = &guid ;
		bytes = sizeof( guid) ;
	}
	// 現在date要求はFILETIME型と実byte長で返します。
	else if( sameKey( *key, DEVPKEY_Device_DriverDate)) {
		*type = DEVPROP_TYPE_FILETIME ;
		data  = &time ;
		bytes = sizeof( time) ;
	} else {
		*type = DEVPROP_TYPE_STRING ;
		// ID列はHardwareとCompatibleを重複させずMULTI_SZ型で返します。
		if( sameKey( *key, DEVPKEY_Device_HardwareIds) ||
		   sameKey( *key, DEVPKEY_Device_CompatibleIds)) {
			// 他nodeの必要native属性失敗を元errorへ保持し、positive DTOを外部から生成しません。
			if( activeNative->nativeCase == SignedIndexBindingNativeCase::INDEX_VERIFIED_PARTIAL &&
			   device && device->DevInst == 2U && sameKey( *key, DEVPKEY_Device_CompatibleIds)) {
				SetLastError( ERROR_ACCESS_DENIED) ;
				return FALSE ;
			}

			*type = DEVPROP_TYPE_STRING_LIST ;
			text =
				sameKey( *key, DEVPKEY_Device_CompatibleIds) ? L"TESTBUS\\SYNTH_COMPAT" : hardware ;
			text.push_back( L'\0') ;
		}
		// 現在INF要求だけへ固定人工公開名を返します。
		else if( sameKey( *key, DEVPKEY_Device_Driver)) {
			text = L"{4d36e978-e325-11ce-bfc1-08002be10318}\\0001" ;
		}
		// 現在INF要求だけへ固定公開名を返します。
		else if( sameKey( *key, DEVPKEY_Device_DriverInfPath)) {
			text = L"oemfixture.inf" ;
		}
		// 現在版要求へ各試験modeの既知版を返します。
		else if( sameKey( *key, DEVPKEY_Device_DriverVersion)) {
			text = updated ? L"1.0.0.0" : activeNative->currentVersion ;
		}
		// providerとmanufacturerの要求へ固定人工vendorを返します。
		else if( sameKey( *key, DEVPKEY_Device_DriverProvider) ||
				sameKey( *key, DEVPKEY_Device_Manufacturer)) {
			text = L"Fixture Vendor" ;
		}
		// Class要求へNetまたはPortsの固定classを返します。
		else if( sameKey( *key, DEVPKEY_Device_Class)) {
			text =
				child ? L"SoftwareComponent"
				: activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_CLASS_UNKNOWN
					? L"Unknown"
				: activeNative->nativeCase == SignedIndexBindingNativeCase::KNOWN_CLASS_MISMATCH &&
						activeNative->changed
					? L"Net"
				: activeNative->network ? L"Net"
										: L"Ports" ;
			// 空文字と不正型を正式NOT_FOUNDから区別します。
			if( activeNative->changed &&
			   activeNative->nativeCase == SignedIndexBindingNativeCase::CLASS_PROPERTY_EMPTY) {
				text.clear() ;
			}

			// 同長の文字列bufferでも元typeをUINT32へ変更した拒否入力です。
			if( activeNative->changed &&
			   activeNative->nativeCase == SignedIndexBindingNativeCase::CLASS_PROPERTY_INVALID) {
				*type = DEVPROP_TYPE_UINT32 ;
			}
		}
		// matching ID要求へ人工Hardware IDを返します。
		else if( sameKey( *key, DEVPKEY_Device_MatchingDeviceId)) {
			text = hardware ;
		}
		// enumerator要求へ人工bus名を返します。
		else if( sameKey( *key, DEVPKEY_Device_EnumeratorName)) {
			text = L"TESTBUS" ;
		}
		// service要求へ固定人工service名を返します。
		else if( sameKey( *key, DEVPKEY_Device_Parent) && child) {
			text = activeNative->nativeCase == SignedIndexBindingNativeCase::REQUIRED_WRONG_PARENT
					   ? L"TESTBUS\\WRONG_PARENT\\FIXTURE"
				   : device->DevInst == 4U &&
						   activeNative->nativeCase !=
							   SignedIndexBindingNativeCase::REQUIRED_CHILD_AMBIGUOUS
					   ? L"TESTBUS\\SYNTH_0002\\FIXTURE"
					   : L"TESTBUS\\SYNTH_0001\\FIXTURE" ;
		}
		// 必要子の現在serviceは他属性の値を借用しません。
		else if( sameKey( *key, DEVPKEY_Device_Service)) {
			text = L"fixture" ;
		}
		// device表示要求へprivacy安全な人工名を返します。
		else if( sameKey( *key, DEVPKEY_Device_FriendlyName) ||
				sameKey( *key, DEVPKEY_Device_DeviceDesc)) {
			text = L"Fixture Device" ;
		} else {
			SetLastError( ERROR_NOT_FOUND) ;
			return FALSE ;
		}

		text.push_back( L'\0') ;
		data  = text.data() ;
		bytes = static_cast<DWORD>( text.size() * sizeof( wchar_t)) ;
	}

	// 必要byte長の出力先がある場合だけ値を返します。
	if( required) {
		*required = bytes ;
	}

	// propertyの二段階照会へ元buffer不足を返します。
	if( !buffer || capacity < bytes) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	std::memcpy( buffer, data, bytes) ;
	SetLastError( ERROR_SUCCESS) ;
	return TRUE ;
}
/** @brief 同fake handleが所有する検索条件をコピーします。
 * @param[in] set 有限fake handleです。
 * @param[in] device ABIで借用するdeviceです。handle別の保存条件を正本にします。
 * @param[out] params 非null出力です。成功時に保存条件全体を設定します。
 * @return 成功時TRUE、不正handleまたは出力欠損時FALSEとERROR_INVALID_HANDLEです。
 */
BOOL WINAPI getParameters( HDEVINFO set, [[maybe_unused]] PSP_DEVINFO_DATA device,
						  PSP_DEVINSTALL_PARAMS_W params)
{
	// 全検索条件を所有するfake handleの有限slot位置。
	const auto i = setIndex( set) ;
	// 無効handleまたは欠損条件出力を拒否します。
	if( !activeNative || i == 32U || !params) {
		SetLastError( ERROR_INVALID_HANDLE) ;
		return FALSE ;
	}

	*params = activeNative->parameters[i] ;
	return TRUE ;
}
/** @brief 同handleの検索条件をSDK cbSize確認後だけ更新します。
 * @param[in] set 有限fake handleです。
 * @param[in] device ABIで借用するdeviceです。handle別の保存条件を正本にします。
 * @param[in] params 同期中借用する非nullかつ正しいcbSizeの条件です。
 * @return 成功時TRUE、不正入力時FALSEとERROR_INVALID_HANDLEで保存値を変更しません。
 */
BOOL WINAPI setParameters( HDEVINFO set, [[maybe_unused]] PSP_DEVINFO_DATA device,
						  PSP_DEVINSTALL_PARAMS_W params)
{
	// 更新対象のfake検索条件の有限slot。失敗時は変更しない。
	const auto i = setIndex( set) ;
	// 無効handleとSDK cbSize不一致の検索条件を拒否します。
	if( !activeNative || i == 32U || !params || params->cbSize != sizeof( *params)) {
		SetLastError( ERROR_INVALID_HANDLE) ;
		return FALSE ;
	}

	activeNative->parameters[i] = *params ;
	// 検証済みsource検索だけを同期中の保護byte差替え試験へ保持します。
	if( params->DriverPath[0] != L'\0' &&
	   std::ranges::find( activeNative->sourceInfs, std::wstring( params->DriverPath)) ==
		   activeNative->sourceInfs.end()) {
		activeNative->sourceInfs.emplace_back( params->DriverPath) ;
	}

	return TRUE ;
}
/** @brief 固定現在版をWindows driver nodeの版数表現へ投影します。
 * @return 同activeNativeの三つの既知現在版に対応する所有数値です。
 * @pre 同workerのactiveNativeが設定済みです。
 */
std::uint64_t packedCurrent() noexcept
{
	return activeNative->currentVersion == L"0.9.0.0"	? 9ULL << 32U
		   : activeNative->currentVersion == L"2.0.0.0" ? 2ULL << 48U
														: 1ULL << 48U ;
}
/** @brief 原検索条件を照合しinstalled-onlyの完全照会回数を保持します。
 * @param[in] set 有限fake handleです。
 * @param[in] device ABIで借用するdeviceです。handle別の条件を検査します。
 * @param[in] type SPDIT_COMPATDRIVERだけを受理します。
 * @return 全条件成立時TRUE、不正typeまたは矛盾したinstalled-only条件時FALSEと元errorです。
 * @pre 同workerのactiveNativeが設定済みです。
 */
BOOL WINAPI buildDrivers( HDEVINFO set, [[maybe_unused]] PSP_DEVINFO_DATA device, DWORD type)
{
	const auto slot = setIndex( set) ;	// 元handleが所有する検索条件の有限位置です。
	// 互換driver構築以外のtypeと無効handleを拒否します。
	if( slot == 32U || type != SPDIT_COMPATDRIVER) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	const auto &parameters = activeNative->parameters[slot] ;	// 同handleへ設定された全条件です。
	// Installed-only証拠はsingle-INF解除と空pathを満たした原callだけへ数えます。
	if( (parameters.FlagsEx & DI_FLAGSEX_INSTALLEDDRIVER) != 0U) {
		// 矛盾する検索条件を空一覧の成功へ変換しません。
		if( (parameters.Flags & DI_ENUMSINGLEINF) != 0U || parameters.DriverPath[0] != L'\0' ||
		   (parameters.FlagsEx & DI_FLAGSEX_ALLOWEXCLUDEDDRVS) == 0U) {
			SetLastError( ERROR_INVALID_PARAMETER) ;
			return FALSE ;
		}

		++activeNative->installedOnlyQueries ;
	}

	// 候補単一INFの一覧構築だけが返却ClassGUIDを更新します。元propertyは変更しません。
	if( parameters.DriverPath[0] != L'\0' && device) {
		device->ClassGuid =
			activeNative->nativeCase == SignedIndexBindingNativeCase::NATIVE_CLASS_MISMATCH
				? NET_CLASS
			: activeNative->network ? NET_CLASS
									: PORTS_CLASS ;
		// 必要roleのnative Classは同実INF byteから返します。
		if( activeNative->requiredRoles) {
			std::array<wchar_t, 128U> name{} ;		// 有限返却名です。
			DWORD					  required{} ;	// NUL込み必要数です。
			// 役割別実INF未確認では成功nodeを生成しません。
			if( !infClass( parameters.DriverPath, &device->ClassGuid, name.data(),
						 static_cast<DWORD>( name.size()), &required)) {
				return FALSE ;
			}
		}
	}

	return TRUE ;
}
/** @brief 原INF検索と現在検索を区別し固定nodeまたは明示的空終端を返します。
 * @param[in] set 保存検索条件を持つ有限fake handleです。
 * @param[in] device ABIで借用するdeviceです。handle別の固定nodeを使用します。
 * @param[in] type SPDIT_COMPATDRIVERだけを受理します。
 * @param[in] index 0だけがnode候補で、後続は正式な空終端です。
 * @param[in,out] driver 非nullかつSDK cbSizeを持つ借用出力です。成功時だけnodeを設定します。
 * @return 成功時TRUE、非適用・空終端・原観測失敗時FALSEとそのWindows errorです。
 */
BOOL WINAPI enumDrivers( HDEVINFO set, [[maybe_unused]] PSP_DEVINFO_DATA device, DWORD type,
						DWORD index, PSP_DRVINFO_DATA_W driver)
{
	// 互換列挙type・driver出力・SDK cbSizeを厳密に照合します。
	if( type != SPDIT_COMPATDRIVER || !driver || driver->cbSize != sizeof( *driver)) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	// 唯一の互換node以降へ正式な列挙終端を返します。
	if( index != 0U) {
		SetLastError( ERROR_NO_MORE_ITEMS) ;
		return FALSE ;
	}

	// 互換nodeを発行する同検索条件の有限位置。
	const auto i = setIndex( set) ;
	// 所有していない検索handleを拒否します。
	if( !activeNative || i == 32U) {
		SetLastError( ERROR_INVALID_HANDLE) ;
		return FALSE ;
	}

	// 指定INF検索なら候補node、空なら現在driver nodeを返す区分。
	const bool candidate = activeNative->parameters[i].DriverPath[0] != L'\0' ;
	const bool updated =
		activeNative->requiredRoles && device && device->DevInst <= 2U &&
		activeNative->deviceInstalls[device->DevInst - 1U] != 0U ;	// 親個別指定API後です。
	// 正式空終端と原installed-only列挙失敗を別入力へ保持します。
	if( !candidate && activeNative->changed &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_ENUMERATION_FAILURE) {
		SetLastError( ERROR_ACCESS_DENIED) ;
		return FALSE ;
	}

	// 明示初回はinstalled-only構築の完全な空終端を必要とします。
	if( !candidate && !updated && (!device || device->DevInst <= 2U) && initialState() &&
	   activeNative->nativeCase != SignedIndexBindingNativeCase::CONTRADICTORY_NODE &&
	   !(activeNative->changed &&
		 activeNative->nativeCase == SignedIndexBindingNativeCase::INITIAL_INSTALLED_NODE)) {
		SetLastError( ERROR_NO_MORE_ITEMS) ;
		return FALSE ;
	}

	// 非適用と観測失敗は別の元Windows結果へ保ちます。
	if( candidate && activeNative->parameters[i].DriverPath[0] != L'\0') {
		const std::wstring path =
			activeNative->parameters[i].DriverPath ;				// このhandleへ指定された原INFです。
		const bool alternate = path.ends_with( L"alternate.inf") ;	// 元第二INFだけの条件です。
		// 選択外importの実元IDはpresent親/必要子に適合しません。
		if( path.ends_with( L"importonly.inf")) {
			SetLastError( ERROR_NO_MORE_ITEMS) ;
			return FALSE ;
		}

		// 元source INFの全非適用だけをinstalled/current検索と区別します。
		if( activeNative->nativeCase == SignedIndexBindingNativeCase::MULTI_ALL_NONAPPLICABLE &&
		   (path.ends_with( L"\\fixture.inf") || path.ends_with( L"\\alternate.inf"))) {
			SetLastError( ERROR_NO_MORE_ITEMS) ;
			return FALSE ;
		}

		// 第二INFの非適用と観測失敗を別の元diagnosticで返します。
		if( alternate &&
		   (activeNative->nativeCase == SignedIndexBindingNativeCase::MULTI_NONAPPLICABLE ||
			activeNative->nativeCase == SignedIndexBindingNativeCase::MULTI_UNKNOWN)) {
			SetLastError( activeNative->nativeCase ==
								 SignedIndexBindingNativeCase::MULTI_NONAPPLICABLE
							 ? ERROR_NO_MORE_ITEMS
							 : ERROR_ACCESS_DENIED) ;
			return FALSE ;
		}
	}

	driver->DriverVersion = candidate || updated ? 1ULL << 48U : packedCurrent() ;
	// 登録nodeが元指定nodeと変わった条件だけを原APIへ返します。
	if( candidate && activeNative->stages != 0U &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::STAGE_WRONG_NODE &&
	   std::wstring_view{activeNative->parameters[i].DriverPath}.starts_with(
		   activeNative->windowsRoot)) {
		driver->DriverVersion = 2ULL << 48U ;
	}

	driver->DriverDate = date( candidate || updated) ;
	wcscpy_s( driver->ProviderName, L"Fixture Vendor") ;
	wcscpy_s( driver->MfgName, L"Fixture Vendor") ;
	wcscpy_s( driver->Description, L"Fixture Device") ;
	driver->Reserved = 1U ;
	return TRUE ;
}
/** @brief 同検索handleの元INFと固定sectionをdetailへ返します。
 * @param[in] set 保存検索条件を持つ有限fake handleです。
 * @param[in] device ABIで借用するdeviceです。同元deviceの基本名選択を返します。
 * @param[in] driver ABIで借用するnodeです。固定detailを返しnativeを呼びません。
 * @param[in,out] detail 借用出力です。nullまたは不足時は書込みません。固定C44はstatic field後FALSEです。
 * @param[in] capacity detailのbyte容量です。
 * @param[out] required null可の必要byte数です。不足時にも返します。
 * @return 完全detail成功TRUE、容量不足/無効handle/固定C44の可変部分不足はFALSEと元診断です。
 */
BOOL WINAPI driverDetail( HDEVINFO set, PSP_DEVINFO_DATA device,
						 [[maybe_unused]] PSP_DRVINFO_DATA_W driver,
						 PSP_DRVINFO_DETAIL_DATA_W detail, DWORD capacity, PDWORD required)
{
	// 固定driver detail全体の必要byte長。
	constexpr DWORD bytes = sizeof( SP_DRVINFO_DETAIL_DATA_W) ;
	// 必要detail byte長の出力先がある場合だけ値を返します。
	if( required) {
		*required = bytes ;
	}

	// detail二段階照会の不足bufferを元errorで返します。
	if( !detail || capacity < bytes) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	// 同検索条件へ結合するINF detailの有限slot。
	const auto i = setIndex( set) ;
	// 無効handleへ人工INF detailを返しません。
	if( !activeNative || i == 32U) {
		SetLastError( ERROR_INVALID_HANDLE) ;
		return FALSE ;
	}

	wcscpy_s( detail->InfFileName, activeNative->parameters[i].DriverPath[0]
									  ? activeNative->parameters[i].DriverPath
									  : L"oemfixture.inf") ;
	wcscpy_s( detail->SectionName, L"Install") ;
	const bool candidate =
		activeNative->parameters[i].DriverPath[0] != L'\0' ;	// 元単一INF照会だけです。
	// 現在driverのdetailを選択節の拒否入力で置き換えません。
	if( candidate) {
		const auto condition = activeNative->nativeCase ;	// 原低位detail条件です。
		// 元nodeの空基本名を解析成功へ補完させません。
		if( condition == SignedIndexBindingNativeCase::SECTION_EMPTY) {
			detail->SectionName[0] = L'\0' ;
		}

		// 元nodeの不正な節文法を渡します。
		if( condition == SignedIndexBindingNativeCase::SECTION_INVALID) {
			wcscpy_s( detail->SectionName, L"Bad/Section") ;
		}

		// 同Modelsにはあるが実節を欠くfallback基本名です。
		if( condition == SignedIndexBindingNativeCase::SECTION_MISSING_FALLBACK) {
			wcscpy_s( detail->SectionName, L"MissingInstall") ;
		}

		// 同filenameの別完全pathへ変更し、basename一致の誤受入を防ぎます。
		if( condition == SignedIndexBindingNativeCase::SECTION_OTHER_INF) {
			wcscpy_s( detail->InfFileName, L"D:\\fictional-other-root\\fixture.inf") ;
		}

		// 元parentだけの別node基本名を返し、必要子のInstallを変更しません。
		if( device && device->DevInst <= 2U &&
		   (condition == SignedIndexBindingNativeCase::SECTION_OTHER_MODEL ||
			(condition == SignedIndexBindingNativeCase::SHARED_SECTION_SUCCESS &&
			 device->DevInst == 2U) ||
			(condition == SignedIndexBindingNativeCase::SECTION_CHANGED &&
			 activeNative->changed))) {
			wcscpy_s( detail->SectionName, L"OtherInstall") ;
		}

		// 装飾済み名をnativeの基本名契約へ誤って返します。
		if( condition == SignedIndexBindingNativeCase::SECTION_DECORATED) {
			wcscpy_s( detail->SectionName, L"Install.NTamd64") ;
		}

		// 別architectureだけの元Models基本名です。
		if( condition == SignedIndexBindingNativeCase::SECTION_OTHER_OS) {
			wcscpy_s( detail->SectionName, L"ForeignOs") ;
		}

		// LINE_LENの終端を失わせ、配列外読取を許可しません。
		if( condition == SignedIndexBindingNativeCase::SECTION_UNTERMINATED) {
			std::fill( std::begin( detail->SectionName), std::end( detail->SectionName), L'X') ;
		}

		// 全static fieldを書込んでも可変IDの不足を元FALSEとして保持します。
		if( condition == SignedIndexBindingNativeCase::SECTION_DETAIL_INCOMPLETE) {
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		// MAX_PATH内NULがない完全path返却を不正detailへ保持します。
		if( condition == SignedIndexBindingNativeCase::SECTION_INF_UNTERMINATED) {
			std::fill( std::begin( detail->InfFileName), std::end( detail->InfFileName), L'X') ;
		}
	}

	return TRUE ;
}
/** @brief 原検索条件に結び付く候補rankと現在rankを別々に返します。
 * @param[in] set 保存検索条件を持つ有限fake handleです。
 * @param[in] device ABIで借用するdeviceです。handleの元検索条件を使用します。
 * @param[in] driver ABIで借用するnodeです。固定rankを返しnativeを呼びません。
 * @param[in,out] params 非nullの借用rank出力です。成功時だけRankを更新します。
 * @return 成功時TRUE、必要rank欠損または無効入力時FALSEと元errorです。
 * @note 同workerだけでcounterを更新し、登録後のrank差を成功へ補完しません。
 */
BOOL WINAPI driverRank( HDEVINFO set, [[maybe_unused]] PSP_DEVINFO_DATA device,
					   [[maybe_unused]] PSP_DRVINFO_DATA_W driver, PSP_DRVINSTALL_PARAMS params)
{
	// Rank観測を記録するfake handleの有限slot。
	const auto i = setIndex( set) ;
	// rank出力の欠損と無効handleを拒否します。
	if( !activeNative || i == 32U || !params) {
		SetLastError( ERROR_INVALID_HANDLE) ;
		return FALSE ;
	}

	++activeNative->rankCalls ;
	// 必要rankの欠損を架空の成功rankへ変換しません。
	if( activeNative->nativeCase == SignedIndexBindingNativeCase::MISSING_RANK &&
	   activeNative->parameters[i].DriverPath[0]) {
		SetLastError( ERROR_NOT_FOUND) ;
		return FALSE ;
	}

	params->Rank = activeNative->parameters[i].DriverPath[0] ? 1U : 0xFFFU ;
	// 登録後だけのrank変化を変更直前guardへ与えます。
	if( activeNative->nativeCase == SignedIndexBindingNativeCase::STAGE_WRONG_RANK &&
	   std::wstring_view{activeNative->parameters[i].DriverPath}.starts_with(
		   activeNative->windowsRoot)) {
		params->Rank = 2U ;
	}

	return TRUE ;
}
/** @brief 固定互換driver一覧の終了条件を照合します。
 * @param[in] set ABIの集合handleです。実Windows一覧を解放しません。
 * @param[in] device ABIで借用するdeviceです。実端末へ触れません。
 * @param[in] type SPDIT_COMPATDRIVERだけを受理します。
 * @return 正しい一覧typeならTRUE、それ以外はFALSEです。
 */
BOOL WINAPI destroyDrivers( [[maybe_unused]] HDEVINFO set, [[maybe_unused]] PSP_DEVINFO_DATA device,
						   DWORD type)
{
	return type == SPDIT_COMPATDRIVER ? TRUE : FALSE ;
}
/** @brief 元INF実byteを隔離登録rootへ一回copyし登録pathを返します。
 * @param[in] source 同期中借用する非null終端付き元INF pathです。
 * @param[in] media nullだけを受理するmedia引数です。
 * @param[in] type SPOST_PATHだけを受理します。
 * @param[in] flags SP_COPY_NOOVERWRITEだけを受理します。
 * @param[out] destination 終端込み登録pathの借用出力です。成功時だけ設定します。
 * @param[in] capacity destinationのwchar_t要素数です。
 * @param[out] required null可の終端込み必要要素数です。成功pathを作成後に設定します。
 * @param[out] component nullだけを受理します。basename pointerを発行しません。
 * @return 完全copyと所有確認時TRUE、それ以外は元Windows errorを持つFALSEです。
 * @note 実Windows INFへ書込みません。失敗前に作成した隔離fileもregistrationが所有します。
 */
BOOL WINAPI stage( PCWSTR source, PCWSTR media, DWORD type, DWORD flags, PWSTR destination,
				  DWORD capacity, PDWORD required, PWSTR *component)
{
	// 必要SYSTEM参照のstage要求は成功/失敗にかかわらず別に数えます。
	if( activeNative && source && std::wstring_view{source}.ends_with( L"\\peer.inf")) {
		++activeNative->dependencySystemStageCalls ;
	}

	// 指定path stageのmedia・type・flags・component条件を厳密照合します。
	if( !activeNative || !source || media || type != SPOST_PATH || flags != SP_COPY_NOOVERWRITE ||
	   component) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	// 呼出しは一度だけ数え、実登録先とは独立の隔離fileを作ります。
	const auto ordinal = activeNative->stages++ ;
	// 先行Extensionのguardがbase stage中にも生存することを実共有規則で確認します。
	if( ordinal == 1U) {
		probeRegisteredExtension() ;
	}

	// 既存stage失敗は元HRESULTのまま返します。
	if( activeNative->stagingFailure ||
	   (activeNative->nativeCase == SignedIndexBindingNativeCase::REQUIRED_STAGE_PARTIAL &&
		ordinal == 1U)) {
		SetLastError( ERROR_ACCESS_DENIED) ;
		return FALSE ;
	}

	// 固定予約を超えるstageを実OSへfallbackしません。
	if( ordinal >= activeNative->stagedPaths.size()) {
		SetLastError( ERROR_NOT_ENOUGH_MEMORY) ;
		return FALSE ;
	}

	const auto name =
		(activeNative->nativeCase == SignedIndexBindingNativeCase::STAGE_EXTERNAL ? L"external\\"
																				  : L"INF\\") +
		std::wstring{L"oem"} + std::to_wstring( 42U + ordinal) + L".inf" ;	// 隔離登録先の有限名です。
	std::wstring registered ;												// このworkspaceが予約した元絶対pathです。
	// 未追跡pathや既存fileを登録先として使いません。
	if( activeNative->registration.prepareExternalFile( name, registered) != 0U ||
	   !CopyFileW( source, registered.c_str(), TRUE)) {
		SetLastError( ERROR_IO_DEVICE) ;
		return FALSE ;
	}

	WIN32_FILE_ATTRIBUTE_DATA attributes{} ;	// 元sourceの実byte長です。
	// 同byte長で所有へ取り込めなければ成功stage値を返しません。
	if( !GetFileAttributesExW( source, GetFileExInfoStandard, &attributes) ||
	   activeNative->registration.adoptFile(
		   name, (static_cast<std::uint64_t>( attributes.nFileSizeHigh) << 32U) |
					 attributes.nFileSizeLow) != 0U) {
		SetLastError( ERROR_IO_DEVICE) ;
		return FALSE ;
	}

	// 内容差条件だけは返却前の隔離fileへ実byte差を作ります。
	if( activeNative->nativeCase == SignedIndexBindingNativeCase::STAGE_CHANGED) {
		const HANDLE changed =
			CreateFileW( registered.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
						0U, nullptr) ;	// 隔離fileだけの変更handleです。
		DWORD	   written{} ;			// 同fixture fileへの一byte書込数です。
		const char byte = 'X' ;			// 元INFの全hashとsizeを変える有限差です。
		// 書込handleを作れない場合も成功へ補完しません。
		if( changed == INVALID_HANDLE_VALUE) {
			return FALSE ;
		}

		SetFilePointer( changed, 0L, nullptr, FILE_END) ;
		const bool wrote = WriteFile( changed, &byte, 1U, &written, nullptr) != FALSE &&
						   // 意図した原byte差の作成結果です。
						   written == 1U ;
		CloseHandle( changed) ;
		// 意図した内容差を作れなければfixture自身の失敗として拒否します。
		if( !wrote) {
			SetLastError( ERROR_IO_DEVICE) ;
			return FALSE ;
		}
	}

	const auto length = registered.size() + 1U ;	// 実返却pathの終端込み要素数です。
	// 保護stage先bufferの必要長を満たさなければ拒否します。
	if( length >= MAX_PATH || !destination || capacity < length) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	wcscpy_s( destination, capacity, registered.c_str()) ;
	// 必要stage先長の出力先がある場合だけ値を返します。
	if( required) {
		*required = static_cast<DWORD>(
			length +
			(activeNative->nativeCase == SignedIndexBindingNativeCase::STAGE_BAD_LENGTH ? 1U : 0U)) ;
	}

	wcscpy_s( activeNative->stagedPaths[ordinal].data(), MAX_PATH, registered.c_str()) ;

	return TRUE ;
}
/** @brief 元登録pathと完全指定nodeの一致時だけfake導入を一度記録します。
 * @param[in] parent ABIの親Windowです。画面を作成しません。
 * @param[in] set 元検索条件を持つ有限fake handleです。
 * @param[in] device 非nullの選択済み人工deviceです。
 * @param[in] driver 非nullの完全指定nodeです。元登録path・版・provider・予約値へ照合します。
 * @param[in] flags 0だけを受理します。
 * @param[out] reboot 非null出力です。実行した人工対象の結果だけを設定します。
 * @return 固定導入成功時TRUE、不正bindingまたは原導入失敗時FALSEと元errorです。
 * @note 実DiInstallDeviceを呼びません。個別実行回数と元部分失敗を同workerに保持します。
 */
BOOL WINAPI install( [[maybe_unused]] HWND parent, HDEVINFO set, PSP_DEVINFO_DATA device,
					PSP_DRVINFO_DATA_W driver, DWORD flags, PBOOL reboot)
{
	// 指定driver・flags・再起動出力の欠損を拒否します。
	if( !activeNative || !driver || !device || flags != 0U || !reboot) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	const auto slot	 = setIndex( set) ;			// 同指定driver検索条件を所有する有限slotです。
	const bool child = device->DevInst >= 3U ;	// 元必要SWCだけです。
	const bool bindingMatches =
		slot < 32U && device->DevInst >= 1U && device->DevInst <= 4U &&
		(child ? activeNative->componentChild &&
					 activeNative->childInstalls[device->DevInst - 3U] == 0U
			   : activeNative->deviceInstalls[device->DevInst - 1U] == 0U) &&
		std::ranges::any_of(
			activeNative->stagedPaths,
			[&]( const auto &path) {
				return !path.empty() && path.front() != L'\0' &&
					   std::wstring_view{activeNative->parameters[slot].DriverPath} == path.data() ;
			}) &&
		driver->cbSize == sizeof( *driver) && driver->DriverVersion == (1ULL << 48U) &&
		std::wstring_view{driver->ProviderName} == L"Fixture Vendor" &&
		// 元nodeの完全指定です。
		driver->Reserved == 1U ;
	activeNative->specifiedBindingMatches &= bindingMatches ;
	// 未登録pathや別nodeを指定するcallは固定成功fakeでも拒否します。
	if( !bindingMatches) {
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	// 指定APIを呼ぶ時点まで同登録byteを固定する契約です。
	probeRegisteredExtension() ;
	++activeNative->installs ;
	// Baseと必要子を役割別に一回だけ記録します。
	if( child) {
		++activeNative->childInstalls[device->DevInst - 3U] ;
	} else {
		++activeNative->deviceInstalls[device->DevInst - 1U] ;
	}

	*reboot = activeNative->mode == 4U || (activeNative->multiple && device->DevInst == 1U) ? TRUE
																							: FALSE ;
	// FALSEの欠落診断を0の成功へ上げない追加C31の低位入力です。
	if( !child &&
	   activeNative->nativeCase == SignedIndexBindingNativeCase::REQUIRED_BASE_DIAGNOSTIC_MISSING) {
		SetLastError( ERROR_SUCCESS) ;
		return FALSE ;
	}

	// 既存拒否の元ERROR_ACCESS_DENIEDを欠落診断と混同しません。
	if( activeNative->mode == 3U || (activeNative->partialFailure && device->DevInst == 2U) ||
	   (child &&
		activeNative->nativeCase == SignedIndexBindingNativeCase::REQUIRED_CHILD_FAILURE) ||
	   (!child &&
		activeNative->nativeCase == SignedIndexBindingNativeCase::REQUIRED_BASE_FAILURE)) {
		SetLastError( ERROR_ACCESS_DENIED) ;
		return FALSE ;
	}

	return TRUE ;
}
/** @brief 有限fixtureのx64 native architectureを返します。
 * @param[out] system 非nullの借用SYSTEM_INFOです。内容を初期化しAMD64だけを設定します。
 * @pre systemは呼出し側が同期中所有する有効出力です。
 */
void WINAPI architecture( LPSYSTEM_INFO system)
{
	*system						   = {} ;
	system->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64 ;
}
/** @brief 実Windows directoryへfallbackせず隔離rootの完全値を返します。
 * @param[out] buffer 所有rootの終端付き出力です。
 * @param[in] capacity wchar_t要素数です。
 * @return 成功時は終端を除く長さ、buffer不足時は必要長です。
 */
UINT WINAPI windowsDirectory( LPWSTR buffer, UINT capacity)
{
	// Workerへ固定した完全rootがなければnativeを呼びません。
	if( !activeNative || activeNative->windowsRoot.empty()) {
		SetLastError( ERROR_INVALID_DATA) ;
		return 0U ;
	}

	const auto length =
		// 有限workspaceの長さです。
		static_cast<UINT>( activeNative->windowsRoot.size()) ;
	// 元Windows APIの不足buffer契約を保持します。
	if( !buffer || capacity <= length) {
		return length + 1U ;
	}

	wcscpy_s( buffer, capacity, activeNative->windowsRoot.c_str()) ;
	return length ;
}
/** @brief 同検査rootの実INF byteへClass名/GUID返却を結合します。
 * @see infClass(PCWSTR,LPGUID,PWSTR,DWORD,PDWORD)
 * @note 読取は1MiB以下の隔離fileだけで、native SetupAPIを呼ばず本体の判断は生成しません。
 */
BOOL WINAPI infClass( PCWSTR path, LPGUID guid, PWSTR name, DWORD capacity, PDWORD required)
{
	// 任意成功DTOを受けず、同scopeの実INF fileと完全出力を要求します。
	if( !activeNative || !path || !guid || !name || !required) {
		SetLastError( ERROR_INVALID_PARAMETER) ;
		return FALSE ;
	}

	std::ifstream input{std::filesystem::path{path},
						std::ios::binary | std::ios::ate} ;	// 同検査rootの実byteです。
	const auto	  length = input.tellg() ;					// 確保前に有限長を確認します。
	// 固定fixtureの実byteを読めない場合はnative成功で補完しません。
	if( !input || length <= 0 || length > 1024 * 1024) {
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	std::string bytes( static_cast<std::size_t>( length), '\0') ;	// 上限確認済みの原INFです。
	input.seekg( 0) ;
	input.read( bytes.data(), static_cast<std::streamsize>( bytes.size())) ;
	const bool network =
		// 元INF directiveだけです。
		bytes.find( "\nClass=Net\r\n") != std::string::npos ;
	const bool ports =
		// 元INF directiveだけです。
		bytes.find( "\nClass=Ports\r\n") != std::string::npos ;
	const bool extension =
		// 元役割Classの厳密行です。
		bytes.find( "\nClass=Extension\r\n") != std::string::npos ;
	const bool component = bytes.find( "\nClass=SoftwareComponent\r\n") !=
						   std::string::npos ;	// 元SWC Classの厳密行です。
	const std::string_view expectedGuid =
		extension	? "ClassGuid={e2f84ce7-8efa-411c-aa69-97454ca4cb57}\r\n"
		: component ? "ClassGuid={5c4c3332-344d-483c-8739-259e934c9cc8}\r\n"
		: network
			? "ClassGuid={4d36e972-e325-11ce-bfc1-08002be10318}\r\n"
			: "ClassGuid={4d36e978-e325-11ce-bfc1-08002be10318}\r\n" ;	// 固定実INFの完全GUIDです。
	// 間違ったraw Class/GUIDや部分読取をClass成功へ補完しません。
	if( !input ||
	   static_cast<unsigned>( network) + static_cast<unsigned>( ports) +
			   static_cast<unsigned>( extension) + static_cast<unsigned>( component) !=
		   1U ||
	   bytes.find( expectedGuid) == std::string::npos) {
		SetLastError( ERROR_INVALID_DATA) ;
		return FALSE ;
	}

	const std::wstring_view value =
		extension	? L"Extension"
		: component ? L"SoftwareComponent"
		: activeNative->nativeCase == SignedIndexBindingNativeCase::INF_CLASS_MISMATCH ? L"Net"
		: network																	   ? L"Net"
				  : L"Ports" ;	// Class不一致は原API返却だけを変更します。
	*required = static_cast<DWORD>( value.size() + 1U) ;
	// 出力不足を切詰めたClass名へ変換しません。
	if( capacity < *required) {
		SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
		return FALSE ;
	}

	*guid = extension	? EXTENSION_CLASS
			: component ? COMPONENT_CLASS
			: network	? NET_CLASS
						: PORTS_CLASS ;
	std::copy( value.begin(), value.end(), name) ;
	name[value.size()] = L'\0' ;
	return TRUE ;
}

/** @brief 全低位呼出しを同worker限定fixtureへ固定した完全tableを返します。
 * @return Native fallbackを含まない借用callback tableの所有コピーです。
 * @note 各callbackはScopedFixtureの有効期間に同workerのactiveNativeだけを借用します。
 */
driver_store_inf_detail::Transport calls()
{
	return {.inventory		  = {openInventory, enumInventory, property, instanceId, closeInventory,
								 nodeStatus},
			.create			  = createInventory,
			.open			  = openDevice,
			.build			  = buildDrivers,
			.enumerate		  = enumDrivers,
			.detail			  = driverDetail,
			.getParameters	  = getParameters,
			.setParameters	  = setParameters,
			.rank			  = driverRank,
			.destroyDrivers	  = destroyDrivers,
			.stage			  = stage,
			.install		  = install,
			.architecture	  = architecture,
			.windowsDirectory = windowsDirectory,
			.infClass		  = infClass} ;
}
/** @brief Windows復旧APIを呼ばず既存保護契約へ結果を返します。 */
class FakeRestore final : public IRestorePointService {
public:
	/** @brief 復旧開始の固定成功または元失敗だけを返します。
	 * @param[in] description 同期中借用する操作説明です。保存せず実復旧APIを呼びません。
	 * @return 固定sequence42の成功、または元E_ACCESSDENIEDの失敗です。
	 */
	RestorePointOperationResult begin(
		[[maybe_unused]] std::wstring_view description) noexcept override
	{
		// 同workerの固定復旧境界だけを観測し、実System Restoreへfallbackしません。
		if( activeNative) {
			// 制御した遅延を実復旧APIへ渡さず、例外時もworker境界を越えません。
			if( activeNative->beforeRestore) {
				try {
					activeNative->beforeRestore() ;
				} catch( ...) {
					return {OutcomeCode::FAILURE, static_cast<NativeError>( E_UNEXPECTED), 0} ;
				}
			}

			++activeNative->restoreBegins ;
			// 復旧開始失敗は元HRESULTを返してProvider導入を止めます。
			if( activeNative->restoreFailure) {
				return {OutcomeCode::FAILURE, static_cast<NativeError>( E_ACCESSDENIED), 0} ;
			}
		}

		return {OutcomeCode::SUCCESS, 0U, 42} ;
	}
	/** @brief 開始済みfake sequenceの終了通知と元終了失敗を保持します。
	 * @param[in] sequence 元開始が返したsequenceです。
	 * @return 同sequenceの成功、または同sequenceを保持する元E_ACCESSDENIEDの失敗です。
	 */
	RestorePointOperationResult complete( std::int64_t sequence) noexcept override
	{
		// 開始したfake復旧だけの終了通知回数を保持します。
		if( activeNative) {
			++activeNative->restoreCompletes ;
			// 完了失敗は導入個別結果を消さずcontrollerへ元診断を返します。
			if( activeNative->nativeCase == SignedIndexBindingNativeCase::RESTORE_END_FAILURE ||
			   activeNative->nativeCase ==
				   SignedIndexBindingNativeCase::INITIAL_RESTORE_END_FAILURE) {
				return {OutcomeCode::FAILURE, static_cast<NativeError>( E_ACCESSDENIED), sequence} ;
			}
		}

		return {OutcomeCode::SUCCESS, 0U, sequence} ;
	}
} ;
/** @brief 最大五秒の協調待機で要求operationの実worker eventを取り出します。
 * @param[in,out] worker 同期待機中生存するworkerです。queueを順に消費します。
 * @param[in] kind 待機するevent種別です。
 * @param[in] operation 元要求operationです。
 * @return 一致したeventの所有値、期限時はnulloptです。
 * @note workerのUI側threadで使用し、mutexを保持して待ちません。
 */
std::optional<WorkerEvent> waitEvent( ProviderWorker &worker, WorkerEventKind kind,
									 OperationId operation)
{
	// 一eventの到着を待つ単調時計の協調期限。上限5秒。
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5} ;
	// 有限期限まで同workerの実event到着を待ちます。
	while( std::chrono::steady_clock::now() < deadline) {
		// 取り出した実eventを順番に確認します。
		for( auto &event : worker.takeEvents()) {
			// 要求kindとoperationが完全一致したeventだけを返します。
			if( event.kind == kind && event.operationId == operation) {
				return std::move( event) ;
			}
		}

		std::this_thread::sleep_for( std::chrono::milliseconds{2}) ;
	}

	return std::nullopt ;
}
/** @brief 元ZIPの全member実byteから完全署名fixture期待値を作ります。
 * @param[in] zip 同期解析中生存する人工ZIP全byteの借用viewです。
 * @return 各元INF/CAT/member名と実SHA-256を所有する集合です。
 * @throws std::runtime_error 元ZIP・member・hash計算を確認できない場合です。
 * @note 展開したheapは各反復で解放し、実署名や実端末の合格を発行しません。
 */
std::vector<driver_package_signature_detail::FixtureFile> signatureFiles( std::string_view zip)
{
	mz_zip_archive archive{} ;
	// 非空ZIPを解析できなければ正常member証拠を作りません。
	if( !mz_zip_reader_init_mem( &archive, zip.data(), zip.size(), 0U)) {
		throw std::runtime_error( "fixture ZIP invalid") ;
	}

	// 全原memberの名前と実SHA-256を所有する固定期待値集合。
	std::vector<driver_package_signature_detail::FixtureFile> result ;
	// 固定INF・SYS・CATの全実member hashを採取します。
	for( mz_uint index = 0U; index < mz_zip_reader_get_num_files( &archive); ++index) {
		mz_zip_archive_file_stat stat{} ;	// 原ZIPのexact member名です。
		// 未知memberを署名成功表へ取り込まず完全なdriver閉包だけを固定します。
		if( !mz_zip_reader_file_stat( &archive, index, &stat) || stat.m_is_directory) {
			mz_zip_reader_end( &archive) ;
			throw std::runtime_error( "fixture member invalid") ;
		}

		const auto *name = stat.m_filename ;	// 同原containerで固定した名前です。
		// 展開した現在memberのbyte数。
		std::size_t bytes{} ;
		void	   *raw = mz_zip_reader_extract_file_to_heap( &archive, name, &bytes, 0U) ;
		// 欠損member時はZIPを解放してfixtureを拒否します。
		if( !raw) {
			mz_zip_reader_end( &archive) ;
			throw std::runtime_error( "fixture member missing") ;
		}

		// 同反復の展開byteをmz_freeで解放する単独所有者。
		const std::unique_ptr<void, decltype( &mz_free)> owner{raw, &mz_free} ;
		// CNGで計算する同memberのSHA-256出力。
		std::wstring									hash ;
		// 実member全byteを署名fixtureの固定期待hashへ結ぶ計算結果。
		const auto										error =
			computeBytesSha256( std::string_view{static_cast<const char *>( raw), bytes}, hash) ;
		// 実member hash失敗を署名成功fixtureへ換算しません。
		if( error != 0U) {
			mz_zip_reader_end( &archive) ;
			throw std::runtime_error( "fixture member hash failure") ;
		}

		// 固定ASCII member名を所有するWindows文字列。
		std::wstring wide ;
		// 固定ASCII member名をlosslessにWindows名へ変換します。
		for( const char character : std::string_view{name}) {
			wide.push_back( static_cast<wchar_t>( character)) ;
		}

		std::replace( wide.begin(), wide.end(), L'/',
					 L'\\') ;	// 実ZIP位置を既存workspaceと同じ区切りへ保持します。

		const auto dot = wide.find_last_of( L'.') ;	// 各完全閉包のbasename境界です。
		const auto ownerName =
			// EXEは同原サービスINFの固定ownerで、basenameから別INFを生成しません。
			wide == L"component_service.exe" || wide == L"extra.exe" ||
					wide == L"service_bin\\component_service.exe" ||
					wide == L"service_bin\\amd64\\component_service.exe" ||
					wide == L"source_bin\\component_service.exe" ||
					wide == L"service_bin\\extra.exe" || wide == L"media\\component_service.exe" ||
					wide == L"media\\service_bin\\component_service.exe" ||
					wide == L"media\\amd64\\service_bin\\nested\\component_service.exe" ||
					wide == L"media\\source_bin\\component_service.exe" ||
					wide == L"media2\\component_service.exe" || wide == L"media\\extra.exe" ||
					wide == L"other_media\\component_service.exe"
				? std::wstring{L"component.inf"}
				: wide.substr( 0U, dot) + L".inf" ;
		result.push_back( {std::move( wide), std::move( hash), ownerName}) ;
	}

	mz_zip_reader_end( &archive) ;
	return result ;
}
}
// tests/unit/signed_index_candidate_binding_tests.hの同宣言を契約の正本とする。
SignedIndexBindingWorker makeSignedIndexBindingWorker(
	provider_worker_index_detail::Services services, const std::string_view zip, const bool partial,
	const bool restoreFailure, const bool stagingFailure,
	const SignedIndexBindingNativeCase nativeCase, const std::string_view installerPayload,
	std::function<void()> observeWorkerStart, std::function<void()> beforeRestore)
{
	auto native = std::make_shared<NativeFixtureState>() ;	// 同worker低位状態の共有所有です。
	native->beforeRestore = std::move( beforeRestore) ;
	native->requiredRoles = zip.find( "extension.inf") != std::string_view::npos ||
							zip.find( "component.inf") != std::string_view::npos ;
	native->componentChild = zip.find( "component.inf") != std::string_view::npos ;
	native->multiple	   = partial ||
					   nativeCase == SignedIndexBindingNativeCase::INDEX_VERIFIED_PARTIAL ||
					   nativeCase == SignedIndexBindingNativeCase::INDEX_NON_UNIQUE ;
	native->partialFailure = partial &&
							 nativeCase != SignedIndexBindingNativeCase::SHARED_SUCCESS &&
							 nativeCase != SignedIndexBindingNativeCase::SHARED_SECTION_SUCCESS ;
	native->nativeCase	   = nativeCase ;
	native->restoreFailure = restoreFailure ;
	native->stagingFailure = stagingFailure ;
	// 同版の既導入baseでも明示指定導入のcallを別観測します。
	if( nativeCase == SignedIndexBindingNativeCase::EXTENSION_BASE_ALREADY_CURRENT) {
		native->currentVersion = L"1.0.0.0" ;
	}

	// 元通常publicationの同版分類を、DTO変更なしで原Windows現在観測へ結びます。
	if( nativeCase == SignedIndexBindingNativeCase::NORMAL_SAME_VERSION) {
		native->currentVersion = L"1.0.0.0" ;
	}

	auto	   files = signatureFiles( zip) ;	// 全原memberを同じ実byte期待値へ固定します。
	const bool missingImportCatalog =
		// 固定欠損CAT負例だけを完全低位期待表へ通します。
		std::ranges::any_of( files,
							[]( const auto &file) { return file.name == L"importonly.inf" ; }) &&
		!std::ranges::any_of( files,
							 []( const auto &file) { return file.name == L"importonly.cat" ; }) ;
	// 実CATを生成せず、製品が実file欠損を拒否する完全API表を作ります。
	if( missingImportCatalog) {
		const auto catalog = std::ranges::find_if( files, []( const auto &file) {
			return file.name == L"fixture.cat" ;
		}) ; // 同一人工CAT byteです。
		// 既知の元CAT期待値がない表を正常fixtureへ補完しません。
		if( catalog == files.end()) {
			throw std::runtime_error( "Missing catalog fixture expectation unavailable") ;
		}

		files.push_back( {L"importonly.cat", catalog->sha256, L"importonly.inf"}) ;
	}

	const bool missingComponentCatalog =	// 新C87の実欠損を期待表だけへ通します。
		std::ranges::any_of( files,
							[]( const auto &file) { return file.name == L"component.inf" ; }) &&
		!std::ranges::any_of( files, []( const auto &file) { return file.name == L"component.cat" ; }) ;
	// 元CAT byteを生成せず、製品の実FILE_NOT_FOUND拒否まで完全API表を開始します。
	if( missingComponentCatalog) {
		const auto catalog = std::ranges::find_if( files, []( const auto &file) {
			return file.name == L"fixture.cat" ;
		}) ; // 元人工CATの期待hashです。
		// 期待値のない欠損表を成功fixtureへ補完しません。
		if( catalog == files.end()) {
			throw std::runtime_error( "Missing component catalog expectation unavailable") ;
		}

		files.push_back( {L"component.cat", catalog->sha256, L"component.inf"}) ;
	}

	// 原サービスEXE全byteを維持し、署名低位の一期待値だけを拒否条件にします。
	if( nativeCase == SignedIndexBindingNativeCase::SERVICE_EXE_MEMBER_FAILURE ||
	   nativeCase == SignedIndexBindingNativeCase::SERVICE_EXE_OTHER_OWNER) {
		// 全元memberのうちサービスEXEだけを変更し、他ownerの期待値を保存します。
		for( auto &file : files) {
			// 原EXE名の完全一致だけを拒否入力へ与えます。
			if( file.name == L"component_service.exe" ||
			   file.name == L"service_bin\\component_service.exe" ||
			   file.name == L"media\\component_service.exe") {
				// CAT memberの所有者拒否と実hash拒否を独立の元条件にします。
				if( nativeCase == SignedIndexBindingNativeCase::SERVICE_EXE_OTHER_OWNER) {
					file.infOwner = L"fixture.inf" ;
				} else {
					file.sha256.front() = file.sha256.front() == L'0' ? L'1' : L'0' ;
				}
			}
		}
	}

	// 一つのCAT期待hash差だけを署名低位表へ入れ、実CAB byteと元payload hashを保持します。
	if( nativeCase == SignedIndexBindingNativeCase::CAB_MEMBER_FAILURE) {
		// 元閉包のCATだけを識別し、他のINF/SYS期待値を変更しません。
		for( auto &file : files) {
			// 実hashとの差を必ず一hex文字だけに固定します。
			if( file.name.ends_with( L".cat") && !file.sha256.empty()) {
				file.sha256.front() = file.sha256.front() == L'0' ? L'1' : L'0' ;
			}
		}
	}

	// 選択外import一ownerのCAT失敗もbase閉包全体の拒否へ残します。
	if( nativeCase == SignedIndexBindingNativeCase::IMPORT_MEMBER_FAILURE) {
		// 元import-only CATの期待hashだけを変更し、原payloadを不変更で保持します。
		for( auto &file : files) {
			// 別ownerの成功で未選択CAT失敗を隠しません。
			if( file.name == L"importonly.cat" && !file.sha256.empty()) {
				file.sha256.front() = file.sha256.front() == L'0' ? L'1' : L'0' ;
			}
		}
	}

	auto signature = std::make_shared<driver_package_signature_detail::ScopedFixture *>(
		nullptr) ;	// 停止前だけ借用します。
	/** @brief 同worker threadの完全な人工Driver Store表を開始します。
	 * @return 登録rootが生成できた完全scope。失敗時は空でnativeへ補完しません。
	 */
	services.driverStoreFixture = [native]() {
		activeNative = native.get() ;
		// 完全rootを生成できなければ不完全fakeを製品へ渡しません。
		if( !initializeRegistration( *native)) {
			return std::unique_ptr<driver_store_inf_detail::ScopedFixture>{} ;
		}

		return driver_store_inf_detail::Access::create( calls()) ;
	} ; // 一workerの同threadに完全な低位呼出し表を固定します。
	/** @brief 全原member hashへ結合したCAT検証scopeを開始します。
	 * @return Worker終端まで所有する完全scopeです。観測pointerは同threadだけで借用します。
	 */
	services.signatureFixture = [files, signature, partial,
								 observeWorkerStart = std::move( observeWorkerStart)]() {
		// 空でない内部観測だけを同workerへ登録し、元署名scopeの検証結果は変更しません。
		if( observeWorkerStart) {
			observeWorkerStart() ;
		}

		auto scope = driver_package_signature_detail::Access::create(
			files, 129U) ;	// 共通archive128上限の超過一件も完全閉包として検証します。
		*signature = scope.get() ;
		return scope ;
	} ; // 二recordでは二保護rootを実hashへ固定します。
	/** @brief 既存byteと同worker署名表に完全五APIを結びます。
	 * @return 実OS trustへfallbackしない所有scopeです。
	 */
	services.dependencyFixture = [native]() {
		inf_dependency_native_detail::Api api ;	// 必須五APIを全て所有します。
		// 同隔離Windows起点と対応Storeへ同byteで固定する人工SYSTEM INFです。
		const std::string				  systemInf =
			"[Version]\r\nSignature=\"$WINDOWS NT$\"\r\nClass=System\r\n"
			"ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}\r\n"
			"Provider=Fixture\r\nDriverVer=01/01/2026,1.0.0.0\r\nCatalogFile=peer.cat\r\n"
			"[Shared]\r\nCopyFiles=@dep.sys\r\n[DestinationDirs]\r\nDefaultDestDir=12\r\n"
			"[SourceDisksNames]\r\n1=Fixture\r\n[SourceDisksFiles]\r\ndep.sys=1\r\n" ;
		const auto storeRelative =
			L"System32\\DriverStore\\FileRepository\\fixture\\peer.inf" ;	// 明示対応Storeです。
		const auto catalogRelative =
			L"System32\\CatRoot\\fixture\\peer.cat" ;					// 同署名CATの固定位置です。
		std::vector<std::pair<std::wstring, std::wstring>> expected ;	// 実fileの元全hashです。
		const auto write = [&]( const std::wstring &relative, std::string_view bytes) {
			HANDLE handle = INVALID_HANDLE_VALUE ;	// 隔離workspaceの単独所有fileです。
			// 実OSのWindows配下へ書込みません。
			if( native->registration.createFile( relative, handle) != 0) {
				return false ;
			}

			DWORD	   written{} ;	// 完全な小さい人工byteだけです。
			const bool ok = WriteFile( handle, bytes.data(), static_cast<DWORD>( bytes.size()),
									  &written, nullptr) != FALSE ;	// 全byteの実書込みです。
			CloseHandle( handle) ;
			std::wstring hash ;											// 原byteへ結合します。
			const auto	 path = native->registration.path( relative) ;	// 同隔離所有者の完全pathです。
			// 部分取得を期待値へ昇格しません。
			if( !ok || written != bytes.size() || computeFileSha256( path, hash) != 0) {
				return false ;
			}

			expected.emplace_back( path, std::move( hash)) ;
			return true ;
		} ; // scope作成前に全人工fileを固定します。
		// 全fixtureを隔離所有し、SYSTEM既提供と対応Storeを別fileとして検査します。
		if( !write( L"INF\\peer.inf", systemInf) || !write( storeRelative, systemInf) ||
		   !write( catalogRelative, "fixture-catalog") ||
		   !write( L"System32\\DriverStore\\FileRepository\\fixture\\dep.sys",
				  "fixture-system-payload") ||
		   !write( L"System32\\drivers\\dep.sys",
				  native->nativeCase == SignedIndexBindingNativeCase::DEPENDENCY_PAYLOAD_CHANGED
					  ? "changed-system-payload"
					  : "fixture-system-payload")) {
			return std::unique_ptr<inf_dependency_native_detail::ScopedFixture>{} ;
		}

		// 同名二観測を先頭へ絞らせない追加入力です。
		if( native->nativeCase == SignedIndexBindingNativeCase::DEPENDENCY_AMBIGUOUS &&
		   !write( L"System32\\peer.inf", systemInf)) {
			return std::unique_ptr<inf_dependency_native_detail::ScopedFixture>{} ;
		}

		auto versions = std::make_shared<std::size_t>( 0U) ;	// 同runの開始終了を観測します。
		api.version	  = [native, versions]( OSVERSIONINFOEXW &version, SYSTEM_INFO &system) {
			  ++native->dependencyVersionCalls ;
			  // 未観測を成功文脈へ補正しません。
			  if( native->nativeCase == SignedIndexBindingNativeCase::DEPENDENCY_NOT_OBSERVED) {
				  return static_cast<NativeError>( E_FAIL) ;
			  }

			  using Query	   = LONG( WINAPI *)( OSVERSIONINFOEXW *) ;	// 公式ABIのread-only境界です。
			  const auto query = reinterpret_cast<Query>( GetProcAddress(
				  // 読取専用の公式ABIです。
				  GetModuleHandleW( L"ntdll.dll"), "RtlGetVersion")) ;
			  // OS情報の読取以外のinventoryを実行しません。
			  if( query == nullptr || query( &version) != 0) {
				  return static_cast<NativeError>( E_FAIL) ;
			  }

			  GetNativeSystemInfo( &system) ;
			  const auto observation = ++*versions ;	// 同runの文脈観測順です。
			  // 終了時文脈差を元のOS成功で隠させません。
			  if( observation > 1U) {
				  // OS build差をarchitecture差と独立に固定します。
				  if( native->nativeCase == SignedIndexBindingNativeCase::DEPENDENCY_CONTEXT_CHANGED) {
					  ++version.dwBuildNumber ;
				  }

				  // 元native architectureだけを終了時に変えます。
				  if( native->nativeCase ==
					 SignedIndexBindingNativeCase::DEPENDENCY_ARCHITECTURE_CHANGED) {
					  system.wProcessorArchitecture = PROCESSOR_ARCHITECTURE_ARM64 ;
				  }

				  // 同OS buildのclient/serverだけを変えます。
				  if( native->nativeCase == SignedIndexBindingNativeCase::DEPENDENCY_SERVER_CHANGED) {
					  version.wProductType = version.wProductType == VER_NT_WORKSTATION
												 ? VER_NT_SERVER
												 : VER_NT_WORKSTATION ;
				  }

				  // 同architectureとbuildを保持してOS minorだけを変えます。
				  if( native->nativeCase == SignedIndexBindingNativeCase::DEPENDENCY_OS_CHANGED) {
					  ++version.dwMinorVersion ;
				  }
			  }

			  return static_cast<NativeError>( 0) ;
		} ; // OS照会だけの原文脈を保持します。
		api.windowsDirectory = [native]( std::wstring &path) {
			++native->dependencyWindowsDirectoryCalls ;
			path = native->windowsRoot ;
			return static_cast<NativeError>( 0) ;
		} ; // 起点は同隔離所有者だけです。
		api.infSignature = [native, catalogRelative]( const std::wstring	  &path,
													 SP_INF_SIGNER_INFO_W &signer) {
			++native->dependencyInfCalls ;
			// 同元rootへの終了照会を、別INF署名の回数から推測しません。
			if( path.ends_with( L"\\fixture.inf")) {
				++native->dependencyRootSignerCalls ;
			}

			// 同閉包PACKAGE必要INFへ到達した元署名callだけを数えます。
			if( !path.starts_with( native->windowsRoot) && path.ends_with( L"\\component.inf")) {
				++native->dependencyPackageObservations ;
			}

			// SYSTEMの人工署名は元隔離位置だけです。
			if( path.starts_with( native->windowsRoot)) {
				// 署名拒否をOriginだけで救済させません。
				if( native->nativeCase ==
				   SignedIndexBindingNativeCase::DEPENDENCY_SIGNATURE_REJECTED) {
					return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
				}

				wcscpy_s( signer.CatalogFile, native->registration.path( catalogRelative).c_str()) ;
				wcscpy_s( signer.DigitalSigner, L"Microsoft Windows fixture") ;
				signer.SignerScore = SIGNERSCORE_INBOX ;
				return static_cast<NativeError>( 0) ;
			}

			const bool succeeded =
				driver_package_signature_detail::setupVerifyInf( path.c_str(), nullptr, &signer) !=
				FALSE ;	// 同元APIの応答です。
			// 元byte/CATを変更せず、低位署名応答の全非NULだけを再現します。
			if( succeeded &&
			   (native->nativeCase ==
					SignedIndexBindingNativeCase::DEPENDENCY_SIGNER_UNTERMINATED ||
				(native->nativeCase ==
					 SignedIndexBindingNativeCase::DEPENDENCY_SIGNER_RECHECK_UNTERMINATED &&
				 native->dependencyRootSignerCalls > 1U && path.ends_with( L"\\fixture.inf")))) {
				std::ranges::fill( signer.CatalogFile, L'X') ;
				std::ranges::fill( signer.DigitalSigner, L'X') ;
			}

			// 非空CATから署名者の存在を推測させません。
			if( succeeded &&
			   (native->nativeCase == SignedIndexBindingNativeCase::DEPENDENCY_SIGNER_EMPTY ||
				(native->nativeCase ==
					 SignedIndexBindingNativeCase::DEPENDENCY_SIGNER_RECHECK_EMPTY &&
				 native->dependencyRootSignerCalls > 1U && path.ends_with( L"\\fixture.inf")))) {
				signer.DigitalSigner[0] = L'\0' ;
			}

			native->dependencySignerMask =
				(signer.CatalogFile[MAX_PATH - 1U] == L'\0' ? 1U : 0U) |
				(signer.DigitalSigner[MAX_PATH - 1U] == L'\0' ? 2U : 0U) |
				(signer.CatalogFile[0] != L'\0' ? 4U : 0U) |
				(signer.DigitalSigner[0] != L'\0' ? 8U : 0U) ;
			native->dependencySignerResponsesValid &=
				!succeeded || (std::wstring_view{signer.CatalogFile, MAX_PATH}.find( L'\0') !=
								   std::wstring_view::npos &&
							   std::wstring_view{signer.DigitalSigner, MAX_PATH}.find( L'\0') !=
								   std::wstring_view::npos &&
							   signer.CatalogFile[0] != L'\0' && signer.DigitalSigner[0] != L'\0') ;
			return succeeded ? static_cast<NativeError>( 0)
							 : static_cast<NativeError>( HRESULT_FROM_WIN32( GetLastError())) ;
		} ; // PACKAGEは元全hash署名表へ戻します。
		api.catalogSignature = [native, expected]( const std::wstring		   &catalog,
												  std::span<const std::wstring> members) {
			++native->dependencyCatalogCalls ;
			// PACKAGEは共通全CAT/member境界を維持します。
			if( !catalog.starts_with( native->windowsRoot)) {
				return verifyOfficialCatalogMembers( catalog, members) ;
			}

			// INFの署名だけでなく全実payload/既存宛先の効果検査へ到達したcallを数えます。
			if( members.size() == 2U) {
				++native->dependencySystemEffectChecks ;
			}

			std::vector<std::wstring> paths{catalog} ;	// SYSTEMのCAT自身も実hashへ結合します。
			paths.insert( paths.end(), members.begin(), members.end()) ;
			// 同隔離閉包の全実byteだけを人工署名対象にします。
			for( const auto &path : paths) {
				const auto	 original = std::ranges::find_if( expected, [&]( const auto &entry) {
					  return entry.first == path ;
				  }) ;			   // 同元期待だけです。
				std::wstring hash ;	// 同じ実fileの終了byteです。
				// 任意pathや改変を名前だけで合格にしません。
				if( original == expected.end() || computeFileSha256( path, hash) != 0 ||
				   hash != original->second) {
					return static_cast<NativeError>( TRUST_E_BAD_DIGEST) ;
				}
			}

			return static_cast<NativeError>( 0) ;
		} ; // 全member原hashを保持します。
		api.driverStore = [native, storeRelative]( const std::wstring &path, std::wstring &store) {
			++native->dependencyDriverStoreCalls ;
			// 明示二SYSTEM起点だけを対応させます。
			if( path != native->registration.path( L"INF\\peer.inf") &&
			   path != native->registration.path( L"System32\\peer.inf")) {
				return static_cast<NativeError>( E_INVALIDARG) ;
			}

			store = native->registration.path( storeRelative) ;
			return static_cast<NativeError>( 0) ;
		} ; // SYSTEM fileをPACKAGEへ複写しません。
		return inf_dependency_native_detail::Access::create( std::move( api)) ;
	} ; // 同workerが停止するまで完全表と元byteを所有します。
	auto installer = std::make_shared<InstallerFixtureState>() ;	// 同worker専用の原低位状態です。
	installer->condition = nativeCase ;
	// EXE/MSIの人工正例は全hashへ固定し完全表を対で結合します。
	if( !installerPayload.empty()) {
		// 元ABI・容量・証拠の拒否を原診断へ残し、成功やnative fallbackで補完しません。
		if( computeBytesSha256( installerPayload, installer->hash) != 0) {
			throw std::runtime_error( "installer fixture hash") ;
		}

		/** @brief 原payload hashと期待publisherへ完全Authenticode表を結びます。
		 * @return 同workerだけで所有する完全scopeです。不完全表は受理しません。
		 */
		services.authenticodeFixture = [installer]() {
			activeInstallerFixture = installer.get() ;
			return driver_package_signature_detail::Access::createAuthenticode(
				{&installerVerify, &installerQuery, &installerMessage, &installerFind,
				 &installerName, &installerFree, &installerCloseMessage, &installerCloseStore}) ;
		} ;
		/** @brief 実processを起動しない完全低位installer表を開始します。
		 * @return 同workerだけで所有する完全scopeです。部分native fallbackはありません。
		 */
		services.installerFixture = []() {
			return signed_index_candidate_binding_detail::Access::createInstaller(
				{&installerCreate, &installerWait, &installerExit, &installerClose,
				 &installerSystemDirectory}) ;
		} ;
	}

	SignedIndexBindingWorker result ;	// 実workerと同終端後観測の所有返却です。
	/** @brief Worker操作終端後の非機密installer counterだけを返します。
	 * @return 原launch数とhandle解放数です。成功DTOを生成しません。
	 */
	result.observeInstaller = [installer]() {
		return installer->observation ;
	} ; // 非機密counterだけです。
	/** @brief WorkerのCOM MTA内で通常の複合Providerを生成します。
	 * @return 元候補を発行する通常Providerの所有権です。
	 */
	const auto providerFactory = []() { return std::make_unique<CompositeUpdateProvider>() ; } ;
	/** @brief 実復旧操作を呼ばない元の復旧fixtureを生成します。
	 * @return 開始・終了・原失敗を観測する復旧fixtureの所有権です。
	 */
	const auto restoreFactory = []() { return std::make_unique<FakeRestore>() ; } ;
	result.worker			  = provider_worker_index_detail::Access::createAcquisitionFixture(
		providerFactory, restoreFactory, std::move( services)) ;
	/** @brief 同期済みの低位counterだけをcopyし、署名scopeを参照しません。
	 * @return 同operation終端またはstop/join後だけ読む非機密観測です。
	 */
	const auto nativeSnapshot = [native]() {
		return SignedIndexBindingObservation{native->stages,
											 native->installs,
											 native->opens,
											 native->closes,
											 native->restoreBegins,
											 native->restoreCompletes,
											 native->specifiedBindingMatches,
											 {},
											 native->deviceInstalls,
											 native->installedOnlyQueries,
											 native->rankCalls,
											 native->dependencyPackageObservations,
											 native->dependencySystemEffectChecks,
											 native->dependencySystemStageCalls,
											 native->dependencyVersionCalls,
											 native->dependencyInfCalls,
											 native->dependencyCatalogCalls,
											 native->dependencyWindowsDirectoryCalls,
											 native->dependencyDriverStoreCalls,
											 native->dependencySignerResponsesValid,
											 native->dependencySignerMask,
											 native->allPresentInventoryOpens,
											 native->registeredExtensionProbes,
											 native->registeredExtensionBlocked,
											 native->registeredExtensionError,
											 native->registeredExtensionBytesUnchanged,
											 native->currentVersion == L"1.0.0.0"} ;
	} ; // 非atomic値は元終端の同期後またはstop/join後だけ読みます。
	result.observeAfterStop = nativeSnapshot ;
	/** @brief 元終端後かつ署名scope生存中の観測へだけ署名receiptを加えます。
	 * @return 同worker終端eventと同期した元低位counterと署名観測です。
	 */
	result.observe = [nativeSnapshot, signature]() {
		auto observed = nativeSnapshot() ;	// 同終端eventの同期済み低位counterです。
		observed.signature =
			*signature ? (*signature)->receipt() : driver_package_signature_detail::Receipt{} ;
		return observed ;
	} ; // Worker停止後はobserveAfterStopだけを使用します。
	/** @brief Join後に低位集合と登録INFの変更非共有handleの解放を照合します。
	 * @return 集合数一致と全隔離登録fileへの変更権限open成功時だけtrueです。
	 * @note 登録fileは変更・削除せず、各probe handleを同slot内で解放します。
	 */
	result.allNativeHandlesClosed = [native]() {
		// SetupAPI集合の未解放を登録fileの後確認で隠しません。
		if( native->opens != native->closes) {
			return false ;
		}

		// 全終端経路で登録INFのpinが解放され、後のWindows処理を妨げないことを確認します。
		for( const auto &path : native->stagedPaths) {
			// 未実行の予約slotから存在pathを作りません。
			if( path.front() == L'\0') {
				continue ;
			}

			const HANDLE opened = CreateFileW(
				path.data(), GENERIC_WRITE | DELETE,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0U,
				nullptr) ;	// 権限openだけでbyte変更と削除は行いません。
			// 全登録guardが解放された事実を同隔離fileの共有規則で確認します。
			if( opened == INVALID_HANDLE_VALUE) {
				return false ;
			}

			const std::unique_ptr<void, decltype( &CloseHandle)> handle{
				opened, &CloseHandle} ;	// 同slot内で解放します。
		}

		return true ;
	} ; // Join後にだけ読む共有counterです。
	// 結果DTOを変更しません。
	/** @brief Idle workerへ送る前に原の低位現在状態だけを変更します。
	 * @note 成功DTOや公開候補を変更せず、元再照合による拒否を検証します。
	 */
	result.changeNativeState = [native]() {
		native->changed = true ;
		// この固定条件だけは元保護閉包のimport-only byteを実際に変更します。
		if( native->nativeCase == SignedIndexBindingNativeCase::IMPORT_HASH_CHANGED ||
		   native->nativeCase == SignedIndexBindingNativeCase::SERVICE_EXE_HASH_CHANGED ||
		   native->nativeCase == SignedIndexBindingNativeCase::DEPENDENCY_PACKAGE_CHANGED) {
			bool changed{} ;	// 必ず対象byteへ到達した事実だけを保持します。
			// Fake source検索で記録した保護fixture親からだけ対象を解決します。
			for( const auto &source : native->sourceInfs) {
				const auto path = std::filesystem::path( source) ;	// Fixtureだけの元完全pathです。
				// 登録rootや他INFをhash拒否の入力へ変更しません。
				if( path.filename() != L"fixture.inf" || source.starts_with( native->windowsRoot)) {
					continue ;
				}

				const auto target =
					// 同保護元閉包の実在importだけです。
					path.parent_path() /
					(native->nativeCase == SignedIndexBindingNativeCase::IMPORT_HASH_CHANGED
						 ? L"importonly.inf"
					 : native->nativeCase ==
							 SignedIndexBindingNativeCase::DEPENDENCY_PACKAGE_CHANGED
						 ? L"component.inf"
						 : L"component_service.exe") ;
				// 検査前未実在を変更成功へ補完しません。
				if( std::filesystem::is_regular_file( target)) {
					std::ofstream stream( target,
										 std::ios::binary |
											 std::ios::app) ;	// 同期fixture byteだけを所有します。
					stream << "; changed original import bytes\r\n" ;
					stream.close() ;
					changed = !stream.fail() ;
				}
			}

			// 実byte未変更のままhash差拒否の合格を宣言しません。
			if( !changed) {
				throw std::runtime_error( "Original import mutation not reached") ;
			}
		}
	} ; // Worker Idleと元operation終端後だけ呼出し、公開結果を変更しません。
	return result ;
}
// tests/unit/signed_index_candidate_binding_tests.hの同宣言を契約の正本とする。
void runSignedIndexCandidateBindingTests( TestContext						   &context,
										 provider_worker_index_detail::Services services,
										 const std::string_view zip, const bool network)
{
	// 今回の限定試験の開始assertion数。
	const auto before = context.assertionCount() ;
	// 開始時の失敗数。既存失敗を今回の結果へ加算しない。
	const auto failures = context.failureCount() ;
	// 元ZIPから採取した全memberの実hash期待値。
	const auto files = signatureFiles( zip) ;
	DRIVERCRATE_EXPECT( context, !driver_store_inf_detail::Access::create(
									{})) ;	// 不完全表のnative fallbackを拒否します。
	const auto ownerInf = std::ranges::find_if( files, []( const auto &file) {
		return file.name.ends_with( L".inf") ;
	}) ; // 元ZIPから既に固定したroot直下INFです。
	DRIVERCRATE_EXPECT( context, ownerInf != files.end()) ;
	// 実ownerがある場合だけ十二不正名を同じ完全表へ追加してfactory拒否を確認します。
	if( ownerInf != files.end()) {
		constexpr std::array<std::wstring_view, 12U> INVALID_MEMBER_NAMES{
			L"..\\component_service.exe",
			L"\\component_service.exe",
			L"bin\\..\\component_service.exe",
			L"bin\\",
			L"bin\\\\component_service.exe",
			L"bin/component_service.exe",
			L"bin:payload.exe",
			L"bin\\CON.exe",
			L"bin\\nul.dll",
			L"bin\\LPT1.exe",
			L"bin\\bad<name.exe",
			L"bin\\bad\u0080.exe"} ;	// 元七と新五の固定拒否分母です。
		// 元INF/CAT/hashを保持し、各不正segmentだけを一度ずつfactoryへ渡します。
		for( const auto name : INVALID_MEMBER_NAMES) {
			auto invalid = files ;	// 各条件で独立所有する完全表です。
			invalid.push_back( {std::wstring( name), std::wstring( 64U, L'0'), ownerInf->name}) ;
			DRIVERCRATE_EXPECT(
				context, !driver_package_signature_detail::Access::create( std::move( invalid))) ;
		}
	}

	// Netは通常更新一回、Portsは版分類・失敗・再起動を別modeで確認します。
	for( unsigned mode = 0U; mode < (network ? 1U : 6U); ++mode) {
		// 同workerが寿命内だけ借用する低位API状態の共有所有者。
		auto native			   = std::make_shared<NativeFixtureState>() ;
		native->mode		   = mode ;
		native->nativeCase	   = mode == 5U ? SignedIndexBindingNativeCase::INITIAL
											: SignedIndexBindingNativeCase::NORMAL ;
		native->network		   = network ;
		native->currentVersion = mode == 1U ? L"1.0.0.0" : mode == 2U ? L"2.0.0.0" : L"0.9.0.0" ;
		// 一modeのworker寿命へ固定する完全fake依存のcopy。
		auto fixed	   = services ;
		auto signature = std::make_shared<driver_package_signature_detail::ScopedFixture *>(
			nullptr) ;	// Idle workerでだけreceiptを借用します。
		fixed.driverStoreFixture = [native]() {
			activeNative = native.get() ;
			// 既存正常試験も実登録root内の別fileを必要とします。
			if( !initializeRegistration( *native)) {
				return std::unique_ptr<driver_store_inf_detail::ScopedFixture>{} ;
			}

			return driver_store_inf_detail::Access::create( calls()) ;
		} ;
		fixed.signatureFixture = [files, signature]() {
			// 全member期待値を所有しworker停止まで有効な署名表の単独所有者。
			auto scope = driver_package_signature_detail::Access::create( files) ;
			*signature = scope.get() ;
			return scope ;
		} ;
		// 通常command queueを使用し全fake依存の寿命を所有する隔離worker。
		auto worker = provider_worker_index_detail::Access::createAcquisitionFixture(
			[]() { return std::make_unique<CompositeUpdateProvider>() ; },
			[]() { return std::make_unique<FakeRestore>() ; }, std::move( fixed)) ;
		DRIVERCRATE_EXPECT( context, worker != nullptr) ;
		// worker生成が失敗した試験を導入成功へ進めません。
		if( !worker) {
			continue ;
		}

		// 同scanのDriver Storeと索引だけを明示選択する設定。
		ScanOptions options ;
		options.useDefaultProviders = false ;
		options.enabledProviderIds	= {std::wstring{DRIVER_STORE_PROVIDER_ID},
									   std::wstring{SIGNED_INDEX_PROVIDER_ID}} ;
		OperationController controller ;	// MainWindowと同じ実core状態機械です。
		// 元scan operationの開始許可とidentity。
		const auto			scan = controller.beginScan() ;
		DRIVERCRATE_EXPECT( context,
						   scan.accepted && worker->requestScan( scan.operationId, options)) ;
		// 同scanの実終端event。以後の同期確認期間を通して所有する。
		auto scanned = waitEvent( *worker, WorkerEventKind::SCAN_COMPLETED, scan.operationId) ;
		DRIVERCRATE_EXPECT( context, scanned && scanned->scanResult.succeeded &&
										scanned->preparationPlan &&
										scanned->indexPreparation.plannedTargets == 1U) ;
		// 同scan準備planがない場合はworkerを停止して拒否を残します。
		if( !scanned || !scanned->preparationPlan) {
			worker->stop() ;
			continue ;
		}

		// 内容検査前の非導入参照行数。内容合格候補へ計上しない。
		const auto references =
			std::ranges::count_if( scanned->scanResult.candidates, []( const auto &candidate) {
				return candidate.providerId == SIGNED_INDEX_PROVIDER_ID && !candidate.installable ;
			}) ;
		DRIVERCRATE_EXPECT( context, references == 1) ;
		// scanned所有eventから同期処理中だけ借用する原計画。
		const auto &plan = *scanned->preparationPlan ;
		DRIVERCRATE_EXPECT( context,
						   controller.completeScan( scan.operationId, scanned->scanResult) &&
							   controller.state() == ApplicationState::SCAN_READY &&
							   controller.setPreparationPlan( scan.operationId, plan)) ;
		// 元計画と有限予算に限定した取得承認。
		OfficialPreparationApproval approval{0U, plan.scanSessionId, plan.planId, plan.limits, {}} ;
		// planの元順序どおり各対象の明示承認を構築します。
		for( const auto &target : plan.targets) {
			approval.decisions.push_back( {target, true, false, false, false}) ;
		}

		// 新取得operationの開始許可。原scan operationと分離する。
		const auto preparation = controller.beginPreparation( approval) ;
		DRIVERCRATE_EXPECT( context, preparation.accepted && worker->requestPreparation( approval)) ;
		// 同取得operationの実byte・内容・適合・publication終端event。
		auto prepared =
			waitEvent( *worker, WorkerEventKind::PREPARATION_COMPLETED, approval.operationId) ;
		// 本体が実bindingから発行した候補の所有copy。
		std::vector<UpdateCandidate> candidates ;
		// 実準備eventがある場合だけ段階別診断を観測します。
		if( prepared) {
			// 各本体監査の元HRESULTと内容・適合・公開件数を保存します。
			for( const auto &report : prepared->preparationResult.auditReports) {
				std::cout << "Index audit: content " << static_cast<unsigned>( report.content) << '/'
						  << report.contentError << ", accepted " << report.acceptedInfCount
						  << ", first content " << report.firstContentRejection << ", pairs "
						  << report.examinedPairCount << '/' << report.applicablePairCount << '/'
						  << report.failedPairCount << ", first pair " << report.firstPairError
						  << ", publication " << report.publication.firstError << '\n' ;
				candidates.insert( candidates.end(), report.publishedCandidates.begin(),
								  report.publishedCandidates.end()) ;
			}
		}

		// 元の内容拒否診断を期待値で置き換えず保持します。
		if( prepared) {
			// 各正規取得のseal付き内容検査件数を保存します。
			for( const auto &item : prepared->indexPreparation.items) {
				std::cout << "Index exact content: acquired " << item.acquisitionError
						  << ", content " << item.contentError << ", accepted "
						  << item.acceptedInfCount << ", rejected signature "
						  << item.signatureRejectedInfCount << ", first INF "
						  << item.firstInfRejection << '\n' ;
			}
		}

		std::cout << "Index pipeline " << (network ? "Net" : "Ports") << " mode " << mode
				  << ": references " << references << ", published " << candidates.size()
				  << ", preparation HRESULT "
				  << (prepared ? prepared->preparationResult.controlError : 0xFFFFFFFFU)
				  << ", Windows set opens " << native->opens << ", rank calls " << native->rankCalls
				  << '\n' ;
		DRIVERCRATE_EXPECT( context, prepared && candidates.size() == 1U) ;
		// 公開候補がない試験では未到達を残してworkerを停止します。
		if( candidates.empty()) {
			worker->stop() ;
			continue ;
		}

		DRIVERCRATE_EXPECT( context,
						   controller.completePreparation( prepared->preparationResult,
														  scanned->scanResult.candidates) &&
							   controller.state() == ApplicationState::SCAN_READY) ;
		// 非空を確認した同publication候補。導入終端まで借用する。
		const auto &candidate = candidates.front() ;
		DRIVERCRATE_EXPECT( context,
						   candidate.installable && !candidate.recommended &&
							   candidate.defaultPreference == CandidateDefaultPreference::NONE &&
							   candidate.discoveryBasis ==
								   CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION &&
							   candidate.action == (mode == 1U	 ? DriverAction::REINSTALL
													: mode == 2U ? DriverAction::DOWNGRADE
													: mode == 5U ? DriverAction::INITIAL_INSTALL
																 : DriverAction::UPDATE)) ;
		// 同controllerが公開・許可した唯一の選択identity。
		const std::array selected{candidate.identity} ;
		// 明示同意なしではfake指定導入へ到達しないことを確認する結果。
		const auto		 refusal = controller.beginInstall( plan.scanSessionId, selected,
														   InstallConfirmation::NOT_CONFIRMED) ;
		DRIVERCRATE_EXPECT( context, !refusal.accepted && native->installs == 0U) ;
		// 同session・同選択へ結合した明示導入operation。
		const auto installation =
			controller.beginInstall( plan.scanSessionId, selected, InstallConfirmation::CONFIRMED) ;
		DRIVERCRATE_EXPECT( context, installation.accepted &&
										worker->requestInstall(
											installation.operationId, plan.scanSessionId, selected,
											nullptr, InstallProtectionMode::WINDOWS_RESTORE_POINT)) ;
		// 取得結果と導入結果を分離した同operationの実終端event。
		auto result =
			waitEvent( *worker, WorkerEventKind::INSTALL_COMPLETED, installation.operationId) ;
		DRIVERCRATE_EXPECT( context, result && result->installResult.updates.size() == 1U) ;
		// 実個別結果一件が得られた場合だけcontroller終端と結果保持を検証します。
		if( result && result->installResult.updates.size() == 1U) {
			DRIVERCRATE_EXPECT( context, controller.completeInstall( installation.operationId,
																   result->installResult) &&
											controller.scanSessionId() == 0U) ;
			// 存在確認済みの選択一件の個別結果。result寿命内だけ借用する。
			const auto &item = result->installResult.updates.front() ;
			DRIVERCRATE_EXPECT( context,
							   item.identity == candidate.identity &&
								   item.downloadOutcome == OutcomeCode::SUCCESS &&
								   item.installOutcome ==
									   (mode == 3U ? OutcomeCode::FAILURE : OutcomeCode::SUCCESS) &&
								   item.rebootRequired == (mode == 4U)) ;
			std::cout << "Index pipeline " << (network ? "Net" : "Ports") << " mode " << mode
					  << ": fake stage " << native->stages << ", fake specified install "
					  << native->installs << ", result HRESULT " << item.installError << ", reboot "
					  << result->installResult.rebootRequired << ", real OS changes 0\n" ;
		}

		// 完了event受領後のidle workerでは全署名callが終了済みで、低位receiptだけを読みます。
		if( *signature) {
			// 全署名処理終了後の固定低位call観測のcopy。
			const auto receipt = (*signature)->receipt() ;
			DRIVERCRATE_EXPECT( context, receipt.setupCalls > 0U && receipt.verifyCalls >= 2U &&
											receipt.verifyCalls == receipt.closeCalls &&
											receipt.rejectedCalls == 0U) ;
			std::cout << "Index signature wrapper receipt: SetupVerify " << receipt.setupCalls
					  << ", WVT VERIFY " << receipt.verifyCalls << ", CLOSE " << receipt.closeCalls
					  << ", rejected " << receipt.rejectedCalls << '\n' ;
		}

		worker->stop() ;
		// 初回正例は実installed-only照会条件を通った場合だけ成立します。
		if( mode == 5U) {
			DRIVERCRATE_EXPECT( context, native->installedOnlyQueries >= 3U) ;
		}

		DRIVERCRATE_EXPECT( context, native->stages == 1U && native->installs == 1U &&
										native->opens == native->closes) ;
	}

	std::cout << "Index candidate binding assertions: " << context.assertionCount() - before
			  << ", failures: " << context.failureCount() - failures
			  << ", native CAT positive UNCONFIRMED\n" ;
}
} // namespace drivercrate::test
