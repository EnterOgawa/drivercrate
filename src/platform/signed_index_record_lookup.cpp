//------------------------------------------------------------------------------
/**
 * @file signed_index_record_lookup.cpp
 * @brief 保存snapshotの期限とcontextを確認して公開ID照合関係を保持します
 * @version 01.11.01
 * @date 2026/10/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  同snapshotと全context限定の私有batch集約を追加
 * Ver.01.02.00 Shunji Ogawa  2026/10/14  同native私有証拠の部分positiveを元不足と分離
 * Ver.01.03.00 Shunji Ogawa  2026/10/27  元cohort/診断と対象一件をprivate証拠へ完全結合
 * Ver.01.04.00 Shunji Ogawa  2026/11/07  全体容量・所有stateと有限進行の契約へ整合
 * Ver.01.04.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.04.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.05.00 Shunji Ogawa  2026/11/19  取得済み根拠を元native列挙の寿命へ照合
 * Ver.01.06.00 Shunji Ogawa  2026/11/20  Catalog対象を端末HardwareIdsと不変証拠へ結ぶ
 * Ver.01.07.00 Shunji Ogawa  2026/11/20  端末用レコード位置と元領域の期限を照合・集約へ適用
 * Ver.01.08.00 Shunji Ogawa  2026/11/20  同じ元行と端末型番に限りHardwareIdsを照合
 * Ver.01.09.00 Shunji Ogawa  2026/11/20  同一端末の全HardwareIdsによる必須群の判定を追加
 * Ver.01.10.00 Shunji Ogawa  2026/11/22  ベンダー配布の完全Hardware IDを端末照合と証拠凍結に接続
 * Ver.01.11.00 Shunji Ogawa  2026/11/23  WiX配布のWindows対象条件と完全Hardware IDを同じ端末へ照合
 * Ver.01.11.01 Shunji Ogawa  2026/11/26  宣言・分岐・反復のコメントの意図を補足
 * </pre>
 *
 * @note 原公開metadataを保持し、Windows適合・rank・導入許可へ昇格しません
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 * @see docs/adr/0413-authenticated-per-device-index-projection.md
 */
//------------------------------------------------------------------------------
#include "platform/signed_index_record_lookup.h"

#include "platform/client_min_build_scope.h"
#include <algorithm>
#include <new>
#include <set>
#include <tuple>
#include <utility>
#include <windows.h>

namespace drivercrate {

//------------------------------------------------------------------------------
/**
 * @brief 元context/ownerとweak寿命にread-open fieldの借用を結びます
 * @param[in] key 元DriverStoreのmint keyです
 * @param[in] context 元operation/scan/inventoryです
 * @param[in] ownerThread 元inventoryのthreadです
 * @param[in] owner 元stateのweak寿命です。強所有しません
 * @param[in] readOpen owner内の元read-open fieldです。lock成功時だけ参照します
 */
//------------------------------------------------------------------------------
NativeIndexLookupLease::NativeIndexLookupLease( MintKey key, IndexLookupContext context,
											   std::uint32_t			 ownerThread,
											   std::weak_ptr<const void> owner,
											   const bool				*readOpen)
	: context_( context), ownerThread_( ownerThread), owner_( std::move( owner)), readOpen_( readOpen)
{
	static_cast<void>( key) ;
}
//------------------------------------------------------------------------------
/**
 * @brief 同context/owner thread・元state寿命/read-openを確認します
 * @param[in] context 元完全contextです
 * @param[in] ownerThread 現在実行中のthreadです
 * @return 元stateが同threadでread-openのときだけtrueです。I/Oを行いません
 */
//------------------------------------------------------------------------------
bool NativeIndexLookupLease::matches( IndexLookupContext context,
									 std::uint32_t		ownerThread) const noexcept
{
	// 別threadから元mutable stateを参照せず、別context/空fieldも拒否します
	if( context != context_ || ownerThread != ownerThread_ || readOpen_ == nullptr) {
		return false ;
	}

	const auto owner = owner_.lock() ;	// fieldを参照する期間だけ元stateの寿命を確保します
	return owner && *readOpen_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元のcontextとthreadで列挙が生存することを取得済み根拠用に検査します
 * @param[in] context 元の操作と列挙の完全contextです
 * @param[in] ownerThread 現在実行中のthreadです
 * @return 完全context、同thread、元列挙の生存が成立する場合trueです
 */
//------------------------------------------------------------------------------
bool NativeIndexLookupLease::matchesOwner( const IndexLookupContext context,
										  const std::uint32_t	   ownerThread) const noexcept
{
	return context == context_ && ownerThread == ownerThread_ && !owner_.expired() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同scanから確認した元公開tupleと既知device集合を不変保存します
 * @param[in] key DriverStoreだけが構築した発行keyです
 * @param[in] context 元worker／scan／inventoryの全contextです
 * @param[in] kind 元公開INF側のidentifier役割です
 * @param[in] publishedId 元公開ASCII identifierを本呼出し中だけ借用してcopyします
 * @param[in] classGuid 元公開Class文字列を本呼出し中だけ借用してcopyします
 * @param[in] ownerThread 同inventoryを所有するWindows thread IDです
 * @param[in] lease Providerが強所有する元scan stateへのweak leaseです
 * @param[in] devices 両native属性と既知Classが検証されたopaque集合を所有moveします
 * @param[in] error 同callbackが保持した元不足診断です
 * @note 元列挙完了と必要属性の検証は発行側の前提です。秘密IDやURLを保持しません
 */
//------------------------------------------------------------------------------
NativeIndexPositiveProof::NativeIndexPositiveProof(
	MintKey key, IndexLookupContext context, IndexPnpIdKind kind, std::string_view publishedId,
	std::string_view classGuid, std::uint32_t ownerThread, std::weak_ptr<const void> lease,
	std::vector<std::wstring> devices, NativeError error)
	: context_( context), kind_( kind), publishedId_( publishedId), classGuid_( classGuid),
	  ownerThread_( ownerThread), lease_( std::move( lease)), devices_( std::move( devices)),
	  error_( error)
{
	static_cast<void>( key) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元tupleとdevice集合の完全一致および同ownerの生存を確認します
 * @param[in] context 現callbackの全contextです
 * @param[in] kind lookupが元recordから読んだ公開役割です
 * @param[in] publishedId lookupが元recordから読んだ公開identifierです
 * @param[in] classGuid lookupが元recordから読んだ公開Classです
 * @param[in] ownerThread lookupを実行中のWindows thread IDです
 * @param[in] devices callbackが返した全opaque集合を本呼出し中だけ借用します
 * @param[in] error callbackまたは私有relationが保持した元不足診断です
 * @return 全一致と生存確認が成立した場合だけtrueです
 * @note I/Oや参照の保持は行いません。失効したscanを再有効化しません
 */
//------------------------------------------------------------------------------
bool NativeIndexPositiveProof::matches( const IndexLookupContext context, const IndexPnpIdKind kind,
									   const std::string_view			   publishedId,
									   const std::string_view			   classGuid,
									   const std::uint32_t				   ownerThread,
									   const std::span<const std::wstring> devices,
									   const NativeError				   error) const noexcept
{
	return context == context_ && kind == kind_ && publishedId == publishedId_ &&
		   classGuid == classGuid_ && ownerThread == ownerThread_ && error == error_ &&
		   !lease_.expired() && !devices_.empty() && devices.size() == devices_.size() &&
		   std::equal( devices.begin(), devices.end(), devices_.begin()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元公開tupleと全cohort、一deviceの完全観測を不変保存します
 * @param[in] key DriverStoreだけが構築した発行keyです
 * @param[in] context 元operation/scan/inventoryです
 * @param[in] kind 元公開IDの役割です
 * @param[in] publishedId 元公開IDをcopyします。端末raw IDではありません
 * @param[in] classGuid 元公開Classをcopyします
 * @param[in] ownerThread 元scanのWindows owner threadです
 * @param[in] lease Providerだけが強所有する元stateです
 * @param[in] devices 同callbackが返す全opaque cohortをcopyします
 * @param[in] error 他node不足も保持する元診断です
 * @param[in] completed 元callbackの全体完了区分です
 * @param[in] deviceIdentity 完全個別観測が成立したopaque一件をcopyします
 * @param[in] hardwareOnly 端末HardwareIdsだけを照合した観測の場合true
 * @param[in] hardwareIds 同じPnPインスタンスで読んだ全HardwareIdsへの弱参照です
 */
//------------------------------------------------------------------------------
NativeIndexDeviceProof::NativeIndexDeviceProof(
	MintKey key, IndexLookupContext context, IndexPnpIdKind kind, std::string_view publishedId,
	std::string_view classGuid, std::uint32_t ownerThread, std::weak_ptr<const void> lease,
	std::vector<std::wstring> devices, NativeError error, bool completed,
	std::wstring deviceIdentity, bool hardwareOnly,
	std::weak_ptr<const std::vector<std::wstring>> hardwareIds)
	: context_( context), kind_( kind), publishedId_( publishedId), classGuid_( classGuid),
	  ownerThread_( ownerThread), lease_( std::move( lease)), devices_( std::move( devices)),
	  error_( error), completed_( completed), deviceIdentity_( std::move( deviceIdentity)),
	  hardwareOnly_( hardwareOnly), hardwareIds_( std::move( hardwareIds))
{
	static_cast<void>( key) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元tuple/診断/全cohortと対象一件、同ownerの生存を完全照合します
 * @param[in] context 使用時の全contextです
 * @param[in] kind 原recordの公開ID役割です
 * @param[in] publishedId 原recordの公開IDです
 * @param[in] classGuid 原recordの公開Classです
 * @param[in] ownerThread 使用中のWindows threadです
 * @param[in] devices 元callbackの全opaque cohortです
 * @param[in] error 消去しない元診断です
 * @param[in] completed 元callbackの完了区分です
 * @param[in] deviceIdentity 使用対象のopaque一件です。同cohortの他deviceも拒否します
 * @param[in] hardwareOnly 使用時に要求する端末HardwareIds限定の照合区分
 * @return 全一致と元leaseの生存が成立した場合だけtrueです
 */
//------------------------------------------------------------------------------
bool NativeIndexDeviceProof::matches(
	const IndexLookupContext context, const IndexPnpIdKind kind, const std::string_view publishedId,
	const std::string_view classGuid, const std::uint32_t ownerThread,
	const std::span<const std::wstring> devices, const NativeError error, const bool completed,
	const std::wstring_view deviceIdentity, const bool hardwareOnly) const noexcept
{
	return hardwareOnly == hardwareOnly_ && context == context_ && kind == kind_ &&
		   publishedId == publishedId_ && classGuid == classGuid_ && ownerThread == ownerThread_ &&
		   !lease_.expired() && error == error_ && completed == completed_ &&
		   deviceIdentity == deviceIdentity_ && !deviceIdentity_.empty() && !devices_.empty() &&
		   devices_.size() <= 32U && devices.size() == devices_.size() &&
		   std::equal( devices.begin(), devices.end(), devices_.begin()) &&
		   std::ranges::find( devices_, deviceIdentity_) != devices_.end() ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同一端末の生存中のHardwareIdsから署名済みの必須群を判定します
 * @param[in] record 元の照合関係に結び付けた署名済み配布レコードです
 * @param[in] context 使用する直前のスキャン・インベントリです
 * @param[in] ownerThread 使用中のWindowsスレッドです
 * @param[in] deviceIdentity 使用対象の同一PnPインスタンスを示すopaque値です
 * @return 元端末が持つ完全な対象IDによる群の判定です。元観測を借用できない場合は判定不能です
 * @pre 元のレコードと照合関係に対するmatchesが成立しています
 */
//------------------------------------------------------------------------------
IndexPlatformFirmwareMatch NativeIndexDeviceProof::platformFirmwareMatch(
	const IndexDistributionRecord &record, const IndexLookupContext context,
	const std::uint32_t ownerThread, const std::wstring_view deviceIdentity) const noexcept
{
	// 同じスキャン・所有スレッド・PnPインスタンスの観測だけを使います
	if( !hardwareOnly_ || kind_ != IndexPnpIdKind::HARDWARE || context != context_ ||
	   ownerThread != ownerThread_ || GetCurrentThreadId() != ownerThread_ ||
	   deviceIdentity.empty() || deviceIdentity != deviceIdentity_ ||
	   record.publishedIdentityEvidence.classGuid != classGuid_) {
		return {} ;
	}

	const auto observed =
		// 元インベントリが生存中だけ同じ端末の全IDを借用します
		hardwareIds_.lock() ;
	return observed ? classifyIndexPlatformFirmwareGroup( record, *observed)
					: IndexPlatformFirmwareMatch{} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Hardware限定を実装していないcallbackは未完了を返す
 * @param[in] publishedId 認証済みレコードの元Hardware ID
 * @param[in] classGuid 同じレコードの元ClassGUID
 * @param[in] context 元scan・inventoryを指定する照合context
 * @param[in] present 照合同期中だけ借用する全present opaque
 * @return 元contextの未完了結果
 * @note 旧callbackへ委譲せず同じ条件を実装するnativeにだけ照合を任せる
 */
//------------------------------------------------------------------------------
IndexPublicIdResolution IndexPublicIdResolver::resolveHardwareId(
	std::string_view publishedId, std::string_view classGuid, IndexLookupContext context,
	std::span<const std::wstring> present) const
{
	static_cast<void>( publishedId) ;
	static_cast<void>( classGuid) ;
	static_cast<void>( present) ;
	return {.context = context} ;
}

//------------------------------------------------------------------------------
/**
 * @brief Windowsが保持する製造元と製品名からメーカー型番を確認します
 * @param[in] manufacturer SMBIOS由来のSystemManufacturerです
 * @param[in] productName SMBIOS由来のSystemProductNameです
 * @return 端末内で確認した製造元と型番です。型番と解釈できない製品名は保持しません
 */
//------------------------------------------------------------------------------
IndexPlatformMachineIdentity parseIndexPlatformMachine( std::wstring_view manufacturer,
													   std::wstring_view productName)
{
	// 外側の空白とASCII英字の大小文字だけを比較用にそろえます
	const auto normalized = []( std::wstring_view value) {
		const auto	 start = value.find_first_not_of( L" \t") ;	// 外側の余白を除いた先頭です
		std::wstring text ;										// 元の表示名と無関係な比較値です
		// 空値を有効な製造元や型番へ変換しません
		if( start != std::wstring_view::npos) {
			text.assign( value.substr( start, value.find_last_not_of( L" \t") - start + 1U)) ;
			// 借用範囲を所有値へ写した後に比較用のcaseへそろえます
			std::ranges::transform( text, text.begin(), []( const wchar_t c) {
				return c >= L'a' && c <= L'z' ? static_cast<wchar_t>( c - L'a' + L'A') : c ;
			}) ;
		}

		return text ;
	} ;
	const auto vendor = normalized( manufacturer) ;	// 製造元の比較値です
	// 製造元不明と、確認できた別の製造元を区別します
	if( vendor.empty()) {
		return {} ;
	}

	// 別メーカーの製品名からLenovo型番を抽出しません
	if( vendor != L"LENOVO") {
		return {.vendor = IndexPlatformMachineVendor::OTHER} ;
	}

	const auto product = normalized( productName) ;	// 型番又はMachine Type/Modelの比較値です
	IndexPlatformMachineIdentity result{
		.vendor = IndexPlatformMachineVendor::LENOVO} ;	// 同じ端末の観測です
	// 製品名の全体が4文字の型番又は10文字のMachine Type/Modelである場合だけ使います
	if( (product.size() == 4U || product.size() == 10U) &&
	   product.find_first_not_of( L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") == product.npos) {
		result.machineType.resize( 4U) ;
		// 上の字句検査でASCIIと確定した型番部分だけを保持します
		std::ranges::transform( std::wstring_view{product}.substr( 0U, 4U),
							   result.machineType.begin(),
							   []( const wchar_t c) { return static_cast<char>( c) ; }) ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元ModelsのID位置を型付き配布対象条件に照合します
 * @param[in] record 元Modelsと対象位置を持つ認証済みレコード
 * @param[in] publicIdIndex 元ModelsでのID位置
 * @return 位置が存在し、対象条件を満たす場合trueです。WiXでは完全Hardware IDに限ります
 */
//------------------------------------------------------------------------------
bool isIndexLookupIdEligible( const IndexDistributionRecord &record,
							 const std::size_t				publicIdIndex) noexcept
{
	const auto &ids = record.publishedIdentityEvidence.pnpIds ;	// 同じ公開Modelsの元ID群です
	return publicIdIndex < ids.size() &&
		   (!record.wixContentEvidence || isExactWixHardwareId( ids[publicIdIndex])) &&
		   (!record.catalogHardwareScope ||
			std::ranges::binary_search( record.catalogHardwareScope->hardwareIdIndices,
									   publicIdIndex)) &&
		   (!record.platformDeviceScope ||
			std::ranges::binary_search( record.platformDeviceScope->hardwareIdIndices,
									   publicIdIndex)) &&
		   (!record.archiveHardwareScope ||
			std::ranges::binary_search( record.archiveHardwareScope->hardwareIdIndices,
									   publicIdIndex)) ;
}

namespace {
//------------------------------------------------------------------------------
/**
 * @brief WiXの元配布が同じスキャンで観測したWindowsに合わない理由を返します
 * @param[in] record 同じ署名索引で確認した元レコードです
 * @param[in] host 同じ操作で取得したWindowsの元観測です。未実施ならnullです
 * @return 対象条件が合うかWiX以外なら空、観測不足又は対象外ならその理由です
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::optional<IndexRecordMatchReason> wixHostRejection(
	const IndexDistributionRecord &record, const WindowsHostPlatformObservation *host) noexcept
{
	// 従来の配布レコードにはWiX専用の対象条件を適用しません
	if( !record.wixContentEvidence) {
		return std::nullopt ;
	}

	const auto result = matchWixIndexHost(
		record, host ? *host : WindowsHostPlatformObservation{}) ;	// 同じスキャンの元観測に限ります
	// Windowsの対象条件が合う場合だけ端末のHardware IDとの照合を許可します
	if( result.state == IndexHostGateState::ALLOW_UNVERIFIED) {
		return std::nullopt ;
	}

	return result.state == IndexHostGateState::UNKNOWN
			   ? IndexRecordMatchReason::WIX_HOST_UNAVAILABLE
			   : IndexRecordMatchReason::WIX_HOST_MISMATCH ;
}

//------------------------------------------------------------------------------
/**
 * @brief 機種条件付きレコードを同スキャンの端末観測に照合します
 * @param[in] record 取得元と元型番を結合した署名済みレコードです
 * @param[in] machine 同じ端末スキャンの製造元と型番です。同じスキャンの観測がなければnullです
 * @return 機種条件なし又は成立なら空、未確認又は不一致ならその理由です
 */
//------------------------------------------------------------------------------
std::optional<IndexRecordMatchReason> platformMachineRejection(
	const IndexDistributionRecord &record, const IndexPlatformMachineIdentity *machine) noexcept
{
	// 通常行とCatalog行には機種観測の状態を適用しません
	if( !record.platformDeviceScope) {
		return std::nullopt ;
	}

	const auto &scope = *record.platformDeviceScope ;	// 同じ取得元に結んだ機種別条件です
	// 同じ製造元の型番として確認できない組合せを照合済みへ変換しません
	if( !machine || scope.machineVendor == IndexPlatformMachineVendor::UNKNOWN ||
	   machine->vendor == IndexPlatformMachineVendor::UNKNOWN ||
	   (machine->vendor == scope.machineVendor && machine->machineType.empty())) {
		return IndexRecordMatchReason::PLATFORM_MACHINE_UNAVAILABLE ;
	}

	// 確認できた型番と元表の完全値を比較します
	if( machine->vendor != scope.machineVendor ||
	   std::ranges::find( scope.machineTypes, machine->machineType) == scope.machineTypes.end()) {
		return IndexRecordMatchReason::PLATFORM_MACHINE_MISMATCH ;
	}

	return std::nullopt ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元レコードが照合結果の分母に持つ公開IDの件数を数えます
 * @param[in] record 領域が所有する不変の元レコードです
 * @return Class付きの公開申告に含まれるID数です。申告不明の場合は0です
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::size_t publishedIdCount( const IndexDistributionRecord &record) noexcept
{
	const auto &evidence = record.publishedIdentityEvidence ;	// 原公開申告です
	return evidence.state == IndexEvidenceState::PUBLISHED && !evidence.classGuid.empty()
			   ? evidence.pnpIds.size()
			   : 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief 元callbackの各個別証拠を全tuple/全cohortへ照合します
 * @param[in] resolution 元callbackの不変結果です
 * @param[in] kind 原recordの公開役割です
 * @param[in] publishedId 原recordの公開IDです
 * @param[in] classGuid 原recordの公開Classです
 * @param[in] hardwareOnly 元の照合が端末HardwareIdsに限定される場合true
 * @return 一件以上の認証済みslotがあり、存在する証拠が全て完全一致した場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool verifiedDeviceProofs( const IndexPublicIdResolution &resolution,
										IndexPnpIdKind kind, std::string_view publishedId,
										std::string_view classGuid, bool hardwareOnly)
{
	// 欠損や大量cohortを一部の成功証拠で補完しません
	if( resolution.devices.empty() || resolution.devices.size() > 32U ||
	   resolution.deviceProofs.size() != resolution.devices.size()) {
		return false ;
	}

	bool found{} ;	// 一件以上の完全証拠が必要です
	// 同順の全slotを確認し、証拠の対象や元errorの改変で全投影を拒否します
	for( std::size_t index = 0U; index < resolution.deviceProofs.size(); ++index) {
		const auto &proof = resolution.deviceProofs[index] ;	// 元node専用の不変証拠です
		// 未認証nodeは成功へ数えず、他の合法nodeの全cohortには残します
		if( !proof) {
			continue ;
		}

		// 同cohortの他deviceや別公開tupleへの転用を認めません
		if( !proof->matches( resolution.context, kind, publishedId, classGuid, GetCurrentThreadId(),
						   resolution.devices, resolution.error, resolution.completed,
						   resolution.devices[index], hardwareOnly)) {
			return false ;
		}

		found = true ;
	}

	return found ;
}

//------------------------------------------------------------------------------
/**
 * @brief 一公開IDのcallback結果を有限に検査し、関係へ反映します
 * @param[in,out] relation 元recordとcontextを持つ格納先
 * @param[in] resolution Callbackの元結果
 * @param[in] present 同contextの有限present検索集合。本呼出し中だけ借用します
 * @param[in,out] retainedIdentities 同batchの保持opaque総数です
 * @param[in] maximumRelatedIdentities 同scanに残る有限opaque枠です
 * @param[in] kind 元recordの公開identifier役割です
 * @param[in] publishedId 元recordの公開identifierです。保持しません
 * @param[in] classGuid 元recordの公開Classです。保持しません
 * @param[in] hardwareOnly 元の照合が端末HardwareIdsに限定される場合true
 */
//------------------------------------------------------------------------------
void applyResolution( IndexRecordRelation &relation, const IndexPublicIdResolution &resolution,
					 const std::set<std::wstring_view> &present, std::size_t &retainedIdentities,
					 std::size_t maximumRelatedIdentities, IndexPnpIdKind kind,
					 std::string_view publishedId, std::string_view classGuid, bool hardwareOnly)
{
	relation.error = resolution.error ;
	// 古いcallbackを現在のrelationへ適用しない
	if( resolution.context != relation.context) {
		relation.reason = IndexRecordMatchReason::RESOLVER_CONTEXT_MISMATCH ;
		return ;
	}

	const bool verifiedPartial =
		!hardwareOnly && !resolution.completed && resolution.positiveProof &&
		resolution.positiveProof->matches(
			relation.context, kind, publishedId, classGuid, GetCurrentThreadId(),
			resolution.devices, resolution.error) ;	// 公開DTOだけでは成立しない同native根拠です
	const bool verifiedDevices = verifiedDeviceProofs( resolution, kind, publishedId, classGuid,
													  hardwareOnly) ;	// 同用途の個別証拠
	// 存在する個別証拠が不正な結果を完全DTOへ読み替えません
	if( (!resolution.deviceProofs.empty() || (hardwareOnly && !resolution.devices.empty())) &&
	   !verifiedDevices) {
		relation.reason = IndexRecordMatchReason::INVALID_OPAQUE_RESULT ;
		return ;
	}

	// 発行済みpartial証拠のcompletedを変更して完全成功へ読み替えません
	if( resolution.positiveProof && (resolution.completed || hardwareOnly)) {
		relation.reason = IndexRecordMatchReason::INVALID_OPAQUE_RESULT ;
		return ;
	}

	// 私有positive根拠のない元失敗を独立した障害として保持します
	if( FAILED( static_cast<HRESULT>( resolution.error)) && !verifiedPartial && !verifiedDevices) {
		relation.reason = IndexRecordMatchReason::RESOLVER_FAILED ;
		return ;
	}

	// 部分的な戻りidentityを照合完了とみなさない
	if( !resolution.completed && !verifiedPartial && !verifiedDevices) {
		relation.reason = IndexRecordMatchReason::RESOLVER_INCOMPLETE ;
		return ;
	}

	// 不正な大量結果を解析せず、有限戻り枠を拒否する
	if( resolution.devices.size() > INDEX_LOOKUP_PRESENT_MAX) {
		relation.reason = IndexRecordMatchReason::INVALID_OPAQUE_RESULT ;
		return ;
	}

	std::set<std::wstring_view> seen ;	// Callback内の重複identityを検出する借用集合
	// 有限な戻りopaqueを一度ずつ確認し、最初の未知または重複で停止する
	for( const auto &device : resolution.devices) {
		// 未知opaque・空値・重複を合法な非一意結果へ読み替えない
		if( device.empty() || !present.contains( device) || !seen.insert( device).second) {
			relation.reason = IndexRecordMatchReason::INVALID_OPAQUE_RESULT ;
			return ;
		}
	}

	// Batch全体の保持枠を超える戻り値を部分的な成功へ削らない
	if( resolution.devices.size() > maximumRelatedIdentities - retainedIdentities) {
		relation.reason = IndexRecordMatchReason::BUDGET_EXHAUSTED ;
		return ;
	}

	relation.relatedDevices = resolution.devices ;
	retainedIdentities += resolution.devices.size() ;
	// 個別観測だけでは全体不足を成功へ変更せず、全cohortと元診断を保持します
	if( !resolution.completed && !verifiedPartial) {
		relation.reason = FAILED( static_cast<HRESULT>( resolution.error))
							  ? IndexRecordMatchReason::RESOLVER_FAILED
							  : IndexRecordMatchReason::RESOLVER_INCOMPLETE ;
		return ;
	}

	// 他node不足を正常完了へ変えず、元errorと既知positiveを独立した区分で保持します
	if( verifiedPartial) {
		relation.state		   = IndexRecordMatchState::VERIFIED_PARTIAL ;
		relation.reason		   = IndexRecordMatchReason::VERIFIED_POSITIVE_PARTIAL ;
		relation.positiveProof = resolution.positiveProof ;
		// 検証済み部分集合が一deviceのときだけ独立した準備対象へ結べます
		if( resolution.devices.size() == 1U) {
			relation.deviceIdentity = resolution.devices.front() ;
		}

		return ;
	}

	relation.state	= IndexRecordMatchState::UNMATCHED ;
	relation.reason = resolution.devices.empty() ? IndexRecordMatchReason::NO_RELATION
												 : IndexRecordMatchReason::NON_UNIQUE_RELATION ;
	// 完了した一つのpresent opaqueだけをread-only関係へ結ぶ
	if( resolution.devices.size() == 1U) {
		relation.deviceIdentity = resolution.devices.front() ;
		relation.state			= IndexRecordMatchState::MATCHED ;
		relation.reason			= IndexRecordMatchReason::UNIQUE_RELATION ;
		// 端末HardwareIds限定の一意照合も発行元の証拠を保持する
		if( hardwareOnly) {
			relation.deviceProof		 = resolution.deviceProofs.front() ;
			relation.resolutionCompleted = resolution.completed ;
		}
	}
}

} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 保存済みconst snapshotの所有を共有し、関係を所有します
 * @param[in] snapshot 完全な原保存snapshot
 * @param[in] relations 同contextの有限関係
 * @param[in] context 元scanの完全context。取得operationへ書き換えません
 * @param[in] progress 同じlookup内だけで検査・commitした原record範囲です
 * @param[in] nativeLease Native元inventoryだけの共有weak寿命証拠です。genericでは空です
 */
//------------------------------------------------------------------------------
SignedIndexRecordLookup::SignedIndexRecordLookup(
	std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot,
	std::vector<IndexRecordRelation> relations, const IndexLookupContext context,
	IndexLookupProgress progress, std::shared_ptr<const NativeIndexLookupLease> nativeLease)
	: snapshot_( std::move( snapshot)), relations_( std::move( relations)), context_( context),
	  progress_( progress), nativeLease_( std::move( nativeLease))
{
}

//------------------------------------------------------------------------------
/**
 * @brief native由来の署名索引について元列挙の寿命と所有threadだけを検査します
 * @param[in] context 今回の取得が参照する元完全contextです
 * @return native元列挙が有効ならtrueです。非nativeは元の検査を適用します
 */
//------------------------------------------------------------------------------
bool SignedIndexRecordLookup::hasLiveNativeOwner( const IndexLookupContext context) const noexcept
{
	return !nativeLease_ || nativeLease_->matchesOwner( context, GetCurrentThreadId()) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原hash・世代・policy・source／record／UNKNOWNを保持するsnapshotを借用します
 * @return 本lookupが所有する不変snapshot
 */
//------------------------------------------------------------------------------
const AuthenticatedIndexSnapshot &SignedIndexRecordLookup::snapshot() const noexcept
{
	return *snapshot_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 公開ID文字列を含まない有限関係を借用します
 * @return 本lookupの寿命まで有効な不変span
 */
//------------------------------------------------------------------------------
std::span<const IndexRecordRelation> SignedIndexRecordLookup::relations() const noexcept
{
	return relations_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 完全record prefixと実callback数だけを借用します
 * @return 同object寿命まで有効な私有構築済み進行です
 */
//------------------------------------------------------------------------------
const IndexLookupProgress &SignedIndexRecordLookup::progress() const noexcept
{
	return progress_ ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原保存snapshotの有限record batchを同worker resolverへ結びます
 * @param[in] snapshot Commit／reloadだけが発行した完全const snapshotの共有所有。Null・move元を拒否します。正規結果を一度moveしてconst
 *                   所有とし、可変aliasを使いません
 * @param[in] request 呼出しが要求する正のcontext
 * @param[in] current 現workerが確認した正のcontext
 * @param[in] present 同contextのopaque present集合。本呼出し中不変です
 * @param[in] budget 有限batchとcallback枠
 * @param[in] nowUtc 現信頼UTC。元本文の有効期間外・確認不能は拒否し、期限切れ領域は未判定です
 * @param[in] resolver 同workerの借用callback。nullptrは未実行として保持します
 * @return 入力拒否、または元snapshotと各関係を所有する読取り結果
 * @note 参照を外へ保持せず、例外を境界で診断へ変換します。独立入力は独立workerで呼出し可能です
 */
//------------------------------------------------------------------------------
IndexRecordLookupResult lookupSignedIndexRecords(
	std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot, const IndexLookupContext request,
	const IndexLookupContext current, const std::span<const std::wstring> present,
	const IndexLookupBudget budget, const std::optional<std::chrono::sys_seconds> nowUtc,
	const IndexPublicIdResolver *resolver) noexcept
{
	IndexRecordLookupResult result ;	// 拒否時には所有lookupを発行しない
	try {
		// 所有根拠のないnull入力ではmetadataやcallbackへ進まない
		if( !snapshot) {
			return result ;
		}

		const auto &schema	 = snapshot->schemaReceipt() ;	// 原schema receiptの呼出し中だけの借用
		const auto &asset	 = schema.assetBytes() ;		// 原byte根拠を借用する
		const auto &manifest = asset.manifest().data() ;	// Scalarだけ残ったmove元も検査する
		// 必須の原byteと認証identityが欠けたmove元をcallbackへ渡さない
		if( snapshot->originalEnvelope().empty() || snapshot->originalGzip().empty() ||
		   asset.expandedBytes().empty() || manifest.manifestBytes.empty() ||
		   manifest.repository.empty() || manifest.channel.empty() || manifest.keyId.empty() ||
		   manifest.asset.tag.empty() || manifest.asset.name.empty()) {
			return result ;
		}

		// 信頼UTC不明を期限内と推測しない
		if( !nowUtc) {
			result.status = IndexRecordLookupStatus::TIME_UNAVAILABLE ;
			return result ;
		}

		// 署名発行前のsnapshotを利用しない
		if( *nowUtc < manifest.publishedAtUtc) {
			result.status = IndexRecordLookupStatus::NOT_YET_VALID ;
			return result ;
		}

		// 署名期限と同値を含め、期限切れsnapshotを利用しない
		if( *nowUtc >= manifest.expiresAtUtc) {
			result.status = IndexRecordLookupStatus::EXPIRED ;
			return result ;
		}

		// 不明またはstaleなworker contextをopaque集合へ結ばない
		if( request.operationId == 0U || request.scanSessionId == 0U ||
		   request.inventoryGeneration == 0U || request != current) {
			result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
			return result ;
		}

		const auto records = snapshot->consumerRecords() ;	// 同snapshotが所有する端末用の原順序です
		// Batch位置と件数・callback枠を有限にし、加算前に残量へ制限する
		if( present.size() > INDEX_LOOKUP_PRESENT_MAX || budget.recordOffset > records.size() ||
		   budget.recordCount == 0U || budget.recordCount > INDEX_LOOKUP_RECORD_BATCH_MAX ||
		   budget.resolverCalls > INDEX_LOOKUP_RESOLVER_CALL_MAX ||
		   budget.maximumRelations > index_capacity::RETAINED_RELATIONS ||
		   budget.maximumRelatedIdentities > index_capacity::RETAINED_OPAQUE_IDENTITIES) {
			result.status = IndexRecordLookupStatus::BUDGET_LIMIT ;
			return result ;
		}

		std::set<std::wstring_view> identities ;	// Workerの有限opaqueを呼出し中だけ借用する
		// Presentの全opaqueを確認し、空・重複ではcallback前に停止する
		for( const auto &identity : present) {
			// 不正present集合から照合成功を作らない
			if( identity.empty() || !identities.insert( identity).second) {
				result.status = IndexRecordLookupStatus::INVALID_PRESENT_SET ;
				return result ;
			}
		}

		const auto nativeLease = resolver != nullptr ? resolver->leaseProof()
													 : nullptr ;	// 元native factoryの証拠だけです
		// staleな元stateを同contextへ読み替えません
		if( nativeLease && !nativeLease->matches( request, GetCurrentThreadId())) {
			result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
			return result ;
		}

		const auto count =
			// 要求prefixです
			std::min( budget.recordCount, records.size() - budget.recordOffset) ;
		// 本呼出しだけが確定する原record coverageです
		IndexLookupProgress progress ;
		progress.recordOffset	  = budget.recordOffset ;
		progress.nextRecordOffset = budget.recordOffset ;
		std::size_t						 retainedIdentities{} ;	// commit済みbatchのopaque総数です
		std::vector<IndexRecordRelation> relations ;			// 完全recordだけを単独所有します
		// 全IDが入るrecordを原順序で処理し、未commit recordは元位置に残します
		for( std::size_t offset = 0U; offset < count; ++offset) {
			const auto	index	  = budget.recordOffset + offset ;		// 原recordの位置です
			const auto &record	  = records[index] ;					// 不変の認証済み原recordです
			const auto &evidence  = record.publishedIdentityEvidence ;	// 原公開申告です
			const auto	publicIds = publishedIdCount( record) ;			// 原公開IDの分母です
			const bool	regionExpired =
				*nowUtc >= snapshot->consumerRecordRegion( index).expiresAtUtc ;	// 期限同値も失効です
			const auto machineRejection =
				platformMachineRejection( record,
										 // 同じスキャンの機種と型番です
										 snapshot->platformMachine( request)) ;
			// 端末条件の拒否を優先し、通過したレコードだけWiXのWindows条件を適用します
			const auto recordRejection =
				machineRejection ? machineRejection
								 : wixHostRejection( record, snapshot->windowsHost( request)) ;
			const bool hardwareOnly =
				// 照合する端末IDの範囲です
				requiresExactIndexHardwareMatch( record) ;
			const auto requiredCalls =
				// 全Modelsの処理件数と端末照合の呼出し数を分ける
				record.wixContentEvidence && publicIds != 0U
					? static_cast<std::size_t>(
						  std::ranges::count_if( evidence.pnpIds, isExactWixHardwareId))
				: hardwareOnly && publicIds != 0U
					? (record.archiveHardwareScope
						   ? record.archiveHardwareScope->hardwareIdIndices.size()
					   : record.catalogHardwareScope
						   ? record.catalogHardwareScope->hardwareIdIndices.size()
						   : record.platformDeviceScope->hardwareIdIndices.size())
					: publicIds ;
			// 取消し・期限後に次recordを開始しません
			if( budget.stopRequested && budget.stopRequested()) {
				progress.stopReason = IndexLookupStopReason::STOP_REQUESTED ;
				break ;
			}

			// 次record全体が残callback枠へ収まるprefixだけを選びます
			if( !regionExpired && !recordRejection && resolver != nullptr &&
			   requiredCalls > budget.resolverCalls - progress.resolverCalls) {
				progress.stopReason = IndexLookupStopReason::CALL_BUDGET ;
				break ;
			}

			IndexRecordRelation base ;	// 同recordの原hash・identity・contextです
			base.recordIndex  = index ;
			base.context	  = request ;
			base.recordSha256 = record.recordSha256 ;
			base.sourceId	  = record.sourceId ;
			base.recordId	  = record.recordId ;
			std::vector<IndexRecordRelation> staged ;			// 原aggregateと全投影をrecord単位で保留します
			auto		stagedIdentities = retainedIdentities ;	// 未commit時は元累計へ戻ります
			std::size_t definitive{} ;							// このrecordの完了した確定不一致ID数です
			const auto	isDefinitive = []( const IndexRecordRelation &relation) {
				 return relation.state == IndexRecordMatchState::UNMATCHED &&
						relation.reason == IndexRecordMatchReason::NO_RELATION &&
						relation.error == 0U && !relation.deviceIdentity &&
						relation.relatedDevices.empty() && !relation.positiveProof &&
						!relation.deviceProof ;
			} ; // 唯一の不一致集約条件です
			bool stopped{} ;	// 一件でも途中停止ならrecord全体を未commitにします
			// 失効行は全IDの元位置を保持したまま、レコード単位の未判定一件だけを発行します
			if( regionExpired) {
				base.reason = IndexRecordMatchReason::RECORD_REGION_EXPIRED ;
				staged.push_back( std::move( base)) ;
			}
			// 機種又はWindowsの対象条件が成立しない行は個別デバイスを照合しません
			else if( recordRejection) {
				base.reason = *recordRejection ;
				base.state =
					(*recordRejection == IndexRecordMatchReason::PLATFORM_MACHINE_MISMATCH ||
					 *recordRejection == IndexRecordMatchReason::WIX_HOST_MISMATCH)
						? IndexRecordMatchState::UNMATCHED
						: IndexRecordMatchState::UNDETERMINED ;
				staged.push_back( std::move( base)) ;
			}
			// 公開証拠不足を不存在成功へ変えず、一件の未判定として保持します
			else if( publicIds == 0U) {
				staged.push_back( std::move( base)) ;
			} else {
				// 全公開IDを原順序で照合し、途中停止で次recordへ飛びません
				for( std::size_t idIndex = 0U; idIndex < publicIds; ++idIndex) {
					// 各同期IDの前にも協調停止を確認します
					if( budget.stopRequested && budget.stopRequested()) {
						progress.stopReason = IndexLookupStopReason::STOP_REQUESTED ;
						stopped				= true ;
						break ;
					}

					auto relation		   = base ;	// 元recordへ結ぶ独立したID結果です
					relation.publicIdIndex = idIndex ;
					const auto &id		   = evidence.pnpIds[idIndex] ;	// 原公開IDの借用です
					// 公式表の対象外は端末への照合を試みず、確定不一致として元位置を保持する
					if( !isIndexLookupIdEligible( record, idIndex)) {
						relation.state	= IndexRecordMatchState::UNMATCHED ;
						relation.reason = IndexRecordMatchReason::NO_RELATION ;
					}
					// 対象IDの端末照合が利用できない場合は未判定を保持する
					else if( resolver == nullptr) {
						relation.reason = IndexRecordMatchReason::RESOLVER_UNAVAILABLE ;
					} else {
						++progress.resolverCalls ;
						const auto stagedBefore =
							// 例外時にこのIDの全投影だけを戻します
							staged.size() ;
						const auto identitiesBefore = stagedIdentities ;	// このID前のopaque累計です
						try {
							const auto resolution =
								// 公式配布対象だけをHardwareIds限定で照合します
								hardwareOnly
									? resolver->resolveHardwareId( id.value, evidence.classGuid,
																  request, present)
									: resolver->resolve( id.kind, id.value, evidence.classGuid,
														request, present) ;
							// 同期処理中の停止は部分recordの発行を禁止します
							if( budget.stopRequested && budget.stopRequested()) {
								result.error = result.error != 0U ? result.error : resolution.error ;
								progress.stopReason = IndexLookupStopReason::STOP_REQUESTED ;
								stopped				= true ;
								break ;
							}

							applyResolution( relation, resolution, identities, stagedIdentities,
											budget.maximumRelatedIdentities, id.kind, id.value,
											evidence.classGuid, hardwareOnly) ;
							// 最初の元診断は保持容量拒否時にも失いません
							if( result.error == 0U) {
								result.error = relation.error ;
							}

							// Opaque不足を一部のpositiveへ切り詰めません
							if( relation.reason == IndexRecordMatchReason::BUDGET_EXHAUSTED) {
								progress.stopReason = IndexLookupStopReason::RETAINED_CAPACITY ;
								stopped				= true ;
								break ;
							}

							// 認証済み個別投影は原aggregateと全slotを原子的に保留します
							if( !relation.deviceIdentity && !relation.relatedDevices.empty() &&
							   verifiedDeviceProofs( resolution, id.kind, id.value,
													evidence.classGuid, hardwareOnly)) {
								const auto proofCount =
									static_cast<std::size_t>( std::ranges::count_if(
										resolution.deviceProofs, []( const auto &proof) {
											return static_cast<bool>( proof) ;
										})) ; // 認証済みslot数です
								// 全投影・全opaqueの残枠がなければrecord全体を残します
								if( proofCount == 0U ||
								   staged.size() + proofCount + 1U >
									   budget.maximumRelations - relations.size() ||
								   resolution.devices.size() >
									   (budget.maximumRelatedIdentities - stagedIdentities) /
										   proofCount) {
									progress.stopReason = IndexLookupStopReason::RETAINED_CAPACITY ;
									stopped				= true ;
									break ;
								}

								staged.push_back( relation) ;
								// 最大32slotを同順で保持し、未認証slotを成功へ投影しません
								for( std::size_t deviceIndex = 0U;
									deviceIndex < resolution.devices.size(); ++deviceIndex) {
									// 不足slotは元aggregateにだけ残します
									if( !resolution.deviceProofs[deviceIndex]) {
										continue ;
									}

									auto projected = relation ;	// 元tupleと全cohortをcopyします
									projected.deviceIdentity = resolution.devices[deviceIndex] ;
									projected.deviceProof	 = resolution.deviceProofs[deviceIndex] ;
									projected.resolutionCompleted = resolution.completed ;
									projected.positiveProof.reset() ;
									projected.state = IndexRecordMatchState::VERIFIED_DEVICE ;
									projected.reason =
										IndexRecordMatchReason::VERIFIED_DEVICE_PROJECTION ;
									staged.push_back( std::move( projected)) ;
								}

								stagedIdentities += resolution.devices.size() * proofCount ;
								continue ;
							}
						} catch( const std::bad_alloc &) {
							staged.resize( stagedBefore) ;
							stagedIdentities	   = identitiesBefore ;
							relation			   = base ;
							relation.publicIdIndex = idIndex ;
							relation.reason		   = IndexRecordMatchReason::RESOLVER_EXCEPTION ;
							relation.error		   = static_cast<NativeError>( E_OUTOFMEMORY) ;
						} catch( ...) {
							staged.resize( stagedBefore) ;
							stagedIdentities	   = identitiesBefore ;
							relation			   = base ;
							relation.publicIdIndex = idIndex ;
							relation.reason		   = IndexRecordMatchReason::RESOLVER_EXCEPTION ;
							relation.error		   = static_cast<NativeError>( E_FAIL) ;
						}
					}

					// 最初の元callback診断を停止時も保持します
					if( result.error == 0U) {
						result.error = relation.error ;
					}

					const bool noRelation =
						// 私有coverageへ集約できる元結果です
						isDefinitive( relation) ;
					definitive += noRelation ? 1U : 0U ;
					// 集約可能な確定不一致以外は、一時結果も残保持枠内だけで保持します
					if( !budget.compactNoRelations || !noRelation) {
						// 次tupleの確保前にrecord全体を残件へ戻します
						if( staged.size() >= budget.maximumRelations - relations.size()) {
							progress.stopReason = IndexLookupStopReason::RETAINED_CAPACITY ;
							stopped				= true ;
							break ;
						}

						staged.push_back( std::move( relation)) ;
					}

					// 一件のrecordでも一時保持枠を超えたら一部だけを発行しません
					if( staged.size() > index_capacity::RETAINED_RELATIONS) {
						progress.stopReason = IndexLookupStopReason::RETAINED_CAPACITY ;
						stopped				= true ;
						break ;
					}
				}
			}

			// callback中に失効した元inventoryから完全recordを発行しません
			if( nativeLease && !nativeLease->matches( request, GetCurrentThreadId())) {
				result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
				return result ;
			}

			// 不足又はcommit直前の停止では原record全体を残件にします
			if( stopped || (budget.stopRequested && budget.stopRequested())) {
				progress.stopReason =
					stopped ? progress.stopReason : IndexLookupStopReason::STOP_REQUESTED ;
				break ;
			}

			// 全recordの確定結果が残保持枠へ入る場合だけcommitします
			if( staged.size() > budget.maximumRelations - relations.size()) {
				progress.stopReason = IndexLookupStopReason::RETAINED_CAPACITY ;
				break ;
			}

			relations.reserve( relations.size() + staged.size()) ;
			// 完全recordの全関係を一括moveした後だけ進行を確定します
			for( auto &relation : staged) {
				relations.push_back( std::move( relation)) ;
			}

			retainedIdentities = stagedIdentities ;
			++progress.completedRecords ;
			progress.nextRecordOffset = index + 1U ;
			progress.processedPublicIds += publicIds ;
			progress.definitiveNoRelationIds += definitive ;
			progress.compactedNoRelationIds += budget.compactNoRelations ? definitive : 0U ;
		}

		result.lookup =
			SignedIndexRecordLookup{snapshot, std::move( relations), request, progress, nativeLease} ;
		result.status = IndexRecordLookupStatus::LOOKUP_READY ;
		return result ;
	} catch( const std::bad_alloc &) {
		result.status = IndexRecordLookupStatus::OUT_OF_MEMORY ;
		result.error  = static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		result.status = IndexRecordLookupStatus::INTERNAL_FAILURE ;
		result.error  = static_cast<NativeError>( E_FAIL) ;
	}

	result.lookup.reset() ;
	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同ownerが発行した全batchだけを一つの不変lookupへ凍結します
 * @param[in] snapshot 同scanの原保存snapshotの共有所有
 * @param[in] context 元scanの完全context
 * @param[in] batches 私有構築済みbatch。公開relationから再構築しません
 * @param[in] nowUtc 現信頼UTC。元本文の期限を確認し、失効領域の正の関係を無効にします
 * @return 同snapshot・全context・原record結合成立時だけ集約lookup
 */
//------------------------------------------------------------------------------
IndexRecordLookupResult SignedIndexRecordLookup::freezeOwnedBatches(
	std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot, const IndexLookupContext context,
	const std::span<const SignedIndexRecordLookup> batches,
	const std::optional<std::chrono::sys_seconds>  nowUtc) noexcept
{
	const auto recordEnd = snapshot ? snapshot->consumerRecords().size() : 0U ;	// 空終端batch位置
	auto result = lookupSignedIndexRecords( snapshot, context, context, {}, {recordEnd, 1U, 0U},
										   nowUtc, nullptr) ;	// 原byte・期限・contextの共通再検査
	// 入力拒否では集約用の空lookupも発行しません
	if( !result.lookup) {
		return result ;
	}

	result.lookup.reset() ;
	try {
		std::vector<IndexRecordRelation> relations ;	// 保持する元tupleだけの私有集合です
		std::set<std::tuple<std::size_t, std::optional<std::size_t>, std::optional<std::wstring>>>
													  seen ;			// 全元tupleの一意性です
		std::size_t									  relatedCount{} ;	// 同scanの全opaque保持数です
		std::shared_ptr<const NativeIndexLookupLease> nativeLease ;		// 全batchで同一の元証拠です
		bool				firstBatch{true} ;							// generic空証拠とnative証拠の混在も拒否します
		IndexLookupProgress progress ;									// 連続した完全record prefixだけを集約します
		const auto			records = snapshot->consumerRecords() ;		// 同一原snapshotの借用です
		// 私有batchの所有・進行範囲・原tupleを全件再検査します
		for( const auto &batch : batches) {
			// 同scanの元private leaseだけを共有し、新しい証拠へ結び直しません
			if( firstBatch) {
				nativeLease = batch.nativeLease_ ;
				firstBatch	= false ;
			}

			// 失効又は別factoryの証拠を部分的に採用しません
			if( batch.nativeLease_ != nativeLease ||
			   (nativeLease && !nativeLease->matches( context, GetCurrentThreadId()))) {
				result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
				return result ;
			}

			const auto &coverage = batch.progress_ ;	// DTOから構築できない元commit範囲です
			// 別snapshot/context、抜け・重複したprefixを受理しません
			if( batch.snapshot_ != snapshot || batch.context_ != context ||
			   coverage.recordOffset != progress.nextRecordOffset ||
			   coverage.completedRecords == 0U || coverage.recordOffset > records.size() ||
			   coverage.completedRecords > records.size() - coverage.recordOffset ||
			   coverage.nextRecordOffset != coverage.recordOffset + coverage.completedRecords) {
				result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
				return result ;
			}

			// 全scanの入力・関係・opaque枠を加算前に検査します
			if( batch.relations_.size() > index_capacity::RETAINED_RELATIONS - relations.size() ||
			   coverage.processedPublicIds >
				   index_capacity::WHOLE_PUBLIC_IDS - progress.processedPublicIds) {
				result.status = IndexRecordLookupStatus::BUDGET_LIMIT ;
				return result ;
			}

			std::size_t expectedIds{} ;	// 同認証範囲に実在する公開ID総数です
			// 完全record範囲の全IDを間引かず数えます
			for( auto index = coverage.recordOffset; index < coverage.nextRecordOffset; ++index) {
				expectedIds += publishedIdCount( records[index]) ;
			}

			std::size_t aggregateIds{} ;	// 投影を重複加算しない元公開IDtuple数です
			// 全保持tupleを元record/hash/source/公開IDとleaseへ結び直します
			for( const auto &relation : batch.relations_) {
				// 他recordへの転用や重複tupleを拒否します
				if( relation.context != context || relation.recordIndex < coverage.recordOffset ||
				   relation.recordIndex >= coverage.nextRecordOffset ||
				   !seen.emplace( relation.recordIndex, relation.publicIdIndex,
								 relation.deviceIdentity)
						.second) {
					result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
					return result ;
				}

				const auto &record	 = records[relation.recordIndex] ;		// 不変の原recordです
				const auto &evidence = record.publishedIdentityEvidence ;	// 元ID/classの借用です
				// 原hash/identity又は個別ID位置が変わったtupleを拒否します
				if( relation.recordSha256 != record.recordSha256 ||
				   relation.sourceId != record.sourceId || relation.recordId != record.recordId ||
				   (relation.publicIdIndex && *relation.publicIdIndex >= evidence.pnpIds.size()) ||
				   relation.relatedDevices.size() >
					   index_capacity::RETAINED_OPAQUE_IDENTITIES - relatedCount) {
					result.status = IndexRecordLookupStatus::BUDGET_LIMIT ;
					return result ;
				}

				const bool hardwareOnly =
					// 元配布の完全ID条件です
					requiresExactIndexHardwareMatch( record) ;
				// 端末へ結び付く対象付き関係は元位置とHardwareIds限定の証拠を必要とする
				if( hardwareOnly && relation.deviceIdentity &&
				   (!relation.publicIdIndex ||
					!isIndexLookupIdEligible( record, *relation.publicIdIndex) ||
					!relation.deviceProof || relation.positiveProof ||
					platformMachineRejection( record, snapshot->platformMachine( context)) ||
					wixHostRejection( record, snapshot->windowsHost( context)))) {
					result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
					return result ;
				}

				// 発行済みpartial/device証拠は凍結時にも元leaseと全tupleへ完全一致させます
				if( relation.positiveProof || relation.deviceProof) {
					// 公開ID又は対象opaqueがない証拠を補完しません
					if( !relation.publicIdIndex ||
					   (relation.deviceProof && !relation.deviceIdentity)) {
						result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
						return result ;
					}

					const auto &id = evidence.pnpIds[*relation.publicIdIndex] ;	// 同原公開IDです
					// 期限後・別cohort・別workerの私有証拠を拒否します
					if( (relation.positiveProof &&
						!relation.positiveProof->matches(
							context, id.kind, id.value, evidence.classGuid, GetCurrentThreadId(),
							relation.relatedDevices, relation.error)) ||
					   (relation.deviceProof &&
						!relation.deviceProof->matches(
							context, id.kind, id.value, evidence.classGuid, GetCurrentThreadId(),
							relation.relatedDevices, relation.error, relation.resolutionCompleted,
							*relation.deviceIdentity, hardwareOnly))) {
						result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
						return result ;
					}
				}

				// 領域の失効や端末機種の不成立で照合していない行は全IDを一件で表します
				if( !relation.publicIdIndex &&
				   (relation.reason == IndexRecordMatchReason::RECORD_REGION_EXPIRED ||
					relation.reason == IndexRecordMatchReason::PLATFORM_MACHINE_UNAVAILABLE ||
					relation.reason == IndexRecordMatchReason::PLATFORM_MACHINE_MISMATCH)) {
					aggregateIds += publishedIdCount( record) ;
				}

				aggregateIds += relation.publicIdIndex &&
										relation.state != IndexRecordMatchState::VERIFIED_DEVICE
									? 1U
									: 0U ;
				// Batch完了後に失効した元関係から取得に使える端末証拠を発行しません
				if( !relation.relatedDevices.empty() &&
				   *nowUtc >= snapshot->consumerRecordRegion( relation.recordIndex).expiresAtUtc) {
					// 元IDの未判定はaggregateに一件だけ保持します
					if( relation.state == IndexRecordMatchState::VERIFIED_DEVICE) {
						continue ;
					}

					// 元record、ID位置、元診断だけを未判定の関係へ保持します
					relations.push_back( {.recordIndex	= relation.recordIndex,
										 .publicIdIndex = relation.publicIdIndex,
										 .context		= relation.context,
										 .recordSha256	= relation.recordSha256,
										 .sourceId		= relation.sourceId,
										 .recordId		= relation.recordId,
										 .reason = IndexRecordMatchReason::RECORD_REGION_EXPIRED,
										 .error	 = relation.error}) ;
					continue ;
				}

				relatedCount += relation.relatedDevices.size() ;
				relations.push_back( relation) ;
			}

			// 元公開IDを全件報告し、確定不一致と期限切れ領域の集約を区別します
			if( expectedIds != coverage.processedPublicIds ||
			   coverage.compactedNoRelationIds > expectedIds ||
			   aggregateIds != expectedIds - coverage.compactedNoRelationIds ||
			   coverage.definitiveNoRelationIds > expectedIds ||
			   coverage.compactedNoRelationIds > coverage.definitiveNoRelationIds) {
				result.status = IndexRecordLookupStatus::STALE_CONTEXT ;
				return result ;
			}

			progress.completedRecords += coverage.completedRecords ;
			progress.nextRecordOffset = coverage.nextRecordOffset ;
			progress.processedPublicIds += coverage.processedPublicIds ;
			progress.definitiveNoRelationIds += coverage.definitiveNoRelationIds ;
			progress.compactedNoRelationIds += coverage.compactedNoRelationIds ;
			progress.resolverCalls += coverage.resolverCalls ;
			progress.stopReason = coverage.stopReason ;
		}

		result.lookup = SignedIndexRecordLookup{std::move( snapshot), std::move( relations), context,
												progress, nativeLease} ;
		result.status = IndexRecordLookupStatus::LOOKUP_READY ;
	} catch( const std::bad_alloc &) {
		result.status = IndexRecordLookupStatus::OUT_OF_MEMORY ;
		result.error  = static_cast<NativeError>( E_OUTOFMEMORY) ;
	} catch( ...) {
		result.status = IndexRecordLookupStatus::INTERNAL_FAILURE ;
		result.error  = static_cast<NativeError>( E_UNEXPECTED) ;
	}

	return result ;
}

} // namespace drivercrate
