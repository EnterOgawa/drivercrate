//------------------------------------------------------------------------------
/**
 * @file metadata_inventory_tests.cpp
 * @brief 現在属性列挙の上限・欠損・停止境界の決定的試験。
 * @version 01.04.02
 * @date 2026/09/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/12  SetupAPIの非実機列挙fixtureを追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  Device観測・Code 28・有限readerのfixtureを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/11  公表IDの種別・多対多・世代・失効試験を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/10/11  通常workerの同scan署名索引読取り境界を接続。
 * Ver.01.03.01 Shunji Ogawa  2026/10/11  元照合診断と取消し・期限の同時発生回帰を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/14  未知Classの必要ID欠損と部分一致非昇格の回帰を追加。
 * Ver.01.04.01 Shunji Ogawa  2026/10/16  未配備status fixtureを実製品root照会から隔離。
 * Ver.01.04.02 Shunji Ogawa  2026/10/17  Native IDの実空listと独立size・実byteの有限回帰を追加。
 * </pre>
 *
 * @note 現在属性とdevnodeの六APIを全てfakeへ置換し、実device列挙と導入を行わない。
 * @see docs/adr/0142-metadata-only-search-contract.md
 */
//------------------------------------------------------------------------------

#include "metadata_inventory_tests.h"
#include "core/device_observation.h"
#include "core/metadata_search.h"
#include "core/metadata_search_budget.h"
#include "core/provider_registry.h"
#include "platform/driver_store_provider.h"
#include "platform/metadata_search_runner.h"
#include "platform/provider_worker_index_internal.h"
#include "platform/signed_index_store_internal.h"
#include "platform/signed_index_acquisition_adapter_internal.h"
#include "test_framework.h"

#include <devpkey.h>
#include <cfg.h>

#include <algorithm>
#include <atomic>
#include <semaphore>
#include <optional>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <iostream>
#include <memory>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <utility>

namespace drivercrate::test {
namespace {

/** @brief 一つのpropertyだけへ注入する有限fault。 */
enum class PropertyFault {
	/// 正規の値を返す。
	NONE,
	/// OSがproperty不存在を返す。
	MISSING,
	/// APIがアクセス拒否を返す。
	ACCESS_DENIED,
	/// APIがERROR_INVALID_DATAを返す。
	INVALID_ERROR,
	/// 正規の空文字を返す。
	EMPTY,
	/// 異なるproperty型を返す。
	WRONG_TYPE,
	/// UTF-16境界ではない容量を要求する。
	ODD_SIZE,
	/// 64 KiBを超える容量を要求する。
	OVER_LIMIT,
	/// 二回目の必要容量が増える。
	GROWING,
	/// 成功時の実sizeを容量より大きく返す。
	OVER_REPORTED,
	/// 成功時の実sizeを0にする。
	ZERO_RETURNED,
	/// 実size内にNULを返さない。
	UNTERMINATED,
	/// NULの後へ余剰文字を返す。
	EMBEDDED_NULL,
} ;

/** @brief Native ID propertyの実byte・必要量・返却量・元API errorを独立注入します。 */
struct IndexIdProperty {
	/// APIが実際にcopyする架空property本文です。
	std::vector<std::byte> bytes ;
	/// 成功時に返すproperty型です。
	DEVPROPTYPE			   type{DEVPROP_TYPE_STRING_LIST} ;
	/// 初回APIが通知する必要byte数です。
	DWORD				   required{} ;
	/// 二回目APIが通知する実byte数です。
	DWORD				   returned{} ;
	/// 初回APIで通知する元Win32失敗です。0は通常の必要量通知です。
	DWORD				   sizeError{} ;
	/// 二回目APIで通知する元Win32失敗です。0は成功です。
	DWORD				   valueError{} ;
} ;

/** @brief 有限な現在属性と列挙障害だけを持つSetupAPI fixture。 */
struct InventoryFixture {
	/// 明示指定時だけHardware／Compatibleの原byte契約を独立注入します。
	std::array<std::optional<IndexIdProperty>, 2U> indexIdProperties ;
	/// 既存値を既定とする架空instance本文です。通常出力へ渡しません。
	std::wstring								   instanceValue{L"fixture-native-node"} ;
	/// 既存値を既定とする架空表示名です。診断出力の非転写を検査します。
	std::wstring								   displayName{L"CP210x Fixture"} ;
	/// 索引専用scanの秘密IDだけを返す明示fixture。
	bool										   indexIds{} ;
	/// Hardware IDを同型二台で共有する場合trueです。
	bool										   sameHardware{} ;
	/// 架空公表IDをnative Compatible集合だけへ置く場合trueです。
	bool										   publishedIdInCompatible{} ;
	/// 同nodeの両native集合へ同公表IDを置く場合trueです。
	bool										   publishedIdInBothKinds{} ;
	/// 同公表IDをHardware=node0、Compatible=node1へ分ける旧非一意fixtureです。
	bool										   splitKindAcrossNodes{} ;
	/// 二台目のClassGUIDを変更する場合trueです。
	bool										   differentClass{} ;
	/// 一台目のClassGUIDを未知にする場合trueです。
	bool										   unknownClass{} ;
	/// 二台目だけ未知classを返す場合trueです。
	bool										   unknownSecondClass{} ;
	/// Property faultを一nodeだけへ限定します。最大値は全nodeです。
	DWORD										   faultNode{std::numeric_limits<DWORD>::max()} ;
	/// 公開文法subset外の安全な別native IDも同listへ加える場合trueです。
	bool										   extraNativeId{} ;
	/// 架空IDの本文。試験以外へ出しません。
	std::wstring								   indexId{L"TESTBUS\\SYNTH_0001"} ;
	/// 一巡目で存在すると報告するnode数。上限probeを超えて列挙しない。
	DWORD										   nodes{2U} ;
	/// trueなら情報集合の開始に失敗する。
	bool										   openFailure{} ;
	/// trueの間は件数確認の一巡目。
	bool										   counting{true} ;
	/// 一巡目でAPI失敗するindex。最大値は注入なし。
	DWORD										   failCountAt{std::numeric_limits<DWORD>::max()} ;
	/// 二巡目で消失を報告するindex。最大値は注入なし。
	DWORD										   disappearAt{std::numeric_limits<DWORD>::max()} ;
	/// このnodeだけinstance ID取得を拒否する。最大値は注入なし。
	DWORD								  missingInstanceAt{std::numeric_limits<DWORD>::max()} ;
	/// 全表示属性を欠損させる場合true。
	bool								  missingAttributes{} ;
	/// 一つの属性へ注入するfault。
	PropertyFault						  propertyFault{PropertyFault::NONE} ;
	/// Fault対象の固定property。値自体を外部送信しない。
	DEVPROPKEY							  faultKey{DEVPKEY_Device_DriverVersion} ;
	/// Fault対象propertyのAPI呼出し回数。
	unsigned							  faultPropertyCalls{} ;
	/// trueなら固定FILETIMEを現在driverの日付として返す。
	bool								  dateAvailable{} ;
	/// OS時計ではない合成日付。初期値は1601年1月1日。
	FILETIME							  dateValue{} ;
	/// Node statusの元CONFIGRET。
	CONFIGRET							  nodeResult{CR_SUCCESS} ;
	/// Node statusの合成bit集合。
	ULONG								  nodeFlags{} ;
	/// 有効bitがない場合には無視される合成problem code。
	ULONG								  nodeProblem{} ;
	/// Devnode照会の回数。
	unsigned							  nodeCalls{} ;
	/// Instance ID bufferを非終端で返す場合true。
	bool								  unterminatedInstance{} ;
	/// Providerが参照するこのoperationだけの取消しflag。
	bool								  cancelled{} ;
	/// Fixture時計のmillisecond。
	std::uint64_t						  ticks{} ;
	/// 情報集合のopen回数。
	unsigned							  opened{} ;
	/// 情報集合のclose回数。
	unsigned							  closed{} ;
	/// 件数確認と最大一回probeの合計API回数。
	unsigned							  countCalls{} ;
	/// 二巡目の詳細列挙API回数。
	unsigned							  detailCalls{} ;
	/// 属性API照会回数。
	unsigned							  propertyCalls{} ;
	/// Hardware／Compatible IDを誤って要求した回数。
	unsigned							  secretPropertyCalls{} ;
	/// DIGCFとcbSize等の必要条件を満たす場合true。
	bool								  validArguments{true} ;
	/// 指定した同期API復帰時に取消し・期限を注入する。
	std::function<void( std::string_view)> hook ;

	/**
     * @brief 明示したAPI段階にだけ故障を注入する。
     * @param[in] stage 固定の段階名。
     */
	void								  visit( const std::string_view stage)
	{
		// Fixtureがhookを指定した場合だけ同期状態を変更する。
		if( hook) {
			hook( stage) ;
		}
	}
} ;

// 集合openには借用handleがないため、試験thread内だけの所有fixtureを参照する。
thread_local InventoryFixture *activeInventoryFixture{} ;

/**
 * @brief 全ての現在属性APIをfixtureで置換する。
 * @return 実SetupAPI handleを生成しない完全なI/O表。
 */
DriverStoreInventoryTransport  inventoryTransport()
{
	DriverStoreInventoryTransport transport ;	// 六つ全てを非実機callbackへ置換する。
	// 固定flagの情報集合要求を検査し、fixture以外のhandleを作らない。
	transport.open = []( const GUID *classGuid, PCWSTR enumerator, HWND parent,
						DWORD flags) -> HDEVINFO {
		auto &fixture = *activeInventoryFixture ;	// 当該試験scopeの所有状態。
		++fixture.opened ;
		fixture.validArguments &= classGuid == nullptr && enumerator == nullptr &&
								  parent == nullptr && flags == (DIGCF_ALLCLASSES | DIGCF_PRESENT) ;
		fixture.visit( "open") ;
		// 開始失敗では有効handleを返さない。
		if( fixture.openFailure) {
			SetLastError( ERROR_ACCESS_DENIED) ;
			return INVALID_HANDLE_VALUE ;
		}

		return &fixture ;
	} ;
	// 同じ集合の一巡目・一回probe・二巡目を区別して有限に再現する。
	transport.enumerate = []( HDEVINFO handle, DWORD index, PSP_DEVINFO_DATA device) -> BOOL {
		auto &fixture = *static_cast<InventoryFixture *>( handle) ;	// 列挙する合成集合。
		fixture.validArguments &= device->cbSize == sizeof( SP_DEVINFO_DATA) && index <= 4096U ;
		const bool counting = fixture.counting ;	// 当該呼出しがどの巡回に所属するか固定する。
		fixture.countCalls += counting ? 1U : 0U ;
		fixture.detailCalls += counting ? 0U : 1U ;
		// 本体失敗、通常終端、上限probeの後は詳細列挙へ切り替える。
		if( counting && (index == fixture.failCountAt || index >= fixture.nodes || index == 4096U)) {
			fixture.counting = false ;
		}

		// 一巡目のprobe障害も元のnative errorで返す。
		if( counting && index == fixture.failCountAt) {
			SetLastError( ERROR_GEN_FAILURE) ;
			return FALSE ;
		}

		// 二巡目での消失は正常件数確認とは異なる不整合として扱わせる。
		if( index >= fixture.nodes || (!counting && index == fixture.disappearAt)) {
			SetLastError( ERROR_NO_MORE_ITEMS) ;
			return FALSE ;
		}

		device->DevInst	  = index ;
		device->ClassGuid = {0x4d36e978U,
							 0xe325U,
							 0x11ceU,
							 {0xbfU, 0xc1U, 0x08U, 0x00U, 0x2bU, 0xe1U, 0x03U, 0x18U}} ;
		// 索引fixtureだけは公開recordと同じ架空classを観測します。
		if( fixture.indexIds) {
			device->ClassGuid = {0x11111111U,
								 0x2222U,
								 0x3333U,
								 {0x44U, 0x44U, 0x55U, 0x55U, 0x55U, 0x55U, 0x55U, 0x55U}} ;
			// Class不一致を同型ID一致だけで合格させません。
			if( fixture.differentClass && index == 1U) {
				device->ClassGuid.Data1 = 0x99999999U ;
			}

			// 未知classを現在版空欄や既知classへ補完しません。
			if( (fixture.unknownClass && index == 0U) ||
			   (fixture.unknownSecondClass && index == 1U)) {
				device->ClassGuid = {} ;
			}
		}

		fixture.visit( counting ? "count" : "detail") ;
		return TRUE ;
	} ;
	// Instance IDは架空値だけをworker内へ返し、UI行に転写されないことを検査する。
	transport.instanceId = []( HDEVINFO handle, PSP_DEVINFO_DATA device, PWSTR output,
							  DWORD characters, PDWORD needed) -> BOOL {
		auto &fixture = *static_cast<InventoryFixture *>( handle) ;	// 現在nodeの合成instance属性。
		fixture.visit( "instance") ;
		// 個別属性の失敗でnodeを捏造しない。
		if( device->DevInst == fixture.missingInstanceAt) {
			SetLastError( ERROR_NOT_FOUND) ;
			return FALSE ;
		}

		const std::wstring_view instanceValue =
			fixture.instanceValue ;	// 実機情報ではない秘密属性相当。
		// 容量照会と取得のどちらでも実際のNUL込み文字数を返す。
		if( needed != nullptr) {
			*needed = static_cast<DWORD>( instanceValue.size() + 1U) ;
		}

		// 二段階APIの容量照会を再現する。
		if( output == nullptr || characters <= instanceValue.size()) {
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		// Buffer全域を非NULにして、不正API成功でも範囲外を読まないことを確認する。
		if( fixture.unterminatedInstance) {
			std::fill_n( output, characters, L'x') ;
			return TRUE ;
		}

		std::copy( instanceValue.begin(), instanceValue.end(), output) ;
		output[instanceValue.size()] = L'\0' ;
		return TRUE ;
	} ;
	// 表示propertyだけを有限UTF-16として返す。Hardware ID map構築を要求されたら記録する。
	transport.property = []( HDEVINFO handle, PSP_DEVINFO_DATA device, const DEVPROPKEY *key,
							DEVPROPTYPE *type, PBYTE output, DWORD capacity, PDWORD needed,
							DWORD flags) -> BOOL {
		auto &fixture = *static_cast<InventoryFixture *>( handle) ;	// 属性faultの所有状態。
		++fixture.propertyCalls ;
		fixture.validArguments &= flags == 0U ;
		fixture.visit( "property") ;
		const bool secret = IsEqualDevPropKey( *key, DEVPKEY_Device_HardwareIds) ||
							// 専用modeの禁止property。
							IsEqualDevPropKey( *key, DEVPKEY_Device_CompatibleIds) ;
		fixture.secretPropertyCalls += secret ? 1U : 0U ;
		const auto fault = IsEqualDevPropKey( *key, fixture.faultKey) &&
								   (device->DevInst == fixture.faultNode ||
									fixture.faultNode == std::numeric_limits<DWORD>::max())
							   ? fixture.propertyFault
							   : PropertyFault::NONE ;	// 固定一属性だけを破損する。
		fixture.faultPropertyCalls += IsEqualDevPropKey( *key, fixture.faultKey) ? 1U : 0U ;
		// 明示された索引propertyだけを独立注入し、旧faultと既定fixtureの動作を維持します。
		if( secret && fixture.indexIds) {
			const auto &injected =
				fixture.indexIdProperties[IsEqualDevPropKey( *key, DEVPKEY_Device_HardwareIds)
											  ? 0U
											  : 1U] ;	// 元種別の注入値。
			// 未指定なら下の既存transportをそのまま使用します。
			if( injected) {
				*type	= injected->type ;
				*needed = output == nullptr ? injected->required : injected->returned ;
				// 必要量通知以外の初回errorも元値のまま返します。
				if( output == nullptr) {
					SetLastError( injected->sizeError != 0U ? injected->sizeError
														   : ERROR_INSUFFICIENT_BUFFER) ;
					return FALSE ;
				}

				// 二回目の失敗では内容を補わず、指定された元Win32診断を保持します。
				if( injected->valueError != 0U) {
					SetLastError( injected->valueError) ;
					return FALSE ;
				}

				std::memset( output, 0, capacity) ;
				const auto copied =
					std::min<std::size_t>( capacity, injected->bytes.size()) ;	// 有限copy量。
				// 空vectorへ触れず、返却実量とは独立した本文だけをcopyします。
				if( copied != 0U) {
					std::memcpy( output, injected->bytes.data(), copied) ;
				}

				SetLastError( ERROR_ACCESS_DENIED) ;
				return TRUE ;
			}
		}

		// 初回照会からのAPI失敗は正規の値を返さない。
		if( fault == PropertyFault::MISSING || fault == PropertyFault::ACCESS_DENIED ||
		   fault == PropertyFault::INVALID_ERROR) {
			SetLastError( fault == PropertyFault::MISSING		 ? ERROR_NOT_FOUND
						 : fault == PropertyFault::ACCESS_DENIED ? ERROR_ACCESS_DENIED
																 : ERROR_INVALID_DATA) ;
			return FALSE ;
		}

		// 欠損属性と禁止propertyは正常値を推測して返さない。
		if( (fixture.missingAttributes && !secret) || (secret && !fixture.indexIds) ||
		   (IsEqualDevPropKey( *key, DEVPKEY_Device_DriverDate) && !fixture.dateAvailable)) {
			SetLastError( ERROR_NOT_FOUND) ;
			return FALSE ;
		}

		std::wstring_view value = L"Fixture" ;	// 明示していない表示文字列の合成値。
		std::wstring	  secretList ;			// 索引fixtureだけが返す実二重NULの原属性。
		// 公表INFの役割とは独立したnative属性を返し、四組合せと非一意を再現します。
		if( secret) {
			const bool hardware = IsEqualDevPropKey( *key, DEVPKEY_Device_HardwareIds) ;	// 元種別。
			const bool sameNode =
				fixture.sameHardware || device->DevInst == 0U ;	// 当該属性の一意／非一意です。
			// 公表文字列のnative側配置だけを選び、INF側roleを予測しません。
			const bool containsPublished =
				fixture.splitKindAcrossNodes
					? (hardware ? device->DevInst == 0U : device->DevInst == 1U)
					: (fixture.publishedIdInBothKinds ||
					   hardware != fixture.publishedIdInCompatible) &&
						  sameNode ;
			secretList = containsPublished ? fixture.indexId
						 : hardware		   ? L"TESTBUS\\NATIVE_HARDWARE_OTHER"
										   : L"TESTBUS\\NATIVE_COMPATIBLE_OTHER" ;
			secretList.push_back( L'\0') ;
			// 別native表記が同じlistにあっても正常matchingを排除しません。
			if( fixture.extraNativeId) {
				secretList.insert( 0U, std::wstring{L"*FAKE_BUSLESS"} + L'\0') ;
			}

			value = secretList ;
		}

		// 現在INF版の未知・既知表示を検証できる固定値。
		if( IsEqualDevPropKey( *key, DEVPKEY_Device_DriverVersion)) {
			value = L"1.0.0.0" ;
		}
		// class照合に使う標準表示名を返す。
		else if( IsEqualDevPropKey( *key, DEVPKEY_Device_Class)) {
			value = L"Ports" ;
		}
		// Device名はmetadata probe対象の合成表示名とする。
		else if( IsEqualDevPropKey( *key, DEVPKEY_Device_FriendlyName) ||
				IsEqualDevPropKey( *key, DEVPKEY_Device_DeviceDesc)) {
			value = fixture.displayName ;
		}

		// 空文字はAPI失敗と区別して成功で返す。
		if( fault == PropertyFault::EMPTY) {
			value = L"" ;
		}

		// 単一STRINGに埋込みNUL後の余剰を含めて拒否を確認する。
		if( fault == PropertyFault::EMBEDDED_NULL) {
			value = std::wstring_view( L"A\0B", 3U) ;
		}

		const bool isDate = IsEqualDevPropKey( *key, DEVPKEY_Device_DriverDate) ;	// 固定型の選択。
		// FILETIMEは固定長、STRINGはNULを含む有限長とする。
		const auto required =
			static_cast<DWORD>( isDate ? sizeof( FILETIME) : (value.size() + 1U) * sizeof( wchar_t)) ;
		*type = isDate	 ? DEVPROP_TYPE_FILETIME
				: secret ? DEVPROP_TYPE_STRING_LIST
						 : DEVPROP_TYPE_STRING ;
		// 型の不一致を、表示文字列の欠損に落とさない。
		if( fault == PropertyFault::WRONG_TYPE) {
			*type = DEVPROP_TYPE_UINT32 ;
		}

		// 呼出し側が容量照会先を指定した場合だけ書き込む。
		if( needed != nullptr) {
			*needed = required ;
		}

		// 初回から不正または過大な必要量だけを返し、buffer確保を検査する。
		if( fault == PropertyFault::ODD_SIZE || fault == PropertyFault::OVER_LIMIT) {
			*needed = fault == PropertyFault::ODD_SIZE ? 3U : 65538U ;
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		// 二回目の容量増大を再試行ループにしないことを検査する。
		if( output != nullptr && fault == PropertyFault::GROWING) {
			*needed = required + 2U ;
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		// 適切なサイズのbufferがある場合だけcopyする。
		if( output == nullptr || capacity < required) {
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		// 日付の生bytesとUTF-16文字列の格納先を型に対応させる。
		if( isDate) {
			std::memcpy( output, &fixture.dateValue, required) ;
		} else {
			std::memcpy( output, value.data(), required) ;
		}

		// 実sizeの過大自己申告をcopy量とは分離して注入する。
		if( fault == PropertyFault::OVER_REPORTED) {
			*needed = capacity + 2U ;
		}

		// 0 byteの成功を、空文字列として受理させない。
		if( fault == PropertyFault::ZERO_RETURNED) {
			*needed = 0U ;
		}

		// 実size一文字内にNULがなく、残り確保領域だけが0の例を再現する。
		if( fault == PropertyFault::UNTERMINATED) {
			std::memset( output, 0, capacity) ;
			const wchar_t character = L'x' ;	// 実際に返した一文字。
			std::memcpy( output, &character, sizeof( character)) ;
			*needed = sizeof( character) ;
		}

		// 成功時のstale errorを保存しないことを試す。
		SetLastError( ERROR_ACCESS_DENIED) ;
		return TRUE ;
	} ;
	// CONFIGRETはWin32診断と独立し、実devnodeへ触れない。
	transport.nodeStatus = []( PULONG flags, PULONG problem, DEVINST node,
							  ULONG options) -> CONFIGRET {
		auto &fixture = *activeInventoryFixture ;	// 当該testの所有fixture。
		++fixture.nodeCalls ;
		fixture.validArguments &= options == 0U && node < fixture.nodes ;
		fixture.visit( "node-status") ;
		*flags	 = fixture.nodeFlags ;
		*problem = fixture.nodeProblem ;
		// この値をCONFIGRET失敗へ混ぜさせない。
		SetLastError( ERROR_ACCESS_DENIED) ;
		return fixture.nodeResult ;
	} ;
	// Fixture handleを本物のSetupAPI解放関数へ渡さない。
	transport.close = []( HDEVINFO handle) -> BOOL {
		++static_cast<InventoryFixture *>( handle)->closed ;
		return TRUE ;
	} ;
	return transport ;
}

/** @brief 実I/Oを持たない現在属性scanを一回だけ実行する所有fixture。 */
struct InventoryCase {
	/// APIとcallbackが借用する最長寿命の状態。
	InventoryFixture			   fixture ;
	/// 同期API中も確認する実装の期限・取消しcontext。
	MetadataSearchExecutionContext execution ;
	/// 現在属性だけに制限したfixture用Provider。
	DriverStoreProvider			   provider ;
	/// 確定進捗を検査する有限通知列。
	std::vector<ProviderProgress>  progress ;

	/** @brief 一回の独立した専用contextを生成する。 */
	InventoryCase()
		: execution(
			  83U,
			  MetadataSearchRequest{
				  .enabledProviderIds = {std::wstring( SILICON_LABS_OFFICIAL_PROVIDER_ID)}},
			  [this] { return fixture.cancelled ; }, [this] { return fixture.ticks ; }),
		  provider( inventoryTransport())
	{
		activeInventoryFixture = &fixture ;
	}

	/** @brief 同期handle解放後にthread内の借用先を外す。 */
	~InventoryCase()
	{
		activeInventoryFixture = nullptr ;
	}

	/**
     * @brief 上限・属性検証・行公開は本番のまま実行する。
     * @return 現在版だけの表示結果。
     */
	ScanResult scan()
	{
		return provider.scanCurrentInventory(
			83U, execution, [this]( const ProviderProgress &value) { progress.push_back( value) ; }) ;
	}
	/** @brief 履歴・導入を発行せず、同じ本番captureを明示的に使用します。
	 * @return 現在表示行と独立した秘密snapshot。
	 */
	ScanResult scanForIndex()
	{
		fixture.indexIds = true ;
		return provider.scanCurrentIndexInventory(
			83U, execution, [this]( const ProviderProgress &value) { progress.push_back( value) ; }) ;
	}
} ;

/** @brief 発行済みpartial値の改変だけを返し、native証拠を新規発行しないnegative seamです。 */
class PartialReplayResolver final : public IndexPublicIdResolver {
public:
	/** @brief 一回発行済みの結果を値として所有します。
	 * @param[in] result Native fixture由来または証拠を除去したpartial結果です。
	 */
	explicit PartialReplayResolver( IndexPublicIdResolution result) : result_( std::move( result))
	{
	}
	/** @brief 元公開tupleを書き換えず、保存済みpartialだけを返します。
	 * @param[in] kind lookupからの元役割です。返却証拠へ代入しません。
	 * @param[in] publishedId 元公開identifierです。返却証拠へ代入しません。
	 * @param[in] classGuid 元公開Classです。返却証拠へ代入しません。
	 * @param[in] context 元contextです。返却証拠へ代入しません。
	 * @param[in] present 元全presentです。返却証拠へ代入しません。
	 * @return 保存した結果のcopyです。元証拠の公開tupleが異なるqueryはlookupで拒否されます。
	 */
	[[nodiscard]] IndexPublicIdResolution resolve(
		IndexPnpIdKind kind, std::string_view publishedId, std::string_view classGuid,
		IndexLookupContext context, std::span<const std::wstring> present) const override
	{
		static_cast<void>( kind) ;
		static_cast<void>( publishedId) ;
		static_cast<void>( classGuid) ;
		static_cast<void>( context) ;
		static_cast<void>( present) ;
		return result_ ;
	}

private:
	/// Native proofを発行できないnegative返却値です。
	IndexPublicIdResolution result_ ;
} ;

/**
 * @brief 実loopで4095／4096／4097とprobe障害を再現する。
 * @param[in,out] context Assertion集計先。
 */
void testInventoryLimits( TestContext &context)
{
	// 正常空集合と固定上限前後を同じ列挙実装で確認する。
	for( const DWORD nodes : {0U, 4095U, 4096U, 4097U}) {
		InventoryCase run ;	// 全APIがこのscopeのfakeだけへ接続する。
		run.fixture.nodes		= nodes ;
		const auto	result		= run.scan() ;							// 実deviceを列挙しない本番loopの結果。
		const auto &measurement = run.provider.inventoryMeasurement() ;	// 同じ列挙の確定母数。
		const auto	represented = std::min<DWORD>( nodes, 4096U) ;		// 上限以内で詳細を確認できる件数。
		DRIVERCRATE_EXPECT( context,
						   result.succeeded && result.purpose == ScanPurpose::METADATA_ONLY) ;
		DRIVERCRATE_EXPECT( context, result.candidates.size() == represented) ;
		DRIVERCRATE_EXPECT( context, measurement.enumeratedDeviceCount.value == nodes) ;
		DRIVERCRATE_EXPECT( context, measurement.enumeratedDeviceCount.extent ==
										(nodes > 4096U ? MeasurementExtent::LOWER_BOUND
													   : MeasurementExtent::EXACT)) ;
		DRIVERCRATE_EXPECT( context, measurement.detailedEnumerationComplete == (nodes <= 4096U)) ;
		DRIVERCRATE_EXPECT( context,
						   measurement.unrepresentedDeviceCount.value == (nodes > 4096U ? 1U : 0U)) ;
		DRIVERCRATE_EXPECT( context, run.fixture.countCalls == represented + 1U) ;
		DRIVERCRATE_EXPECT( context, run.fixture.detailCalls == represented) ;
		DRIVERCRATE_EXPECT( context, run.fixture.opened == 1U && run.fixture.closed == 1U) ;
		DRIVERCRATE_EXPECT( context,
						   run.fixture.validArguments && run.fixture.secretPropertyCalls == 0U) ;
		DRIVERCRATE_EXPECT( context, result.coverage.assessedDeviceCount == 0U) ;
		DRIVERCRATE_EXPECT( context, hasOnlyMetadataDisplayCandidates( result)) ;
		DRIVERCRATE_EXPECT(
			context,
			std::all_of( result.candidates.begin(), result.candidates.end(), []( const auto &row) {
				return row.current && row.version == L"1.0.0.0" && !row.installable &&
					   !row.recommended && row.action == DriverAction::NONE &&
					   row.packageIdentity.empty() &&
					   row.identity.find( L"fixture-native-node") == std::wstring::npos ;
			})) ;
		DRIVERCRATE_EXPECT( context,
						   !run.provider.deviceIdentityForHardwareId( L"fixture-native-node")) ;
	}

	InventoryCase failedProbe ;	// 4096件目の保持後、一回probeだけが失敗する。
	failedProbe.fixture.nodes		= 4096U ;
	failedProbe.fixture.failCountAt = 4096U ;
	const auto	result		= failedProbe.scan() ;							// 4096行は残し、件数の確定度を下限とする。
	const auto &measurement = failedProbe.provider.inventoryMeasurement() ;	// Probe失敗の診断。
	DRIVERCRATE_EXPECT( context, result.candidates.size() == 4096U &&
									result.outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
	DRIVERCRATE_EXPECT( context, measurement.enumeratedDeviceCount.value == 4096U &&
									measurement.enumeratedDeviceCount.extent ==
										MeasurementExtent::LOWER_BOUND) ;
	DRIVERCRATE_EXPECT( context,
					   !measurement.detailedEnumerationComplete &&
						   measurement.error ==
							   static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_GEN_FAILURE))) ;
	DRIVERCRATE_EXPECT( context, failedProbe.fixture.countCalls == 4097U) ;
}

/**
 * @brief 属性欠損・二巡目消失・API停止を確認する。
 * @param[in,out] context Assertion集計先。
 */
void testInventoryFailures( TestContext &context)
{
	InventoryCase missing ;	// 表示属性が全て不明でも現在deviceの存在は残す。
	missing.fixture.missingAttributes = true ;
	const auto	missingResult		  = missing.scan() ;					// 不明版を推測しない。
	const auto &missingCounts = missing.provider.inventoryMeasurement() ;	// 属性別の実欠損数。
	DRIVERCRATE_EXPECT( context, missingResult.candidates.size() == 2U &&
									missingCounts.missingCurrentVersionCount.value == 2U &&
									missingCounts.missingClassCount.value == 2U &&
									missingCounts.missingManufacturerCount.value == 2U) ;
	DRIVERCRATE_EXPECT( context, missingCounts.detailedEnumerationComplete) ;
	DRIVERCRATE_EXPECT( context, std::all_of( missingResult.candidates.begin(),
											missingResult.candidates.end(), []( const auto &row) {
												return row.current && row.version.empty() &&
													   row.manufacturer.empty() &&
													   row.driverClass.empty() && !row.installable ;
											})) ;
	// 件数確認後の消失、instance ID欠損、非終端応答を個別に処理する。
	for( unsigned mode = 0U; mode < 3U; ++mode) {
		InventoryCase run ;	// 一巡目は常に二件が存在する。
		run.fixture.disappearAt			 = mode == 0U ? 1U : std::numeric_limits<DWORD>::max() ;
		run.fixture.missingInstanceAt	 = mode == 1U ? 0U : std::numeric_limits<DWORD>::max() ;
		run.fixture.unterminatedInstance = mode == 2U ;
		const auto	result				 = run.scan() ;					// Node消失以外は代表行を残す。
		const auto &measurement = run.provider.inventoryMeasurement() ;	// 一巡目の母数との差を保持。
		DRIVERCRATE_EXPECT( context, result.candidates.size() == (mode == 0U ? 1U : 2U)) ;
		DRIVERCRATE_EXPECT( context, result.outcome == OutcomeCode::SUCCEEDED_WITH_ERRORS) ;
		DRIVERCRATE_EXPECT( context, measurement.enumeratedDeviceCount.value == 2U &&
										!measurement.detailedEnumerationComplete &&
										measurement.error != 0) ;
		DRIVERCRATE_EXPECT( context,
						   measurement.unrepresentedDeviceCount.value == (mode == 0U ? 1U : 0U)) ;
	}

	// 各同期APIで取消しが成立した場合、その後の現在行をcommitしない。
	for( const std::string_view stage :
		{"open", "count", "detail", "instance", "property", "node-status"}) {
		InventoryCase run ;	// 二件の合成deviceの途中で停止する。
		run.fixture.hook = [&]( const std::string_view actual) {
			// 注入対象API復帰点だけで取消しを要求する。
			if( actual == stage) {
				run.fixture.cancelled = true ;
			}
		} ;
		const auto result = run.scan() ;	// API中止を正常空集合にしない。
		DRIVERCRATE_EXPECT( context, !result.succeeded && result.outcome == OutcomeCode::ABORTED) ;
		DRIVERCRATE_EXPECT( context, result.candidates.empty()) ;
		DRIVERCRATE_EXPECT( context,
						   !run.provider.inventoryMeasurement().detailedEnumerationComplete) ;
		DRIVERCRATE_EXPECT( context, run.fixture.closed == 1U) ;
		DRIVERCRATE_EXPECT( context,
						   run.execution.sessionStopReason() == MetadataSearchReason::CANCELLED) ;
	}

	InventoryCase deadline ;	// Local列挙も300秒の全体期限に入る。
	deadline.fixture.hook = [&]( const std::string_view stage) {
		// API待機復帰時に固定期限ちょうどへ進める。
		if( stage == "count") {
			deadline.fixture.ticks = 300000U ;
		}
	} ;
	const auto timedOut = deadline.scan() ;	// 部分母数を成功にしない結果。
	DRIVERCRATE_EXPECT( context, !timedOut.succeeded && timedOut.candidates.empty()) ;
	DRIVERCRATE_EXPECT( context, deadline.execution.sessionStopReason() ==
									MetadataSearchReason::DEADLINE_EXCEEDED) ;
}

/**
 * @brief Windows型に依存しない観測分類と整合性を検証する。
 * @param[in,out] context Assertion集計先。
 */
void testObservationContract( TestContext &context)
{
	DeviceObservation observation ;	// 全属性は未照会であり、正常動作を仮定しない。
	observation.scanSessionId  = 83U ;
	observation.deviceIdentity = L"device:83:0" ;
	DRIVERCRATE_EXPECT( context, isDeviceObservationBound( observation, 83U, L"device:83:0")) ;
	DRIVERCRATE_EXPECT( context, !isDeviceObservationBound( observation, 84U, L"device:83:0")) ;
	DRIVERCRATE_EXPECT( context, !isDeviceObservationBound( observation, 83U, L"device:83:1")) ;
	observation.driverKey.state = DevicePropertyReadState::VALUE ;
	observation.driverPresence =
		classifyDeviceDriverPresence( observation.node, observation.driverKey) ;
	DRIVERCRATE_EXPECT( context, observation.driverPresence == DeviceDriverPresence::REGISTERED) ;
	DRIVERCRATE_EXPECT( context, isDeviceObservationValid( observation)) ;
	observation.node = {
		{DevicePropertyReadState::VALUE, {}}, DN_HAS_PROBLEM, CM_PROB_FAILED_INSTALL} ;
	observation.driverPresence =
		classifyDeviceDriverPresence( observation.node, observation.driverKey) ;
	DRIVERCRATE_EXPECT( context, observation.driverPresence == DeviceDriverPresence::NOT_INSTALLED) ;
	DRIVERCRATE_EXPECT( context, isDeviceObservationValid( observation)) ;
	observation.node.statusFlags = 0U ;
	DRIVERCRATE_EXPECT( context, !isDeviceNodeObservationValid( observation.node)) ;
	DRIVERCRATE_EXPECT( context,
					   classifyDeviceDriverPresence( observation.node, observation.driverKey) ==
						   DeviceDriverPresence::UNKNOWN) ;
	observation.node.problemCode.reset() ;
	observation.driverPresence = DeviceDriverPresence::REGISTERED ;
	DRIVERCRATE_EXPECT( context, isDeviceObservationValid( observation)) ;
	observation.node.read.diagnostic = {DeviceDiagnosticDomain::WINDOWS_ERROR, ERROR_ACCESS_DENIED} ;
	DRIVERCRATE_EXPECT( context, !isDeviceObservationValid( observation)) ;
	observation.node.read.diagnostic = {} ;
	observation.version				 = {DevicePropertyReadState::NOT_PRESENT,
										{DeviceDiagnosticDomain::WINDOWS_ERROR, ERROR_NOT_FOUND}} ;
	DRIVERCRATE_EXPECT( context, isDeviceObservationValid( observation)) ;
	observation.version.diagnostic.domain = DeviceDiagnosticDomain::CONFIGURATION_MANAGER ;
	DRIVERCRATE_EXPECT( context, !isDeviceObservationValid( observation)) ;
	observation.version = {DevicePropertyReadState::FAILED,
						   {DeviceDiagnosticDomain::CONFIGURATION_MANAGER, CR_FAILURE}} ;
	DRIVERCRATE_EXPECT( context, isDeviceObservationValid( observation)) ;
	observation.version.diagnostic.code = CR_SUCCESS ;
	DRIVERCRATE_EXPECT( context, !isDeviceObservationValid( observation)) ;
	observation.version		   = {} ;
	observation.driverPresence = static_cast<DeviceDriverPresence>( 99U) ;
	DRIVERCRATE_EXPECT( context, !isDeviceObservationValid( observation)) ;
	observation.driverPresence = DeviceDriverPresence::REGISTERED ;
	observation.version.state  = static_cast<DevicePropertyReadState>( 99U) ;
	DRIVERCRATE_EXPECT( context, !isDeviceObservationValid( observation)) ;
	observation.version = {} ;
	observation.deviceIdentity.assign( 257U, L'x') ;
	DRIVERCRATE_EXPECT( context, !isDeviceObservationValid( observation)) ;
}

/**
 * @brief Propertyの欠損・失敗・空・型と実sizeの異常を本番readerで検証する。
 * @param[in,out] context Assertion集計先。
 */
void testObservedPropertyFailures( TestContext &context)
{
	const std::array<std::pair<PropertyFault, DevicePropertyReadState>, 12> cases{{
		{PropertyFault::MISSING, DevicePropertyReadState::NOT_PRESENT},
		{PropertyFault::ACCESS_DENIED, DevicePropertyReadState::FAILED},
		{PropertyFault::INVALID_ERROR, DevicePropertyReadState::INVALID_DATA},
		{PropertyFault::EMPTY, DevicePropertyReadState::EMPTY},
		{PropertyFault::WRONG_TYPE, DevicePropertyReadState::INVALID_DATA},
		{PropertyFault::ODD_SIZE, DevicePropertyReadState::INVALID_DATA},
		{PropertyFault::OVER_LIMIT, DevicePropertyReadState::LIMIT_REACHED},
		{PropertyFault::GROWING, DevicePropertyReadState::LIMIT_REACHED},
		{PropertyFault::OVER_REPORTED, DevicePropertyReadState::INVALID_DATA},
		{PropertyFault::ZERO_RETURNED, DevicePropertyReadState::INVALID_DATA},
		{PropertyFault::UNTERMINATED, DevicePropertyReadState::INVALID_DATA},
		{PropertyFault::EMBEDDED_NULL, DevicePropertyReadState::INVALID_DATA},
	}} ; // 固定一属性だけを変更する正例・反例集合。
	// 全faultを一deviceの同じ経路で検証し、失敗時のnative fallbackを許さない。
	for( const auto &[fault, expected] : cases) {
		InventoryCase run ;	// OSを変更しない完全fakeの一回scan。
		run.fixture.nodes		  = 1U ;
		run.fixture.propertyFault = fault ;
		const auto result		  = run.scan() ;	// 属性失敗でもnode代表行を残す。
		DRIVERCRATE_EXPECT( context, result.candidates.size() == 1U) ;
		// 先行の失敗を記録した後にtest自身の範囲外参照を防ぐ。
		if( result.candidates.empty()) {
			continue ;
		}

		const auto &row = result.candidates.front() ;	// 同じscanの代表行。
		DRIVERCRATE_EXPECT( context, row.deviceObservation.has_value()) ;
		// 未実装または欠損の観測を成功値としてdereferenceしない。
		if( !row.deviceObservation) {
			continue ;
		}

		const auto &observed = *row.deviceObservation ;	// 診断だけで生属性を持たないsnapshot。
		DRIVERCRATE_EXPECT( context, observed.version.state == expected) ;
		DRIVERCRATE_EXPECT( context, row.version.empty() && !row.installable && row.current) ;
		DRIVERCRATE_EXPECT( context, observed.driverPresence == DeviceDriverPresence::REGISTERED) ;
		DRIVERCRATE_EXPECT( context, isDeviceObservationBound( observed, 83U, row.deviceIdentity)) ;
		DRIVERCRATE_EXPECT( context, run.fixture.faultPropertyCalls <= 2U) ;
		DRIVERCRATE_EXPECT( context,
						   run.fixture.nodeCalls == 1U && run.fixture.secretPropertyCalls == 0U) ;
		DRIVERCRATE_EXPECT( context,
						   observed.driverKey.diagnostic.domain == DeviceDiagnosticDomain::NONE) ;
	}
}

/**
 * @brief 未導入・問題・CONFIGRET失敗と名前fallbackを本番列挙で検証する。
 * @param[in,out] context Assertion集計先。
 */
void testObservedNodeStates( TestContext &context)
{
	// Code 28、別問題、無効problem buffer、API失敗を独立したrunで比較する。
	for( unsigned mode = 0U; mode < 4U; ++mode) {
		InventoryCase run ;	// Status以外を同じ条件に固定する。
		run.fixture.nodes		= 1U ;
		run.fixture.nodeFlags	= mode < 2U ? DN_HAS_PROBLEM : 0U ;
		run.fixture.nodeProblem = mode == 1U ? CM_PROB_FAILED_START : CM_PROB_FAILED_INSTALL ;
		run.fixture.nodeResult	= mode == 3U ? CR_NO_SUCH_DEVNODE : CR_SUCCESS ;
		const auto result		= run.scan() ;	// Status失敗でも表示を保持する。
		DRIVERCRATE_EXPECT( context, result.candidates.size() == 1U) ;
		// 前提未成立でもtestをクラッシュさせずassertionで報告する。
		if( result.candidates.empty() || !result.candidates.front().deviceObservation) {
			DRIVERCRATE_EXPECT( context, false) ;
			continue ;
		}

		const auto &observed = *result.candidates.front().deviceObservation ;	// 一回のstatus観測。
		DRIVERCRATE_EXPECT( context, isDeviceObservationValid( observed)) ;
		DRIVERCRATE_EXPECT( context, observed.driverPresence ==
										(mode == 0U ? DeviceDriverPresence::NOT_INSTALLED
													: DeviceDriverPresence::REGISTERED)) ;
		DRIVERCRATE_EXPECT( context, observed.node.problemCode.has_value() == (mode < 2U)) ;
		DRIVERCRATE_EXPECT( context, !result.candidates.front().installable) ;
		// CONFIGRET失敗をstaleなWin32 errorへ取り違えない。
		if( mode == 3U) {
			DRIVERCRATE_EXPECT( context, observed.node.read.diagnostic.domain ==
											DeviceDiagnosticDomain::CONFIGURATION_MANAGER) ;
			DRIVERCRATE_EXPECT( context, observed.node.read.diagnostic.code == CR_NO_SUCH_DEVNODE) ;
		}
	}

	InventoryCase fallback ;	// FriendlyNameだけが空のdeviceを標準説明で残す。
	fallback.fixture.nodes		   = 1U ;
	fallback.fixture.faultKey	   = DEVPKEY_Device_FriendlyName ;
	fallback.fixture.propertyFault = PropertyFault::EMPTY ;
	const auto result			   = fallback.scan() ;	// 元の空とfallback成功を両方保持する。
	DRIVERCRATE_EXPECT( context, result.candidates.size() == 1U) ;
	// 観測不在は明示的な失敗として扱う。
	if( !result.candidates.empty() && result.candidates.front().deviceObservation) {
		const auto &row = result.candidates.front() ;	// Fallback後の現在構成行。
		DRIVERCRATE_EXPECT( context, !row.model.empty()) ;
		DRIVERCRATE_EXPECT( context, row.deviceObservation->friendlyName.state ==
										DevicePropertyReadState::EMPTY) ;
		DRIVERCRATE_EXPECT( context, row.deviceObservation->deviceDescription.state ==
										DevicePropertyReadState::VALUE) ;
	} else {
		DRIVERCRATE_EXPECT( context, false) ;
	}
}

/**
 * @brief Key未確認と日付の型・size・暦変換を独立に検証する。
 * @param[in,out] context Assertion集計先。
 */
void testObservedKeyAndDate( TestContext &context)
{
	// Key欠損と正規の空値を未導入と誤分類しない。
	for( const auto fault : {PropertyFault::MISSING, PropertyFault::EMPTY}) {
		InventoryCase run ;	// 固定版があっても登録状態を推測しないfixture。
		run.fixture.nodes		  = 1U ;
		run.fixture.faultKey	  = DEVPKEY_Device_Driver ;
		run.fixture.propertyFault = fault ;
		const auto result		  = run.scan() ;	// Key以外は読取り可能なdevice。
		DRIVERCRATE_EXPECT( context, result.candidates.size() == 1U) ;
		// 前提不成立はassertionへ残し、不正な要素参照を避ける。
		if( result.candidates.empty() || !result.candidates.front().deviceObservation) {
			DRIVERCRATE_EXPECT( context, false) ;
			continue ;
		}

		const auto &row = result.candidates.front() ;	// Versionと登録状態は別の軸。
		DRIVERCRATE_EXPECT( context, !row.version.empty() && !row.installable) ;
		DRIVERCRATE_EXPECT( context,
						   row.deviceObservation->driverPresence == DeviceDriverPresence::UNKNOWN) ;
		DRIVERCRATE_EXPECT( context, isDeviceObservationValid( *row.deviceObservation)) ;
	}

	const std::array<PropertyFault, 7> faults{
		PropertyFault::NONE,	PropertyFault::WRONG_TYPE,	  PropertyFault::ODD_SIZE,
		PropertyFault::GROWING, PropertyFault::OVER_REPORTED, PropertyFault::ZERO_RETURNED,
		PropertyFault::NONE} ;	// 最後は不正なFILETIME値を注入する。
	// 日付の正例と型・容量・暦変換の失敗を最大二回の照会で確認する。
	for( std::size_t index = 0U; index < faults.size(); ++index) {
		InventoryCase run ;	// 各日付ケースの副作用を分離する。
		run.fixture.nodes		  = 1U ;
		run.fixture.dateAvailable = true ;
		run.fixture.faultKey	  = DEVPKEY_Device_DriverDate ;
		run.fixture.propertyFault = faults[index] ;
		// WindowsのFILETIME変換範囲外を再現し、空の日付へ診断なしに落とさない。
		if( index == faults.size() - 1U) {
			run.fixture.dateValue = {0xFFFFFFFFU, 0xFFFFFFFFU} ;
		}

		const auto result = run.scan() ;	// 実時計や実driverを参照しない日付読取り。
		DRIVERCRATE_EXPECT( context, result.candidates.size() == 1U) ;
		// 観測を得られない場合も後続ケースを検証できるようにする。
		if( result.candidates.empty() || !result.candidates.front().deviceObservation) {
			DRIVERCRATE_EXPECT( context, false) ;
			continue ;
		}

		const auto &row = result.candidates.front() ;	// 日付表示と読取りの同じsnapshot。
		const auto	expected =
			 index == 0U   ? DevicePropertyReadState::VALUE
			 : index == 3U ? DevicePropertyReadState::LIMIT_REACHED
						   : DevicePropertyReadState::INVALID_DATA ;	// 実size増大と型不正を区別する。
		DRIVERCRATE_EXPECT( context, row.deviceObservation->date.state == expected) ;
		DRIVERCRATE_EXPECT( context, row.driverDate == (index == 0U ? L"1601/01/01" : L"")) ;
		DRIVERCRATE_EXPECT( context, isDeviceObservationValid( *row.deviceObservation)) ;
		DRIVERCRATE_EXPECT( context, run.fixture.faultPropertyCalls <= 2U &&
										run.fixture.secretPropertyCalls == 0U) ;
	}

	InventoryCase malformed ;	// 問題flagがあるのにproblem codeが0の不正応答。
	malformed.fixture.nodes		= 1U ;
	malformed.fixture.nodeFlags = DN_HAS_PROBLEM ;
	const auto result			= malformed.scan() ;	// 不正statusを正常な問題なしへ変換しない。
	DRIVERCRATE_EXPECT( context, result.candidates.size() == 1U) ;
	// 欠損観測では明示的なassertion失敗を残す。
	if( !result.candidates.empty() && result.candidates.front().deviceObservation) {
		const auto &node =
			// 有効値を持たない失敗観測。
			result.candidates.front().deviceObservation->node ;
		DRIVERCRATE_EXPECT( context, node.read.state == DevicePropertyReadState::INVALID_DATA) ;
		DRIVERCRATE_EXPECT( context, !node.statusFlags && !node.problemCode) ;
	} else {
		DRIVERCRATE_EXPECT( context, false) ;
	}
}

/**
 * @brief 開始失敗後の公式callback非実行とtest入口の用途拒否を確認する。
 * @param[in,out] context Assertion集計先。
 */
void testInventoryIsolation( TestContext &context)
{
	InventoryCase run ;	// 実inventory開始だけをAPI失敗させる。
	run.fixture.openFailure = true ;
	unsigned								officialCalls{} ;	// Metadata-only callbackへ進んだ回数。
	std::vector<MetadataSearchRegistration> entries ;			// 正本の全29登録。
	// 対応能力のcallbackだけをfakeで埋め、未選択通常経路を追加しない。
	for( const auto &descriptor : builtInProviderDescriptors()) {
		MetadataSearchRegistration entry{descriptor, {}} ;	// 正本descriptorと一致する一登録。
		// 能力がある全登録へ同じ非通信callbackを置く。
		if( isMetadataSearchProvider( descriptor)) {
			entry.scan = [&]( ScanSessionId, std::span<const OfficialCatalogDevice>, bool,
							 std::uint32_t, MetadataSearchExecutionContext &,
							 const ProviderProgressCallback &, ProviderMeasurementEvidence &) {
				++officialCalls ;
				return ScanResult{} ;
			} ;
		}

		entries.push_back( std::move( entry)) ;
	}

	ScanMeasurementContext conditions ;	// 固定の非機密条件。
	conditions.applicationVersion = L"fixture" ;
	conditions.osKind			  = MeasurementOsKind::CLIENT ;
	conditions.osBuild			  = 26100U ;
	const auto result			  = runMetadataSearch(
		83U, run.execution.request(), run.execution, entries,
		[&]( ScanSessionId session, MetadataSearchExecutionContext &execution,
			const ProviderProgressCallback &progress, DeviceInventoryMeasurement &measurement) {
			auto inventory = run.provider.scanCurrentInventory( session, execution,
																		   progress) ;	// 本番inventory実装。
			measurement	   = run.provider.inventoryMeasurement() ;
			return inventory ;
		},
		conditions, []( const ProviderProgress &) {}) ;	// Registry実行を外部UIなしで完結する。
	DRIVERCRATE_EXPECT( context, !result.succeeded && officialCalls == 0U) ;
	DRIVERCRATE_EXPECT( context, run.fixture.opened == 1U && run.fixture.closed == 0U) ;
	const auto standard =
		// Test専用instanceの用途違反。
		run.provider.scan( 84U, {}, []( const ProviderProgress &) {}) ;
	DRIVERCRATE_EXPECT( context, !standard.succeeded && run.fixture.opened == 1U) ;
	auto incomplete		= inventoryTransport() ;	// 一つの必須関数を欠落させる。
	incomplete.property = nullptr ;
	DriverStoreProvider invalid( incomplete) ;	// Native fallbackを持たないtest instance。
	const auto			invalidResult =
		invalid.scanCurrentInventory( 83U, run.execution, []( const ProviderProgress &) {
		}) ; // API表の欠損はWindowsを呼ぶ前に拒否。
	DRIVERCRATE_EXPECT( context, !invalidResult.succeeded && run.fixture.opened == 1U) ;
	incomplete			  = inventoryTransport() ;
	incomplete.nodeStatus = nullptr ;
	DriverStoreProvider missingStatus( incomplete) ;	// 新callback欠損でもnativeへfallbackしない。
	const auto			missingStatusResult = missingStatus.scanCurrentInventory(
		 83U, run.execution, []( const ProviderProgress &) {}) ;	// 本番API呼出し前に拒否する。
	DRIVERCRATE_EXPECT( context, !missingStatusResult.succeeded && run.fixture.nodeCalls == 0U) ;
}

/** @brief 実workerとUI役が共有する有限fixture信号です。 */
struct WorkerIndexState {
	/// 0正常、1非一意、2入力不足、3元API障害のinventory mode。
	std::atomic_uint		 mode{} ;
	/// 0真store、1未配備製品入口、2真genesis、3合成I/O拒否です。
	std::atomic_uint		 loadMode{} ;
	/// 0正常、1UTC不明、2期限以上、3発行前です。
	std::atomic_uint		 timeMode{} ;
	/// 真再認証直前を有限signalで待つ場合trueです。
	std::atomic_bool		 holdLoad{} ;
	/// 索引完了後の計画読取りを待つ場合trueです。
	std::atomic_bool		 holdPlan{} ;
	/// 元通常scanを失敗させる場合trueです。
	std::atomic_bool		 failScan{} ;
	/// 通常scanで人工例外を返す場合trueです。
	std::atomic_bool		 throwScan{} ;
	/// Loadで人工例外を返す場合trueです。
	std::atomic_bool		 throwLoad{} ;
	/// 元resolver復帰後を有限signalで待つ場合trueです。
	std::atomic_bool		 holdResolver{} ;
	/// 元resolver復帰後に人工時計を期限へ進める場合trueです。
	std::atomic_bool		 expireResolver{} ;
	/// 停止hook後にlookupが診断へ変換する例外を返す場合trueです。
	std::atomic_bool		 throwResolver{} ;
	/// 停止hook直前に実resolverが返した非機密診断です。
	std::atomic<NativeError> originalResolverError{} ;
	/// 停止hook直前に実resolverが照合を完了した場合trueです。
	std::atomic_bool		 originalResolverCompleted{} ;
	/// 停止hook直前の有限opaque戻り件数です。値自体は共有しません。
	std::atomic_size_t		 originalResolverDeviceCount{} ;
	/// 実resolver復帰後に実行した停止hookの回数です。
	std::atomic_uint		 resolverHooks{} ;
	/// Resolver発行contextのsessionを一つ変える場合trueです。
	std::atomic_bool		 stale{} ;
	/// 単調fixture時計のmillisecondです。
	std::atomic_int64_t		 ticks{} ;
	/// 時計照会ごとに進めるmillisecondです。
	std::atomic_int64_t		 tickStep{} ;
	/// Fake導入の誤呼出し回数です。
	std::atomic_uint		 installs{} ;
	/// 復旧fakeの誤呼出し回数です。
	std::atomic_uint		 restores{} ;
	/// Loadまたはplan待機の開始通知です。
	std::binary_semaphore	 entered{0} ;
	/// 2秒以内に終了するfixture待機の解放です。
	std::binary_semaphore	 release{0} ;
} ;

/** @brief 同threadの実resolver復帰直後に有限な停止条件だけを注入します。 */
class WorkerIndexStoppingResolver final : public IndexPublicIdResolver {
public:
	/** @brief 実capture由来のcallbackと非通信fixture信号を所有します。
	 * @param[in] inner 同worker threadで生成した実resolver。NULL不可です。
	 * @param[in] state UI役と共有する非機密fixture信号です。
	 */
	WorkerIndexStoppingResolver( std::unique_ptr<IndexPublicIdResolver> inner,
								std::shared_ptr<WorkerIndexState>	   state)
		: inner_( std::move( inner)), state_( std::move( state))
	{
	}
	/** @brief 元種別・context・全presentを実resolverへそのまま渡します。
	 * @param[in] kind 元公開ID種別です。
	 * @param[in] publishedId 公表IDの借用です。保持しません。
	 * @param[in] classGuid 公表classの借用です。保持しません。
	 * @param[in] context 実workerが発行した同scan contextです。
	 * @param[in] present 同captureの全opaque集合です。保持しません。
	 * @return 元resolverの実結果です。人工停止はその返却直前だけに設定します。
	 * @throws std::runtime_error 例外と停止が同時のfixtureだけが送出します。
	 * @note 借用文字列を共有stateやeventへ出さず、待機は最大2秒です。
	 */
	[[nodiscard]] IndexPublicIdResolution resolve(
		IndexPnpIdKind kind, std::string_view publishedId, std::string_view classGuid,
		IndexLookupContext context, std::span<const std::wstring> present) const override
	{
		auto result =
			// 実照合結果です。
			inner_->resolve( kind, publishedId, classGuid, context, present) ;
		// 最初の実callback復帰だけを指定した停止地点へ結びます。
		const bool hold	  = state_->holdResolver.exchange( false) ;
		const bool expire = state_->expireResolver.exchange( false) ;	// 人工期限の一回限定指定です。
		// 元の正常経路では結果へ手を加えず、そのまま返します。
		if( !hold && !expire) {
			return result ;
		}

		state_->originalResolverError		= result.error ;
		state_->originalResolverCompleted	= result.completed ;
		state_->originalResolverDeviceCount = result.devices.size() ;
		++state_->resolverHooks ;
		// UI役が同operation取消しを受理させてから実callbackを返します。
		if( hold) {
			state_->entered.release() ;
			static_cast<void>( state_->release.try_acquire_for( std::chrono::seconds{2})) ;
		}

		// 協調期限を実時間待機なしでちょうど到達させます。
		if( expire) {
			state_->ticks = 5000 ;
		}

		// Lookupが例外診断を作った後の停止でも、その診断を保持させます。
		if( state_->throwResolver) {
			throw std::runtime_error( "fixture resolver failure") ;
		}

		return result ;
	}

private:
	/// 同scan秘密captureをweak参照する実resolverを所有します。
	std::unique_ptr<IndexPublicIdResolver> inner_ ;
	/// 非機密scalarと有限signalだけをUI役へ共有します。
	std::shared_ptr<WorkerIndexState>	   state_ ;
} ;

/** @brief 六fake inventoryを通常worker commandへ返す試験専用Providerです。 */
class WorkerIndexProvider final : public IUpdateProvider, public IIndexScanInventory {
public:
	/** @brief Worker thread内で完全fake transportを所有します。
	 * @param[in] state 非通信試験信号。
	 */
	explicit WorkerIndexProvider( std::shared_ptr<WorkerIndexState> state)
		: state_( std::move( state)), inventory_( inventoryTransport())
	{
		activeInventoryFixture = &fixture_ ;
	}
	/** @brief 秘密inventoryの同thread所有が終わると借用先を外します。 */
	~WorkerIndexProvider() override
	{
		activeInventoryFixture = nullptr ;
	}
	/** @brief Fake scanを通常commandとして有限captureへ結びます。
	 * @param[in] sessionId 実worker発行session。
	 * @param[in] options Fakeは使用しない設定。
	 * @param[in] progress Fakeは使用しない通知。
	 * @return 通常用途のfake結果。DriverStore通常fixture禁止は保持します。
	 */
	[[nodiscard]] ScanResult scan( ScanSessionId sessionId, const ScanOptions &options,
								  const ProviderProgressCallback &progress) override
	{
		return scanWithCancellation( sessionId, options, {}, progress) ;
	}
	/** @brief 既存禁止を緩めず現在属性captureだけを通常fake結果へ接続します。
	 * @param[in] sessionId 同worker発行session。
	 * @param[in] options Fakeは使用しない設定。
	 * @param[in] cancellation 同operationの信号。
	 * @param[in] progress Fakeは使用しない通知。
	 * @return 生IDを持たない通常fake結果。実DriverStore scanやinstallは呼びません。
	 */
	[[nodiscard]] ScanResult scanWithCancellation( ScanSessionId					  sessionId,
												  const ScanOptions				 &options,
												  const ProviderScanCancellation &cancellation,
												  const ProviderProgressCallback &progress) override
	{
		static_cast<void>( options) ;
		// Provider例外時の秘密session破棄を通常workerで確認します。
		if( state_->throwScan) {
			throw std::runtime_error( "fixture scan failure") ;
		}

		fixture_			  = InventoryFixture{} ;
		fixture_.indexIds	  = true ;
		fixture_.sameHardware = state_->mode == 1U ;
		fixture_.unknownClass = state_->mode == 2U ;
		// 元HRESULT保持を現在属性の実検証分岐で起こします。
		if( state_->mode == 3U) {
			fixture_.faultKey	   = DEVPKEY_Device_HardwareIds ;
			fixture_.propertyFault = PropertyFault::ACCESS_DENIED ;
		}

		MetadataSearchExecutionContext execution{
			sessionId,
			MetadataSearchRequest{
				.enabledProviderIds = {std::wstring( SILICON_LABS_OFFICIAL_PROVIDER_ID)}},
			cancellation} ;	// 全APIがfakeの実capture contextです。
		auto result =
			inventory_.scanCurrentIndexInventory( sessionId, execution,
												 progress) ;	// 同workerの有効callbackを借用します。
		result.purpose = ScanPurpose::STANDARD ;
		result.candidates.clear() ;
		// 元scan失敗時は索引loaderを実行させません。
		if( state_->failScan) {
			result.succeeded = false ;
			result.error	 = static_cast<NativeError>( E_ACCESSDENIED) ;
		}

		return result ;
	}
	/** @brief 同captureの実resolverを借り、不正contextだけを人工注入します。
	 * @param[in] operationId 正の実operation。
	 * @param[out] context 実発行context。
	 * @param[out] present 全opaque。
	 * @return 同threadだけで使える実callback。
	 */
	[[nodiscard]] std::unique_ptr<IndexPublicIdResolver> indexScanInventory(
		OperationId operationId, IndexLookupContext &context,
		std::vector<std::wstring> &present) override
	{
		auto resolver = inventory_.makeIndexPublicIdResolver(
			operationId, context, present) ;	// 同fake captureからだけです。
		// 別sessionの発行をworkerが拒否することを確認します。
		if( state_->stale) {
			++context.scanSessionId ;
		}

		// Factory不成立ではNULLを保ち、別callbackへfallbackしません。
		if( !resolver) {
			return resolver ;
		}

		return std::make_unique<WorkerIndexStoppingResolver>( std::move( resolver), state_) ;
	}
	/** @brief 索引後の最終取消しを試す有限計画待機です。
	 * @param[in] sessionId 使用しないsession。
	 * @param[in] planId 使用しないplan。
	 * @return Fakeは取得計画を発行しません。
	 */
	[[nodiscard]] std::optional<OfficialPreparationPlan> preparationPlan(
		ScanSessionId sessionId, std::uint64_t planId) override
	{
		static_cast<void>( sessionId) ;
		static_cast<void>( planId) ;
		// 索引完了後の取消しを有限待機位置へ結びます。
		if( state_->holdPlan.exchange( false)) {
			state_->entered.release() ;
			static_cast<void>( state_->release.try_acquire_for( std::chrono::seconds{2})) ;
		}

		return std::nullopt ;
	}
	/** @brief 誤って導入境界を呼んだ回数だけを記録します。
	 * @param[in] sessionId 使用しないsession。
	 * @param[in] identities 使用しない選択。
	 * @param[in] parent 使用しないWindow。
	 * @param[in] progress 使用しない通知。
	 * @return 失敗。実installを呼びません。
	 */
	[[nodiscard]] InstallResult install( ScanSessionId					sessionId,
										std::span<const std::wstring>	identities,
										std::uintptr_t					parent,
										const ProviderProgressCallback &progress) override
	{
		static_cast<void>( sessionId) ;
		static_cast<void>( identities) ;
		static_cast<void>( parent) ;
		static_cast<void>( progress) ;
		++state_->installs ;
		return {} ;
	}

private:
	/// UI役と共有するfixture信号です。
	std::shared_ptr<WorkerIndexState> state_ ;
	/// 同worker threadだけが六APIへ貸す架空inventoryです。
	InventoryFixture				  fixture_ ;
	/// 通常scan／install禁止を維持する完全fake Providerです。
	DriverStoreProvider				  inventory_ ;
} ;

/** @brief 実復旧APIへ入らない拒否専用fakeです。 */
class WorkerIndexRestore final : public IRestorePointService {
public:
	/** @brief 誤呼出し検出信号を共有します。
	 * @param[in] state Fixture信号。
	 */
	explicit WorkerIndexRestore( std::shared_ptr<WorkerIndexState> state) : state_( std::move( state))
	{
	}
	/** @brief 誤beginを数えて拒否します。
	 * @param[in] description 使用しない本文。
	 * @return 元診断付き失敗。
	 */
	[[nodiscard]] RestorePointOperationResult begin( std::wstring_view description) noexcept override
	{
		static_cast<void>( description) ;
		++state_->restores ;
		return {.error = static_cast<NativeError>( E_ACCESSDENIED)} ;
	}
	/** @brief 誤completeを数えて拒否します。
	 * @param[in] sequenceNumber 使用しない番号。
	 * @return 元診断付き失敗。
	 */
	[[nodiscard]] RestorePointOperationResult complete(
		std::int64_t sequenceNumber) noexcept override
	{
		static_cast<void>( sequenceNumber) ;
		++state_->restores ;
		return {.error = static_cast<NativeError>( E_ACCESSDENIED)} ;
	}

private:
	/// 実APIを呼ばず誤呼出し回数だけを共有します。
	std::shared_ptr<WorkerIndexState> state_ ;
} ;

/** @brief 同operationの実worker終端を最大3秒以内だけ待ちます。
 * @param[in,out] worker 実command queueを持つworker。
 * @param[in] operationId 待つoperation。
 * @param[in] kind 待つ終端用途。
 * @return 同operationのowned event。期限後nulloptです。
 */
[[nodiscard]] std::optional<WorkerEvent> indexWorkerEvent(
	ProviderWorker &worker, OperationId operationId,
	WorkerEventKind kind = WorkerEventKind::SCAN_COMPLETED)
{
	// 3秒以内に到着したeventだけを照合し、外部Windowを使用しません。
	for( unsigned attempt = 0U; attempt < 3000U; ++attempt) {
		const auto events = worker.takeEvents() ;	// 生IDや秘密snapshotを持たないowned packetです。
		// 同operation終端だけを返し、progressを結果に数えません。
		for( const auto &event : events) {
			// 別operationの古い通知を現結果へ適用しません。
			if( event.operationId == operationId && event.kind == kind) {
				return event ;
			}
		}

		std::this_thread::sleep_for( std::chrono::milliseconds{1}) ;
	}

	return std::nullopt ;
}

/** @brief UTF-16の実要素だけをraw propertyへcopyし、終端を追加しません。
 * @param[in] text 呼出し中だけ借用する架空要素列です。長さに終端も明示します。
 * @param[in] capacity 必要byte数です。0は実要素数と同じ容量です。
 * @return 実byteと必要量・返却量を独立変更できるfixture値です。
 */
[[nodiscard]] IndexIdProperty indexIdProperty( const std::wstring_view text,
											  const DWORD			  capacity = 0U)
{
	IndexIdProperty property ;	// 人工byteだけを所有する一属性です。
	property.bytes.resize( text.size() * sizeof( wchar_t)) ;
	// 空入力ではdataの参照を要求しません。
	if( !property.bytes.empty()) {
		std::memcpy( property.bytes.data(), text.data(), property.bytes.size()) ;
	}

	property.returned = static_cast<DWORD>( property.bytes.size()) ;
	property.required = capacity == 0U ? property.returned : capacity ;
	return property ;
}

/** @brief 正常・不正propertyと期待する同scan照合結果を保持します。 */
struct IndexIdListCase {
	/// 私有本文を含まない固定test IDです。
	std::string					   id ;
	/// 元Hardware属性の明示注入値です。未指定なら従来値です。
	std::optional<IndexIdProperty> hardware ;
	/// 元Compatible属性の明示注入値です。未指定なら従来値です。
	std::optional<IndexIdProperty> compatible ;
	/// 元Win32診断に対応する期待HRESULTです。
	NativeError					   expectedError{} ;
	/// 当該一nodeに対する期待exact一致件数です。
	std::size_t					   expectedMatches{1U} ;
	/// 公表IDをCompatible側だけへ置く場合trueです。
	bool						   publishedInCompatible{} ;
	/// 架空privacy canaryを内部値へ設定する場合trueです。
	bool						   privacy{} ;
} ;

/** @brief 診断streamを一scopeだけRAMへ借り、破棄時に元の出力先へ戻します。 */
struct IndexDiagnosticCapture {
	/// 正常診断の人工検査用bufferです。
	std::ostringstream output ;
	/// 失敗診断の人工検査用bufferです。
	std::ostringstream error ;
	/// 借用期間後に必ず戻す元stdoutです。
	std::streambuf	  *previousOutput ;
	/// 借用期間後に必ず戻す元stderrです。
	std::streambuf	  *previousError ;
	/** @brief 同threadの診断だけをscope内でRAMへ保持します。 */
	IndexDiagnosticCapture()
		: previousOutput( std::cout.rdbuf( output.rdbuf())),
		  previousError( std::cerr.rdbuf( error.rdbuf()))
	{
	}
	/** @brief 元のstreamを復元し、private値を外部へ転送しません。 */
	~IndexDiagnosticCapture()
	{
		std::cout.rdbuf( previousOutput) ;
		std::cerr.rdbuf( previousError) ;
	}
} ;

/** @brief 事前固定したempty-listの62新条件を61実行・1未実行として保持します。
 * @param[in,out] context 旧groupと分離するassertion集計先です。
 * @note 全APIはInventoryCaseのfakeだけを使用し、欠損をemptyへ変換しません。
 */
void testIndexIdExplicitEmptyLists( TestContext &context)
{
	const int		  first	   = context.assertionCount() ;	// 新groupだけの実assertion数です。
	const int		  failures = context.failureCount() ;	// 元失敗を保持する差分基準です。
	const NativeError invalid =
		// 元不正診断。
		static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
	std::vector<IndexIdListCase> cases ;											// 事前固定の新transport分母です。
	const std::wstring			 oneNull( 1U, L'\0') ;								// 実一文字だけの明示空list。
	const std::wstring			 twoNull( 2U, L'\0') ;								// 従来受理する明示空list。
	const std::wstring canonical = std::wstring{L"TESTBUS\\SYNTH_0001"} + twoNull ;	// 通常list。
	// 各属性の必要量だけを変更し、実一文字NULと確保末尾を区別します。
	for( const DWORD capacity : {2U, 8U}) {
		const auto suffix = capacity == 2U ? "2" : "8" ;	// 固定test IDの数値部分です。
		cases.push_back(
			{std::string{"P02-required"} + suffix, {}, indexIdProperty( oneNull, capacity)}) ;
		cases.push_back( {std::string{"P03-required"} + suffix,
						 indexIdProperty( oneNull, capacity),
						 {},
						 0U,
						 1U,
						 true}) ;
		cases.push_back( {std::string{"P05-both-two"} + (capacity == 2U ? "" : "-cap8"),
						 indexIdProperty( oneNull, capacity), indexIdProperty( oneNull, capacity), 0U,
						 0U}) ;
	}

	cases.push_back( {"P01-canonical"}) ;
	cases.push_back( {"P04-both-four", indexIdProperty( twoNull), indexIdProperty( twoNull), 0U, 0U}) ;
	// 両種別へ同じfaultを独立に一度ずつ注入する有限builderです。所有値をcopyします。
	const auto addBoth = [&]( const std::string &id, const IndexIdProperty &property,
							 const NativeError error) {
		cases.push_back( {id + "-H", property, {}, error, 0U}) ;
		cases.push_back( {id + "-C", {}, property, error, 0U}) ;
	} ;
	// 非NUL実一文字は、確保領域の残りが0でも空listへ昇格させません。
	for( const DWORD capacity : {2U, 8U}) {
		cases.push_back( {std::string{"N06-H"} + (capacity == 2U ? "2" : "8"),
						 indexIdProperty( L"A", capacity),
						 {},
						 invalid,
						 0U}) ;
		cases.push_back( {std::string{"N06-C"} + (capacity == 2U ? "2" : "8"),
						 {},
						 indexIdProperty( L"A", capacity),
						 invalid,
						 0U}) ;
	}

	addBoth( "N07-nonascii", indexIdProperty( L"\u00e9"), invalid) ;
	addBoth( "N07-surrogate", indexIdProperty( std::wstring( 1U, static_cast<wchar_t>( 0xd800U))),
			invalid) ;
	// 2byte・4byteいずれの明示空値も型不一致なら拒否します。
	for( const auto &text : {oneNull, twoNull}) {
		auto property = indexIdProperty( text) ;	// 本文と実sizeは正しい型違いです。
		property.type = DEVPROP_TYPE_STRING ;
		addBoth( text.size() == 1U ? "N08-type2" : "N08-type4", property, invalid) ;
	}

	// 必要量・実量のzeroとoddを本文から独立させます。
	for( const bool required : {true, false}) {
		// 全三境界を各一回だけ実行し、失敗を分母から外しません。
		for( const DWORD bytes : {0U, 1U, 3U}) {
			auto property = indexIdProperty( oneNull, 4U) ;	// 確保内の本文は常に実NULです。
			(required ? property.required : property.returned) = bytes ;
			const std::string id = std::string{bytes == 0U ? "N09-" : "N10-"} +
								   (required ? "required" : "returned") +
								   // 固定境界ID。
								   std::to_string( bytes) ;
			addBoth( id, property, invalid) ;
		}
	}

	auto overreturn		= indexIdProperty( oneNull) ;	// 実量自己申告だけが確保容量を超えます。
	overreturn.returned = 4U ;
	addBoth( "N11-overreturn", overreturn, invalid) ;
	auto cap = indexIdProperty( oneNull, 65538U) ;	// 既存64KiB上限を超える必要量です。
	addBoth( "N11-cap", cap, static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_MORE_DATA))) ;
	auto growth		  = indexIdProperty( oneNull) ;	// 二回目の容量増大は再確保しません。
	growth.returned	  = 4U ;
	growth.valueError = ERROR_INSUFFICIENT_BUFFER ;
	addBoth( "N11-growth", growth,
			static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INSUFFICIENT_BUFFER))) ;
	auto missing	  = indexIdProperty( oneNull) ;	// 正常NUL本文を持っていても初回不存在です。
	missing.sizeError = ERROR_NOT_FOUND ;
	addBoth( "N12-missing", missing, static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_FOUND))) ;
	// 初回・二回目の二診断を別々に保持します。
	for( const bool sizeQuery : {true, false}) {
		// Win32診断をERROR_INVALID_DATAへまとめず、元codeを期待します。
		for( const DWORD error : {ERROR_ACCESS_DENIED, ERROR_INVALID_DATA}) {
			auto property = indexIdProperty( oneNull) ;	// 失敗APIが値を保証しないfixtureです。
			(sizeQuery ? property.sizeError : property.valueError) = error ;
			const std::string id =
				std::string{"N13-"} + (sizeQuery ? "size-" : "value-") +
				(error == ERROR_ACCESS_DENIED ? "access" : "invalid") ;	// 固定診断ID。
			addBoth( id, property, static_cast<NativeError>( HRESULT_FROM_WIN32( error))) ;
		}
	}

	cases.push_back( {"N14-single-term",
					 indexIdProperty( std::wstring{L"TESTBUS\\SYNTH_0001"} + oneNull),
					 {},
					 invalid,
					 0U}) ;
	cases.push_back( {"N15-truncated",
					 indexIdProperty( L"TESTBUS\\SYNTH_0001",
									 static_cast<DWORD>( canonical.size() * sizeof( wchar_t))),
					 {},
					 invalid,
					 0U}) ;
	auto finalNonNull	= canonical ;	// 最終list終端だけを非NULへ変えます。
	finalNonNull.back() = L'X' ;
	cases.push_back( {"N15-final-nonnull", indexIdProperty( finalNonNull), {}, invalid, 0U}) ;
	auto penultimateNonNull = canonical ;	// 最終要素終端だけを非NULへ変えます。
	penultimateNonNull[penultimateNonNull.size() - 2U] = L'X' ;
	cases.push_back(
		{"N15-penultimate-nonnull", indexIdProperty( penultimateNonNull), {}, invalid, 0U}) ;
	const auto duplicate = std::wstring{L"TESTBUS\\SYNTH_0001"} + oneNull ;	// 第一要素です。
	cases.push_back(
		{"N16-exact", indexIdProperty( duplicate + duplicate + oneNull), {}, invalid, 0U}) ;
	cases.push_back( {"N16-case",
					 indexIdProperty( duplicate + L"testbus\\synth_0001" + twoNull),
					 {},
					 invalid,
					 0U}) ;
	cases.push_back( {"N17-trailing-data", indexIdProperty( oneNull + canonical), {}, invalid, 0U}) ;
	cases.push_back( {"N18-extra-null", indexIdProperty( std::wstring( 3U, L'\0')), {}, invalid, 0U}) ;
	// Native grammarを補正せず、元の文字種と512文字上限を保持します。
	for( const auto &entry : std::array<std::pair<std::string_view, std::wstring>, 4U>{
			{{"N19-control", L"TESTBUS\\BAD\x01"},
			 {"N19-space", L"TESTBUS\\BAD NAME"},
			 {"N19-nonascii", L"TESTBUS\\\u00e9"},
			 {"N19-length513", std::wstring( 513U, L'A')}}}) {
		cases.push_back(
			{std::string{entry.first}, indexIdProperty( entry.second + twoNull), {}, invalid, 0U}) ;
	}

	cases.push_back( {"N24-output-canary", {}, {}, 0U, 0U, false, true}) ;
	DRIVERCRATE_EXPECT( context, cases.size() == 61U) ;
	std::size_t executed{} ;	// 前提不成立でも当該caseを失敗として数えます。
	// 全61transport条件を固定順に一回だけ実行し、結果を静的IDだけで報告します。
	for( const auto &testCase : cases) {
		const int before = context.failureCount() ;	// この行の原失敗数です。
		{
			IndexDiagnosticCapture diagnostics ;	// 私有値はRAMに留める診断検査です。
			InventoryCase		   run ;			// 同じ正式fixture所有者だけを使います。
			run.fixture.nodes					= 1U ;
			run.fixture.indexIdProperties		= {testCase.hardware, testCase.compatible} ;
			run.fixture.publishedIdInCompatible = testCase.publishedInCompatible ;
			// 実機情報を使わず、ID・表示名・instance/serial/opaque相当の漏出を検出します。
			if( testCase.privacy) {
				run.fixture.indexId		  = L"TESTBUS\\DC231_PRIVATE_ID_PROPERTY" ;
				run.fixture.displayName	  = L"DC231_PRIVATE_NAME" ;
				run.fixture.instanceValue = L"DC231_PRIVATE_INSTANCE_SERIAL_OPAQUE" ;
			}

			const auto		   scanned = run.scanForIndex() ;	// 実deviceへ入らない本番captureです。
			IndexLookupContext issued ;							// このcaseだけの発行contextです。
			std::vector<std::wstring> present ;					// 当該captureの全opaqueだけです。
			auto					  resolver =
				// 元能力。
				run.provider.makeIndexPublicIdResolver( 1101U, issued, present) ;
			DRIVERCRATE_EXPECT( context,
							   scanned.candidates.size() == 1U && resolver && present.size() == 1U) ;
			// 前提失敗も分母に残し、不正pointerへ進みません。
			if( resolver && present.size() == 1U) {
				const auto propertyCalls = run.fixture.propertyCalls ;	// Resolveは再照会しません。
				const auto result		 = resolver->resolve(
					   IndexPnpIdKind::HARDWARE, "TESTBUS\\SYNTH_0001",
					   "{11111111-2222-3333-4444-555555555555}", issued, present) ;	// 元公開tuple。
				DRIVERCRATE_EXPECT( context, result.completed == (testCase.expectedError == 0U)) ;
				DRIVERCRATE_EXPECT( context, result.error == testCase.expectedError) ;
				DRIVERCRATE_EXPECT( context, result.devices.size() == testCase.expectedMatches &&
												!result.positiveProof) ;
				DRIVERCRATE_EXPECT( context, result.context == issued &&
												run.fixture.propertyCalls == propertyCalls) ;
				DRIVERCRATE_EXPECT( context, result.devices.empty() ||
												result.devices.front() == present.front()) ;
			}

			DRIVERCRATE_EXPECT( context, run.fixture.validArguments &&
											run.fixture.opened == run.fixture.closed) ;
			// 診断の内容とUIのopaque識別子へprivate本文を転記していないことを確認します。
			if( testCase.privacy) {
				DRIVERCRATE_EXPECT( context, diagnostics.output.str().find( "DC231_PRIVATE") ==
													std::string::npos &&
												diagnostics.error.str().find( "DC231_PRIVATE") ==
													std::string::npos) ;
				// 表示名のUI表示は許可し、秘密IDとinstanceだけを通常行から除外します。
				for( const auto &row : scanned.candidates) {
					DRIVERCRATE_EXPECT(
						context,
						row.identity.find( run.fixture.instanceValue) == std::wstring::npos &&
							row.deviceIdentity.find( run.fixture.instanceValue) ==
								std::wstring::npos &&
							row.title.find( run.fixture.indexId) == std::wstring::npos) ;
				}
			}
		}

		++executed ;
		std::cout << "Native ID empty-list " << testCase.id << ": "
				  << (context.failureCount() == before ? "PASS" : "FAIL") << '\n' ;
	}

	std::cout
		<< "Native ID empty-list N20-class-api: NOT_RUN inventory-only transport bypasses native Class snapshot\n" ;
	std::cout << "Native ID empty-list variants: " << executed
			  << "/62 executed, 1 NOT_RUN; assertions: " << context.assertionCount() - first
			  << ", failures: " << context.failureCount() - failures << '\n' ;
}

} // namespace

/** @see metadata_inventory_tests.h */
void runWorkerSignedIndexScanTests( TestContext &context, std::shared_ptr<SignedIndexStore> store,
								   const std::chrono::sys_seconds nowUtc,
								   const std::size_t			  expectedRecords)
{
	const int  first	= context.assertionCount() ;	// 新worker groupの実件数です。
	const int  failures = context.failureCount() ;		// 原groupと失敗を分けます。
	const auto verified = store->reload( nowUtc) ;		// 境界を実保存manifestから読みます。
	DRIVERCRATE_EXPECT( context, verified.snapshot.has_value()) ;
	// 真入力の不成立を拒否fixture成功へ換算しません。
	if( !verified.snapshot) {
		return ;
	}

	const auto published = verified.snapshot->schemaReceipt()
							   .assetBytes()
							   .manifest()
							   .data()
							   .publishedAtUtc ;	// 元署名発行UTCです。
	const auto expires = verified.snapshot->schemaReceipt()
							 .assetBytes()
							 .manifest()
							 .data()
							 .expiresAtUtc ;			// 元署名期限UTCです。
	auto state = std::make_shared<WorkerIndexState>() ;	// Fake間だけで共有する非通信信号です。
	provider_worker_index_detail::Services services ;	// Private constructorだけへ渡す隔離能力です。
	services.load = [store, state]( std::optional<std::chrono::sys_seconds> now) {
		// Loader例外で古い秘密sessionを保持しません。
		if( state->throwLoad) {
			throw std::runtime_error( "fixture load failure") ;
		}

		// 真reload直前の有限待機で取消し／stopを観測します。
		if( state->holdLoad.exchange( false)) {
			state->entered.release() ;
			static_cast<void>( state->release.try_acquire_for( std::chrono::seconds{2})) ;
		}

		// 同workerの未配備status伝達だけをfake化し、製品rootへ進みません。
		if( state->loadMode == 1U) {
			return IndexStoreResult{.status = IndexStoreStatus::TRUST_UNAVAILABLE} ;
		}

		// 真genesisをreloadして空を成功と区別します。
		if( state->loadMode == 2U) {
			auto empty =
				// 自作隔離rootだけです。
				signed_index_store_detail::Access::createIsolated( {}) ;
			return empty.store ? empty.store->reload( now) : IndexStoreResult{.error = empty.error} ;
		}

		// 明示I/O失敗の元診断を維持します。
		if( state->loadMode == 3U) {
			return IndexStoreResult{.status = IndexStoreStatus::IO_FAILURE,
									.error	= static_cast<NativeError>( E_ACCESSDENIED)} ;
		}

		return store->reload( now) ;
	} ; // 真署名・隔離保護storeの同再認証を実workerから呼びます。
	services.utc = [state, nowUtc, published,
					expires]() -> std::optional<std::chrono::sys_seconds> {
		// 時刻不明を現在有効へ補正しません。
		if( state->timeMode == 1U) {
			return std::nullopt ;
		}

		// 署名期限ちょうどを拒否します。
		if( state->timeMode == 2U) {
			return expires ;
		}

		// 発行前を拒否します。
		if( state->timeMode == 3U) {
			return published - std::chrono::seconds{1} ;
		}

		return nowUtc ;
	} ; // FixtureのUTCだけです。
	services.monotonic = [state] {
		return std::chrono::steady_clock::time_point{
			std::chrono::milliseconds{state->ticks.fetch_add( state->tickStep)}} ;
	} ; // 実時間から独立した協調時計です。
	const auto makeWorker = [state]( provider_worker_index_detail::Services current) {
		return provider_worker_index_detail::Access::create(
			[state] { return std::make_unique<WorkerIndexProvider>( state) ; },
			[state] { return std::make_unique<WorkerIndexRestore>( state) ; }, std::move( current)) ;
	} ; // Worker thread内生成でresolver owner threadも一致します。
	auto		worker	  = makeWorker( services) ;	// 実通常ScanCommand queueを使用します。
	OperationId operation = 1U ;					// UI役の単調operationです。
	const auto	scan	  = [&]() {
		  DRIVERCRATE_EXPECT( context, worker->requestScan( operation)) ;
		  return indexWorkerEvent( *worker, operation++) ;
	} ; // 同workerへ通常scanだけを要求します。
	const auto normal = scan() ;	// 513recordを三batchで実行します。
	DRIVERCRATE_EXPECT( context, normal && normal->scanResult.succeeded &&
									normal->indexSummary.status == IndexScanStatus::COMPLETED) ;
	DRIVERCRATE_EXPECT( context, normal && normal->indexSummary.totalRecords == expectedRecords &&
									normal->indexSummary.processedRecords == expectedRecords &&
									normal->indexSummary.remainingRecords == 0U) ;
	DRIVERCRATE_EXPECT( context,
					   normal && normal->indexSummary.matchedRelations == 2U * expectedRecords &&
						   normal->indexSummary.resolverCalls == 2U * expectedRecords &&
						   normal->scanResult.candidates.empty() && !normal->preparationPlan) ;
	state->mode		 = 1U ;
	const auto multi = scan() ;	// 一Hardware IDが二opaqueへ結ぶ非一意です。
	DRIVERCRATE_EXPECT( context, multi && multi->indexSummary.status == IndexScanStatus::COMPLETED &&
									multi->indexSummary.nonUniqueRelations == 2U * expectedRecords) ;
	state->mode		   = 2U ;
	const auto unknown = scan() ;	// 必須class不明を更新なしへしません。
	DRIVERCRATE_EXPECT( context, unknown &&
									unknown->indexSummary.status == IndexScanStatus::PARTIAL &&
									unknown->indexSummary.undeterminedRelations > 0U) ;
	state->mode		   = 3U ;
	const auto partial = scan() ;	// 実property検証の元HRESULTです。
	DRIVERCRATE_EXPECT( context,
					   partial && partial->indexSummary.status == IndexScanStatus::PARTIAL &&
						   partial->indexSummary.error ==
							   static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED))) ;
	const NativeError originalFailure = static_cast<NativeError>(
		// 元property診断の変換です。
		HRESULT_FROM_WIN32( ERROR_ACCESS_DENIED)) ;
	const NativeError stopFailure = static_cast<NativeError>(
		// 元error0の場合の停止診断です。
		HRESULT_FROM_WIN32( ERROR_TIMEOUT)) ;
	// 正常・元API障害・例外の各復帰と取消し／期限到達を同時に起こします。
	for( unsigned outcome = 0U; outcome < 3U; ++outcome) {
		// 各入力に対して同operation取消しと協調期限を独立に確認します。
		for( unsigned stop = 0U; stop < 2U; ++stop) {
			state->mode			  = outcome == 1U ? 3U : 0U ;
			state->throwResolver  = outcome == 2U ;
			state->ticks		  = 0 ;
			state->holdResolver	  = stop == 0U ;
			state->expireResolver = stop == 1U ;
			state->resolverHooks  = 0U ;
			const auto id		  = operation++ ;	// 停止を結合する実commandです。
			DRIVERCRATE_EXPECT( context, worker->requestScan( id)) ;
			// 実callbackの元結果を得る前には取消しを注入しません。
			if( stop == 0U) {
				DRIVERCRATE_EXPECT( context,
								   state->entered.try_acquire_for( std::chrono::seconds{3})) ;
				DRIVERCRATE_EXPECT( context, worker->requestScanCancel( id)) ;
				state->release.release() ;
			}

			const auto		  event = indexWorkerEvent( *worker, id) ;	// 通常workerの非機密終端です。
			// 元API診断・例外変換・元error0の停止診断を独立に期待します。
			const NativeError expectedError = outcome == 1U	  ? originalFailure
											  : outcome == 2U ? static_cast<NativeError>( E_FAIL)
															  : stopFailure ;
			DRIVERCRATE_EXPECT( context,
							   state->resolverHooks == 1U &&
								   state->originalResolverError ==
									   (outcome == 1U ? originalFailure : NativeError{}) &&
								   state->originalResolverCompleted == (outcome != 1U) &&
								   state->originalResolverDeviceCount == (outcome == 1U ? 0U : 1U)) ;
			DRIVERCRATE_EXPECT( context,
							   event && event->indexSummary.status ==
											(stop == 0U ? IndexScanStatus::CANCELLED
														: IndexScanStatus::BUDGET_EXHAUSTED)) ;
			DRIVERCRATE_EXPECT( context, event && event->indexSummary.error == expectedError) ;
			DRIVERCRATE_EXPECT( context, event && event->indexSummary.resolverCalls == 1U &&
											event->indexSummary.matchedRelations == 0U &&
											event->indexSummary.relatedDeviceCount == 0U &&
											event->scanResult.candidates.empty() &&
											!event->preparationPlan) ;
			// 取消したbatchは一recordも処理済みへ数えず、既存ABORTEDを維持します。
			if( stop == 0U) {
				DRIVERCRATE_EXPECT( context,
								   event && !event->scanResult.succeeded &&
									   event->scanResult.outcome == OutcomeCode::ABORTED &&
									   event->indexSummary.processedRecords == 0U &&
									   event->indexSummary.remainingRecords == expectedRecords) ;
				const std::array<std::wstring, 1U> selected{
					L"not-an-index-install-token"} ;	// 導入tokenではありません。
				DRIVERCRATE_EXPECT(
					context, worker->requestInstall(
								 operation, event ? event->scanResult.scanSessionId : 1U, selected,
								 nullptr, InstallProtectionMode::WINDOWS_RESTORE_POINT)) ;
				const auto install = indexWorkerEvent(
					*worker, operation++,
					WorkerEventKind::INSTALL_COMPLETED) ;	// 失効を復旧・導入前に拒否します。
				DRIVERCRATE_EXPECT( context,
								   install && state->installs == 0U && state->restores == 0U) ;
			} else {
				DRIVERCRATE_EXPECT( context, event &&
												event->indexSummary.undeterminedRelations > 0U &&
												event->indexSummary.remainingRecords > 0U) ;
			}

			state->mode			 = 0U ;
			state->throwResolver = false ;
			state->ticks		 = 0 ;
			const auto resumed	 = scan() ;	// 新scanは前回診断を引き継ぎません。
			DRIVERCRATE_EXPECT(
				context, resumed && resumed->indexSummary.status == IndexScanStatus::COMPLETED &&
							 resumed->indexSummary.error == 0U &&
							 resumed->indexSummary.processedRecords == expectedRecords &&
							 resumed->indexSummary.matchedRelations == 2U * expectedRecords) ;
		}
	}

	state->mode					   = 3U ;
	auto relationBound			   = services ;	// 最初のbatchを保持枠だけで拒否する有限予算です。
	relationBound.maximumRelations = 1U ;
	auto relationWorker = makeWorker( relationBound) ;	// 実callback診断を早期return前に保持します。
	DRIVERCRATE_EXPECT( context, relationWorker->requestScan( 1U)) ;
	const auto relationRejected =
		// 保持拒否した通常終端です。
		indexWorkerEvent( *relationWorker, 1U) ;
	DRIVERCRATE_EXPECT(
		context, relationRejected &&
					 relationRejected->indexSummary.status == IndexScanStatus::BUDGET_EXHAUSTED &&
					 relationRejected->indexSummary.error == originalFailure &&
					 relationRejected->indexSummary.processedRecords == 0U &&
					 relationRejected->indexSummary.remainingRecords == expectedRecords &&
					 relationRejected->indexSummary.matchedRelations == 0U) ;
	relationWorker->stop() ;
	state->mode = 0U ;
	// 時計・未配備・空・I/O拒否を同通常commandから読みます。
	for( unsigned mode = 1U; mode <= 3U; ++mode) {
		state->timeMode		= mode ;
		const auto event	= scan() ;	// 元scanは成功し索引だけを拒否します。
		const auto expected = mode == 1U   ? IndexScanStatus::TIME_UNAVAILABLE
							  : mode == 2U ? IndexScanStatus::EXPIRED
										   : IndexScanStatus::NOT_YET_VALID ;	// 時刻別の元区分です。
		DRIVERCRATE_EXPECT( context, event && event->scanResult.succeeded &&
										event->indexSummary.status == expected) ;
	}

	state->timeMode = 0U ;
	// 保存入口の未配備・空・I/O診断をそれぞれ独立に確認します。
	for( unsigned mode = 1U; mode <= 3U; ++mode) {
		state->loadMode		= mode ;
		const auto event	= scan() ;	// 実通常branchです。
		const auto expected = mode == 1U ? IndexScanStatus::TRUST_UNAVAILABLE
							  : mode == 2U
								  ? IndexScanStatus::EMPTY_STORE
								  : IndexScanStatus::LOAD_REJECTED ;	// 空は索引完了ではありません。
		DRIVERCRATE_EXPECT( context, event && event->scanResult.succeeded &&
										event->indexSummary.status == expected) ;
	}

	state->loadMode	 = 0U ;
	state->stale	 = true ;
	const auto stale = scan() ;	// 別sessionのresolver発行です。
	DRIVERCRATE_EXPECT( context,
					   stale && stale->indexSummary.status == IndexScanStatus::STALE_CONTEXT) ;
	state->stale	  = false ;
	state->failScan	  = true ;
	const auto failed = scan() ;	// 元scan失敗は索引を読みません。
	DRIVERCRATE_EXPECT( context, failed && !failed->scanResult.succeeded &&
									failed->indexSummary.status == IndexScanStatus::SCAN_FAILED) ;
	state->failScan	  = false ;
	state->throwScan  = true ;
	const auto thrown = scan() ;	// 実通常workerの例外終端です。
	DRIVERCRATE_EXPECT( context, thrown && !thrown->scanResult.succeeded &&
									thrown->indexSummary.status == IndexScanStatus::SCAN_FAILED) ;
	state->throwScan	  = false ;
	state->throwLoad	  = true ;
	const auto loadThrown = scan() ;	// 索引失敗は旧Provider候補の失敗へまとめません。
	DRIVERCRATE_EXPECT( context,
					   loadThrown && loadThrown->scanResult.succeeded &&
						   loadThrown->indexSummary.status == IndexScanStatus::INTERNAL_FAILURE) ;
	state->throwLoad = false ;
	// Load中と索引完了後の双方で最終取消しを照合します。
	for( unsigned stage = 0U; stage < 2U; ++stage) {
		state->holdLoad = stage == 0U ;
		state->holdPlan = stage == 1U ;
		const auto id	= operation++ ;	// 同commandにだけ結ぶ取消しIDです。
		DRIVERCRATE_EXPECT( context, worker->requestScan( id)) ;
		DRIVERCRATE_EXPECT( context, state->entered.try_acquire_for( std::chrono::seconds{3})) ;
		DRIVERCRATE_EXPECT( context, worker->requestScanCancel( id)) ;
		state->release.release() ;
		const auto cancelled = indexWorkerEvent( *worker, id) ;	// 実終端の失効結果です。
		DRIVERCRATE_EXPECT( context,
						   cancelled && !cancelled->scanResult.succeeded &&
							   cancelled->indexSummary.status == IndexScanStatus::CANCELLED &&
							   !cancelled->preparationPlan) ;
		DRIVERCRATE_EXPECT( context, !worker->requestScanCancel( id)) ;
		const std::array<std::wstring, 1U> selected{
			L"not-an-index-install-token"} ;	// 索引からtokenを作れません。
		DRIVERCRATE_EXPECT( context,
						   worker->requestInstall(
							   operation, cancelled ? cancelled->scanResult.scanSessionId : 1U,
							   selected, nullptr, InstallProtectionMode::WINDOWS_RESTORE_POINT)) ;
		const auto install = indexWorkerEvent(
			*worker, operation++,
			WorkerEventKind::INSTALL_COMPLETED) ;	// 元scan失効を導入境界前に拒否します。
		DRIVERCRATE_EXPECT( context, install && state->installs == 0U && state->restores == 0U) ;
	}

	const auto renewed = scan() ;	// 取消し後の新sessionだけが再読取りできます。
	DRIVERCRATE_EXPECT(
		context, renewed && renewed->indexSummary.status == IndexScanStatus::COMPLETED && normal &&
					 renewed->scanResult.scanSessionId > normal->scanResult.scanSessionId) ;
	worker->stop() ;
	DRIVERCRATE_EXPECT( context, !worker->requestScan( operation)) ;
	// Record・callback・tupleの縮小予算を全batch共通で確認します。
	for( unsigned limit = 0U; limit < 3U; ++limit) {
		auto bounded			 = services ;	// 製品上限を拡大しない内部予算です。
		bounded.maximumRecords	 = limit == 0U ? 256U : 16384U ;
		bounded.maximumCalls	 = limit == 1U ? 513U : 32768U ;
		bounded.maximumRelations = limit == 2U ? 512U : 32768U ;
		auto limited			 = makeWorker( bounded) ;	// それぞれ実通常commandです。
		DRIVERCRATE_EXPECT( context, limited->requestScan( 1U)) ;
		const auto event = indexWorkerEvent( *limited, 1U) ;	// 二batch目も同じ残枠です。
		DRIVERCRATE_EXPECT(
			context, event && event->indexSummary.status == IndexScanStatus::BUDGET_EXHAUSTED &&
						 event->indexSummary.resolverCalls <= bounded.maximumCalls) ;
		// 256recordで止めた残件が更新なしへ数えられないことを厳密に確認します。
		if( limit == 0U) {
			DRIVERCRATE_EXPECT( context,
							   event && event->indexSummary.processedRecords == 256U &&
								   event->indexSummary.remainingRecords == expectedRecords - 256U) ;
		}

		limited->stop() ;
	}

	state->tickStep	 = 1 ;
	auto timed		 = services ;	// 期限中のcallbackで止める人工時計です。
	timed.duration	 = std::chrono::milliseconds{10} ;
	auto timedWorker = makeWorker( timed) ;	// 実通常commandでdeadlineを検証するworkerです。
	DRIVERCRATE_EXPECT( context, timedWorker->requestScan( 1U)) ;
	const auto timedEvent = indexWorkerEvent( *timedWorker, 1U) ;	// 一batch中でも超過を確認します。
	DRIVERCRATE_EXPECT( context,
					   timedEvent &&
						   timedEvent->indexSummary.status == IndexScanStatus::BUDGET_EXHAUSTED &&
						   timedEvent->indexSummary.undeterminedRelations > 0U) ;
	timedWorker->stop() ;
	state->tickStep = 0 ;
	state->holdLoad = true ;
	auto stopping	= makeWorker( services) ;	// 実stopが同scan取消しを設定します。
	DRIVERCRATE_EXPECT( context, stopping->requestScan( 1U)) ;
	DRIVERCRATE_EXPECT( context, state->entered.try_acquire_for( std::chrono::seconds{3})) ;
	std::thread stopThread( [&] { stopping->stop() ; }) ;	// Worker完了まで寿命を保持します。
	std::this_thread::sleep_for( std::chrono::milliseconds{2}) ;
	state->release.release() ;
	stopThread.join() ;
	const auto stopped =
		// 停止終端後に残るのは非機密結果だけです。
		indexWorkerEvent( *stopping, 1U) ;
	DRIVERCRATE_EXPECT( context, stopped &&
									stopped->indexSummary.status == IndexScanStatus::CANCELLED &&
									!stopped->scanResult.succeeded) ;
	DRIVERCRATE_EXPECT( context, state->installs == 0U && state->restores == 0U) ;
	const std::array<std::byte, 1U> badPlain{std::byte{0}} ;	// Wireだけが壊れた実DPAPI正例です。
	DRIVERCRATE_EXPECT( context,
					   signed_index_store_detail::Access::replacePlain( *store, badPlain) == 0U) ;
	auto broken = makeWorker( services) ;	// 既存head破損を初回へ戻しません。
	DRIVERCRATE_EXPECT( context, broken->requestScan( 1U)) ;
	const auto brokenEvent =
		// 真保護headの実拒否を読む通常commandです。
		indexWorkerEvent( *broken, 1U) ;
	DRIVERCRATE_EXPECT(
		context, brokenEvent && brokenEvent->scanResult.succeeded &&
					 brokenEvent->indexSummary.status == IndexScanStatus::LOAD_REJECTED &&
					 brokenEvent->indexSummary.storeStatus == IndexStoreStatus::STATE_REJECTED) ;
	broken->stop() ;
	std::cout << "Worker signed index scan assertions: " << context.assertionCount() - first
			  << ", failures: " << context.failureCount() - failures << '\n' ;
}

/** @see metadata_inventory_tests.h */
void runMetadataInventoryTests( TestContext &context)
{
	testInventoryLimits( context) ;
	testInventoryFailures( context) ;
	testInventoryIsolation( context) ;
	testObservationContract( context) ;
	testObservedPropertyFailures( context) ;
	testObservedNodeStates( context) ;
	testObservedKeyAndDate( context) ;
}

void runDriverStoreIndexResolverTests( TestContext									   &context,
									  std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot,
									  const std::chrono::sys_seconds					nowUtc)
{
	testIndexIdExplicitEmptyLists( context) ;
	const int initialAssertions =
		// 今回追加した実assertionだけを測ります。
		context.assertionCount() ;
	const int initialFailures = context.failureCount() ;				// 既存groupと失敗数を分離します。
	constexpr std::string_view PUBLISHED_ID = "TESTBUS\\SYNTH_0001" ;	// 架空公表IDだけです。
	constexpr std::string_view PUBLISHED_CLASS =
		"{11111111-2222-3333-4444-555555555555}" ;				// 架空class。
	InventoryCase			  unique ;							// 六API全部がfakeの実Providerです。
	const auto				  scanned = unique.scanForIndex() ;	// 任意DTOでmapを作らない実capture。
	IndexLookupContext		  active ;							// Factoryが発行するcontext。
	std::vector<std::wstring> present ;							// 全present opaqueだけです。
	auto					  resolver =
		// Weak callback。
		unique.provider.makeIndexPublicIdResolver( 701U, active, present) ;
	DRIVERCRATE_EXPECT( context, scanned.succeeded && resolver && present.size() == 2U) ;
	DRIVERCRATE_EXPECT( context, active.operationId == 701U && active.scanSessionId == 83U &&
									active.inventoryGeneration != 0U) ;
	// Factory不成立を後続のpointer参照で隠しません。
	if( !resolver || present.size() != 2U) {
		return ;
	}

	const unsigned propertyCalls = unique.fixture.propertyCalls ;	// Callback前の全I/O件数。
	const unsigned enumCalls =
		unique.fixture.countCalls + unique.fixture.detailCalls ;	// 同じ列挙回数。
	const auto hardware = resolver->resolve( IndexPnpIdKind::HARDWARE, PUBLISHED_ID, PUBLISHED_CLASS,
											active, present) ;	// 公表Hardwareだけ。
	const auto compatible =
		resolver->resolve( IndexPnpIdKind::COMPATIBLE, PUBLISHED_ID, PUBLISHED_CLASS, active,
						  present) ;	// 同文字列の別種別。
	DRIVERCRATE_EXPECT( context, hardware.completed && hardware.error == 0U &&
									hardware.devices == std::vector<std::wstring>{present[0]}) ;
	DRIVERCRATE_EXPECT( context, compatible.completed && compatible.error == 0U &&
									compatible.devices == std::vector<std::wstring>{present[0]}) ;
	DRIVERCRATE_EXPECT( context,
					   unique.fixture.propertyCalls == propertyCalls &&
						   unique.fixture.countCalls + unique.fixture.detailCalls == enumCalls) ;
	DRIVERCRATE_EXPECT( context,
					   !unique.provider.deviceIdentityForHardwareId( L"TESTBUS\\SYNTH_0001")) ;
	const auto connected = lookupSignedIndexRecords( snapshot, active, active, present, {}, nowUtc,
													// 保存済み真snapshotと実Provider callback。
													resolver.get()) ;
	DRIVERCRATE_EXPECT( context, connected.lookup && connected.lookup->relations().size() == 2U) ;
	// 両種別の実関係と原snapshot所有を独立して確認します。
	if( connected.lookup && connected.lookup->relations().size() == 2U) {
		DRIVERCRATE_EXPECT( context,
						   connected.lookup->relations()[0].deviceIdentity == present[0] &&
							   connected.lookup->relations()[1].deviceIdentity == present[0]) ;
		DRIVERCRATE_EXPECT( context, &connected.lookup->snapshot() == snapshot.get()) ;
		DRIVERCRATE_EXPECT(
			context, connected.lookup->relations()[0].state == IndexRecordMatchState::MATCHED &&
						 connected.lookup->relations()[1].state == IndexRecordMatchState::MATCHED) ;
	}

	// 全contextの三fieldを一つずつ変え、stale値から結果を作らせません。
	for( unsigned field = 0U; field < 3U; ++field) {
		auto stale = active ;	// 一fieldだけの不一致。
		stale.operationId += field == 0U ? 1U : 0U ;
		stale.scanSessionId += field == 1U ? 1U : 0U ;
		stale.inventoryGeneration += field == 2U ? 1U : 0U ;
		const auto rejected =
			resolver->resolve( IndexPnpIdKind::HARDWARE, PUBLISHED_ID, PUBLISHED_CLASS, stale,
							  present) ;	// Callback自身の拒否。
		DRIVERCRATE_EXPECT( context,
						   !rejected.completed && rejected.error != 0U && rejected.devices.empty()) ;
	}

	// 部分、重複、余剰present集合を完了としません。
	for( const auto &invalid :
		{std::vector<std::wstring>{present[0]}, std::vector<std::wstring>{present[0], present[0]},
		 std::vector<std::wstring>{present[0], L"unknown-opaque"}}) {
		const auto rejected =
			resolver->resolve( IndexPnpIdKind::HARDWARE, PUBLISHED_ID, PUBLISHED_CLASS, active,
							  invalid) ;	// 不正全present要求。
		DRIVERCRATE_EXPECT( context, !rejected.completed && rejected.error != 0U) ;
	}

	const std::vector<std::wstring> reversed{present[1], present[0]} ;	// 順序だけ変えた同集合。
	DRIVERCRATE_EXPECT(
		context,
		resolver->resolve( IndexPnpIdKind::HARDWARE, PUBLISHED_ID, PUBLISHED_CLASS, active, reversed)
			.completed) ;
	// 非ASCII・UTF-8不正byte・小文字・空IDを入力拒否へ残します。
	for( const std::string_view invalid :
		{"", "TESTBUS\\bad", "TESTBUS\\BAD\\TAIL", "TESTBUS\\\xff"}) {
		const auto rejected = resolver->resolve( IndexPnpIdKind::HARDWARE, invalid, PUBLISHED_CLASS,
												active, present) ;	// 元公開grammarの拒否。
		DRIVERCRATE_EXPECT( context, !rejected.completed && rejected.error != 0U) ;
	}

	const auto badKind = resolver->resolve( static_cast<IndexPnpIdKind>( 99), PUBLISHED_ID,
										   PUBLISHED_CLASS, active, present) ;	// 未知の元種別。
	DRIVERCRATE_EXPECT( context, !badKind.completed && badKind.error != 0U) ;
	const auto badGuid =
		resolver->resolve( IndexPnpIdKind::HARDWARE, PUBLISHED_ID,
						  "{11111111-2222-3333-4444-55555555555Z}", active, present) ;	// 不正class。
	DRIVERCRATE_EXPECT( context, !badGuid.completed && badGuid.error != 0U) ;
	IndexPublicIdResolution wrongThread ;	// 別threadからの結果だけを受け取ります。
	std::thread				other( [&] {
		wrongThread = resolver->resolve( IndexPnpIdKind::HARDWARE, PUBLISHED_ID, PUBLISHED_CLASS,
													active, present) ;
	}) ; // Immutable stateを借用し、joinまでlifetimeを保持します。
	other.join() ;
	DRIVERCRATE_EXPECT( context, !wrongThread.completed && wrongThread.error != 0U) ;
	bool		wrongThreadFactory{} ;	// Factory自体のowner拒否結果だけを受けます。
	std::thread factoryThread( [&] {
		IndexLookupContext		  rejectedContext ;	// 別threadの出力先。
		std::vector<std::wstring> rejectedPresent ;	// 非機密opaqueだけの出力。
		wrongThreadFactory =
			!unique.provider.makeIndexPublicIdResolver( 701U, rejectedContext, rejectedPresent) &&
			rejectedContext.operationId == 0U && rejectedPresent.empty() ;
	}) ; // MainはjoinまでProviderを変更しません。
	factoryThread.join() ;
	DRIVERCRATE_EXPECT( context, wrongThreadFactory) ;
	IndexLookupContext		  zeroContext ;					// 拒否時に空へ戻る出力。
	std::vector<std::wstring> zeroPresent{L"sentinel"} ;	// 出力resetを検査します。
	DRIVERCRATE_EXPECT( context,
					   !unique.provider.makeIndexPublicIdResolver( 0U, zeroContext, zeroPresent) &&
						   zeroContext.operationId == 0U && zeroPresent.empty()) ;
	// 新scanが同sessionを使ってもinventory世代と旧weak能力を失効させます。
	unique.fixture.counting = true ;
	static_cast<void>( unique.scanForIndex()) ;
	DRIVERCRATE_EXPECT(
		context,
		!resolver->resolve( IndexPnpIdKind::HARDWARE, PUBLISHED_ID, PUBLISHED_CLASS, active, present)
			 .completed) ;
	IndexLookupContext		  renewed ;			// 同sessionの次世代。
	std::vector<std::wstring> renewedPresent ;	// 次scanの全opaque集合。
	auto					  renewedResolver =
		// 新能力。
		unique.provider.makeIndexPublicIdResolver( 702U, renewed, renewedPresent) ;
	DRIVERCRATE_EXPECT( context,
					   renewedResolver && renewed.inventoryGeneration > active.inventoryGeneration) ;
	const std::array<std::wstring, 1U> selection{
		L"unknown-update"} ;	// Fixture導入guardを拒否させます。
	const auto deniedInstall = unique.provider.install(
		83U, selection, 0U, []( const ProviderProgress &) {}) ;	// 実導入なし。
	DRIVERCRATE_EXPECT( context, !deniedInstall.succeeded) ;
	DRIVERCRATE_EXPECT( context,
					   renewedResolver && !renewedResolver
											   ->resolve( IndexPnpIdKind::HARDWARE, PUBLISHED_ID,
														 PUBLISHED_CLASS, renewed, renewedPresent)
											   .completed) ;

	// 同型二台、class相違、class欠損、表示欠損を独立の同scanで比較します。
	for( unsigned mode = 0U; mode < 4U; ++mode) {
		InventoryCase run ;	// 任意DTOへ置換しない同じcapture。
		run.fixture.sameHardware			  = true ;
		run.fixture.differentClass			  = mode == 1U ;
		run.fixture.unknownClass			  = mode == 2U ;
		run.fixture.missingAttributes		  = mode == 3U ;
		const auto				  scannedMode = run.scanForIndex() ;	// 表示欠損もpresentへ残します。
		IndexLookupContext		  issued ;								// 当該caseだけのcontext。
		std::vector<std::wstring> nodes ;								// 当該caseの全opaque。
		auto					  callback =
			// 実秘密state。
			run.provider.makeIndexPublicIdResolver( 801U, issued, nodes) ;
		DRIVERCRATE_EXPECT( context,
						   callback && scannedMode.candidates.size() == 2U && nodes.size() == 2U) ;
		// 前提不成立は明示失敗に残し不正pointerへ進みません。
		if( !callback) {
			continue ;
		}

		const auto result =
			callback->resolve( IndexPnpIdKind::HARDWARE, PUBLISHED_ID, PUBLISHED_CLASS, issued,
							  nodes) ;	// Class条件を持つ原種別照合。
		DRIVERCRATE_EXPECT( context, result.completed == (mode != 2U)) ;
		DRIVERCRATE_EXPECT( context, result.devices.size() == (mode == 1U || mode == 2U ? 1U : 2U)) ;
		const auto relation =
			lookupSignedIndexRecords( snapshot, issued, issued, nodes, {}, nowUtc,
									 // 真snapshotから同型集合の全保持を確認します。
									 callback.get()) ;
		DRIVERCRATE_EXPECT( context, relation.lookup && relation.lookup->relations().size() == 2U) ;
		// 非一意と未知classをWindows適合へ昇格しません。
		if( relation.lookup && !relation.lookup->relations().empty()) {
			const auto &first = relation.lookup->relations()[0] ;	// 公表Hardwareの一関係。
			DRIVERCRATE_EXPECT( context,
							   first.state == (mode == 2U ? IndexRecordMatchState::VERIFIED_PARTIAL
											   : mode == 1U ? IndexRecordMatchState::MATCHED
															: IndexRecordMatchState::UNMATCHED)) ;
			DRIVERCRATE_EXPECT( context, mode == 2U || first.relatedDevices == result.devices) ;
			// Class不足を完了へ変えず、DriverStoreが確認した別known nodeだけを保持します。
			if( mode == 2U) {
				DRIVERCRATE_EXPECT(
					context, first.positiveProof && first.relatedDevices == result.devices &&
								 first.reason == IndexRecordMatchReason::VERIFIED_POSITIVE_PARTIAL) ;
			}
		}
	}

	// 無関係なnodeの欠損と既知positiveを同居させ、query単位の完了軸を検証します。
	for( unsigned mode = 0U; mode < 3U; ++mode) {
		InventoryCase run ;	// Positiveはnode0、追加の必要情報はnode1です。
		run.fixture.differentClass	   = mode == 0U ;
		run.fixture.unknownSecondClass = mode != 0U ;
		run.fixture.faultKey		   = DEVPKEY_Device_HardwareIds ;
		run.fixture.faultNode		   = 1U ;
		run.fixture.propertyFault = mode == 1U ? PropertyFault::NONE : PropertyFault::ACCESS_DENIED ;
		static_cast<void>( run.scanForIndex()) ;
		IndexLookupContext		  issued ;	// この混在caseの結合context。
		std::vector<std::wstring> nodes ;	// 常に二つの全presentです。
		auto					  callback =
			// 実必要属性からの能力。
			run.provider.makeIndexPublicIdResolver( 850U, issued, nodes) ;
		DRIVERCRATE_EXPECT( context, callback && nodes.size() == 2U) ;
		// 不成立のfixtureを成功へ換算しません。
		if( callback) {
			const auto result =
				callback->resolve( IndexPnpIdKind::HARDWARE, PUBLISHED_ID, PUBLISHED_CLASS, issued,
								  nodes) ;	// 関係し得るnodeだけを判定します。
			DRIVERCRATE_EXPECT( context, result.completed == (mode != 2U)) ;
			DRIVERCRATE_EXPECT( context, result.devices == std::vector<std::wstring>{nodes[0]}) ;
			DRIVERCRATE_EXPECT( context,
							   result.error ==
								   (mode == 2U ? static_cast<NativeError>( E_ACCESSDENIED) : 0)) ;
		}
	}

	// 実観測の未知class ID欠損を再現し、部分一致を完了へ補完しません。
	for( unsigned mode = 0U; mode < 4U; ++mode) {
		InventoryCase run ;	// 二nodeとも六APIが完全fakeの同scanです。
		run.fixture.unknownSecondClass = mode != 2U ;
		run.fixture.differentClass	   = mode == 2U ;
		run.fixture.faultKey		   = DEVPKEY_Device_HardwareIds ;
		run.fixture.faultNode		   = 1U ;
		run.fixture.propertyFault =
			mode == 3U ? PropertyFault::ACCESS_DENIED : PropertyFault::MISSING ;
		run.fixture.indexId = mode == 0U ? L"TESTBUS\\SYNTH_0002" : L"TESTBUS\\SYNTH_0001" ;
		static_cast<void>( run.scanForIndex()) ;
		IndexLookupContext		  issued ;	// 同workerの新発行contextです。
		std::vector<std::wstring> nodes ;	// 全presentのopaqueだけです。
		// 同じ有限fixtureから得た結果を所有し、実deviceやnetworkを呼びません。
		auto callback = run.provider.makeIndexPublicIdResolver( 870U + mode, issued, nodes) ;
		DRIVERCRATE_EXPECT( context, callback && nodes.size() == 2U) ;
		// Fixture不成立を正常な空集合へ置換せず、このcaseを明示失敗へ残します。
		if( !callback || nodes.size() != 2U) {
			continue ;
		}

		const unsigned propertyCallsBefore =
			run.fixture.propertyCalls ;	// CallbackのI/O非実行を確認します。
		const unsigned enumerationCallsBefore =
			run.fixture.countCalls + run.fixture.detailCalls ;	// 同scanの列挙完了回数です。
		const NativeError expectedError =
			mode == 2U ? NativeError{}
			: mode == 3U
				? static_cast<NativeError>( E_ACCESSDENIED)
				: static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_FOUND)) ;	// 元拒否診断です。
		const auto result =
			callback->resolve( IndexPnpIdKind::HARDWARE, PUBLISHED_ID, PUBLISHED_CLASS, issued,
							  nodes) ;	// 型・Class・全contextを元入力のまま渡します。
		DRIVERCRATE_EXPECT( context, result.context == issued && result.completed == (mode == 2U) &&
										result.error == expectedError) ;
		DRIVERCRATE_EXPECT( context, result.devices.size() == (mode == 0U ? 0U : 1U)) ;
		// 部分的に見つけた一台を未知nodeの欠損解消へ代入しません。
		if( mode != 0U && !result.devices.empty()) {
			DRIVERCRATE_EXPECT( context, result.devices[0] == nodes[0]) ;
		}

		const auto lookedUp =
			lookupSignedIndexRecords( snapshot, issued, issued, nodes, {}, nowUtc,
									 // 同認証fixture snapshotの公開関係へ接続します。
									 callback.get()) ;
		DRIVERCRATE_EXPECT( context, lookedUp.status == IndexRecordLookupStatus::LOOKUP_READY &&
										lookedUp.lookup &&
										lookedUp.lookup->relations().size() == 2U) ;
		// 結合不成立を関係成功として扱わず、元の失敗を保持します。
		if( lookedUp.lookup && lookedUp.lookup->relations().size() == 2U) {
			const auto &relation = lookedUp.lookup->relations()[0] ;	// 原Hardwareの一関係です。
			DRIVERCRATE_EXPECT(
				context,
				relation.error == expectedError &&
					relation.state == (mode == 2U	? IndexRecordMatchState::MATCHED
									   : mode == 0U ? IndexRecordMatchState::UNDETERMINED
													: IndexRecordMatchState::VERIFIED_PARTIAL) &&
					relation.reason == (mode == 2U ? IndexRecordMatchReason::UNIQUE_RELATION
										: mode == 0U
											? IndexRecordMatchReason::RESOLVER_FAILED
											: IndexRecordMatchReason::VERIFIED_POSITIVE_PARTIAL)) ;
			DRIVERCRATE_EXPECT( context, relation.relatedDevices ==
												(mode != 0U ? std::vector<std::wstring>{nodes[0]}
															: std::vector<std::wstring>{}) &&
											relation.deviceIdentity.has_value() == (mode != 0U)) ;
		}

		DRIVERCRATE_EXPECT( context, run.fixture.propertyCalls == propertyCallsBefore &&
										run.fixture.countCalls + run.fixture.detailCalls ==
											enumerationCallsBefore) ;
		std::cout << "Index unknown-class ID regression mode=" << mode
				  << " completed=" << result.completed << " error=" << result.error
				  << " related=" << result.devices.size() << '\n' ;
	}

	// 公表INF側二役割とnative側二種別を独立に選び、四組合せ全てを実resolverで照合します。
	for( unsigned combination = 0U; combination < 4U; ++combination) {
		InventoryCase run ;	// 通信・実端末を使わない完全captureです。
		run.fixture.publishedIdInCompatible = combination >= 2U ;
		static_cast<void>( run.scanForIndex()) ;
		IndexLookupContext		  issued ;	// 組合せごとの元contextです。
		std::vector<std::wstring> nodes ;	// 全opaqueです。
		// 同じ有限fixtureから得た結果を所有し、実deviceやnetworkを呼びません。
		auto callback = run.provider.makeIndexPublicIdResolver( 880U + combination, issued, nodes) ;
		DRIVERCRATE_EXPECT( context, callback && nodes.size() == 2U) ;
		// 発行失敗を四組合せ合格へ変換しません。
		if( callback && nodes.size() == 2U) {
			const auto kind = combination % 2U == 0U
								  ? IndexPnpIdKind::HARDWARE
								  : IndexPnpIdKind::COMPATIBLE ;	// 元INF側の役割です。
			// 同じ有限fixtureから得た結果を所有し、実deviceやnetworkを呼びません。
			const auto result =
				callback->resolve( kind, PUBLISHED_ID, PUBLISHED_CLASS, issued, nodes) ;
			DRIVERCRATE_EXPECT( context, result.completed && result.error == 0U &&
											result.devices == std::vector<std::wstring>{nodes[0]}) ;
		}
	}

	// 同nodeの両集合重複は一device、旧逆node fixtureは二deviceの非一意として残します。
	for( unsigned mode = 0U; mode < 2U; ++mode) {
		InventoryCase run ;	// 元同文字列の役割を保ったままnode配置だけを変えます。
		run.fixture.publishedIdInBothKinds = mode == 0U ;
		run.fixture.splitKindAcrossNodes   = mode == 1U ;
		static_cast<void>( run.scanForIndex()) ;
		IndexLookupContext		  issued ;	// 当該caseの全contextです。
		std::vector<std::wstring> nodes ;	// 全presentです。
		// 同じ有限fixtureから得た結果を所有し、実deviceやnetworkを呼びません。
		auto callback = run.provider.makeIndexPublicIdResolver( 887U + mode, issued, nodes) ;
		DRIVERCRATE_EXPECT( context, callback && nodes.size() == 2U) ;
		// 不成立を正例へ置換しません。
		if( callback && nodes.size() == 2U) {
			const auto lookedUp =
				lookupSignedIndexRecords( snapshot, issued, issued, nodes, {}, nowUtc,
										 // 同認証recordを使います。
										 callback.get()) ;
			DRIVERCRATE_EXPECT( context,
							   lookedUp.lookup && lookedUp.lookup->relations().size() == 2U) ;
			// 非一意を推測で一deviceへ縮めません。
			if( lookedUp.lookup && lookedUp.lookup->relations().size() == 2U) {
				const auto &relation = lookedUp.lookup->relations()[0] ;	// 原Hardwareの関係です。
				DRIVERCRATE_EXPECT(
					context,
					relation.relatedDevices.size() == mode + 1U &&
						relation.state == (mode == 0U ? IndexRecordMatchState::MATCHED
													  : IndexRecordMatchState::UNMATCHED) &&
						relation.reason == (mode == 0U
												? IndexRecordMatchReason::UNIQUE_RELATION
												: IndexRecordMatchReason::NON_UNIQUE_RELATION)) ;
			}
		}
	}

	{
		InventoryCase run ;	// 013と同じ合法cross一致と別unknown nodeのHardware欠損です。
		run.fixture.publishedIdInCompatible = true ;
		run.fixture.unknownSecondClass		= true ;
		run.fixture.faultKey				= DEVPKEY_Device_HardwareIds ;
		run.fixture.faultNode				= 1U ;
		run.fixture.propertyFault			= PropertyFault::MISSING ;
		static_cast<void>( run.scanForIndex()) ;
		IndexLookupContext		  issued ;	// Native発行の全contextです。
		std::vector<std::wstring> nodes ;	// 同scanの全presentです。
		// 同じ有限fixtureから得た結果を所有し、実deviceやnetworkを呼びません。
		auto callback = run.provider.makeIndexPublicIdResolver( 899U, issued, nodes) ;
		DRIVERCRATE_EXPECT( context, callback && nodes.size() == 2U) ;
		// Native発行が不成立なら証拠を合成しません。
		if( callback && nodes.size() == 2U) {
			const auto result =
				callback->resolve( IndexPnpIdKind::HARDWARE, PUBLISHED_ID, PUBLISHED_CLASS, issued,
								  nodes) ;	// 元errorを保持した真partialです。
			DRIVERCRATE_EXPECT(
				context,
				!result.completed && result.positiveProof &&
					result.error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_FOUND))) ;
			// 不成立の証拠へアクセスしてtestを中断しません。
			if( result.positiveProof) {
				DRIVERCRATE_EXPECT( context, result.positiveProof->matches(
												issued, IndexPnpIdKind::HARDWARE, PUBLISHED_ID,
												PUBLISHED_CLASS, GetCurrentThreadId(),
												result.devices, result.error)) ;
				auto stale = issued ;	// 一世代だけ変えた拒否tupleです。
				++stale.inventoryGeneration ;
				DRIVERCRATE_EXPECT( context, !result.positiveProof->matches(
												stale, IndexPnpIdKind::HARDWARE, PUBLISHED_ID,
												PUBLISHED_CLASS, GetCurrentThreadId(),
												result.devices, result.error)) ;
				DRIVERCRATE_EXPECT( context, !result.positiveProof->matches(
												issued, IndexPnpIdKind::COMPATIBLE, PUBLISHED_ID,
												PUBLISHED_CLASS, GetCurrentThreadId(),
												result.devices, result.error)) ;
				DRIVERCRATE_EXPECT(
					context, !result.positiveProof->matches( issued, IndexPnpIdKind::HARDWARE,
															"TESTBUS\\OTHER_PUBLIC_ID",
															PUBLISHED_CLASS, GetCurrentThreadId(),
															result.devices, result.error)) ;
				DRIVERCRATE_EXPECT( context,
								   !result.positiveProof->matches(
									   issued, IndexPnpIdKind::HARDWARE, PUBLISHED_ID,
									   "{99999999-2222-3333-4444-555555555555}",
									   GetCurrentThreadId(), result.devices, result.error)) ;
				DRIVERCRATE_EXPECT( context, !result.positiveProof->matches(
												issued, IndexPnpIdKind::HARDWARE, PUBLISHED_ID,
												PUBLISHED_CLASS, 0U, result.devices, result.error)) ;
				DRIVERCRATE_EXPECT( context, !result.positiveProof->matches(
												issued, IndexPnpIdKind::HARDWARE, PUBLISHED_ID,
												PUBLISHED_CLASS, GetCurrentThreadId(),
												std::span<const std::wstring>{nodes}.subspan( 1U),
												result.error)) ;
				DRIVERCRATE_EXPECT( context,
								   !result.positiveProof->matches(
									   issued, IndexPnpIdKind::HARDWARE, PUBLISHED_ID,
									   PUBLISHED_CLASS, GetCurrentThreadId(), result.devices, 0U)) ;
			}

			// 公開partial DTOだけ、device変更、元error消去、completed改変をそれぞれ拒否します。
			for( unsigned fault = 0U; fault < 4U; ++fault) {
				auto altered = result ;	// 私有証拠の内容自体は変更できません。
				// 証拠なしpartialを既知positiveへ昇格しません。
				if( fault == 0U) {
					altered.positiveProof.reset() ;
				}
				// 別deviceへ私有証拠を移植する改変を再現します。
				else if( fault == 1U) {
					altered.devices = {nodes[1]} ;
				}
				// 元不足診断の消去を再現します。
				else if( fault == 2U) {
					altered.error = 0U ;
				} else { // 元全体不足を完了へ書き換える改変を再現します。
					altered.completed = true ;
				}

				PartialReplayResolver replay{std::move( altered)} ;	// 証拠を新規発行しないseamです。
				// 同じ有限fixtureから得た結果を所有し、実deviceやnetworkを呼びません。
				const auto			  rejected =
					lookupSignedIndexRecords( snapshot, issued, issued, nodes, {}, nowUtc, &replay) ;
				DRIVERCRATE_EXPECT( context,
								   rejected.lookup && rejected.lookup->relations().size() == 2U) ;
				// 改変があっても未知positiveを取得可能な関係へ変換しません。
				if( rejected.lookup && rejected.lookup->relations().size() == 2U) {
					DRIVERCRATE_EXPECT( context,
									   rejected.lookup->relations()[0].state ==
											   IndexRecordMatchState::UNDETERMINED &&
										   rejected.lookup->relations()[0].relatedDevices.empty()) ;
				}
			}

			run.fixture.counting = true ;
			static_cast<void>( run.scanForIndex()) ;
			// 新scanの後では発行済みproofを元contextへ戻しても生存根拠がありません。
			DRIVERCRATE_EXPECT( context, result.positiveProof &&
											!result.positiveProof->matches(
												issued, IndexPnpIdKind::HARDWARE, PUBLISHED_ID,
												PUBLISHED_CLASS, GetCurrentThreadId(),
												result.devices, result.error)) ;
		}
	}

	InventoryCase nativeForms ;	// 安全なbuslessとmatching IDが同居する実list。
	nativeForms.fixture.extraNativeId = true ;
	static_cast<void>( nativeForms.scanForIndex()) ;
	IndexLookupContext		  nativeContext ;	// 同scanで発行したcontext。
	std::vector<std::wstring> nativePresent ;	// 全opaque集合だけ。
	auto nativeResolver = nativeForms.provider.makeIndexPublicIdResolver( 890U, nativeContext,
																		 nativePresent) ;	// 弱能力。
	DRIVERCRATE_EXPECT( context, nativeResolver != nullptr) ;
	// 発行失敗を新表記対応の成功へ換算しません。
	if( nativeResolver) {
		const auto result =
			nativeResolver->resolve( IndexPnpIdKind::HARDWARE, PUBLISHED_ID, PUBLISHED_CLASS,
									nativeContext, nativePresent) ;	// 同listのmatching結果。
		DRIVERCRATE_EXPECT( context, result.completed && result.devices.size() == 1U &&
										result.devices[0] == nativePresent[0]) ;
	}

	// 不正Native byteや制御文字を正常不一致へ分類しません。
	for( const std::wstring_view invalid : {L"TESTBUS\\BAD\x01", L"TESTBUS\\\xd800"}) {
		InventoryCase run ;	// 生属性の破損だけを分離します。
		run.fixture.indexId = invalid ;
		static_cast<void>( run.scanForIndex()) ;
		IndexLookupContext		  issued ;	// 当該scan context。
		std::vector<std::wstring> nodes ;	// 全present opaque。
		auto					  callback =
			// 不正属性の元診断。
			run.provider.makeIndexPublicIdResolver( 895U, issued, nodes) ;
		DRIVERCRATE_EXPECT( context, callback != nullptr) ;
		// 前提不成立を成功へ隠しません。
		if( callback) {
			const auto result =
				callback->resolve( IndexPnpIdKind::HARDWARE, PUBLISHED_ID, PUBLISHED_CLASS, issued,
								  nodes) ;	// 必要属性不正は未完了。
			DRIVERCRATE_EXPECT( context, !result.completed && result.error != 0U) ;
		}
	}

	std::unique_ptr<IndexPublicIdResolver> expired ;		// Provider破棄後はweak能力だけを保持します。
	IndexLookupContext					   expiredContext ;	// 元context。
	std::vector<std::wstring>			   expiredPresent ;	// 元opaqueだけ。
	{
		InventoryCase run ;	// Scope終了で秘密stateを解放します。
		static_cast<void>( run.scanForIndex()) ;
		expired = run.provider.makeIndexPublicIdResolver( 897U, expiredContext, expiredPresent) ;
	}
	DRIVERCRATE_EXPECT( context,
					   expired && !expired
									   ->resolve( IndexPnpIdKind::HARDWARE, PUBLISHED_ID,
												 PUBLISHED_CLASS, expiredContext, expiredPresent)
									   .completed) ;
	// 必要propertyの型、size、実終端、元API errorを有限に注入します。
	for( const auto fault :
		{PropertyFault::MISSING, PropertyFault::ACCESS_DENIED, PropertyFault::WRONG_TYPE,
		 PropertyFault::ODD_SIZE, PropertyFault::OVER_LIMIT, PropertyFault::GROWING,
		 PropertyFault::OVER_REPORTED, PropertyFault::ZERO_RETURNED, PropertyFault::UNTERMINATED,
		 PropertyFault::EMBEDDED_NULL}) {
		InventoryCase run ;	// 一種別の失敗を他種別へ混ぜません。
		run.fixture.faultKey	  = DEVPKEY_Device_HardwareIds ;
		run.fixture.propertyFault = fault ;
		static_cast<void>( run.scanForIndex()) ;
		IndexLookupContext		  issued ;	// 同caseの発行tuple。
		std::vector<std::wstring> nodes ;	// 同caseの全opaque。
		auto					  callback =
			// 不完全でも弱能力。
			run.provider.makeIndexPublicIdResolver( 901U, issued, nodes) ;
		DRIVERCRATE_EXPECT( context, callback != nullptr) ;
		// 発行失敗をfixture成功にしません。
		if( !callback) {
			continue ;
		}

		const auto result =
			callback->resolve( IndexPnpIdKind::HARDWARE, PUBLISHED_ID, PUBLISHED_CLASS, issued,
							  nodes) ;	// 元property診断を返します。
		DRIVERCRATE_EXPECT( context,
						   !result.completed && result.error != 0U && result.devices.empty()) ;
		DRIVERCRATE_EXPECT( context, !callback
										 ->resolve( IndexPnpIdKind::COMPATIBLE, PUBLISHED_ID,
												   PUBLISHED_CLASS, issued, nodes)
										 .completed) ;
		// アクセス拒否は元HRESULTのまま保持します。
		if( fault == PropertyFault::ACCESS_DENIED) {
			DRIVERCRATE_EXPECT( context, result.error == static_cast<NativeError>( E_ACCESSDENIED)) ;
		}
	}

	// 一巡目partial、二巡目消失、途中取消しは正常な空集合にしません。
	for( unsigned mode = 0U; mode < 3U; ++mode) {
		InventoryCase run ;	// 列挙の各停止点を分離します。
		run.fixture.failCountAt = mode == 0U ? 1U : std::numeric_limits<DWORD>::max() ;
		run.fixture.disappearAt = mode == 1U ? 1U : std::numeric_limits<DWORD>::max() ;
		// 最初のproperty後で停止し、partial captureを完了へ変換させません。
		if( mode == 2U) {
			run.fixture.hook = [&]( const std::string_view stage) {
				// Fake同期API復帰点だけで取消しを要求します。
				if( stage == "property") {
					run.fixture.cancelled = true ;
				}
			} ;
		}

		static_cast<void>( run.scanForIndex()) ;
		IndexLookupContext		  issued ;	// Partial stateの正のcontext。
		std::vector<std::wstring> nodes ;	// Partial全観測opaqueであり全端末集合ではありません。
		auto					  callback =
			// 完了falseの能力。
			run.provider.makeIndexPublicIdResolver( 1001U, issued, nodes) ;
		DRIVERCRATE_EXPECT( context, (mode == 2U) == !callback) ;
		DRIVERCRATE_EXPECT( context, mode != 2U || (issued.operationId == 0U && nodes.empty())) ;
		// 前提不成立を結果参照で隠しません。
		if( callback) {
			const auto result =
				callback->resolve( IndexPnpIdKind::HARDWARE, PUBLISHED_ID, PUBLISHED_CLASS, issued,
								  nodes) ;	// 元列挙診断を保持します。
			DRIVERCRATE_EXPECT( context, !result.completed && result.error != 0U) ;
			DRIVERCRATE_EXPECT(
				context, mode != 0U || result.error == static_cast<NativeError>(
														   HRESULT_FROM_WIN32( ERROR_GEN_FAILURE))) ;
		}
	}

	std::cout << "Driver Store index resolver assertions: "
			  << context.assertionCount() - initialAssertions
			  << ", failures: " << context.failureCount() - initialFailures << '\n' ;
}

/** @see metadata_inventory_tests.h 宣言側の契約を正本とします。 */
void runNativePartialIndexPreparationTests(
	TestContext &context, std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot,
	const std::chrono::sys_seconds nowUtc)
{
	const int firstAssertions = context.assertionCount() ;	// この追加統合だけの件数です。
	const int firstFailures	  = context.failureCount() ;	// 元失敗を消さない差分です。
	// 既知一device正例と二device非一意拒否を同じ署名recordへ接続します。
	const OfficialPreparationLimits limits{64U, 128U, 256U, 2U,
										   4U} ;	// 元22byte fixtureを有限予約します。
	// 全二条件を有限予約のまま実行し、非一意と失効を独立して拒否します。
	for( unsigned mode = 0U; mode < 2U; ++mode) {
		InventoryCase run ;	// 六APIの完全fakeからだけ秘密captureを作ります。
		run.fixture.publishedIdInCompatible = true ;
		run.fixture.unknownSecondClass		= true ;
		run.fixture.nodes					= mode == 0U ? 2U : 3U ;
		run.fixture.sameHardware			= mode == 1U ;
		run.fixture.faultKey				= DEVPKEY_Device_HardwareIds ;
		run.fixture.faultNode				= 1U ;
		run.fixture.propertyFault			= PropertyFault::MISSING ;
		static_cast<void>( run.scanForIndex()) ;
		IndexLookupContext		  issued ;	// Native発行の元contextです。
		std::vector<std::wstring> nodes ;	// 同scanの全presentです。
		auto					  resolver =
			// 元弱能力です。
			run.provider.makeIndexPublicIdResolver( 905U + mode, issued, nodes) ;
		auto read = lookupSignedIndexRecords( snapshot, issued, issued, nodes, {}, nowUtc,
											 // 公開partial DTOからlookupを構築しません。
											 resolver.get()) ;
		DRIVERCRATE_EXPECT( context, resolver && read.lookup && !read.lookup->relations().empty()) ;
		// 不成立のfixtureから準備権限を作りません。
		if( !read.lookup || read.lookup->relations().empty()) {
			continue ;
		}

		auto lookup = std::make_shared<const SignedIndexRecordLookup>(
			// 原私有所有です。
			std::move( *read.lookup)) ;
		const auto &relation = lookup->relations()[0] ;	// 元不足を保持するHardwareの関係です。
		DRIVERCRATE_EXPECT(
			context,
			relation.state == IndexRecordMatchState::VERIFIED_PARTIAL &&
				relation.error == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_NOT_FOUND)) &&
				relation.relatedDevices.size() == mode + 1U && relation.positiveProof) ;
		SignedIndexAcquisitionAdapter adapter ;	// 固定RAM fixture trustだけを使用します。
		DRIVERCRATE_EXPECT( context,
						   signed_index_acquisition_detail::Access::beginFixture(
							   adapter, lookup, issued, IndexTargetOs::WINDOWS_11, nowUtc) == 0U) ;
		SignedIndexPreparationDescription description ;	// URLを持たない同原recordの対象です。
		const auto						  error =
			// 元recordを再照合します。
			adapter.describe( 0U, issued, nowUtc, limits, description) ;
		DRIVERCRATE_EXPECT( context, mode == 0U ? error == 0U && description.target &&
													 description.target->providerId ==
														 SIGNED_INDEX_PROVIDER_ID &&
													 description.target->deviceCount == 1U
											   : error != 0U && !description.target) ;
		auto stale = issued ;	// 一世代だけ変えた公開入力です。
		++stale.inventoryGeneration ;
		SignedIndexPreparationDescription refused ;	// 失敗時はtargetを持ちません。
		DRIVERCRATE_EXPECT( context, adapter.describe( 0U, stale, nowUtc, limits, refused) != 0U &&
										!refused.target) ;
		run.fixture.counting = true ;
		static_cast<void>( run.scanForIndex()) ;
		// 同Providerの新scanで元weak leaseが失効し、元contextでも再記述を拒否します。
		DRIVERCRATE_EXPECT( context, adapter.describe( 0U, issued, nowUtc, limits, refused) != 0U &&
										!refused.target) ;
	}

	std::cout << "Native partial index preparation assertions: "
			  << context.assertionCount() - firstAssertions
			  << ", failures: " << context.failureCount() - firstFailures << '\n' ;
}

} // namespace drivercrate::test
