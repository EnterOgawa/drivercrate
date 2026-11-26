//------------------------------------------------------------------------------
/**
 * @file mtd_handler_internal.cpp
 * @brief 指定導入に関与するクラスと端末の登録を型付きで観測する
 * @version 01.02.00
 * @date 2026/11/17
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/17  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/11/19  独自クラスの登録と端末の作用の読み取りを追加
 * Ver.01.02.00 Shunji Ogawa  2026/11/22  選択端末の上位フィルターの型と全原値を検査
 * </pre>
 *
 * @note 未知handlerを実行せず、正式ERROR_NOT_FOUNDだけを不存在とします
 */
//------------------------------------------------------------------------------
#include "platform/mtd_handler_internal.h"
#include "platform/driver_store_inf_transport_internal.h"
#include <devpkey.h>
#include <objbase.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <iterator>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>

namespace drivercrate {
namespace {
// 正式なMTD classだけのinstaller登録を照会します
constexpr GUID MTD_CLASS{
	0x4d36e970, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}} ;
// host propertyがこのbyte数を超える場合は内容を受理しません
constexpr DWORD MAXIMUM_HANDLER_BYTES = 65536U ;

//------------------------------------------------------------------------------
/**
 * @brief 非零Windows errorをHRESULTへ変換します
 * @param[in] error 元API又は固定検査errorです
 * @return 非零診断を持つHRESULTです
 */
//------------------------------------------------------------------------------
NativeError		handlerError( DWORD error) noexcept
{
	return static_cast<NativeError>( HRESULT_FROM_WIN32( error ? error : ERROR_INVALID_DATA)) ;
}

//------------------------------------------------------------------------------
/**
 * @brief 原UTF-16 handler propertyの型、全byteと終了を分類します
 * @param[in,out] result 同APIの型と全byteを保持する観測です
 * @param[in] list STRING_LISTの場合true、STRINGならfalseです
 * @param[in] allowTypedEmpty 独自クラスの観測で単一NULの空値も区別する場合trueです
 * @return 正常型と全終端が成立する場合trueです
 */
//------------------------------------------------------------------------------
bool classifyHandler( MtdHandlerProperty &result, bool list, bool allowTypedEmpty)
{
	// 型とUTF-16単位が一致しない値を文字列として扱いません
	if( result.type !=
		   static_cast<std::uint32_t>( list ? DEVPROP_TYPE_STRING_LIST : DEVPROP_TYPE_STRING) ||
	   result.bytes.empty() || result.bytes.size() % sizeof( wchar_t) != 0U) {
		return false ;
	}

	// 原byteを変更せずUTF-16要素として終端を検査します
	std::vector<wchar_t> value( result.bytes.size() / sizeof( wchar_t)) ;
	std::memcpy( value.data(), result.bytes.data(), result.bytes.size()) ;
	// 文字列の型を保ったまま単一NULで表現される空値を観測します
	if( allowTypedEmpty && value.size() == 1U && value[0] == L'\0') {
		result.state = list ? MtdHandlerState::EMPTY_LIST : MtdHandlerState::EMPTY_STRING ;
		return true ;
	}

	// 単一STRINGは途中NULを許さず登録済みhandlerとして保持します
	if( !list) {
		// 空文字列と途中NULを正常なinstaller名とみなしません
		if( value.size() < 2U || value.back() != L'\0' ||
		   std::find( value.begin(), value.end() - 1, L'\0') != value.end() - 1) {
			return false ;
		}

		result.state = MtdHandlerState::PRESENT ;
		return true ;
	}

	// STRING_LISTには正規の二重NUL終端が必要です
	if( value.size() < 2U || value.back() != L'\0' || value[value.size() - 2U] != L'\0') {
		return false ;
	}

	// 正規の空listだけを非空handlerと区別します
	if( value.size() == 2U && value[0] == L'\0') {
		result.state = MtdHandlerState::EMPTY_LIST ;
		return true ;
	}

	// 各文字列の先頭から次のNULまで進めます
	std::size_t position{} ;
	// 最後の空要素より前に不正な空要素がないか検査します
	while( position < value.size() - 1U) {
		// 同要素を終える最初のNULを探します
		const auto end =
			std::find( value.begin() + static_cast<std::ptrdiff_t>( position), value.end(), L'\0') ;
		// 終端欠損や途中空要素を非空listとして受理しません
		if( end == value.end() || end == value.begin() + static_cast<std::ptrdiff_t>( position)) {
			return false ;
		}

		position = static_cast<std::size_t>( end - value.begin()) + 1U ;
	}

	// 全要素を終えて最終NULに正確に到達した場合だけ登録済みとします
	if( position != value.size() - 1U) {
		return false ;
	}

	result.state = MtdHandlerState::PRESENT ;
	return true ;
}

//------------------------------------------------------------------------------
/**
 * @brief 同propertyを一回の容量照会と一回の取得で固定します
 * @tparam Getter 同期中だけ使用する完全低位getterです
 * @param[in] getter 固定class又はdeviceに結ぶ低位getterです
 * @param[in] list STRING_LISTの場合true、STRINGならfalseです
 * @param[in] allowTypedEmpty 独自クラスで単一NULと別々に通知された型を確認する場合trueです
 * @return 原状態、型、全byte又は最初のWindows errorです
 */
//------------------------------------------------------------------------------
template <typename Getter>
MtdHandlerProperty readHandler( Getter getter, bool list, bool allowTypedEmpty = false)
{
	// 容量照会と本取得の元状態を同じ観測へ保存します
	MtdHandlerProperty result ;
	// getterが返した正式property型です
	DEVPROPTYPE		   type{} ;
	// 元propertyの必要byte数です
	DWORD			   required{} ;
	SetLastError( ERROR_SUCCESS) ;
	// 最初のcallは容量照会だけを行います
	const BOOL	sized = getter( &type, nullptr, 0U, &required) ;
	// 容量照会直後のWindows診断を保持します
	const DWORD firstError = sized ? ERROR_SUCCESS : GetLastError() ;
	// 正式なNOT_FOUNDだけをhandler不在とします
	if( !sized && firstError == ERROR_NOT_FOUND) {
		result.state = MtdHandlerState::ABSENT ;
		return result ;
	}

	// 権限失敗などの他の診断を不在へ変換しません
	if( !sized && firstError != ERROR_INSUFFICIENT_BUFFER) {
		result.state = MtdHandlerState::FAILED ;
		result.error = firstError ? firstError : ERROR_INVALID_DATA ;
		return result ;
	}

	// 空・過大・UTF-16単位でないbyte列を取得前に拒否します
	if( !required || required > MAXIMUM_HANDLER_BYTES || required % sizeof( wchar_t) != 0U) {
		result.state = MtdHandlerState::INVALID ;
		result.error =
			required > MAXIMUM_HANDLER_BYTES ? ERROR_BUFFER_OVERFLOW : ERROR_INVALID_DATA ;
		return result ;
	}

	result.bytes.resize( required) ;
	// 二回目のgetterが返した実byte数です
	DWORD		returned{} ;
	// 独自クラスの観測は本取得が実際に返した型を使います
	DEVPROPTYPE returnedType = allowTypedEmpty ? DEVPROP_TYPE_EMPTY : type ;
	SetLastError( ERROR_SUCCESS) ;
	// 容量照会後の変化や読取失敗は元失敗として保持します
	if( !getter( &returnedType, reinterpret_cast<PBYTE>( result.bytes.data()), required, &returned)) {
		// 第二call直後のWindows診断です
		const auto error = GetLastError() ;
		result.bytes.clear() ;
		result.state = MtdHandlerState::FAILED ;
		result.error =
			error == ERROR_NOT_FOUND ? ERROR_RETRY : (error ? error : ERROR_INVALID_DATA) ;
		return result ;
	}

	result.type = returnedType ;
	// 既知の型や容量が変化した場合と不正な終端は読取り失敗として保持します
	if( returned != required ||
	   (allowTypedEmpty && type != DEVPROP_TYPE_EMPTY && type != returnedType) ||
	   !classifyHandler( result, list, allowTypedEmpty)) {
		result.state = MtdHandlerState::INVALID ;
		result.error = ERROR_INVALID_DATA ;
		return result ;
	}

	return result ;
}

//------------------------------------------------------------------------------
/**
 * @brief クラス名とGUIDの両方向照会をクラスキーの存在と照合する
 * @param[in] target 元INFの対象クラスGUID
 * @param[in] expectedName 元INFの対象クラス名
 * @param[in] api 検査済みの読み取りAPI表
 * @param[out] registration 三照会が一致した場合だけ登録状態を設定する
 * @return 登録または未登録が確認できれば0、矛盾や照会失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError observeClassRegistration( const GUID &target, const std::wstring &expectedName,
									 const SetupClassReadApi &api,
									 SetupClassRegistration	 &registration)
{
	std::array<wchar_t, MAX_CLASS_NAME_LEN> name{} ;	// 登録済みクラスの終端を含む名前
	DWORD									chars{} ;	// APIから返された終端を含む文字数
	SetLastError( ERROR_SUCCESS) ;
	const bool	named	  = api.className( &target, name.data(), static_cast<DWORD>( name.size()),
										  &chars) != FALSE ;			// 元GUIDの照会成否
	const DWORD nameError = named ? ERROR_SUCCESS : GetLastError() ;	// 元照会の診断
	// クラス不存在と異なるエラーは読み取り失敗として返します
	if( !named && nameError != ERROR_INVALID_CLASS && nameError != ERROR_FILE_NOT_FOUND) {
		return handlerError( nameError) ;
	}

	// 同じGUIDであっても登録済みのクラス名が元INFと異なる場合は衝突です
	if( named &&
	   (chars != expectedName.size() + 1U || name[chars - 1U] != L'\0' ||
		CompareStringOrdinal( name.data(), static_cast<int>( chars - 1U), expectedName.c_str(),
							 static_cast<int>( expectedName.size()), TRUE) != CSTR_EQUAL)) {
		return handlerError( ERROR_INVALID_DATA) ;
	}

	GUID  reverse{} ;	// 名前の逆引きで取得したGUID
	DWORD count{} ;		// 同じ名前に登録されているGUIDの件数
	SetLastError( ERROR_SUCCESS) ;
	// 逆引き失敗や二件以上を未登録へ変換しません
	if( !api.classGuids( expectedName.c_str(), &reverse, 1U, &count)) {
		return handlerError( GetLastError()) ;
	}

	// 既存クラスは両方向で一意、未登録は逆引き成功かつ0件が必要です
	if( named ? (count != 1U || !IsEqualGUID( target, reverse)) : count != 0U) {
		return handlerError( ERROR_INVALID_DATA) ;
	}

	SetLastError( ERROR_SUCCESS) ;
	const HKEY key = api.openClassKey( &target, KEY_QUERY_VALUE, DIOCR_INSTALLER, nullptr,
									  nullptr) ;	// 対象クラスのキーを読み取りで開いた結果
	// APIが規定する無効ハンドルと診断でクラスキーの不在を確認します
	if( key == INVALID_HANDLE_VALUE) {
		const DWORD error = GetLastError() ;	// クラスキーを開けなかった理由
		// 名前が取得済みでもキーが消えていれば照会中の変化です
		if( error == ERROR_INVALID_CLASS || error == ERROR_FILE_NOT_FOUND) {
			// 両方向の照会が未登録だった時だけキーの不在を確定できます
			if( !named) {
				registration = SetupClassRegistration::UNREGISTERED ;
				return 0U ;
			}

			return handlerError( ERROR_RETRY) ;
		}

		return handlerError( error) ;
	}

	// 無効な成功値をクラス登録の証拠にしません
	if( !key) {
		return handlerError( ERROR_INVALID_DATA) ;
	}

	const LSTATUS closed = api.closeKey( key) ;	// 開いた読取りキーを解放した結果
	// 読み取り専用ハンドルの異常も診断に保持します
	if( closed != ERROR_SUCCESS) {
		return handlerError( static_cast<DWORD>( closed)) ;
	}

	// 逆引きに無いクラスキーは部分登録や同時変更として保留します
	if( !named) {
		return handlerError( ERROR_RETRY) ;
	}

	registration = SetupClassRegistration::REGISTERED ;
	return 0U ;
}

//------------------------------------------------------------------------------
/**
 * @brief クラスキーと独立したコインストーラーのGUID別値を取得する
 * @param[in] target 元INFの対象クラスGUID
 * @param[in] api 検査済みの読み取りAPI表
 * @param[out] value 不在または型付きのクラス別値
 * @return 確認が完了すれば0、キーの照会失敗はHRESULT
 */
//------------------------------------------------------------------------------
NativeError observeClassCoInstallers( const GUID &target, const SetupClassReadApi &api,
									 MtdHandlerProperty &value)
{
	HKEY		  handle{} ;	// Control直下のコインストーラーキー
	const LSTATUS opened =
		api.openKey( HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\CoDeviceInstallers",
					0U, KEY_QUERY_VALUE, &handle) ;	// 当該キーを読み取りで開いた結果
	// キー全体が存在しない場合は対象GUIDの値も存在しません
	if( opened == ERROR_FILE_NOT_FOUND) {
		value.state = MtdHandlerState::ABSENT ;
		return 0U ;
	}

	// 権限エラーや無効なハンドルを不存在へ変換しません
	if( opened != ERROR_SUCCESS || !handle || handle == INVALID_HANDLE_VALUE) {
		return handlerError( static_cast<DWORD>( opened)) ;
	}

	const std::unique_ptr<std::remove_pointer_t<HKEY>, decltype( &RegCloseKey)> key(
		handle, api.closeKey) ;			// 読んだキーは例外時も解放します
	std::array<wchar_t, 39U> name{} ;	// 中括弧と終端を含む対象GUIDの値名
	// 変換した完全なGUIDだけを値名として照会します
	if( StringFromGUID2( target, name.data(), static_cast<int>( name.size())) !=
	   static_cast<int>( name.size())) {
		return handlerError( ERROR_INVALID_DATA) ;
	}

	value = readHandler(
		[&]( DEVPROPTYPE *type, PBYTE bytes, DWORD capacity, PDWORD size) -> BOOL {
			DWORD registryType{} ;	// 元値のレジストリ型
			*size				 = capacity ;
			const LSTATUS status = api.readValue( key.get(), name.data(), nullptr, &registryType,
												 bytes, size) ;	// 容量または値本体の読取り結果
			*type = registryType == REG_MULTI_SZ ? DEVPROP_TYPE_STRING_LIST : DEVPROP_TYPE_NULL ;
			// レジストリの値不在を共通readerの診断に合わせます
			if( status == ERROR_FILE_NOT_FOUND) {
				SetLastError( ERROR_NOT_FOUND) ;
				return FALSE ;
			}

			// 容量通知を共通readerが受理するWindows診断へ変換します
			if( status == ERROR_MORE_DATA) {
				SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
				return FALSE ;
			}

			SetLastError( static_cast<DWORD>( status)) ;
			return status == ERROR_SUCCESS ;
		},
		true, true) ;
	return 0U ;
}
} // namespace

//------------------------------------------------------------------------------
/**
 * @brief 同MTD class/deviceの登録handlerを読み既知空だけを許します
 * @param[in] set 同一deviceを含む所有集合です
 * @param[in,out] device 同一選択の元deviceです
 * @param[out] observation 不在/空/登録/不正/読取失敗を保持します
 * @return 全propertyが正式不在又は空listなら0、それ以外は最初のHRESULTです
 * @note 欠損fake slotからnativeへfallbackせず、registryやdeviceを変更しません
 */
//------------------------------------------------------------------------------
NativeError inspectMtdHandlers( HDEVINFO set, SP_DEVINFO_DATA &device,
							   MtdHandlerObservation &observation)
{
	observation = {} ;
	// classとdeviceを同workerの完全API表で照会します
	const auto &api = driver_store_inf_detail::transport() ;
	// 別classや不完全なfake表からhost nativeへfallbackしません
	if( !driver_store_inf_detail::mtdTransportReady() || !api.inventory.property || !set ||
	   set == INVALID_HANDLE_VALUE || device.cbSize != sizeof( device) ||
	   !IsEqualGUID( device.ClassGuid, MTD_CLASS)) {
		return handlerError( ERROR_INVALID_PARAMETER) ;
	}

	try {
		// 同MTD classのinstaller propertyを正式なinstaller旗で読みます
		const auto classRead = [&]( const DEVPROPKEY &key, bool list) {
			return readHandler(
				[&]( DEVPROPTYPE *type, PBYTE buffer, DWORD size, PDWORD required) {
					return api.mtd.classProperty( &MTD_CLASS, &key, type, buffer, size, required,
												 DICLASSPROP_INSTALLER) ;
				},
				list) ;
		} ;
		observation.classInstaller	   = classRead( DEVPKEY_DeviceClass_ClassInstaller, false) ;
		observation.classCoInstallers  = classRead( DEVPKEY_DeviceClass_ClassCoInstallers, true) ;
		observation.deviceCoInstallers = readHandler(
			[&]( DEVPROPTYPE *type, PBYTE buffer, DWORD size, PDWORD required) {
				return api.inventory.property( set, &device, &DEVPKEY_Device_DriverCoInstallers,
											  type, buffer, size, required, 0U) ;
			},
			true) ;
		// 三propertyを不在・空・登録・失敗に分けて判定します
		const std::array values{&observation.classInstaller, &observation.classCoInstallers,
								&observation.deviceCoInstallers} ;
		// 実行され得る未知handlerを一つでも見逃さないよう全観測を確認します
		for( const auto value : values) {
			// 非空handlerはこの限定経路では評価していません
			if( value->state == MtdHandlerState::PRESENT) {
				return handlerError( ERROR_NOT_SUPPORTED) ;
			}

			// 不正値や読取失敗をhandler不在へ変換しません
			if( value->state == MtdHandlerState::INVALID ||
			   value->state == MtdHandlerState::FAILED) {
				return handlerError( value->error) ;
			}
		}

		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_FAIL ;
	}
}

//------------------------------------------------------------------------------
/**
 * @brief 対象クラスと選択端末の登録状態を指定導入の評価用に読み取る
 * @param[in] set 選択端末を含む情報集合
 * @param[in,out] device 一覧構築前の選択端末
 * @param[in] targetClass 元INFが宣言する対象クラスGUID
 * @param[in] expectedName 元INFが宣言する対象クラス名
 * @param[in] api 読取りだけの完全なWindows API表
 * @param[out] observation 登録状態と効果の型付き観測。失敗時は空
 * @return 正常観測時は0、照会失敗、矛盾、または不正な型はHRESULT
 * @note 既存の非空値は元の観測として保持し、ここでは導入可否を決めない
 */
//------------------------------------------------------------------------------
NativeError observeDeclarativeClassEffects( HDEVINFO set, SP_DEVINFO_DATA &device,
										   const GUID			   &targetClass,
										   const std::wstring	   &expectedName,
										   const SetupClassReadApi &api,
										   DeclarativeClassEffects &observation)
{
	observation = {} ;
	// 有効な端末と完全な読取りAPIがそろった場合だけ照会します
	if( !set || set == INVALID_HANDLE_VALUE || device.cbSize != sizeof( device) ||
	   IsEqualGUID( targetClass, GUID_NULL) || expectedName.empty() ||
	   expectedName.size() >= MAX_CLASS_NAME_LEN ||
	   expectedName.find( L'\0') != std::wstring::npos || !api.className || !api.classGuids ||
	   !api.openClassKey || !api.classProperty || !api.deviceProperty || !api.openKey ||
	   !api.readValue || !api.closeKey) {
		return handlerError( ERROR_INVALID_PARAMETER) ;
	}

	try {
		DeclarativeClassEffects pending ;	// 全照会が終わるまで呼出し元へ渡さない観測
		pending.sourceClass = device.ClassGuid ;
		// 対象クラスの登録と端末の現在クラスは別の観測値です
		const auto registrationError = observeClassRegistration(
			targetClass, expectedName, api, pending.registration) ;	// 対象クラスの最初の照会結果
		// 登録を判定できない場合は関連する値の不存在を推測しません
		if( registrationError != 0U) {
			return registrationError ;
		}

		const auto coError =
			observeClassCoInstallers( targetClass, api,
									 pending.classCoInstallers) ;	// 独立したクラス別値の照会結果
		// クラス未登録でも独立した値の読み取り失敗は保持します
		if( coError != 0U) {
			return coError ;
		}

		const auto &coInstallers = pending.classCoInstallers ;	// 型と容量を検査したクラス別値
		// 値の不存在または正しい型を確認できた場合だけ後続照会へ進みます
		if( coInstallers.state == MtdHandlerState::INVALID ||
		   coInstallers.state == MtdHandlerState::FAILED) {
			return handlerError( coInstallers.error) ;
		}

		/** @brief 一つのプロパティの読取り元と観測先 */
		struct PropertyRead {
			/// Windowsの型付きキー
			const DEVPROPKEY   &key ;
			/// 同キーの観測先
			MtdHandlerProperty &value ;
			/// 文字列リストならtrue
			bool				list ;
			/// 対象クラスのキーならtrue、元端末のキーならfalse
			bool				setupClass ;
		} ;
		const PropertyRead properties[]{
			// 対象クラスと元端末から読む固定プロパティ
			{DEVPKEY_DeviceClass_ClassInstaller, pending.classInstaller, false, true},
			{DEVPKEY_DeviceClass_PropPageProvider, pending.classPropPage, false, true},
			{DEVPKEY_DeviceClass_UpperFilters, pending.classUpperFilters, true, true},
			{DEVPKEY_DeviceClass_LowerFilters, pending.classLowerFilters, true, true},
			{DEVPKEY_Device_DriverCoInstallers, pending.deviceCoInstallers, true, false},
			{DEVPKEY_Device_DriverPropPageProvider, pending.devicePropPage, false, false},
			{DEVPKEY_Device_UpperFilters, pending.deviceUpperFilters, true, false},
			{DEVPKEY_Device_LowerFilters, pending.deviceLowerFilters, true, false},
		} ;
		// 導入先クラスと元端末の値を混在させず、読み取り元を固定します
		for( const auto &property : properties) {
			// 存在しないクラスのキー内の値は不存在として保持します
			if( property.setupClass &&
			   pending.registration == SetupClassRegistration::UNREGISTERED) {
				property.value.state = MtdHandlerState::ABSENT ;
				continue ;
			}

			property.value = readHandler(
				[&]( DEVPROPTYPE *type, PBYTE bytes, DWORD capacity, PDWORD size) {
					return property.setupClass
							   ? api.classProperty( &targetClass, &property.key, type, bytes,
												   capacity, size, DICLASSPROP_INSTALLER)
							   : api.deviceProperty( set, &device, &property.key, type, bytes,
													capacity, size, 0U) ;
				},
				property.list, true) ;
			// 未知の値と確認済みの既存値を区別します
			if( property.value.state == MtdHandlerState::INVALID ||
			   property.value.state == MtdHandlerState::FAILED) {
				return handlerError( property.value.error) ;
			}
		}

		SetupClassRegistration after{} ;	// 全値の読取り後に再観測した登録状態
		const auto			   afterError = observeClassRegistration( targetClass, expectedName, api,
																	 after) ;	// 読取り後の登録照会結果
		// 観測中に登録が変化した場合は複数時点の値を同時の根拠にしません
		if( afterError != 0U || after != pending.registration) {
			return afterError != 0U ? afterError : handlerError( ERROR_RETRY) ;
		}

		observation = std::move( pending) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_FAIL ;
	}
}
//------------------------------------------------------------------------------
/**
 * @brief 選択端末の上位フィルターの置換で別フィルターが失われないことを確認する
 * @param[in] set 対象を列挙した有効なdevice情報集合です
 * @param[in,out] device 同集合の選択端末を示すSetupAPI情報です
 * @param[in] property 同じAPI表の端末プロパティ読取りです
 * @param[out] observed 正式な状態、型、全raw byteです。失敗時は空です
 * @return 現在の上位フィルターが不存在、型付き空又は単一vwifibusで0です。それ以外はHRESULTです
 * @note 元のMULTI_SZを変更せず、読取り中の型・容量の変化も拒否します
 */
//------------------------------------------------------------------------------
NativeError observeWifiBusUpperFilters( HDEVINFO set, SP_DEVINFO_DATA &device,
									   DevicePropertyRead property, MtdHandlerProperty &observed)
{
	observed = {} ;
	// 別APIへの代替をせず、同じ端末の検査に必要な入力だけを受け入れます
	if( set == INVALID_HANDLE_VALUE || set == nullptr || !property ||
	   device.cbSize != sizeof( SP_DEVINFO_DATA)) {
		return E_INVALIDARG ;
	}

	try {
		// 端末のハードウェア側の値だけを二回の照会で読み取ります
		auto current = readHandler(
			[&]( DEVPROPTYPE *type, PBYTE bytes, DWORD capacity, PDWORD size) {
				return property( set, &device, &DEVPKEY_Device_UpperFilters, type, bytes, capacity,
								size, 0U) ;
			},
			true, true) ;	// 型、終端と全raw byteを確認した直後の元値です
		// 読取失敗や不正なREG_MULTI_SZを正式不存在として扱いません
		if( current.state == MtdHandlerState::INVALID || current.state == MtdHandlerState::FAILED) {
			return handlerError( current.error) ;
		}

		// 登録済みの場合は単一の仮想Wi-Fiバスだけを受け入れます
		if( current.state == MtdHandlerState::PRESENT) {
			constexpr wchar_t FILTER[] = L"vwifibus\0" ;		// 単一要素と二つの終端です
			std::array<wchar_t, std::size( FILTER)> text{} ;	// 比較用に整列した同じUTF-16です
			// 別フィルター又は複数要素を置換で失う場合は止めます
			if( current.bytes.size() != sizeof( FILTER)) {
				return handlerError( ERROR_NOT_SUPPORTED) ;
			}

			std::memcpy( text.data(), current.bytes.data(), sizeof( FILTER)) ;
			// サービス名の比較は大文字小文字を区別せず、元バイトはそのまま保持します
			if( CompareStringOrdinal( text.data(), -1, FILTER, -1, TRUE) != CSTR_EQUAL) {
				return handlerError( ERROR_NOT_SUPPORTED) ;
			}
		}

		observed = std::move( current) ;
		return 0U ;
	} catch( const std::bad_alloc &) {
		return E_OUTOFMEMORY ;
	} catch( ...) {
		return E_UNEXPECTED ;
	}
}
} // namespace drivercrate
