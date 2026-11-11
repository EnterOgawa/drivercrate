//------------------------------------------------------------------------------
/**
 * @file app_update_service.cpp
 * @brief 公式Release解析と一要求のApp更新workerを実装します。
 * @version 01.00.00
 * @date 2026/11/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/11  App専用の通知付き更新を追加。
 * </pre>
 * @note COM/JSONはworker内で使い、UIへURLやfile handleを渡しません。
 * @see docs/adr/0481-app-inno-setup-and-update-checks.md
 */
//------------------------------------------------------------------------------
#include "platform/app_update_service.h"
#include "platform/com_raii.h"
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <cmath>
#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace drivercrate {
namespace {
/** @brief 原UTF-8をWindows JSONへ渡すUTF-16へ変換します。
 * @param[in] raw 上限内の原byteです。
 * @return 変換結果。不正は例外です。
 */
std::wstring jsonText( const std::string_view raw)
{
	// 空/過大入力をWin32のint長へ変換しません。
	if( raw.empty() || raw.size() > 256U * 1024U) {
		throw std::invalid_argument( "metadata") ;
	}

	const int length =
		MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, raw.data(), static_cast<int>( raw.size()),
							nullptr, 0) ;	// 必要UTF-16文字数です。
	// 不正UTF-8を置換文字で受理しません。
	if( length <= 0) {
		throw std::invalid_argument( "utf8") ;
	}

	std::wstring text( static_cast<std::size_t>( length), L'\0') ;	// 所有する変換領域です。
	// 変換長の不一致も成功にしません。
	if( MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS, raw.data(), static_cast<int>( raw.size()),
						   text.data(), length) != length) {
		throw std::invalid_argument( "utf8") ;
	}

	return text ;
}
/** @brief 必須JSON文字列を型/長さ付きで読みます。
 * @param[in] object 検査済みobjectです。
 * @param[in] key 固定のfield名です。
 * @param[in] maximum 許容文字数です。
 * @return 所有文字列。不正は例外です。
 */
std::wstring stringValue( const winrt::Windows::Data::Json::JsonObject &object, const wchar_t *key,
						 const std::size_t maximum)
{
	const auto value = object.GetNamedValue( key) ;	// 必須fieldです。
	// 型の暗黙変換を認めません。
	if( value.ValueType() != winrt::Windows::Data::Json::JsonValueType::String) {
		throw std::invalid_argument( "string") ;
	}

	const auto text = value.GetString() ;	// WinRTが所有する文字列です。
	// NULや長い値をURL/版へ渡しません。
	if( text.empty() || text.size() > maximum ||
	   std::wstring_view( text).find( L'\0') != std::wstring_view::npos) {
		throw std::invalid_argument( "length") ;
	}

	return std::wstring( text) ;
}
}
/** @see app_update_service.h 宣言側の契約を正本とします。 */
AppUpdateFailure parseAppUpdateReleaseJson( const std::string_view raw, const AppVersion &current,
										   std::optional<AppUpdateRelease> &release) noexcept
{
	release.reset() ;
	try {
		const ComApartment apartment(
			COINIT_MULTITHREADED) ;	// このscopeで成功した初期化だけ解放します。
		using winrt::Windows::Data::Json::JsonValueType ;
		winrt::hresult_error factoryFailure ;	// 元activation失敗を保持します。
		const auto			 factory =
			winrt::try_get_activation_factory<winrt::Windows::Data::Json::JsonObject,
											  winrt::Windows::Data::Json::IJsonObjectStatics>(
				factoryFailure) ;	// 静的cacheを使わずこのapartment内だけで所有します。
		// 失敗したfactoryを参照しません。
		if( !factory) {
			return {AppUpdateFailureKind::METADATA, factoryFailure.code(), 0U, 0U} ;
		}

		const auto root =
			// COM解放後の静的factory cacheを再利用しません。
			factory.Parse( jsonText( raw)) ;
		// 明示的な正式公開だけを候補にします。
		if( root.GetNamedValue( L"draft").ValueType() != JsonValueType::Boolean ||
		   root.GetNamedValue( L"prerelease").ValueType() != JsonValueType::Boolean ||
		   root.GetNamedBoolean( L"draft") || root.GetNamedBoolean( L"prerelease")) {
			throw std::invalid_argument( "release") ;
		}

		const auto tag = stringValue( root, L"tag_name", 24U) ;	// canonical tagです。
		// ASCIIのv付き三要素だけを許可します。
		if( tag.size() < 2U || tag.front() != L'v' ||
		   std::any_of( tag.begin(), tag.end(), []( wchar_t c) { return c > 127 ; })) {
			throw std::invalid_argument( "tag") ;
		}

		std::string versionText ;	// 検査済みASCIIを明示してnarrowingします。
		// v以降の各ASCII文字だけをcopyします。
		for( std::size_t index = 1U; index < tag.size(); ++index) {
			versionText.push_back( static_cast<char>( tag[index])) ;
		}

		const auto version = parseAppVersion( versionText) ;	// 数値比較用の値です。
		// 不正tagを新しい版へ見立てません。
		if( !version) {
			throw std::invalid_argument( "version") ;
		}

		// 旧正式版にSetupがなくても現在のApp更新を失敗にしません。
		if( *version <= current) {
			return {} ;
		}

		const auto assets = root.GetNamedValue( L"assets") ;	// 新版のasset集合です。
		// 小さい有限配列だけを調べます。
		if( assets.ValueType() != JsonValueType::Array || assets.GetArray().Size() > 32U) {
			throw std::invalid_argument( "assets") ;
		}

		const auto array = assets.GetArray() ;	// 同期scope中だけのWinRT所有参照です。
		// 正確な一件を探し、重複を拒否します。
		for( std::uint32_t index{}; index < array.Size(); ++index) {
			const auto item = array.GetAt( index) ;	// 現assetです。
			// 配列の異種要素は正常なRelease宣言ではありません。
			if( item.ValueType() != JsonValueType::Object) {
				throw std::invalid_argument( "asset") ;
			}

			const auto asset = item.GetObject() ;					// 現objectです。
			const auto name	 = stringValue( asset, L"name", 256U) ;	// 正確なasset名です。
			// ZIPやCollector等の別assetを取得しません。
			if( name != L"DriverCrateSetup-windows-x64.exe") {
				continue ;
			}

			// 重複や未完了uploadの一方を勝手に選びません。
			if( release || stringValue( asset, L"state", 16U) != L"uploaded" ||
			   asset.GetNamedValue( L"size").ValueType() != JsonValueType::Number) {
				throw std::invalid_argument( "state") ;
			}

			const double bytes =
				// 整数範囲を確認してから変換します。
				asset.GetNamedNumber( L"size") ;
			// 非整数/非有限/上限超過は取得前に拒否します。
			if( !std::isfinite( bytes) || bytes < 1.0 ||
			   bytes > static_cast<double>( APP_UPDATE_MAX_BYTES) || std::floor( bytes) != bytes) {
				throw std::invalid_argument( "size") ;
			}

			const auto digest = stringValue( asset, L"digest", 71U) ;	// sha256:と64桁です。
			// 別算法や欠けたdigestを補いません。
			if( digest.size() != 71U || digest.substr( 0U, 7U) != L"sha256:") {
				throw std::invalid_argument( "digest") ;
			}

			AppUpdateRelease candidate{
				*version, static_cast<std::uint64_t>( bytes), {}} ;	// 未確定の宣言です。
			// 公開digestのASCII hexだけを小文字へ正規化します。
			for( const wchar_t digit : digest.substr( 7U)) {
				// 正常hex以外をnarrowingしません。
				if( !((digit >= L'0' && digit <= L'9') || (digit >= L'a' && digit <= L'f') ||
					 (digit >= L'A' && digit <= L'F'))) {
					throw std::invalid_argument( "hex") ;
				}

				candidate.sha256.push_back( static_cast<char>(
					digit >= L'A' && digit <= L'F' ? digit - L'A' + L'a' : digit)) ;
			}

			// 宣言URLと固定tupleが一致する場合だけ提示します。
			if( !validAppUpdateRelease( candidate) ||
			   stringValue( asset, L"browser_download_url", 512U) != appUpdateAssetUrl( candidate)) {
				throw std::invalid_argument( "url") ;
			}

			release = std::move( candidate) ;
		}

		// 新版の必要assetがない場合は代替経路へ行きません。
		if( !release) {
			throw std::invalid_argument( "missing") ;
		}

		return {} ;
	} catch( const winrt::hresult_error &error) {
		release.reset() ;
		return {AppUpdateFailureKind::METADATA, error.code(), 0U, 0U} ;
	} catch( ...) {
		release.reset() ;
		return {AppUpdateFailureKind::METADATA, static_cast<NativeError>( E_INVALIDARG), 0U, 0U} ;
	}
}
/** @see app_update_service.h 宣言側の契約を正本とします。 */
AppUpdateService::AppUpdateService( const HWND window, const UINT message,
								   std::unique_ptr<AppUpdateBackend> backend)
	: window_( window), message_( message), backend_( std::move( backend))
{
	// 欠損backendを実通信で補完しません。
	if( !backend_) {
		throw std::invalid_argument( "backend") ;
	}

	// このobjectの停止までだけ借用します。
	thread_ = std::thread( [this]() { run() ; }) ;
}
/** @see app_update_service.h 宣言側の契約を正本とします。 */
AppUpdateService::~AppUpdateService()
{
	stop() ;
}
/** @see app_update_service.h 宣言側の契約を正本とします。 */
bool AppUpdateService::enqueue( const AppUpdateStage operation, const bool manual)
{
	std::scoped_lock lock( mutex_) ;	// 一要求/一結果の排他です。
	// 停止/未受領結果/二重要求は状態を変えません。
	if( stopping_ || request_ || event_) {
		return false ;
	}

	const bool check =
		operation == AppUpdateStage::CHECKING &&
		(stage_ == AppUpdateStage::IDLE || stage_ == AppUpdateStage::OFFERED) ;	// 再確認だけです。
	const bool download = operation == AppUpdateStage::DOWNLOADING &&
						  // 元提示への同意です。
						  stage_ == AppUpdateStage::OFFERED && offered_ ;
	const bool launch = operation == AppUpdateStage::HANDING_OFF &&
						// 元取得からだけの引継ぎです。
						stage_ == AppUpdateStage::READY && offered_ ;
	// 任意の段階遷移を許可しません。
	if( !check && !download && !launch) {
		return false ;
	}

	stage_	   = operation ;
	request_   = operation ;
	manual_	   = manual ;
	cancelled_ = false ;
	ready_.notify_one() ;
	return true ;
}
/** @see app_update_service.h 宣言側の契約を正本とします。 */
bool AppUpdateService::requestCheck( const bool manual)
{
	return enqueue( AppUpdateStage::CHECKING, manual) ;
}
/** @see app_update_service.h 宣言側の契約を正本とします。 */
bool AppUpdateService::requestDownload()
{
	return enqueue( AppUpdateStage::DOWNLOADING, true) ;
}
/** @see app_update_service.h 宣言側の契約を正本とします。 */
bool AppUpdateService::requestLaunch()
{
	return enqueue( AppUpdateStage::HANDING_OFF, true) ;
}
/** @see app_update_service.h 宣言側の契約を正本とします。 */
void AppUpdateService::dismiss() noexcept
{
	std::scoped_lock lock( mutex_) ;	// 提示中だけを見送ります。
	// 実取得や実引継ぎを同意なしへ巻き戻しません。
	if( stage_ == AppUpdateStage::OFFERED && offered_) {
		dismissed_ = offered_->version ;
		offered_.reset() ;
		stage_ = AppUpdateStage::IDLE ;
	}
}
/** @see app_update_service.h 宣言側の契約を正本とします。 */
void AppUpdateService::cancel() noexcept
{
	cancelled_ = true ;
}
/** @see app_update_service.h 宣言側の契約を正本とします。 */
void AppUpdateService::stop() noexcept
{
	stopping_  = true ;
	cancelled_ = true ;
	ready_.notify_one() ;
	// 所有threadだけを停止し、他のProviderへ作用しません。
	if( thread_.joinable()) {
		thread_.join() ;
	}
}
/** @see app_update_service.h 宣言側の契約を正本とします。 */
std::optional<AppUpdateEvent> AppUpdateService::takeEvent()
{
	std::scoped_lock lock( mutex_) ;				// 結果を一回だけ所有移転します。
	auto			 result = std::move( event_) ;	// 空の場合も元slotを空へ戻します。
	event_.reset() ;
	return result ;
}
/** @see app_update_service.h 宣言側の契約を正本とします。 */
AppUpdateStage AppUpdateService::stage() const noexcept
{
	std::scoped_lock lock( mutex_) ;	// 同期I/Oのlockではありません。
	return stage_ ;
}
/** @see app_update_service.h 宣言側の契約を正本とします。 */
void AppUpdateService::run() noexcept
{
	try {
		const ComApartment apartment( COINIT_MULTITHREADED) ;	// backendのCOMをこのthreadへ閉じます。
		// 停止まで有限な一要求ずつ処理します。
		while( !stopping_) {
			AppUpdateStage					operation{} ;	// 今回だけの操作です。
			std::optional<AppUpdateRelease> release ;		// 元提示の所有copyです。
			bool							manual{} ;		// 今回の表示方針です。
			{
				std::unique_lock lock( mutex_) ;	// I/O前に必ず解放します。
				ready_.wait( lock, [this]() { return stopping_ || request_.has_value() ; }) ;
				// 終了後の残要求を送信しません。
				if( stopping_) {
					return ;
				}

				operation = *request_ ;
				request_.reset() ;
				release = offered_ ;
				manual	= manual_ ;
			}
			AppUpdateEvent result ;	// 確定した一結果だけをpublishします。
			result.operation						 = operation ;
			result.manual							 = manual ;
			const AppUpdateCancellation cancellation = [this]() {
				return stopping_.load() || cancelled_.load() ;
			} ; // threadの終了までobjectが生存します。
			// Checkは実行物を取らず、明示同意は元提示からだけ通ります。
			if( operation == AppUpdateStage::CHECKING) {
				result			 = backend_->check( cancellation) ;
				result.operation = operation ;
				result.manual	 = manual ;
			}
			// 元の提示を保持した取得/引継ぎだけを許可します。
			else if( release) {
				result.failure = operation == AppUpdateStage::DOWNLOADING
									 ? backend_->download( *release, cancellation)
									 : backend_->launch( *release, cancellation) ;
				result.release = release ;
			} else {
				result.failure = {AppUpdateFailureKind::METADATA,
								  static_cast<NativeError>( E_UNEXPECTED), 0U, 0U} ;
			}

			// 遅い成功結果も取消し後の実行権限へ戻しません。
			if( cancelled_ && operation != AppUpdateStage::HANDING_OFF) {
				result.failure = {AppUpdateFailureKind::CANCELLED,
								  HRESULT_FROM_WIN32( ERROR_CANCELLED), 0U, 0U} ;
				result.release.reset() ;
			}

			{
				std::scoped_lock lock( mutex_) ;	// publishだけを短く排他します。
				// Window停止後の通知は破棄します。
				if( stopping_) {
					return ;
				}

				// 同じ新版の周期通知を同process内では繰り返しません。
				if( operation == AppUpdateStage::CHECKING && !manual && result.release &&
				   dismissed_ && result.release->version == *dismissed_) {
					result.release.reset() ;
				}

				// backendの不正宣言を取得へ進めません。
				if( result.release && !validAppUpdateRelease( *result.release)) {
					result.failure = {AppUpdateFailureKind::METADATA,
									  static_cast<NativeError>( E_INVALIDARG), 0U, 0U} ;
					result.release.reset() ;
				}

				// 失敗では次の明示確認からやり直します。
				if( result.failure.kind != AppUpdateFailureKind::NONE) {
					stage_ = AppUpdateStage::IDLE ;
					offered_.reset() ;
				}
				// 確認成功は提示で止め、取得同意を発行しません。
				else if( operation == AppUpdateStage::CHECKING) {
					offered_ = result.release ;
					stage_	 = offered_ ? AppUpdateStage::OFFERED : AppUpdateStage::IDLE ;
				} else {
					stage_ = operation == AppUpdateStage::DOWNLOADING ? AppUpdateStage::READY
																	  : AppUpdateStage::IDLE ;
				}

				event_ = std::move( result) ;
			}
			// HWNDの所有状態を参照せず、数値通知だけを送ります。
			if( window_) {
				static_cast<void>( PostMessageW( window_, message_, 0U, 0)) ;
			}
		}
	} catch( ...) {
		{
			std::scoped_lock lock( mutex_) ;	// 例外後にも待機中と偽りません。
			stage_ = AppUpdateStage::IDLE ;
			request_.reset() ;
			offered_.reset() ;
			event_.emplace() ;
			event_->manual	= true ;
			event_->failure = {AppUpdateFailureKind::STORAGE, E_UNEXPECTED, 0U, 0U} ;
			stopping_		= true ;
		}
		// 例外をthread外へ漏らさず、固定の失敗だけを通知します。
		if( window_) {
			static_cast<void>( PostMessageW( window_, message_, 0U, 0)) ;
		}
	}
}
}
