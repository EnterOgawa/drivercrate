//------------------------------------------------------------------------------
/**
 * @file index_store_migration_main.cpp
 * @brief 旧署名索引storeの認証移動だけを明示実行します。
 * @version 01.00.00
 * @date 2026/10/19
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/19  期待head pin必須の限定移行CLIを追加。
 * </pre>
 *
 * @note 通信・秘密鍵・Task・導入を呼びません。管理者manifestとOS権限を維持します。
 * @see docs/adr/0380-signed-index-trust-domain-store-migration.md
 */
//------------------------------------------------------------------------------
#include "platform/signed_index_store.h"

#include <chrono>
#include <cstdio>
#include <string>
#include <string_view>

/** @brief 旧headの完全pinと明示modeだけを固定移行へ渡します。
 * @param[in] count OSが渡す引数数です。
 * @param[in] args 呼出し中だけ借用する終端文字列集合です。
 * @return 成功0、引数拒否または移行拒否2です。
 */
int wmain( const int count, wchar_t **args)
{
	try {
		// 別modeやpath/trustの注入を受理しません。
		if( count != 4 || args == nullptr ||
		   std::wstring_view{args[1]} != L"--migrate-legacy-store" ||
		   std::wstring_view{args[2]} != L"--expected-head-sha256") {
			return 2 ;
		}

		const std::wstring_view wide{args[3]} ;	// 原ciphertextの事前確認pinだけです。
		std::string				expected ;		// 正規化せずASCIIの完全pinを渡します。
		// 小文字hex以外をProgramData照会前に拒否します。
		for( const wchar_t value : wide) {
			// 曖昧な表記を信頼根拠へ補完しません。
			if( !((value >= L'0' && value <= L'9') || (value >= L'a' && value <= L'f'))) {
				return 2 ;
			}

			expected.push_back( static_cast<char>( value)) ;
		}

		const auto now = std::chrono::floor<std::chrono::seconds>(
			// 現在UTCだけです。
			std::chrono::system_clock::now()) ;
		const auto result = drivercrate::SignedIndexStore::migrateFixedLegacyStore(
			expected, now) ;	// 明示変更はこの一呼出しです。
		std::printf(
			"INDEX_STORE_MIGRATION code=0x%08lx commit=%u localDomain=%u alreadyMigrated=%u generation=%llu\n",
			static_cast<unsigned long>( result.error), static_cast<unsigned>( result.commit),
			result.localDomain ? 1U : 0U, result.alreadyMigrated ? 1U : 0U,
			static_cast<unsigned long long>( result.generation.value_or( 0U))) ;
		return result.error == 0 ? 0 : 2 ;
	} catch( ...) {
		std::printf( "INDEX_STORE_MIGRATION unexpectedFailure=1\n") ;
		return 2 ;
	}
}
