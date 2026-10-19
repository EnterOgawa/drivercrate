//------------------------------------------------------------------------------
/**
 * @file local_collector_projected_json.h
 * @brief 新収集応答専用の有限canonical byte部品を定義します。
 * @version 01.00.00
 * @date 2026/09/29
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/29  有限byte・厳密字句・envelope部品を追加。
 * </pre>
 *
 * @note 内部codec部品です。型付きmetadata検査・親受入・保存・取得許可ではありません。
 * @see docs/adr/0220-collector-metadata-projection-and-cache.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "core/update_types.h"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace drivercrate::collector_projected_json {

// 各層は独立した実byte上限です。上位の予算で下位を拡張しません。
inline constexpr std::size_t   METADATA_LIMIT = 512U * 1024U ;
// 応答本文の実byte上限。
inline constexpr std::size_t   RESPONSE_LIMIT = 768U * 1024U ;
// 応答をJSON文字列として持つ外側の上限。
inline constexpr std::size_t   ENVELOPE_LIMIT = 2U * 1024U * 1024U ;
// 旧I/O v1の独立上限。
inline constexpr std::size_t   IO_LIMIT = 4096U ;
// JSON numberで丸めなしに扱う非負整数上限。
inline constexpr std::uint64_t MAX_INTEGER = 9007199254740991ULL ;

/** @brief 字句不成立・byte超過・API障害を区別する内部結果です。 */
enum class Status {
	/// 有限byte検査が成立しました。意味検査の合格ではありません。
	OK,
	/// 固定文法またはhashの整合が不成立です。
	INVALID,
	/// 追記前に実byte予算を超えました。
	SIZE_LIMIT,
	/// CNGの元HRESULT失敗です。
	HASH_FAILURE,
	/// 確保失敗です。上限超過へ読み替えません。
	OUT_OF_MEMORY
} ;

/** @brief 内部unwind用の数値だけの例外です。 */
struct Failure {
	/// 失敗した処理区分。
	Status status ;
} ;

/** @brief 有限byte処理の結果と元HRESULTです。 */
struct Result {
	/// 成立または固定失敗区分。
	Status		status{Status::INVALID} ;
	/// Hash障害／OOMの元値。それ以外は0です。
	NativeError error{} ;
} ;

/** @brief 加算前の予算検査を行う新形式だけのUTF-8 sinkです。 */
class Writer final {
public:
	/** @brief 固定上限内の空sinkを作ります。
     * @param[in] limit 1～ENVELOPE_LIMITの実byte上限。
     * @throws Failure 上限指定が不正な場合。
     */
	explicit Writer( std::size_t limit) ;
	/** @brief 固定構文または検証済み断片をそのまま追加します。
     * @param[in] bytes 借用断片。UTF-8やschemaはこの関数では検査しません。
     * @throws Failure 追加前の容量検査に失敗した場合。
     * @note byte上限違反では元sinkを変更しません。確保失敗は伝播します。
     */
	void						   append( std::string_view bytes) ;
	/** @brief 正しいUTF-8文字列を二種類のescapeだけで出力します。
     * @param[in] value NUL／制御文字を含まない元文字列。
     * @throws Failure 不正Unicodeまたは実byte超過。
     */
	void						   text( std::string_view value) ;
	/** @brief UTF-16のscalarを正規化せずUTF-8へ符号化します。
     * @param[in] value Windowsの元公開文字列。孤立surrogateは拒否します。
     * @throws Failure 不正Unicodeまたは実byte超過。
     */
	void						   wideText( std::wstring_view value) ;
	/** @brief 正確な非負整数を十進で出力します。
     * @param[in] value MAX_INTEGER以下の値。
     * @throws Failure 範囲外または実byte超過。
     */
	void						   number( std::uint64_t value) ;
	/** @brief 所有byteを変更せず借用します。
     * @return このsinkの変更・破棄まで有効なview。
     */
	[[nodiscard]] std::string_view view() const noexcept ;
	/** @brief 完成byteを移譲します。
     * @return 元順序の所有byte。この後のsinkは空です。
     */
	[[nodiscard]] std::string	   take() noexcept ;

private:
	/// 再設定できない実byte上限。
	std::size_t limit_ ;
	/// 正規化しない所有byte。
	std::string bytes_ ;
} ;

/** @brief 有限・厳密UTF-8・深さ16・canonical字句を先に検査する借用readerです。
 * @note Objectのfield集合・順序・重複は型付きcallerがliteralで消費して検査します。
 * この字句層は公開text policyやmetadataの意味を検査しません。
 */
class Reader final {
public:
	/** @brief 全入力を確保なしで事前走査し、読み位置を先頭へ置きます。
     * @param[in] bytes Readerの寿命中に変更しない元byte。
     * @param[in] limit 対象層の独立した実byte上限。
     * @throws Failure サイズ・UTF-8・文法・深さが不成立の場合。
     */
	Reader( std::string_view bytes, std::size_t limit) ;
	/** @brief 固定field順序やdelimiterを完全一致で消費します。
     * @param[in] expected 型付きcodecが固定した構文。
     * @throws Failure 一致しない場合。
     */
	void						   literal( std::string_view expected) ;
	/** @brief 文字列を解除し、解除後のbyte上限も検査します。
     * @param[in] limit 解除後の独立上限。
     * @return 元Unicodeを保持するUTF-8。公開text policyは別検査です。
     * @throws Failure 文字列型以外または上限超過。
     */
	[[nodiscard]] std::string	   text( std::size_t limit) ;
	/** @brief Canonical非負整数を読みます。
     * @return MAX_INTEGER以下の元値。
     * @throws Failure 数値型以外の場合。
     */
	[[nodiscard]] std::uint64_t	   number() ;
	/** @brief 次の値を原byteのまま借用します。
     * @return 一つの有限JSON値。型と関係の検証はcallerが行います。
     * @throws Failure 値がない場合。
     */
	[[nodiscard]] std::string_view value() ;
	/** @brief 末尾の余分なfield・byteを拒否します。
     * @throws Failure 全入力を消費していない場合。
     */
	void						   finish() const ;

private:
	/// 呼出し元が所有する有限入力。
	std::string_view bytes_ ;
	/// 事前検査済み入力の消費位置。
	std::size_t		 position_{} ;
} ;

/** @brief Envelopeから取り出す元byteと内部hashです。意味検査済み型ではありません。 */
struct EnvelopeBytes {
	/// 原byteをStringifyせず保持する応答本文。
	std::string	 response ;
	/// responseだけのCNG SHA-256。外側全体のhashではありません。
	std::wstring responseSha256 ;
} ;

/** @brief Hash直前に失敗HRESULTだけを返す開発依存です。0なら実CNGを行います。 */
using HashFailureProbe = std::function<NativeError()> ;

/** @brief 新v4の外側だけを有限encodeし、本文hashを実CNGで作ります。
 * @param[in] response 字句検査とv4 schema prefixを満たす本文。型付き意味検査は別途必須です。
 * @param[out] envelope 成立時の外側byte。失敗時は空です。入力とのaliasは禁止です。
 * @param[out] body 成立時の元応答とhash。失敗時は空です。
 * @param[in] probe 任意の失敗専用診断。digestや成功DTOを返せません。
 * @return 有限処理結果。保存・親受入・CACHE更新は行いません。
 */
[[nodiscard]] Result encodeEnvelope( std::string_view response, std::string &envelope,
									EnvelopeBytes		   &body,
									const HashFailureProbe &probe = {}) noexcept ;

/** @brief 新形式envelopeの固定順序と実本文hashを独立に検査します。
 * @param[in] envelope 最大2 MiBの元byte。
 * @param[out] body 成立時の元応答とhash。失敗時は空です。入力とのaliasは禁止です。
 * @param[in] probe 任意の失敗専用診断。0でもhash照合を省略しません。
 * @return 有限処理結果。metadataの全field・関係は後続の専用codecが検査します。
 */
[[nodiscard]] Result decodeEnvelope( std::string_view envelope, EnvelopeBytes &body,
									const HashFailureProbe &probe = {}) noexcept ;

/** @brief 内部identityに使う小文字64桁hexだけを許可します。
 * @param[in] value 原文字列。
 * @return 長さと全byteが固定文法に一致する場合true。
 */
[[nodiscard]] bool	 isHash( std::wstring_view value) noexcept ;

} // namespace drivercrate::collector_projected_json
