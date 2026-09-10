// Generic big-endian 32-byte-word splitting/joining for RSA moduli wider
// than a single EVM word (256 bits) — used by test/js/utils/lightningRSA.ts
// and its vector generator to encode/decode values the same way
// src/grimoire/LightningRSA/LightningRSAAccount.yul lays them out in
// storage/calldata: most-significant word first, each word right-aligned
// (standard unsigned big-endian multi-word convention).

const WORD_BITS = 256n;
const WORD_MASK = (1n << WORD_BITS) - 1n;

/** Split a non-negative bigint into `wordCount` big-endian 32-byte words (most-significant first). Throws if it doesn't fit. */
export function splitWords(value: bigint, wordCount: number): bigint[] {
	if (value < 0n) throw new Error('splitWords: value must be non-negative');
	if (value >= 1n << (WORD_BITS * BigInt(wordCount))) {
		throw new Error(`splitWords: value does not fit in ${wordCount} word(s)`);
	}
	const words: bigint[] = [];
	for (let i = wordCount - 1; i >= 0; i--) {
		words.push((value >> (WORD_BITS * BigInt(i))) & WORD_MASK);
	}
	return words;
}

/** Inverse of splitWords: reassemble big-endian 32-byte words (most-significant first) into one bigint. */
export function joinWords(words: readonly bigint[]): bigint {
	let value = 0n;
	for (const w of words) {
		if (w < 0n || w > WORD_MASK) throw new Error('joinWords: word out of range');
		value = (value << WORD_BITS) | w;
	}
	return value;
}

/** Number of 32-byte words needed to hold `value` (minimum 1). */
export function wordsNeeded(value: bigint): number {
	if (value === 0n) return 1;
	let bits = 0n;
	let v = value;
	while (v > 0n) {
		bits += 1n;
		v >>= 1n;
	}
	return Number((bits + WORD_BITS - 1n) / WORD_BITS);
}
