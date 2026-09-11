// ML-DSA-44 (FIPS 204, formerly CRYSTALS-Dilithium) — CONCEPTUAL/PARTIAL
// this pass, deliberately: real parameters below, no working sign() or
// verify(). This file documents the gap on purpose rather than shipping a
// half-working implementation — the same discipline this repo applies
// everywhere else (no half-finished implementations, see the top-level
// engineering guidelines this whole grimoire follows).
//
// Why ML-DSA stopped here, next to MlKem going all the way: both are
// Module-Lattice schemes over the same ring dimension (n=256), and both
// were candidates for the "prove the pattern" full-build slot in this
// survey — MlKem won that slot specifically because it needed nothing
// beyond a matrix of noisy linear equations (Module-LWE) and a
// straightforward NTT. ML-DSA needs everything MlKem needs PLUS a whole
// second layer MlKem never touches:
//
//   - Fiat-Shamir with Aborts (Lyubashevsky's technique): unlike MlKem's
//     encryption, which just tolerates its own noise, ML-DSA's signing
//     loop must REJECT and RETRY whenever the candidate signature's
//     coefficients get too large or leak information about the secret key
//     — this is a genuine control-flow loop with a real (small, bounded)
//     probability of many retries, not a single deterministic pass.
//   - High/low bit decomposition (Decompose, HighBits, LowBits): splitting
//     each coefficient of the noisy product `w = A·y` into a
//     coarse "high" part (what actually gets included, compressed, in the
//     signature) and a "low" part (discarded, but only after being used to
//     decide whether THIS attempt is even valid) — MlKem's Compress/
//     Decompress are lossy rounding for bandwidth; ML-DSA's decomposition
//     is that AND a rejection-sampling gate in the same step.
//   - Hint bits: a compact side-channel-safe way to tell the verifier
//     which of `w`'s coefficients need "help" reconstructing the correct
//     high bits after the low bits were thrown away — a whole extra
//     encoded structure (`h`) MlKem's ciphertext has no analog of at all.
//
// None of that is exotic, individually — each piece has a clean spec in
// FIPS 204 — but stacking three extra, genuinely stateful/branchy
// mechanisms on top of an already-real NTT ring is a meaningfully bigger
// lift than MlKem's, and would deserve the same primary-source-derivation
// rigor (cross-checked byte-for-byte against @noble/post-quantum's
// `ml_dsa44`, the way MlKem/Falcon both were) rather than a rushed partial
// attempt. Real parameters and sizes below are worth having on record now
// regardless — confirmed against @noble/post-quantum's own `PARAMS` and
// `ml_dsa44.lengths`, not guessed.

/** FIPS 204 ML-DSA-44 (NIST security category 2) parameters. */
export const ML_DSA_44_PARAMS = {
	n: 256, // ring dimension — same as MlKem's
	q: 8_380_417, // modulus — a much larger prime than MlKem's q=3329
	k: 4, // rows of the public matrix A (module rank, "output" dimension)
	l: 4, // columns of A (module rank, "input"/secret dimension)
	d: 13, // bits dropped when compressing t into the public key (t1 = t >> d)
	gamma1: 131_072, // 2^17 — bound on the y vector sampled each signing attempt
	gamma2: 95_232, // (q-1)/88 — the low/high-bits rounding boundary
	tau: 39, // number of ±1 coefficients in the challenge polynomial c
	eta: 2, // bound on the secret key vectors s1, s2
	omega: 80, // max number of 1s allowed in the hint vector h
} as const;

/** Real wire sizes, in bytes (ML-DSA-44) — confirmed via @noble/post-quantum's `ml_dsa44.lengths`. */
export const ML_DSA_44_SIZES = {
	publicKey: 1312,
	secretKey: 2560,
	signature: 2420,
	seed: 32,
} as const;

// A future full pass would follow the same shape every other entry here
// does: derive KeyGen/Sign/Verify from the FIPS 204 PDF directly (not from
// memory, not from reading @noble/post-quantum's source — the same
// primary-source discipline MlKem's derivation needed, given how easy the
// Decompose/MakeHint/UseHint boundary conditions are to get subtly wrong),
// cross-check byte-for-byte against `ml_dsa44` at every step the way
// MlKem's generator does, and — because the *signing* loop's rejection
// behavior is genuinely random-length — pin down whether byte-exact
// matching is even possible for Sign (it likely isn't, without also
// reimplementing @noble/post-quantum's exact rejection-retry RNG
// consumption) versus settling for Verify-only, the same scope Falcon
// landed on for a different reason (floating point) this pass.
