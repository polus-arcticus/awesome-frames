/// @title ToyCurveECDH — a spellbook, not an account
/// @notice A minimal, deliberately-insecure elliptic-curve Diffie-Hellman
/// key exchange, written directly in Yul as an excuse to get fluent in the
/// same geometry that powers this repo's real secp256k1/BIP-340 work (see
/// ../../BIP340/BIP340.sol and ../../NostrFrameAccount/NostrFrameAccount.yul)
/// — shrunk down until the entire group fits on one page. Unlike those two,
/// this contract needs none of EIP-8141's new opcodes: it's ordinary point
/// arithmetic, callable on any EVM, tested entirely against a local
/// simulated network. It is not a VERIFY-frame account and authorizes
/// nothing; it's a small, stateless calculator you can read as a poem.
///
/// @dev The curve: E: y² = x³ + 2x + 2 (mod 17) — the textbook toy example
/// from Hankerson/Menezes/Vanstone's "Guide to Elliptic Curve
/// Cryptography". Verified here, not just cited: brute-force enumeration
/// (see ../../../test/js/utils/toyCurve.ts's `enumeratePoints`, and
/// ../../../scripts/gen-toy-curve-vectors.ts, which runs it) finds exactly
/// 18 affine points, so the group — points plus the point at infinity — has
/// order 19. 19 is prime, which buys two simplifications used throughout
/// this file:
///   1. The group is cyclic and EVERY non-identity point generates it —
///      there's no separate "is G actually a generator" check to write.
///      G = (5, 1) is used below; any of the other 17 non-identity points
///      would work identically.
///   2. 19 is odd, so the curve has no point of order 2 — which means NO
///      point on this curve ever has y = 0. That fact is load-bearing: it's
///      what makes (0, 0) a safe, always-unambiguous encoding for the point
///      at infinity O (the identity) in every function below. A real
///      secp256k1-scale implementation can't get away with this — it needs
///      an explicit "is infinity" flag — but here it's not a shortcut, it's
///      a true fact about this specific group, and worth knowing why.
///
/// @dev A glossary, since the poetry lives beside the code rather than
/// inside it — Yul's identifier grammar is ASCII-only (checked directly:
/// `function 弦(...)` is a hard ParserError from solc, not a style choice),
/// so every spell's name is ASCII pinyin, paired here with the character it
/// transliterates:
///
///   jia_add          加 (jiā)   "to add"      — general point addition;
///                                                the dispatcher: identity,
///                                                inverse-cancellation, or
///                                                delegate to 弦/切 below.
///   xian_chord        弦 (xián)  "the chord"   — the line through two
///                                                DISTINCT points, and the
///                                                third point on the curve
///                                                it must also cross.
///   qie_tangent       切 (qiē)   "the tangent" — the line touching ONE
///                                                point twice: doubling.
///   cheng_multiply    乘 (chéng) "to multiply" — scalar multiplication,
///                                                the double-and-add
///                                                ladder built from 加.
///   sheng_generate    生 (shēng) "to beget"    — a private scalar begets
///                                                a public point: k·G.
///   he_unite          合 (hé)    "to unite"    — two private scalars,
///                                                applied to each other's
///                                                public points, unite at
///                                                the same point: this is
///                                                the entire Diffie-Hellman
///                                                exchange, k_a·(k_b·G) =
///                                                k_b·(k_a·G).
///
/// @dev Every function returns (x, y) as plain uint256 words; the caller
/// reads (0, 0) as O. Modular subtraction is spelled out by hand (EVM's
/// `sub` wraps rather than going negative — the classic first bug in any
/// hand-rolled modular arithmetic); addition and multiplication reuse the
/// EVM's native `addmod`/`mulmod`. Modular inverse reuses the exact
/// MODEXP-precompile / Fermat's-little-theorem trick already implemented
/// for the secp256k1 group order in BIP340.sol's `_invmodN` — same
/// precompile, same idea, a two-digit modulus instead of a 256-bit one.
///
/// @dev DO NOT reuse any of this for anything real. 19 is small enough
/// that the discrete log of any public point is brute-forceable by hand in
/// under a minute — that's the entire point: the whole group is meant to
/// be legible, not secure.
object "ToyCurveECDH" {
	code {
		datacopy(0, dataoffset("runtime"), datasize("runtime"))
		return(0, datasize("runtime"))
	}
	object "runtime" {
		code {
			// ── Curve constants live as parameterless functions further
			// down (constP/constA/constN/constGX/constGY) rather than as
			// `let`s here: Yul functions are not closures — a function can
			// only see its own parameters and locals, never a `let` from
			// an enclosing block — so anything shared across functions has
			// to be reachable as a call. See the header for the constants'
			// derivation.

			// ── Selector routing ──
			if lt(calldatasize(), 4) { revert(0, 0) }
			let selector := shr(224, calldataload(0))

			switch selector
			// jia_add(uint256,uint256,uint256,uint256) 0x88677028
			case 0x88677028 {
				let x3, y3 :=
					jia_add(calldataload(4), calldataload(36), calldataload(68), calldataload(100))
				mstore(0, x3)
				mstore(32, y3)
				return(0, 64)
			}
			// xian_chord(uint256,uint256,uint256,uint256) 0xa1160ead
			case 0xa1160ead {
				let x3, y3 :=
					xian_chord(calldataload(4), calldataload(36), calldataload(68), calldataload(100))
				mstore(0, x3)
				mstore(32, y3)
				return(0, 64)
			}
			// qie_tangent(uint256,uint256) 0x26bbbaae
			case 0x26bbbaae {
				let x3, y3 := qie_tangent(calldataload(4), calldataload(36))
				mstore(0, x3)
				mstore(32, y3)
				return(0, 64)
			}
			// cheng_multiply(uint256,uint256,uint256) 0x63985254
			case 0x63985254 {
				let x3, y3 :=
					cheng_multiply(calldataload(4), calldataload(36), calldataload(68))
				mstore(0, x3)
				mstore(32, y3)
				return(0, 64)
			}
			// sheng_generate(uint256) 0xc4aa4fb3
			case 0xc4aa4fb3 {
				let x, y := sheng_generate(calldataload(4))
				mstore(0, x)
				mstore(32, y)
				return(0, 64)
			}
			// he_unite(uint256,uint256,uint256) 0xf7aa550e
			case 0xf7aa550e {
				let x, y :=
					he_unite(calldataload(4), calldataload(36), calldataload(68))
				mstore(0, x)
				mstore(32, y)
				return(0, 64)
			}
			default { revert(0, 0) }

			// ── Curve constants, as calls (see the note above the
			// selector routing for why these can't just be `let`s) ──
			// P: the field modulus. A: the curve's x-coefficient
			// (y² = x³ + Ax + B — B never appears below, only P/A/N/G do).
			// N: the group order. GX/GY: a base point — any non-identity
			// point would do (header point 1).
			function constP() -> p { p := 17 }
			function constA() -> a { a := 2 }
			function constN() -> n { n := 19 }
			function constGX() -> x { x := 5 }
			function constGY() -> y { y := 1 }

			// ── (a - b) mod P, guarding against EVM's wrapping `sub` ──
			function submodP(a, b) -> r {
				let p := constP()
				let am := mod(a, p)
				let bm := mod(b, p)
				r := mod(add(am, sub(p, bm)), p)
			}

			// ── Modular inverse mod P via MODEXP (Fermat: a^(P-2) mod P,
			// P prime) — the same trick BIP340.sol's `_invmodN` uses for
			// the (much larger) secp256k1 group order.
			function invmodP(a) -> r {
				let p := constP()
				mstore(0x00, 0x20)
				mstore(0x20, 0x20)
				mstore(0x40, 0x20)
				mstore(0x60, mod(a, p))
				mstore(0x80, sub(p, 2))
				mstore(0xa0, p)
				// staticcall(gas, addr, argsOffset, argsSize, retOffset, retSize) -> success
				//   gas()  — forward all remaining gas
				//   0x05   — target address: the MODEXP precompile
				//   0x00   — read call input starting at memory offset 0
				//   0xc0   — input is 192 bytes (the 3 length-words + 3 value-words above)
				//   0x00   — write the return data back to memory offset 0 (overwrites the input)
				//   0x20   — return data is 32 bytes (one word: the result)
				if iszero(staticcall(gas(), 0x05, 0x00, 0xc0, 0x00, 0x20)) { revert(0, 0) }
				r := mload(0x00)
			}

			// 弦 xián — the chord through two DISTINCT points (x1,y1) and
			// (x2,y2) with x1 ≠ x2: slope = (y2-y1)/(x2-x1), then the
			// standard "third intersection, reflected over the x-axis"
			// formula every EC-crypto course derives geometrically.
			function xian_chord(x1, y1, x2, y2) -> x3, y3 {
				let p := constP()
				let slope := mulmod(submodP(y2, y1), invmodP(submodP(x2, x1)), p)
				x3 := submodP(submodP(mulmod(slope, slope, p), x1), x2)
				y3 := submodP(mulmod(slope, submodP(x1, x3), p), y1)
			}

			// 切 qiē — the tangent at a single point (x1,y1): doubling.
			// slope = (3x1² + A) / (2y1). If y1 = 0 the tangent would be
			// vertical (a point of order 2) — this curve's order (19) is
			// odd, so that never happens (see header point 2), but the
			// guard stays: better a clean O than a silently-corrupt slope
			// from invmodP(0).
			function qie_tangent(x1, y1) -> x3, y3 {
				if iszero(y1) { leave } // x3,y3 default to 0,0 = O
				let p := constP()
				let num := addmod(mulmod(3, mulmod(x1, x1, p), p), constA(), p)
				let slope := mulmod(num, invmodP(mulmod(2, y1, p)), p)
				x3 := submodP(submodP(mulmod(slope, slope, p), x1), x1)
				y3 := submodP(mulmod(slope, submodP(x1, x3), p), y1)
			}

			// 加 jiā — general addition: the identity element, the
			// P + (−P) = O cancellation, then a dispatch to 弦 or 切.
			function jia_add(x1, y1, x2, y2) -> x3, y3 {
				// O + Q = Q (O is (0,0) — see header point 2)
				if and(iszero(x1), iszero(y1)) {
					x3 := x2
					y3 := y2
					leave
				}
				// P + O = P
				if and(iszero(x2), iszero(y2)) {
					x3 := x1
					y3 := y1
					leave
				}
				// P + (−P) = O: same x, y-coordinates sum to 0 mod P
				if and(eq(x1, x2), iszero(addmod(y1, y2, constP()))) { leave }
				if and(eq(x1, x2), eq(y1, y2)) {
					x3, y3 := qie_tangent(x1, y1)
					leave
				}
				x3, y3 := xian_chord(x1, y1, x2, y2)
			}

			// 乘 chéng — scalar multiplication, the double-and-add ladder,
			// the direct small-scale analogue of the ladder any real
			// secp256k1 `scalarMul` runs. k is reduced mod N (the group
			// order) first, so k=0 and k=N both correctly yield O with no
			// special-casing.
			function cheng_multiply(k, x1, y1) -> x3, y3 {
				let n := mod(k, constN())
				let rx := 0
				let ry := 0
				let ax := x1
				let ay := y1
				for {

				} gt(n, 0) {
					n := shr(1, n)
				} {
					if and(n, 1) {
						rx, ry := jia_add(rx, ry, ax, ay)
					}
					ax, ay := jia_add(ax, ay, ax, ay)
				}
				x3 := rx
				y3 := ry
			}

			// 生 shēng — a private scalar begets a public point: priv·G.
			function sheng_generate(priv) -> x, y {
				x, y := cheng_multiply(priv, constGX(), constGY())
			}

			// 合 hé — the exchange itself: priv·(their public point). Two
			// parties calling this with their own priv and each other's
			// public point arrive at the same point independently —
			// that's the entire protocol.
			function he_unite(priv, theirX, theirY) -> x, y {
				x, y := cheng_multiply(priv, theirX, theirY)
			}
		}
	}
}
