/// @title StarkPedersen — Starknet's actual Pedersen hash, verbatim, on Ethereum
/// @notice Starknet's Pedersen hash function (the one StarkWare's own docs
/// specify, the one `@scure/starknet`'s `pedersen()` implements, the one
/// ScarabSign's README names as the reason its bid-signature aggregation
/// works: https://docs.starkware.co/starkex/pedersen-hash-function.html)
/// — implemented directly in Yul, callable from any Ethereum contract.
/// Unlike ../ToyCurveECDH/ToyCurveECDH.yul, every number in this file is a
/// REAL Starknet constant, not a shrunk-for-legibility toy: the curve, the
/// field, and the five "nothing up my sleeve" generator points are exactly
/// what a Starknet node uses. This is the first grimoire step toward
/// verifying Starknet-flavored (ScarabSign-style) signatures on Ethereum —
/// not that verification itself, which needs STARK-curve ECDSA on top of
/// this and is out of scope here.
///
/// @dev The curve: E: y² = x³ + x + b (mod p) — Starknet's "STARK-friendly"
/// curve. https://docs.starkware.co/starkex/stark-curve.html
///   p = 2^251 + 17·2^192 + 1
///   a = 1
/// `b` (StarkWare's own literal digits of π) never appears in the
/// addition/doubling slope formulas below — same as ToyCurveECDH's unused
/// `B` — so it isn't encoded here at all.
///
/// @dev Pedersen has no notion of a group order or a base point G: unlike
/// ToyCurveECDH's Diffie-Hellman (which repeatedly doubles and adds ONE
/// point via a scalar's bits), Pedersen folds each of its two field-element
/// inputs against its OWN pair of fixed, independent, "nothing up my
/// sleeve" generator points — chosen so that nobody (StarkWare included)
/// knows a discrete-log relation between them. There is no `cheng_multiply`
/// here, and no `sheng_generate`/`he_unite` — the whole shape of the
/// top-level function is different, see 融 below.
///
/// @dev The five constant points, exactly as `@scure/starknet` reads them
/// from StarkWare's own generator script
/// (starkex-for-spot-trading/.../nothing_up_my_sleeve_gen.py):
/// SHIFT_POINT, P0, P1, P2, P3. The hash of two field elements (x, y) is:
///   shift_point + (x_low·P0 + x_high·P1) + (y_low·P2 + y_high·P3)
/// where "low" is the low 248 bits and "high" is the high 4 bits of a
/// (at most 252-bit) field element, and each "value·point" term is a
/// bit-conditional subset sum over repeated doublings of that point — see
/// 叠 below for exactly how.
///
/// @dev A glossary, since the poetry lives beside the code rather than
/// inside it (see ../ToyCurveECDH/ToyCurveECDH.yul's header for why: Yul's
/// identifier grammar is ASCII-only, verified directly against this repo's
/// `solc`):
///
///   jia_add          加 (jiā)   "to add"      — point addition, guarded:
///                                                reverts if the two points
///                                                share an x-coordinate.
///                                                Unlike ToyCurveECDH's
///                                                jia_add, there is no O or
///                                                P+(-P) case to special-
///                                                case here — Pedersen's
///                                                construction is chosen so
///                                                neither should ever
///                                                arise, so hitting either
///                                                (same x-coordinate, which
///                                                covers both "same point"
///                                                AND "point plus its own
///                                                negation") is treated as
///                                                a genuine integrity
///                                                failure, not a case to
///                                                handle gracefully: it
///                                                would either mean two of
///                                                the "nothing up my
///                                                sleeve" generators secretly
///                                                share a discrete-log
///                                                relation, or the slope
///                                                formula below is about to
///                                                divide by zero.
///   xian_chord        弦 (xián)  "the chord"   — same geometry as
///                                                ToyCurveECDH's: the line
///                                                through two distinct
///                                                points.
///   qie_tangent        切 (qiē)  "the tangent" — same geometry: doubling.
///   die_walk           叠 (dié)  "to stack, to fold" — walks `steps` low
///                                                bits of a value, folding
///                                                a doubled `basis` point
///                                                into the accumulator
///                                                whenever the current bit
///                                                is set. This is
///                                                StarkWare's separate
///                                                "precompute a table of
///                                                doublings, then walk the
///                                                table" collapsed into one
///                                                loop: a Yul contract has
///                                                no persistent state to
///                                                precompute into ahead of
///                                                a call, so the doubling
///                                                happens inline, fresh,
///                                                every call — see the gas
///                                                note below for what that
///                                                costs.
///   rong_fuse          融 (róng) "to fuse,     — the entry point: fuses
///                                to blend"       the shift point with the
///                                                folded low/high halves of
///                                                x, then of y, into the
///                                                final Pedersen hash.
///
/// @dev Gas: real, and worth stating honestly rather than guessing. Each
/// `die_walk` step touches the basis point (one `qie_tangent`, i.e. one
/// MODEXP-precompile call for the field inverse) and, when the bit is set,
/// the accumulator too (one `jia_add`/`xian_chord`, another MODEXP call) —
/// up to ~1000 MODEXP calls across the full fold (248+4+248+4 = 504 steps).
/// That sounds like it should be enormous, but MODEXP's own gas formula is
/// cheap for inputs this size (a 251-bit modulus, well under the
/// precompile's quadratic-cost regime) — measured on-chain, a full
/// `pedersen(x, y)` call costs on the order of 2.7M gas, comfortably inside
/// an ordinary block, not the impractical-on-a-real-network number the raw
/// call count might suggest. See ../../../test/js/StarkPedersen.test.ts for
/// the exact measured figure. It is still real, non-trivial cost for what
/// is a single primitive hash of two field elements — on Starknet itself,
/// Pedersen is a native builtin the STARK VM was designed around, at
/// negligible cost. Reproducing it as ordinary EVM arithmetic makes that
/// asymmetry legible, and is a concrete data point in the long-running
/// "should Ethereum have a Pedersen/Poseidon precompile" debate (see
/// EIP-5988, stagnant) rather than a theoretical one.
///
/// @dev DO NOT use this for anything real. It is not written or reviewed
/// for constant-time execution (MODEXP's own gas cost already leaks the
/// modulus's bit length; the `and(v, 1)` branch above leaks each folded
/// value's bits through the presence or absence of a `jia_add` call), and
/// it has had none of the scrutiny a production Starknet-interop contract
/// would need. It is a small, stateless calculator you can read as a poem
/// — the same spirit as every other grimoire entry.
object "StarkPedersen" {
	code {
		datacopy(0, dataoffset("runtime"), datasize("runtime"))
		return(0, datasize("runtime"))
	}
	object "runtime" {
		code {
			// ── Curve/point constants live as parameterless functions
			// further down (see ../ToyCurveECDH/ToyCurveECDH.yul's header
			// for why: Yul functions are not closures, so anything shared
			// across functions has to be reachable as a call, not a `let`
			// in an enclosing block).

			// ── Selector routing ──
			if lt(calldatasize(), 4) { revert(0, 0) }
			let selector := shr(224, calldataload(0))

			switch selector
			// pedersen(uint256,uint256) 0x0e5828ac
			case 0x0e5828ac {
				let h := rong_fuse(calldataload(4), calldataload(36))
				mstore(0, h)
				return(0, 32)
			}
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
			// die_walk(uint256,uint256,uint256,uint256,uint256,uint256) 0x500b714a
			case 0x500b714a {
				let x3, y3 := die_walk(
					calldataload(4),
					calldataload(36),
					calldataload(68),
					calldataload(100),
					calldataload(132),
					calldataload(164)
				)
				mstore(0, x3)
				mstore(32, y3)
				return(0, 64)
			}
			default { revert(0, 0) }

			// ── Field/curve constants ──
			// P: the field modulus. A: the curve's x-coefficient
			// (y² = x³ + Ax + b — b never appears below, only P/A do).
			function constP() -> p {
				p := 0x800000000000011000000000000000000000000000000000000000000000001
			}
			function constA() -> a { a := 1 }

			// ── The five "nothing up my sleeve" generator points — see
			// the header for their provenance. ──
			function constSHIFTX() -> x { x := 2089986280348253421170679821480865132823066470938446095505822317253594081284 }
			function constSHIFTY() -> y { y := 1713931329540660377023406109199410414810705867260802078187082345529207694986 }
			function constP0X() -> x { x := 996781205833008774514500082376783249102396023663454813447423147977397232763 }
			function constP0Y() -> y { y := 1668503676786377725805489344771023921079126552019160156920634619255970485781 }
			function constP1X() -> x { x := 2251563274489750535117886426533222435294046428347329203627021249169616184184 }
			function constP1Y() -> y { y := 1798716007562728905295480679789526322175868328062420237419143593021674992973 }
			function constP2X() -> x { x := 2138414695194151160943305727036575959195309218611738193261179310511854807447 }
			function constP2Y() -> y { y := 113410276730064486255102093846540133784865286929052426931474106396135072156 }
			function constP3X() -> x { x := 2379962749567351885752724891227938183011949129833673362440656643086021394946 }
			function constP3Y() -> y { y := 776496453633298175483985398648758586525933812536653089401905292063708816422 }

			// ── (a - b) mod P, guarding against EVM's wrapping `sub` ──
			function submodP(a, b) -> r {
				let p := constP()
				let am := mod(a, p)
				let bm := mod(b, p)
				r := mod(add(am, sub(p, bm)), p)
			}

			// ── Modular inverse mod P via MODEXP (Fermat: a^(P-2) mod P,
			// P prime) — the same trick ../ToyCurveECDH/ToyCurveECDH.yul's
			// `invmodP` uses, just a 251-bit modulus instead of a
			// two-digit one.
			function invmodP(a) -> r {
				let p := constP()
				mstore(0x00, 0x20)
				mstore(0x20, 0x20)
				mstore(0x40, 0x20)
				mstore(0x60, mod(a, p))
				mstore(0x80, sub(p, 2))
				mstore(0xa0, p)
				if iszero(staticcall(gas(), 0x05, 0x00, 0xc0, 0x00, 0x20)) { revert(0, 0) }
				r := mload(0x00)
			}

			// 弦 xián — the chord through two DISTINCT points (x1,y1) and
			// (x2,y2) with x1 ≠ x2: slope = (y2-y1)/(x2-x1), then the
			// standard "third intersection, reflected over the x-axis"
			// formula.
			function xian_chord(x1, y1, x2, y2) -> x3, y3 {
				let p := constP()
				let slope := mulmod(submodP(y2, y1), invmodP(submodP(x2, x1)), p)
				x3 := submodP(submodP(mulmod(slope, slope, p), x1), x2)
				y3 := submodP(mulmod(slope, submodP(x1, x3), p), y1)
			}

			// 切 qiē — the tangent at a single point (x1,y1): doubling.
			// slope = (3x1² + A) / (2y1). A vertical tangent (y1 = 0)
			// would mean this point has order 2 — none of the five
			// generator points do, so this is never expected to fire; it
			// reverts rather than silently returning a corrupt (0,0).
			function qie_tangent(x1, y1) -> x3, y3 {
				if iszero(y1) { revert(0, 0) }
				let p := constP()
				let num := addmod(mulmod(3, mulmod(x1, x1, p), p), constA(), p)
				let slope := mulmod(num, invmodP(mulmod(2, y1, p)), p)
				x3 := submodP(submodP(mulmod(slope, slope, p), x1), x1)
				y3 := submodP(mulmod(slope, submodP(x1, x3), p), y1)
			}

			// 加 jiā — guarded addition: reverts on a shared x-coordinate
			// (see the glossary above for why that's the right call here,
			// unlike ToyCurveECDH's jia_add), otherwise delegates to 弦.
			function jia_add(x1, y1, x2, y2) -> x3, y3 {
				if eq(x1, x2) { revert(0, 0) }
				x3, y3 := xian_chord(x1, y1, x2, y2)
			}

			// 叠 dié — see the glossary above. Walks `steps` low bits of
			// `value`, folding the running-doubled (basisX,basisY) point
			// into the running accumulator (accX,accY) whenever the
			// current bit is set.
			function die_walk(accX, accY, value, basisX, basisY, steps) -> x3, y3 {
				let bx := basisX
				let by := basisY
				let v := value
				for { let i := 0 } lt(i, steps) { i := add(i, 1) } {
					if and(v, 1) {
						accX, accY := jia_add(accX, accY, bx, by)
					}
					v := shr(1, v)
					bx, by := qie_tangent(bx, by)
				}
				x3 := accX
				y3 := accY
			}

			// 融 róng — Starknet's Pedersen hash of two field elements.
			// Reverts if either input is not a valid field element
			// (x or y ≥ P) — required for correctness, not just hygiene:
			// an out-of-range input would silently desync the 248-low/
			// 4-high bit split from the canonical 252-bit representation
			// every other Starknet implementation assumes.
			function rong_fuse(x, y) -> h {
				let p := constP()
				if iszero(lt(x, p)) { revert(0, 0) }
				if iszero(lt(y, p)) { revert(0, 0) }
				let accX := constSHIFTX()
				let accY := constSHIFTY()
				accX, accY := die_walk(accX, accY, x, constP0X(), constP0Y(), 248)
				accX, accY := die_walk(accX, accY, shr(248, x), constP1X(), constP1Y(), 4)
				accX, accY := die_walk(accX, accY, y, constP2X(), constP2Y(), 248)
				accX, accY := die_walk(accX, accY, shr(248, y), constP3X(), constP3Y(), 4)
				h := accX
			}
		}
	}
}
