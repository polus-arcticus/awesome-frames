// `solc` ships no type declarations and no `@types/solc` package exists.
// This file exists solely so `tsc -p test/js` doesn't fail on the import
// in ToyCurveECDH.test.ts — the actual API surface used (`solc.compile`)
// is typed loosely as `any` on purpose, matching what's actually used.
declare module 'solc' {
	const solc: {
		compile: (input: string) => string;
	};
	export default solc;
}
