# Skipped-slot SlotHashes lookup evaluation

## Problem

`validate_nonce` currently treats the numeric distance between the newest slot
and the submitted truncated slot as an index into SlotHashes. This is correct
when every intervening slot has an entry. Skipped slots have no entry, so the
signed slot moves toward index zero and the direct lookup returns the wrong
hash.

For example, if a payload is signed at slot 10 and lands at slot 14 while slots
11–13 are skipped, the numeric distance is 4 but slot 10 is at SlotHashes index
1.

## Required lookup shape

Keep the existing constant-time lookup as the default:

1. Compute the modular numeric slot distance `distance`.
2. Reject `distance >= 150` as expired.
3. Derive the full expected slot as `newest_slot - distance`.
4. Read SlotHashes at index `distance`.
5. Return immediately when that entry's full slot equals the expected slot.
6. Only on mismatch, search indices `distance - 1` through `0`.

Comparing the full `u64` slot avoids performing `% 1000` for every fallback
candidate and avoids matching another slot with the same truncated value.
No search below the initial index is necessary: omitted slots can only move the
target toward index zero.

## Algorithms evaluated

Each candidate was compiled to SBF with an identical fast path:

1. **Reverse linear scan** — inspect `distance - 1`, `distance - 2`, and so on.
   This should be the lowest-overhead option when only a few slots are skipped.
2. **Binary search** — search the descending slot heights in
   `0..distance`. This bounds fallback reads to roughly eight for the 150-slot
   validity window.
3. **Galloping plus binary search** — probe upward by 1, 2, 4, … entries, then
   binary-search the discovered bracket. This may retain the small-gap behavior
   of linear search while bounding larger gaps.

Do not benchmark a full scan from index zero: it discards the useful direct
index estimate and makes common small-gap cases unnecessarily expensive.

## Correctness matrix

Exercise the lookup directly and through the existing LiteSVM WebAuthn flow:

- no skipped slots, including distance 0 and distance 149;
- 1, 2, 3, 4, 8, 16, 32, 64, and 148 skipped slots;
- truncated-slot wraparound across 999 to 0;
- target at index 0 and index 1;
- target absent from SlotHashes;
- malformed submitted truncated slot (`>= 1000`);
- distance 150 (expired);
- a shortened SlotHashes vector to verify every read is bounds checked.

The end-to-end reproduction now expects success and retains the same
skipped-slot fixture.

## CU results

The primary benchmark is a feature-gated instruction executed by the deployed
SBF program. It calls the real `validate_nonce` with the real SlotHashes sysvar
account and a transaction signer. It includes entrypoint dispatch, account
borrowing, signer and stack-height checks, expiration, direct lookup, and the
fallback. It excludes WebAuthn work, Memo and system-program CPIs.

Each isolated case was run five times and each full authentication case was run
three times. All measurements were deterministic.

| Case | Linear isolated | Binary isolated | Linear full auth | Binary full auth |
| --- | ---: | ---: | ---: | ---: |
| Fast path, distance 149 | 268 | 270 | 34,996 | 34,998 |
| Distance 4, 3 skipped | 300 | 306 | 35,028 | 35,034 |
| Distance 149, 1 skipped | 284 | 376 | 35,012 | 35,104 |
| Distance 149, 4 skipped | 308 | 348 | 35,036 | 35,076 |
| Distance 149, 8 skipped | 340 | 390 | 35,068 | 35,118 |
| Distance 149, 16 skipped | 404 | 376 | 35,132 | 35,104 |
| Distance 149, 32 skipped | 532 | 348 | 35,260 | 35,076 |
| Distance 149, 64 skipped | 788 | 390 | 35,516 | 35,118 |
| Distance 149, 148 skipped | 1,460 | 376 | 36,188 | 35,104 |

The isolated and full-auth deltas match exactly. For example, one skipped slot
adds 16 CU to linear in both measurements, and the maximum binary path adds
120 CU in both measurements. The roughly 35K full-auth base is unrelated work;
the empty Memo CPI alone consumes 14,630 CU in this fixture.

Binary search cost depends on the target's position in its search tree, not
only on the number of skipped slots. Reverse linear depends only on missing
entries: 16 CU for the first fallback check, then 8 CU per additional skipped
slot.

## Skip-rate-weighted cost

Assuming independent skipped slots, the number of missing entries between
signing and landing is binomial with `n = distance - 1`. Applying the measured
per-comparison CU costs gives:

| Landing distance | Skip rate | Expected skips | Linear expected CU | Binary expected CU | Better choice |
| ---: | ---: | ---: | ---: | ---: | --- |
| 4 | 1% | 0.03 | 268.48 | 271.07 | Linear by 2.59 |
| 4 | 30% | 0.90 | 280.46 | 291.01 | Linear by 10.55 |
| 8 | 1% | 0.07 | 269.10 | 273.37 | Linear by 4.27 |
| 8 | 30% | 2.10 | 292.14 | 308.66 | Linear by 16.52 |
| 16 | 1% | 0.15 | 270.32 | 278.83 | Linear by 8.51 |
| 16 | 30% | 4.50 | 311.96 | 322.73 | Linear by 10.77 |
| 32 | 1% | 0.31 | 272.62 | 290.39 | Linear by 17.77 |
| 32 | 30% | 9.30 | 350.40 | 335.34 | Binary by 15.06 |
| 64 | 1% | 0.63 | 276.79 | 311.58 | Linear by 34.79 |
| 64 | 30% | 18.90 | 427.20 | 348.60 | Binary by 78.60 |
| 149 | 1% | 1.48 | 286.03 | 347.23 | Linear by 61.20 |
| 149 | 30% | 44.40 | 631.20 | 366.81 | Binary by 264.39 |

At the historical 30% skip rate and maximum valid age, exactly 45 skipped
slots cost 636 CU with linear and 390 CU with binary, a 246 CU saving. This is
the realistic historical extreme—not the synthetic 148-skipped case. At the
current 1% rate, linear remains cheaper even across the full 149-slot window.
For short 4–16-slot landing delays, linear also remains cheaper at the
historical rate.

This model assumes independent skips. Correlated skip bursts would change the
distribution, but the fixed-skip benchmark rows still bound the cost for any
observed number of missing entries.

SBF sizes were:

- reverse linear: 139,688 bytes;
- binary: 139,776 bytes;
- galloping: 140,208 bytes.

## Decision

Use reverse linear as the fallback. It is the smallest SBF variant and the
lowest-CU algorithm for realistic 1–4 skipped-slot cases. In the concrete
slot-10-to-slot-14 example, linear consumes 300 CU and binary consumes 306 CU
for the full nonce-validation instruction. Linear's worst case at 148 skipped
slots adds 1,192 CU over its fast path. Binary caps successful fallback
overhead at 120 CU in the tested 149-slot window and becomes preferable for
larger skip counts.

The production path therefore:

1. performs the original direct lookup;
2. compares the candidate's full slot to the reconstructed expected slot;
3. scans only toward index zero after a mismatch;
4. returns `InvalidSlothashIndex` if the target is absent.

The binary and benchmark-only program paths used for this evaluation were
removed after measurement. Production contains only the selected
reverse-linear fallback.
