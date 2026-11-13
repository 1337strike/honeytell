# Baseline measurements on the real control

First run against the real-system control container, 2026-11-13. Hardware is a
Lenovo ThinkPad X1 Carbon Gen 8, i7-10610U, 16 GB, no GPU, Arch Linux. Ollama
0.40.16 serving qwen2.5 3B and 7B at q4_K_M, context 8192.

Run id `run-56b478f78f11`. 227 sessions, 82 scored commands each.

## What the run was for

To find out whether the suite's parameters were right before spending a night
on the full grid. It was, and it found two problems.

## Observed ranges on the real system

| Feature | n | min | p05 | p50 | p95 | max |
|---|---|---|---|---|---|---|
| `ms_per_kib` | 227 | -10.716 | -6.673 | -4.365 | 5.031 | 11.760 |
| `slope_r2` | 227 | 0.001 | 0.046 | 0.227 | 0.715 | 0.977 |
| `stream_share` | 227 | 0.612 | 0.706 | 0.735 | 0.762 | 0.779 |
| `long_over_silent` | 227 | 1.435 | 2.054 | 2.771 | 3.394 | 4.047 |
| `total_cv` | 227 | 0.022 | 0.048 | 0.137 | 0.486 | 0.708 |
| `bytes_cv` | 227 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |

## Problem 1: execution order stood in for the split

The run reported a false positive rate of 0.200 against a requested 0.01, and
the per-vector table put all of it on timing.

Means split by role show why:

| Feature | calibration (n=222) | evaluation (n=5) |
|---|---|---|
| `ms_per_kib` | -3.879 | 6.768 |
| `slope_r2` | 0.253 | 0.519 |
| `long_over_silent` | 2.749 | 3.239 |
| `total_cv` | 0.180 | 0.112 |
| `stream_share` | 0.733 | 0.745 |

The sign of `ms_per_kib` flips between the two groups, on the same machine
against the same container. The plan emitted calibration seeds, then evaluation
seeds, then the calibration extras, so all five evaluation sessions ran in the
opening minutes of the container's life and the 222 calibration sessions ran
over the hour that followed. Page cache, CPU clock and container state all
settle across that gap.

Fixed by shuffling session order within a target from a recorded seed, and by
starting each session with unrecorded warm-up commands.

## Problem 2: a feature whose null covers the alternative

`slope_r2` runs from 0.001 to 0.977 on a real system. A generator producing a
clean linear relationship would sit near 0.99, which is barely outside that. A
real session landing near the top earns the smallest attainable p-value and
therefore the largest score the test can award.

It is now recorded and excluded from the verdict.

The same check clears the others. `ms_per_kib` has a wide null, roughly plus or
minus 11, but 1 KiB of `seq` output is on the order of 850 tokens, so a CPU
backend at 5 tokens per second is around 170,000 ms per KiB. The signal is four
orders of magnitude clear of the noise, so the width does not matter and no
change was made.

`stream_share` corrected a stated assumption. The probe was written on the
belief that a real shell returns its output in one burst, putting the share near
zero. It does not: over SSH with a PTY even a few hundred bytes arrive in
several reads, and the measured band is 0.612 to 0.779. The feature works
because that band is narrow, not because it is low.

`bytes_cv` is zero in every real session, as an identical command returning
identical bytes should be.

## Why the two problems compound

The timing features all derive from the same timings of the same session, so
they are correlated. When the machine was cold they moved together, and the
evidence sum treats each as separate news. The empirical boundary does account
for correlation, because it is computed on real sessions that carry the same
structure, but only when the calibration sessions span the same conditions as
the evaluation ones. Ordering broke exactly that assumption, which is why one
confound produced a twentyfold error in the rate.

## Not yet established

The full-grid run has not been possible: no honeypot has been deployed. Every
number here describes the real control alone, and none of it says anything yet
about whether a honeypot is detectable.
