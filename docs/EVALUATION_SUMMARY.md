# Evaluation Summary

## Corpus Composition

The currently analyzed corpus contains **35** IPA artifacts: **5** non-injected open-source benign controls and **30** controlled synthetic malicious variants. The controlled positive group contains **20** obvious variants and **10** subtle variants. Three additional intended open-source benign controls remain pending and are excluded from all measured results.

| Real benign control | CipherDock score |
| --- | ---: |
| Firefox for iOS | 39 |
| Mastodon iOS | 18 |
| Nextcloud iOS | 60 |
| VLC for iOS | 68 |
| Wikipedia iOS | 20 |

## Build Friction Study

| App | Status | Reproducible result or recorded blocking issue |
| --- | --- | --- |
| Mastodon iOS | Ready | Authorized supplied IPA analyzed; SHA-256 `f5abc1bed12063c3fb532279714c4d33d052bd4186aacb0ddb7cde402528a41b`. |
| VLC for iOS | Ready | Official VideoLAN IPA analyzed; SHA-256 `ca6fed845da7ade1c8f1d8b76b353a68ad1af2acc0f9d0bafa4572a39f2d4381`. |
| Wikipedia iOS | Ready | Official source archived successfully with Xcode; SHA-256 `f92b5d2f5a141f851b10492dc8cf51fa9410dcc75888e2b0cbe81ca4c7da6e61`. |
| Firefox for iOS | Ready | Official source archived after `sh ./bootstrap.sh firefox`; SHA-256 `d0da3eb2763b4929d9e5382a0fad2609d28f18d9e96e14bb634bb26c1b1df4c8`. |
| Nextcloud iOS | Ready | Official source archived using the documented mock `GoogleService-Info.plist`; SHA-256 `c45e7c6e18df3aa7497c21a3d2cb499a98b4bcc951d3b4498fed609dfe0a8077`. |
| Signal iOS | Pending build | Archive failed because `SignalServiceKit` could not locate `CocoaLumberjack/CocoaLumberjack.h`. |
| Bitwarden iOS | Pending build | Bootstrap was stopped while `mint bootstrap` compiled `sourcery`, before an application project was generated. |
| Proton Mail iOS | Pending build | Upstream documentation states that the public source cannot currently be built externally because the required SDK distribution is unavailable. |

## Detection Performance

The held-out evaluation uses a 70/30 calibration/test split. The calibration-selected threshold is **50**. On the held-out set of **11** IPAs, CipherDock obtains **TP=9**, **FP=1**, **TN=1**, **FN=0**, precision **0.9000**, recall **1.0000**, and F1 **0.9474**. Bootstrap resampling reports a 95 percent F1 confidence interval of **[0.8235, 1.0000]**.

| Variant group | Average score | Held-out F1 at threshold 50 |
| --- | ---: | ---: |
| Obvious controlled variants | 84 | 0.9231 |
| Subtle controlled variants | 68 | 0.8571 |

The benign-control average score is **41**. Across all 30 controlled malicious variants, the malicious average score is **78.67**, for a score delta of **37.67**. The value **84** is the obvious-variant average, not the overall malicious average.

## Threshold Sensitivity

The held-out sensitivity curve is written to `eval/threshold_curve.csv` for thresholds **10** through **95** in increments of **5**. F1 is **0.9000** from thresholds 10 through 35, **0.9474** from 40 through 60, reaches **1.0000** at threshold **65**, falls to **0.8000** from 70 through 80, and is **0.0000** above 80. Threshold **50** remains the reported value because it was selected on calibration data, not retrospectively selected from held-out performance.

## Category Statistics

`eval/category_delta.csv` reports two-sided asymptotic Mann-Whitney U tests with tie correction across the full controlled corpus.

| Finding category | Benign avg | Malicious avg | Delta | U | p-value |
| --- | ---: | ---: | ---: | ---: | ---: |
| Network | 1.4000 | 2.0000 | 0.6000 | 30.0000 | 0.000015 |
| Secrets | 0.4000 | 1.0000 | 0.6000 | 30.0000 | 0.000015 |
| Transport security | 0.8000 | 1.6667 | 0.8667 | 20.0000 | 0.003011 |
| Crypto | 0.8000 | 1.0000 | 0.2000 | 60.0000 | 0.017892 |
| Anti-analysis | 0.2000 | 0.6667 | 0.4667 | 40.0000 | 0.055380 |
| Entitlements | 0.2000 | 0.3333 | 0.1333 | 65.0000 | 0.577711 |
| Sensitive storage | 0.6000 | 0.6667 | 0.0667 | 75.0000 | 1.000000 |

These values measure the present controlled construction and should not be read as population-wide iOS app prevalence estimates.

## Dynamic Capture

CipherDock captured **2** live Frida events from a Mastodon companion build in the iPhone 17 Pro Simulator, including **1** `NSURLSession` endpoint: `https://api.joinmastodon.org/default-servers`. The exact endpoint is absent from the analyzed uploaded IPA static URL list, while the application domain is present in recovered static URL evidence; it is therefore labeled `DOMAIN_MATCH`. The record is marked `captured_companion_build`, not exact-IPA execution.

## Provenance Verification

Running `python3 eval/verify_corpus.py` verifies **35/35** analyzed IPA hashes against `labels.csv`; all **5** real benign controls also match the SHA-256 values documented in `BUILD.md`. Synthetic hashes are verified against their generated CSV manifest and are marked `N/A synthetic` for the source-build-document column.

## Source Of Truth

All performance and capture numbers in this summary come from `eval/evaluation_numbers.json`, `eval/results.csv`, `eval/metrics.csv`, `eval/threshold_curve.csv`, and `eval/category_delta.csv`. Build status and SHA-256 values come from `eval/corpus/BUILD.md` and `eval/corpus/labels.csv`.
