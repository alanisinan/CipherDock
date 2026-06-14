# Evaluation Numbers

These statements are generated for evaluation review from the current evaluation artifacts. The authoritative machine-readable source is `eval/evaluation_numbers.json`; rows and category calculations originate in `eval/results.csv` and `eval/metrics.csv`.

## Corpus

The corpus contains [35] IPAs: [5] real, non-injected open-source benign controls and [30] controlled synthetic malicious variants.

The controlled malicious group contains [20] obvious variants and [10] subtle variants.

The corpus currently excludes [3] pending benign source builds: Signal iOS, Bitwarden iOS, and Proton Mail iOS.

## Per-App Scores

Firefox for iOS has a CipherDock score of [39] with [4] findings.

Mastodon iOS has a CipherDock score of [18] with [3] findings.

Nextcloud iOS has a CipherDock score of [60] with [5] findings.

VLC for iOS has a CipherDock score of [68] with [8] findings.

Wikipedia iOS has a CipherDock score of [20] with [2] findings.

The mean benign-control score is [41].

The mean score for all controlled malicious variants is [78.67].

The score delta between controlled malicious variants and benign controls is [37.67].

The obvious controlled variants have an average score of [84].

The subtle controlled variants have an average score of [68].

## Held-Out Metrics

The evaluation holds out [30%] of labeled samples, producing a held-out set of [11] IPAs after calibration on [24] IPAs.

At the calibration-selected threshold of [50], CipherDock records [9] true positives, [1] false positive, [1] true negative, and [0] false negatives; precision is [0.9000], recall is [1.0000], and F1 is [0.9474].

At threshold [50], the bootstrap 95 percent F1 confidence interval is [[0.8235, 1.0000]], summarized in `evaluation_numbers.json` as [0.95 +/- 0.09].

At threshold [70], CipherDock records [6] true positives, [0] false positives, [2] true negatives, and [3] false negatives; precision is [1.0000], recall is [0.6667], F1 is [0.8000], and the 95 percent confidence interval is [[0.5000, 1.0000]].

At threshold [90], CipherDock records [0] true positives, [0] false positives, [2] true negatives, and [9] false negatives; precision, recall, and F1 are all [0.0000], with confidence interval [[0.0000, 0.0000]].

At the selected threshold [50], obvious-variant held-out F1 is [0.9231] and subtle-variant held-out F1 is [0.8571].

The threshold sensitivity curve contains [18] held-out thresholds from [10] through [95] in increments of [5].

Held-out F1 reaches [1.0000] at threshold [65], while threshold [50] remains the reported calibration-selected operating point with F1 [0.9474].

## Finding Counts By Category

The transport-security category averages [0.80] findings per benign control and [1.67] per controlled malicious variant, with [50] malicious findings and a delta of [0.87].

The network category averages [1.40] findings per benign control and [2.00] per controlled malicious variant, with [60] malicious findings and a delta of [0.60].

The secrets category averages [0.40] findings per benign control and [1.00] per controlled malicious variant, with [30] malicious findings and a delta of [0.60].

The anti-analysis category averages [0.20] findings per benign control and [0.67] per controlled malicious variant, with [20] malicious findings and a delta of [0.47].

The crypto category averages [0.80] findings per benign control and [1.00] per controlled malicious variant, with [30] malicious findings and a delta of [0.20].

The entitlements category averages [0.20] findings per benign control and [0.33] per controlled malicious variant, with [10] malicious findings and a delta of [0.13].

The sensitive-storage category averages [0.60] findings per benign control and [0.67] per controlled malicious variant, with [20] malicious findings and a delta of [0.07].

The mean finding count is [4.4] per benign control and [7.33] per controlled malicious variant. The largest malicious finding total is in the [network] category.

## Category Statistical Tests

The category-delta analysis applies a [two-sided asymptotic Mann-Whitney U test with tie correction] to [7] finding categories.

The network category has U [30.0000] and p-value [0.000015].

The secrets category has U [30.0000] and p-value [0.000015].

The transport-security category has U [20.0000] and p-value [0.003011].

The crypto category has U [60.0000] and p-value [0.017892].

The anti-analysis category has U [40.0000] and p-value [0.055380].

The entitlements category has U [65.0000] and p-value [0.577711].

The sensitive-storage category has U [75.0000] and p-value [1.000000].

## Dynamic Evidence

The dynamic status is [captured_companion_build], representing an Xcode Simulator and Frida capture rather than exact-IPA execution.

CipherDock captured [2] live dynamic events from Mastodon running in the [iPhone 17 Pro Simulator].

CipherDock captured [1] network call to [https://api.joinmastodon.org/default-servers].

The captured endpoint correlation is [DOMAIN_MATCH] because that exact URL is not present in the analyzed uploaded IPA static URL list, but its application domain occurs in recovered static URL evidence.

## Build Friction

The build-friction record contains [5] ready benign IPA artifacts and [3] pending builds.

Corpus verification passes for [35/35] analyzed IPA hashes; all [5/5] real benign control hashes match both `labels.csv` and the provenance hashes recorded in `BUILD.md`.

Signal iOS has [1] recorded blocking archive error: `SignalServiceKit` could not locate `CocoaLumberjack/CocoaLumberjack.h`.

Bitwarden iOS has [1] incomplete bootstrap attempt, stopped while `mint bootstrap` compiled `sourcery`.

Proton Mail iOS has [1] upstream availability blocker: its required SDK distribution is unavailable for external public builds.

## Limitations

The evaluation is a controlled synthetic study with official open-source builds still pending for three candidate benign controls. VirusTotal was not queried in the current outputs, so no VirusTotal comparison count is reported.
