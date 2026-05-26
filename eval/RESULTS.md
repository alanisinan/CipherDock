## Evaluation Results

Controlled synthetic evaluation. Official open-source builds remain pending. Open-source controls are labeled benign/negative as non-injected benchmark controls; the label does not assert absence of ordinary security findings.

### Table 1 - Corpus Composition

| Category | Count | % |
| --- | ---: | ---: |
| Real benign control analyzed | 5 | 14.3% |
| Controlled malicious variant | 30 | 85.7% |
| Total | 35 | 100.0% |
| Pending official benign builds (excluded) | 3 | - |

### Table 2 - Held-Out Detection Performance

| Threshold | TP | FP | TN | FN | Precision | Recall | F1 | 95% CI |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 50 | 9 | 1 | 1 | 0 | 0.9000 | 1.0000 | 0.9474 | [0.8235, 1.0000] |
| 70 | 6 | 0 | 2 | 3 | 1.0000 | 0.6667 | 0.8000 | [0.5000, 1.0000] |
| 90 | 0 | 0 | 2 | 9 | 0.0000 | 0.0000 | 0.0000 | [0.0000, 0.0000] |

At the threshold selected on calibration data, obvious and subtle controlled positives are reported separately:

| Variant Type | Held-Out F1 |
| --- | ---: |
| Obvious | 0.9231 |
| Subtle | 0.8571 |

### Table 3 - CipherDock vs VirusTotal

| App | CipherDock Score | VT Detections | CipherDock Findings |
| --- | ---: | ---: | ---: |
| mastodon-ios__irez.eval001.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval002.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval003.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval004.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval005.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval006.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval007.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval008.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval009.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval010.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval011.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval012.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval013.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval014.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval015.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval016.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval017.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval018.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval019.ipa | 84 | not queried | 7 |
| mastodon-ios__irez.eval020.ipa | 84 | not queried | 7 |
| vlc-ios.ipa | 68 | not queried | 8 |
| vlc-ios__irez.subtle001.ipa | 68 | not queried | 8 |
| vlc-ios__irez.subtle002.ipa | 68 | not queried | 8 |
| vlc-ios__irez.subtle003.ipa | 68 | not queried | 8 |
| vlc-ios__irez.subtle004.ipa | 68 | not queried | 8 |
| vlc-ios__irez.subtle005.ipa | 68 | not queried | 8 |
| vlc-ios__irez.subtle006.ipa | 68 | not queried | 8 |
| vlc-ios__irez.subtle007.ipa | 68 | not queried | 8 |
| vlc-ios__irez.subtle008.ipa | 68 | not queried | 8 |
| vlc-ios__irez.subtle009.ipa | 68 | not queried | 8 |
| vlc-ios__irez.subtle010.ipa | 68 | not queried | 8 |
| nextcloud-ios.ipa | 60 | not queried | 5 |
| firefox-ios.ipa | 39 | not queried | 4 |
| wikipedia-ios.ipa | 20 | not queried | 2 |
| mastodon-ios.ipa | 18 | not queried | 3 |

### Table 4 - Findings by Category

| Category | Benign avg | Malicious avg | Delta |
| --- | ---: | ---: | ---: |
| transport-security | 0.80 | 1.67 | 0.87 |
| network | 1.40 | 2.00 | 0.60 |
| secrets | 0.40 | 1.00 | 0.60 |
| anti-analysis | 0.20 | 0.67 | 0.47 |
| crypto | 0.80 | 1.00 | 0.20 |
| entitlements | 0.20 | 0.33 | 0.13 |
| sensitive-storage | 0.60 | 0.67 | 0.07 |

### Dynamic Evidence

CipherDock captured live NSURLSession calls via Frida instrumentation of Mastodon iOS running in an iPhone 17 Pro Simulator. The dynamic layer observed 1 network endpoint (`https://api.joinmastodon.org/default-servers`), labeled `DOMAIN_MATCH` against the analyzed IPA static URL list. This is companion-build evidence and is not asserted as exact IPA execution.
