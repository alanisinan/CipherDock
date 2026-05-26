# Open-Source iOS Evaluation Corpus

## Label Boundary

`negative` means a non-injected open-source control sample in this benchmark. It is not a claim that the app is free of security findings. All SHAs identify the exact IPA artifact analyzed.

## Prepare Artifacts

```bash
python3 eval/build_corpus.py --discover-mastodon --download-official vlc-ios
# For locally archived apps:
python3 eval/build_corpus.py --import-ipa wikipedia-ios=/path/to/Wikipedia.ipa --import-ipa firefox-ios=/path/to/Firefox.ipa
# Optional source acquisition:
python3 eval/build_corpus.py --clone-sources
```

- Corpus directory: `/path/to/project/eval/corpus`
- Labels and SHA-256 provenance: `/path/to/project/eval/corpus/labels.csv`

A source build archive must be packaged as `Payload/<App>.app` inside an `.ipa` zip before import. Code signing is not required for static evaluation; a signed artifact is needed for real device execution.

## Application Sources And Build Commands

### Mastodon iOS (`mastodon-ios`)

- Official source: [https://github.com/mastodon/mastodon-ios.git](https://github.com/mastodon/mastodon-ios.git)
- Official IPA: no upstream IPA asset documented here; build from official source.
- Note: A locally authorized IPA has already been supplied for this evaluation.

```bash
git clone --depth 1 https://github.com/mastodon/mastodon-ios.git eval/corpus/sources/mastodon-ios
cd eval/corpus/sources/mastodon-ios
xcodebuild -list -workspace Mastodon.xcworkspace
xcodebuild -workspace Mastodon.xcworkspace -scheme Mastodon -configuration Release -sdk iphoneos -archivePath "$PWD/build/Mastodon.xcarchive" archive CODE_SIGNING_ALLOWED=NO
mkdir -p "$PWD/build/package/Payload"
cp -R "$PWD/build/Mastodon.xcarchive/Products/Applications/"*.app "$PWD/build/package/Payload/"
(cd "$PWD/build/package" && ditto -c -k --sequesterRsrc --keepParent Payload "../mastodon-ios.ipa")
```

If the scheme or project changes upstream, use the `xcodebuild -list` output to select the application scheme and record that change with the corpus manifest.

### Wikipedia iOS (`wikipedia-ios`)

- Official source: [https://github.com/wikimedia/wikipedia-ios.git](https://github.com/wikimedia/wikipedia-ios.git)
- Official IPA: no upstream IPA asset documented here; build from official source.
- Note: Official Wikimedia client; run ./scripts/setup, then archive the Wikipedia scheme from Wikipedia.xcodeproj.

```bash
git clone --depth 1 https://github.com/wikimedia/wikipedia-ios.git eval/corpus/sources/wikipedia-ios
cd eval/corpus/sources/wikipedia-ios
./scripts/setup
xcodebuild -list -project Wikipedia.xcodeproj
xcodebuild -project Wikipedia.xcodeproj -scheme Wikipedia -configuration Release -sdk iphoneos -archivePath "$PWD/build/Wikipedia.xcarchive" archive CODE_SIGNING_ALLOWED=NO
mkdir -p "$PWD/build/package/Payload"
cp -R "$PWD/build/Wikipedia.xcarchive/Products/Applications/"*.app "$PWD/build/package/Payload/"
(cd "$PWD/build/package" && ditto -c -k --sequesterRsrc --keepParent Payload "../wikipedia-ios.ipa")
```

If the scheme or project changes upstream, use the `xcodebuild -list` output to select the application scheme and record that change with the corpus manifest.

### Firefox for iOS (`firefox-ios`)

- Official source: [https://github.com/mozilla-mobile/firefox-ios.git](https://github.com/mozilla-mobile/firefox-ios.git)
- Official IPA: no upstream IPA asset documented here; build from official source.
- Note: Official Mozilla source; bootstrap with fxios where available, then archive Fennec from firefox-ios/Client.xcodeproj.

```bash
git clone --depth 1 https://github.com/mozilla-mobile/firefox-ios.git eval/corpus/sources/firefox-ios
cd eval/corpus/sources/firefox-ios
sh ./bootstrap.sh firefox
xcodebuild -list -project firefox-ios/Client.xcodeproj
xcodebuild -project firefox-ios/Client.xcodeproj -scheme Fennec -configuration Release -sdk iphoneos -archivePath "$PWD/build/Fennec.xcarchive" archive CODE_SIGNING_ALLOWED=NO
mkdir -p "$PWD/build/package/Payload"
cp -R "$PWD/build/Fennec.xcarchive/Products/Applications/"*.app "$PWD/build/package/Payload/"
(cd "$PWD/build/package" && ditto -c -k --sequesterRsrc --keepParent Payload "../firefox-ios.ipa")
```

If the scheme or project changes upstream, use the `xcodebuild -list` output to select the application scheme and record that change with the corpus manifest.

### VLC for iOS (`vlc-ios`)

- Official source: [https://code.videolan.org/videolan/vlc-ios.git](https://code.videolan.org/videolan/vlc-ios.git)
- Official IPA: [https://get.videolan.org/vlc-iOS/3.5.0/VLC-iOS.ipa](https://get.videolan.org/vlc-iOS/3.5.0/VLC-iOS.ipa)
- Note: VideoLAN publishes an official IPA binary; prefer it for reproducible static evaluation.

```bash
git clone --depth 1 https://code.videolan.org/videolan/vlc-ios.git eval/corpus/sources/vlc-ios
cd eval/corpus/sources/vlc-ios
xcodebuild -list -workspace VLC.xcworkspace
xcodebuild -workspace VLC.xcworkspace -scheme VLC-iOS -configuration Release -sdk iphoneos -archivePath "$PWD/build/VLC-iOS.xcarchive" archive CODE_SIGNING_ALLOWED=NO
mkdir -p "$PWD/build/package/Payload"
cp -R "$PWD/build/VLC-iOS.xcarchive/Products/Applications/"*.app "$PWD/build/package/Payload/"
(cd "$PWD/build/package" && ditto -c -k --sequesterRsrc --keepParent Payload "../vlc-ios.ipa")
```

If the scheme or project changes upstream, use the `xcodebuild -list` output to select the application scheme and record that change with the corpus manifest.

### Bitwarden iOS (`bitwarden-ios`)

- Official source: [https://github.com/bitwarden/ios.git](https://github.com/bitwarden/ios.git)
- Official IPA: no upstream IPA asset documented here; build from official source.
- Note: Official GPL iOS repository; follow its contribution setup for generated projects/dependencies.

```bash
git clone --depth 1 https://github.com/bitwarden/ios.git eval/corpus/sources/bitwarden-ios
cd eval/corpus/sources/bitwarden-ios
./Scripts/bootstrap.sh
xcodebuild -list -workspace Bitwarden.xcworkspace
xcodebuild -workspace Bitwarden.xcworkspace -scheme Bitwarden -configuration Release -sdk iphoneos -archivePath "$PWD/build/Bitwarden.xcarchive" archive CODE_SIGNING_ALLOWED=NO
mkdir -p "$PWD/build/package/Payload"
cp -R "$PWD/build/Bitwarden.xcarchive/Products/Applications/"*.app "$PWD/build/package/Payload/"
(cd "$PWD/build/package" && ditto -c -k --sequesterRsrc --keepParent Payload "../bitwarden-ios.ipa")
```

If the scheme or project changes upstream, use the `xcodebuild -list` output to select the application scheme and record that change with the corpus manifest.

### Signal iOS (`signal-ios`)

- Official source: [https://github.com/signalapp/Signal-iOS.git](https://github.com/signalapp/Signal-iOS.git)
- Official IPA: no upstream IPA asset documented here; build from official source.
- Note: Official repository; consult BUILDING.md for environment setup before producing an archive.

```bash
git clone --depth 1 https://github.com/signalapp/Signal-iOS.git eval/corpus/sources/signal-ios
cd eval/corpus/sources/signal-ios
git submodule update --init --recursive
make dependencies
xcodebuild -list -workspace Signal.xcworkspace
xcodebuild -workspace Signal.xcworkspace -scheme Signal -configuration Release -sdk iphoneos -archivePath "$PWD/build/Signal.xcarchive" archive CODE_SIGNING_ALLOWED=NO
mkdir -p "$PWD/build/package/Payload"
cp -R "$PWD/build/Signal.xcarchive/Products/Applications/"*.app "$PWD/build/package/Payload/"
(cd "$PWD/build/package" && ditto -c -k --sequesterRsrc --keepParent Payload "../signal-ios.ipa")
```

If the scheme or project changes upstream, use the `xcodebuild -list` output to select the application scheme and record that change with the corpus manifest.

### Nextcloud iOS (`nextcloud-ios`)

- Official source: [https://github.com/nextcloud/ios.git](https://github.com/nextcloud/ios.git)
- Official IPA: no upstream IPA asset documented here; build from official source.
- Note: Official repository; add the documented mock GoogleService-Info.plist before archiving from Nextcloud.xcodeproj.

```bash
git clone --depth 1 https://github.com/nextcloud/ios.git eval/corpus/sources/nextcloud-ios
cd eval/corpus/sources/nextcloud-ios
curl -L --fail --output GoogleService-Info.plist https://raw.githubusercontent.com/firebase/quickstart-ios/master/mock-GoogleService-Info.plist
xcodebuild -list -project Nextcloud.xcodeproj
xcodebuild -project Nextcloud.xcodeproj -scheme Nextcloud -configuration Release -sdk iphoneos -archivePath "$PWD/build/Nextcloud.xcarchive" archive CODE_SIGNING_ALLOWED=NO
mkdir -p "$PWD/build/package/Payload"
cp -R "$PWD/build/Nextcloud.xcarchive/Products/Applications/"*.app "$PWD/build/package/Payload/"
(cd "$PWD/build/package" && ditto -c -k --sequesterRsrc --keepParent Payload "../nextcloud-ios.ipa")
```

If the scheme or project changes upstream, use the `xcodebuild -list` output to select the application scheme and record that change with the corpus manifest.

### Proton Mail iOS (`protonmail-ios`)

- Official source: [https://github.com/ProtonMail/ios-mail.git](https://github.com/ProtonMail/ios-mail.git)
- Official IPA: no upstream IPA asset documented here; build from official source.
- Note: Upstream README states this public repository cannot currently be built externally because its Mail SDK distribution is not public.

No public build command is available from upstream at this time; retain this entry as `pending_build` rather than counting it as an analyzed benign artifact.

## Reproducible Evaluation Run

```bash
python3 eval/synthetic_builder.py eval/corpus/benign/mastodon-ios.ipa --all --count 20 --output-dir eval/corpus/synthetic --update-labels eval/corpus/labels.csv
python3 eval/synthetic_builder.py eval/corpus/benign/vlc-ios.ipa --subtle --count 10 --output-dir eval/corpus/subtle --update-labels eval/corpus/labels.csv
python3 eval/run_all.py --corpus-dir eval/corpus --labels eval/corpus/labels.csv --reuse-reports --split 0.3
```

## Build Attempt Log - 2026-05-25

Only `ready` IPAs below are included in `eval/results.csv`. A pending or failed source build is not counted as a benign control.

| App | Corpus status | Evidence |
| --- | --- | --- |
| Mastodon iOS | Ready | Authorized supplied IPA, SHA-256 `f5abc1bed12063c3fb532279714c4d33d052bd4186aacb0ddb7cde402528a41b`. |
| VLC for iOS | Ready | Official VideoLAN IPA, SHA-256 `ca6fed845da7ade1c8f1d8b76b353a68ad1af2acc0f9d0bafa4572a39f2d4381`. |
| Wikipedia iOS | Ready | Official source archived successfully with Xcode, SHA-256 `f92b5d2f5a141f851b10492dc8cf51fa9410dcc75888e2b0cbe81ca4c7da6e61`. |
| Firefox for iOS | Ready | Official source archived after documented `sh ./bootstrap.sh firefox`, SHA-256 `d0da3eb2763b4929d9e5382a0fad2609d28f18d9e96e14bb634bb26c1b1df4c8`. |
| Nextcloud iOS | Ready | Official source archived with documented mock `GoogleService-Info.plist`, SHA-256 `c45e7c6e18df3aa7497c21a3d2cb499a98b4bcc951d3b4498fed609dfe0a8077`. |
| Signal iOS | Pending build | Dependencies prepared; archive failed because `SignalServiceKit` could not locate `CocoaLumberjack/CocoaLumberjack.h`. |
| Bitwarden iOS | Pending build | Official bootstrap installed prerequisites but was stopped while `mint bootstrap` compiled `sourcery`, before an app project was generated. |
| Proton Mail iOS | Pending build | Upstream README states the public source cannot currently be built externally due to unavailable SDK distribution. |
