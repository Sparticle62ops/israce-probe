# israce-probe

On-device repro probe for the IOSurfaceRoot kernel UAF on iOS 27.0.1 (24A446),
from the public writeup (Kimi-2011/ios27-iosurface-uaf, CVE-2026-112477).
App-reachable, no private entitlements. Built as an unsigned ipa via GitHub Actions
macOS runner; sign + sideload with Sideloadly/AltStore to test on device.

Log lands in the app's Documents/israce.log. A kernel panic during the run is the
expected positive signal (fingerprint: iter log stops mid-run, panic log on next boot).
