# Building the experimental Dopamine 3 port

This branch combines Dopamine 3.x commit
`939a3a21400f0dc6d6163b2b5999ba2ace0d2732` with roothide 2.4.9.27 commit
`3824f2731275423c970ff6ed6685957dec269073`. Keep the recorded submodule
revisions: the port uses upstream Dopamine 3's XPF and ChOma, not the old
roothide XPF fork.

## GitHub Actions

Fork the repository and select **Actions > Build roothide Dopamine > Run
workflow**, selecting the branch containing this port. The workflow checks
out that branch with its submodules, runs host regressions, builds, and uploads
`roothide-Dopamine-<version>-<commit>.tipa` as an artifact. GitHub wraps the
artifact in a ZIP file; extract it to obtain the TIPA.

A green workflow establishes build and host-test results, not successful
jailbreaking or hiding on a physical device.

## Local prerequisites

Use macOS with Xcode and its iPhoneOS SDK selected by `xcode-select`, the
roothide fork of Theos with its iPhoneOS 16.5 SDK, GNU Make, `ldid`,
`trustcache`, and Homebrew `libarchive`. The Xcode SDK is used for the native
base binaries; the Theos SDK is used for the Theos projects. Do not delete or
replace Xcode's XPC headers to build this port.

The dependency installation steps are in
[the workflow](.github/workflows/roothide.yml). Point `THEOS` at the installed
roothide Theos tree and put `ldid` and `trustcache` on `PATH`, then run:

```sh
git submodule update --init --recursive
sh tests/run_host_tests.sh
gmake -j4 BUILD_STANDALONE=0
```

Successful packaging produces `Application/Dopamine.ipa`,
`Application/Dopamine.tipa`, and `BaseBin/basebin.tar`. The app is ad-hoc
signed; these commands do not provision, install, launch, or activate it on
a device. Installation requirements depend on the device and firmware.

This port builds the iOS application, not Dopamine's separate standalone /
Corellium installer. That installer still assumes the upstream bind-mounted
filesystem layout and is not included in the basebin archive or produced as
`Standalone/Dopamine.tar`. `BUILD_STANDALONE=1` is rejected explicitly rather
than packaging an unported activation workflow.

`libjailbreak` builds separate arm64 and arm64e translation units and combines
the two dylibs. Header dependencies and compiler-option changes invalidate
the corresponding cached objects. `gmake -C BaseBin/libjailbreak clean`
removes that component's object cache.

## Host regressions

```sh
sh tests/run_host_tests.sh
sh tests/run_host_tests.sh /absolute/path/to/kernelcache
```

The host suite checks upstream exploit and kernel-source preservation,
serialized state, submodule revisions, IPC domain assignments, CI wiring,
version ordering, and code-signing hash handling. It compiles the patchfinder
harness on every run. Without an explicit kernelcache argument, it reports
that kernel-fixture execution was skipped.

The suite also verifies XPC reply return-ownership types with and without
ARC, timestamp-preserving header staging, and exclusion of the unported
standalone installer. Theos uses a project-local module cache and validates
system headers so SDK overlays cannot reuse another build's Clang modules.

The kernel harness initializes upstream XPF and resolves the additional
roothide name-cache and AMFI sysctl fields. It does not execute a kernel
exploit or mutate a live kernel. Use a fixture matching the exact device
model and OS build; a result for iOS 26.0.1 is not validation of iOS 26.0.

## Integration boundaries

Roothide's existing clients retain IPC domain 5. Dopamine 3's app-only
service uses domain 6 in this port to avoid colliding with that ABI.
The new code-signing helpers preserve the caller's TXM flags while updating
the first code slot after roothide's executable randomization.

The upstream exploit/version selection remains authoritative: iPhone 11
support for iOS 26.0 and 26.0.1 does not imply support for every iOS 26
release. No physical-device validation of this port has been completed.
Activation, userspace reboot, bootstrap updates and removal, package-manager
launch, tweak injection, safe mode, and per-application hiding still require
end-to-end testing on the exact target firmware. Simulators cannot validate
those kernel and system-process interactions.
