# roothide Dopamine 3 (experimental port)

This development branch integrates [roothide 2.4.9.27](https://github.com/roothide/Dopamine2-roothide/tree/3824f2731275423c970ff6ed6685957dec269073)
with [Dopamine 3.x](https://github.com/opa334/Dopamine/tree/939a3a21400f0dc6d6163b2b5999ba2ace0d2732), based on Dopamine 3.0.9.
It is not an official release from either upstream project.

## Compatibility

The port retains Dopamine 3's exploit implementations and device/version selection.
In particular, upstream supports iPhone 11 on iOS 26.0 and 26.0.1; this does not mean
that every iOS 26 release is supported. See the [upstream compatibility information](https://ellekit.space/dopamine/).

**The roothide integration has not been validated on a physical iPhone.** A successful
build or host-side test does not establish that jailbreak activation, a userspace
reboot, tweak injection, or jailbreak hiding works on a given firmware. Do not treat
this branch as a device-tested release.

## Building and testing

See [BUILD.md](BUILD.md) for build instructions and validation boundaries.
The [GitHub Actions workflow](.github/workflows/roothide.yml) builds the checked-out
branch, rather than cloning and building the old roothide release.

## Upstream resources

- [Roothide developer documentation](https://github.com/roothide/Developer)
- [Roothide support](https://twitter.com/roothideDev)
- [Roothide Discord](https://discord.gg/ZvY2Yjw8GA)
