# cca

The `cca` crate provides an implementation of the [ARM Confidential Computing Architecture (CCA)](https://www.arm.com/architecture/security-features/arm-confidential-compute-architecture) ABIs.

`NOTE`: As of the `0.0.1` release, this crate is **very** experimental. It has only been tested in the ARMv9 FVP, not on real hardware. It also relies on KVM API changes that are **not in upstream Linux**. As such, the `kvm-bindings` and `kvm-ioctls` rust crates do not yet contain the relevant changes to the KVM API either. Because of this, `0.0.1` of this crate relies on personal branches of these crates.

### License
Apache-2.0
