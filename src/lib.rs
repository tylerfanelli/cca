// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

pub mod error;

use error::*;

use std::cmp::max;

use kvm_bindings::*;
use kvm_ioctls::{Cap, Kvm, VmFd};

pub struct Realm {
    vm_fd: VmFd,
    ipa_bits: u32,
}

impl Realm {
    // Check if the ARM Realm Management Extension (RME) is supported. This capability is required
    // to launch realm VMs.
    pub fn supported(kvm: &Kvm) -> bool {
        kvm.check_extension(Cap::ArmRme)
    }

    // Given the maximum IPA space needed, create a realm VM.
    pub fn new(kvm: &Kvm, max_ipa: usize) -> Result<Self, Error> {
        let ipa_bits = max(1 << max_ipa.trailing_zeros(), 32) + 1;

        let vm_fd = kvm
            .create_vm_with_type(
                (KVM_VM_TYPE_ARM_REALM | (ipa_bits & KVM_VM_TYPE_ARM_IPA_SIZE_MASK)).into(),
            )
            .map_err(Error::VmCreate)?;

        Ok(Self { vm_fd, ipa_bits })
    }

    // Fetch the realm's underlying VM file descriptor.
    pub fn vm_fd(&mut self) -> &mut VmFd {
        &mut self.vm_fd
    }
}
