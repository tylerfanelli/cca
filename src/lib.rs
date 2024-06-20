// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

pub mod error;

use error::*;

use std::{cmp::max, ptr};

use kvm_bindings::*;
use kvm_ioctls::{Cap, DeviceFd, Kvm, VmFd};

pub struct Realm {
    ipa_bits: u32,
    vm_fd: VmFd,
    gic_fd: DeviceFd,
}

pub enum Algo {
    AlgoSha256,
    AlgoSha512
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

        // Create IRQ chip in kernel: IRQCHIP_GICV3
        let mut gic_device = kvm_bindings::kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
            fd: 0,
            flags: 0,
        };

        let gic_fd = vm_fd
            .create_device(&mut gic_device)
            .map_err(Error::GICCreate)?;

        // these values are hard-coded based on kvmtool
        let gic_redists_base: u64 = 0x3FFD0000;
        let dist_addr: u64 = 0x3FFF0000;
        let redist_attr = kvm_bindings::kvm_device_attr {
            flags: 0,
            group: KVM_DEV_ARM_VGIC_GRP_ADDR,
            attr: u64::from(KVM_VGIC_V3_ADDR_TYPE_REDIST),
            addr: ptr::addr_of!(gic_redists_base) as u64,
        };

        gic_fd
            .set_device_attr(&redist_attr)
            .map_err(Error::GICCreate)?;

        let dist_attr = kvm_bindings::kvm_device_attr {
            flags: 0,
            group: KVM_DEV_ARM_VGIC_GRP_ADDR,
            attr: u64::from(KVM_VGIC_V3_ADDR_TYPE_DIST),
            addr: ptr::addr_of!(dist_addr) as u64,
        };

        gic_fd
            .set_device_attr(&dist_attr)
            .map_err(Error::GICCreate)?;

        Ok(Self {
            vm_fd,
            ipa_bits,
            gic_fd,
        })
    }

    // Fetch the realm's underlying VM file descriptor.
    pub fn vm_fd(&mut self) -> &mut VmFd {
        &mut self.vm_fd
    }

    pub fn ipa_bits(&self) -> u32 {
        self.ipa_bits
    }

    pub fn vgic_initialize(&self) -> Result<(), Error> {
        // initialize vGiC after VCPU creation. Note that this is a minimal setup
        let vgic_init_attr = kvm_bindings::kvm_device_attr {
            flags: 0,
            group: KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT),
            addr: 0x0,
        };
        self.gic_fd
            .set_device_attr(&vgic_init_attr)
            .map_err(Error::GICInit)?;
        Ok(())
    }

    pub fn configure_measurement(&self, _algo: Algo) -> Result<(), Error> {
        let mut hash_algo_cfg: kvm_cap_arm_rme_config_item = Default::default();
        hash_algo_cfg.cfg = KVM_CAP_ARM_RME_CFG_HASH_ALGO;
        hash_algo_cfg.data.hash_algo = KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA256;

        let mut rme_config: kvm_enable_cap = Default::default();

        rme_config.cap = KVM_CAP_ARM_RME;
        rme_config.args[0] = KVM_CAP_ARM_RME_CONFIG_REALM;
        rme_config.args[1] = ptr::addr_of!(hash_algo_cfg) as u64;

        self.vm_fd
            .enable_cap(&rme_config)
            .map_err(Error::Config)?;

        Ok(())
    }

    pub fn create_realm_descriptor(&self) -> Result<(), Error> {
        let mut rme_config: kvm_enable_cap = Default::default();
        rme_config.cap = KVM_CAP_ARM_RME;
        rme_config.args[0] = KVM_CAP_ARM_RME_CREATE_RD;
        self.vm_fd
            .enable_cap(&rme_config)
            .map_err(Error::RDCreate)?;

        Ok(())
    }

    pub fn populate(&self, addr: u64, size: u64) -> Result<(), Error> {
        let mut populate_args: kvm_cap_arm_rme_populate_realm_args = Default::default();
        let mut rme_config: kvm_enable_cap = Default::default();
        populate_args.populate_ipa_base = addr;
        populate_args.populate_ipa_size = size;
        populate_args.flags = KVM_ARM_RME_POPULATE_FLAGS_MEASURE;
        rme_config.cap = KVM_CAP_ARM_RME;
        rme_config.args[0] = KVM_CAP_ARM_RME_POPULATE_REALM;
        rme_config.args[1] = ptr::addr_of!(populate_args) as u64;
        self.vm_fd
            .enable_cap(&rme_config)
            .map_err(Error::RPopulate)?;
        Ok(())
    }

    pub fn activate(&self) -> Result<(), Error> {
        let mut rme_config: kvm_enable_cap = Default::default();
        rme_config.cap = KVM_CAP_ARM_RME;
        rme_config.args[0] = KVM_CAP_ARM_RME_ACTIVATE_REALM;
        self.vm_fd
            .enable_cap(&rme_config)
            .map_err(Error::RActivate)?;
        Ok(())
    }
}
