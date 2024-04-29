// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

pub mod error;

use error::*;

use std::ptr;

use kvm_bindings::*;
use kvm_ioctls::{Cap, Kvm, VmFd};

pub struct Realm;

pub enum Algo {
    AlgoSha256,
    AlgoSha512,
}

type Result<T> = std::result::Result<T, Error>;

pub const ARM_GIC_REDIST_SIZE: u64 = 0x20000;
pub const ARM_GIC_DIST_SIZE: u64 = 0x10000;
pub const ARM_AXI_AREA: u64 = 0x40000000;
pub const ARM_GIC_DIST_BASE: u64 = ARM_AXI_AREA - ARM_GIC_DIST_SIZE;

impl Realm {
    // Check if the ARM Realm Management Extension (RME) is supported. This capability is required
    // to launch realm VMs.
    pub fn supported(kvm: &Kvm) -> bool {
        kvm.check_extension(Cap::ArmRme)
    }

    pub fn new() -> Self {
        Self {}
    }

    pub fn configure_measurement(&self, vmfd: &VmFd, _algo: Algo) -> Result<()> {
        let mut hash_algo_cfg = kvm_cap_arm_rme_config_item {
            cfg: KVM_CAP_ARM_RME_CFG_HASH_ALGO,
            ..Default::default()
        };

        hash_algo_cfg.data.hash_algo = KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA256;

        let mut rme_config = kvm_enable_cap {
            cap: KVM_CAP_ARM_RME,
            ..Default::default()
        };

        rme_config.args[0] = KVM_CAP_ARM_RME_CONFIG_REALM;
        rme_config.args[1] = ptr::addr_of!(hash_algo_cfg) as u64;

        vmfd.enable_cap(&rme_config).map_err(Error::Config)?;

        Ok(())
    }

    pub fn create_realm_descriptor(&self, vmfd: &VmFd) -> Result<()> {
        let mut rme_config = kvm_enable_cap {
            cap: KVM_CAP_ARM_RME,
            ..Default::default()
        };

        rme_config.args[0] = KVM_CAP_ARM_RME_CREATE_RD;
        vmfd.enable_cap(&rme_config).map_err(Error::RDCreate)?;

        Ok(())
    }

    pub fn populate(&self, vmfd: &VmFd, addr: u64, size: u64) -> Result<()> {
        let mut populate_args: kvm_cap_arm_rme_populate_realm_args = Default::default();
        let mut rme_config = kvm_enable_cap {
            cap: KVM_CAP_ARM_RME,
            ..Default::default()
        };
        populate_args.populate_ipa_base = addr;
        populate_args.populate_ipa_size = size;
        populate_args.flags = KVM_ARM_RME_POPULATE_FLAGS_MEASURE;
        rme_config.args[0] = KVM_CAP_ARM_RME_POPULATE_REALM;
        rme_config.args[1] = ptr::addr_of!(populate_args) as u64;
        vmfd.enable_cap(&rme_config).map_err(Error::RPopulate)?;
        Ok(())
    }

    pub fn initiate(&self, vmfd: &VmFd, addr: u64, size: u64) -> Result<()> {
        let mut init_args: kvm_cap_arm_rme_init_ipa_args = Default::default();
        let mut rme_config = kvm_enable_cap {
            cap: KVM_CAP_ARM_RME,
            ..Default::default()
        };
        init_args.init_ipa_base = addr;
        init_args.init_ipa_size = size;
        rme_config.args[0] = KVM_CAP_ARM_RME_INIT_IPA_REALM;
        rme_config.args[1] = ptr::addr_of!(init_args) as u64;
        vmfd.enable_cap(&rme_config).map_err(Error::RInitiate)?;
        Ok(())
    }

    pub fn activate(&self, vmfd: &VmFd) -> Result<()> {
        let mut rme_config = kvm_enable_cap {
            cap: KVM_CAP_ARM_RME,
            ..Default::default()
        };
        rme_config.args[0] = KVM_CAP_ARM_RME_ACTIVATE_REALM;
        vmfd.enable_cap(&rme_config).map_err(Error::RActivate)?;
        Ok(())
    }
}
