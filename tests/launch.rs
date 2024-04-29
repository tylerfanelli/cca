// SPDX-License-Identifier: Apache-2.0

use std::slice::from_raw_parts_mut;
use std::{cmp::max, os::fd::RawFd, ptr};

use cca::{Algo, Realm, ARM_GIC_DIST_BASE, ARM_GIC_REDIST_SIZE};
use kvm_bindings::*;

use kvm_ioctls::{Kvm, VcpuExit};

#[test]
fn launch() {
    let kvm = Kvm::new().unwrap();

    let code = [
        0x01, 0x00, 0x00, 0xf9, /* str x1, [x0] */
        0x00, 0x00, 0x00,
        0x14, /* b <this address>; shouldn't get here, but if so loop forever */
    ];

    assert_eq!(Realm::supported(&kvm), true);

    const MEM_ADDR: u64 = 0x10000;

    const CODE_SIZE: u64 = 0x1000;

    let max_ipa = MEM_ADDR + CODE_SIZE as u64 - 1;
    let ipa_bits = max(1 << max_ipa.trailing_zeros(), 32) + 1;

    let vm_fd = kvm
        .create_vm_with_type(
            (KVM_VM_TYPE_ARM_REALM | (ipa_bits & KVM_VM_TYPE_ARM_IPA_SIZE_MASK)).into(),
        )
        .unwrap();

    let realm = Realm::new();

    // Create IRQ chip in kernel: IRQCHIP_GICV3
    let mut gic_device = kvm_create_device {
        type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
        fd: 0,
        flags: 0,
    };

    let gic_fd = vm_fd.create_device(&mut gic_device).unwrap();

    // "1" is the number of vcpus
    let gic_redists_size: u64 = 1u64 * ARM_GIC_REDIST_SIZE;
    let gic_redists_base: u64 = ARM_GIC_DIST_BASE - gic_redists_size;

    let redist_attr = kvm_device_attr {
        flags: 0,
        group: KVM_DEV_ARM_VGIC_GRP_ADDR,
        attr: u64::from(KVM_VGIC_V3_ADDR_TYPE_REDIST),
        addr: ptr::addr_of!(gic_redists_base) as u64,
    };

    gic_fd.set_device_attr(&redist_attr).unwrap();

    let dist_addr: u64 = ARM_GIC_DIST_BASE;
    let dist_attr = kvm_device_attr {
        flags: 0,
        group: KVM_DEV_ARM_VGIC_GRP_ADDR,
        attr: u64::from(KVM_VGIC_V3_ADDR_TYPE_DIST),
        addr: ptr::addr_of!(dist_addr) as u64,
    };

    gic_fd.set_device_attr(&dist_attr).unwrap();

    let address_space = unsafe { libc::mmap(0 as _, CODE_SIZE.try_into().unwrap(), 3, 34, -1, 0) };
    if address_space == libc::MAP_FAILED {
        panic!("mmap() failed");
    }

    let address_space: &mut [u8] =
        unsafe { from_raw_parts_mut(address_space as *mut u8, code.len()) };

    address_space[..code.len()].copy_from_slice(&code[..]);

    let userspace_addr = address_space as *const [u8] as *const u8 as u64;

    let gmem = kvm_create_guest_memfd {
        size: CODE_SIZE,
        flags: 0,
        reserved: [0; 6],
    };

    let id: RawFd = vm_fd.create_guest_memfd(gmem).unwrap();

    let mem_region = kvm_userspace_memory_region2 {
        slot: 0,
        flags: KVM_MEM_GUEST_MEMFD,
        guest_phys_addr: MEM_ADDR,
        memory_size: CODE_SIZE,
        userspace_addr,
        guest_memfd_offset: 0,
        guest_memfd: id as u32,
        pad1: 0,
        pad2: [0; 14],
    };

    unsafe {
        vm_fd.set_user_memory_region2(mem_region).unwrap();
    }

    let mut vcpu_fd = vm_fd.create_vcpu(0).unwrap();

    let mut kvi = kvm_vcpu_init::default();
    vm_fd.get_preferred_target(&mut kvi).unwrap();

    kvi.features[0] |= 1u32 << KVM_ARM_VCPU_PSCI_0_2;

    vcpu_fd.vcpu_init(&kvi).unwrap();

    // initialize vGiC after VCPU creation. Note that this is a minimal setup
    let vgic_init_attr = kvm_device_attr {
        flags: 0,
        group: KVM_DEV_ARM_VGIC_GRP_CTRL,
        attr: u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT),
        addr: 0x0,
    };

    gic_fd.set_device_attr(&vgic_init_attr).unwrap();

    realm
        .configure_measurement(&vm_fd, Algo::AlgoSha256)
        .unwrap();

    realm.create_realm_descriptor(&vm_fd).unwrap();

    realm.populate(&vm_fd, MEM_ADDR, CODE_SIZE as u64).unwrap();

    let core_reg_base: u64 = 0x6030_0000_0010_0000;

    // set x1 to known value
    let nr_magic: u64 = 0x1987;
    vcpu_fd
        .set_one_reg(core_reg_base + 2 * 1, &(nr_magic as u128).to_le_bytes())
        .unwrap();

    // set x0 to a mmio region out of ipa
    let mmio_addr: u64 = (1 << ipa_bits - 1) + 0x1000;
    vcpu_fd
        .set_one_reg(core_reg_base + 2 * 0, &(mmio_addr as u128).to_le_bytes())
        .unwrap();

    // set pc
    let guest_addr: u64 = MEM_ADDR;
    vcpu_fd
        .set_one_reg(core_reg_base + 2 * 32, &(guest_addr as u128).to_le_bytes())
        .unwrap();

    let feature = KVM_ARM_VCPU_REC as i32;
    vcpu_fd.vcpu_finalize(&feature).unwrap();

    realm.activate(&vm_fd).unwrap();

    loop {
        match vcpu_fd.run().expect("run failed") {
            VcpuExit::MmioWrite(addr, data) => {
                assert_eq!(addr, 0x1000);
                assert_eq!(data[0], 0x87);
                assert_eq!(data[1], 0x19);
                break;
            }
            exit_reason => panic!("unexpected exit reason: {:?}", exit_reason),
        }
    }
}
