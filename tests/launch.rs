// SPDX-License-Identifier: Apache-2.0

use std::os::fd::RawFd;
use std::slice::from_raw_parts_mut;

use cca::{Realm, Algo};
use kvm_bindings::KVM_ARM_VCPU_REC;
use kvm_bindings::{
    kvm_create_guest_memfd, kvm_userspace_memory_region2, kvm_vcpu_init, KVM_ARM_VCPU_PSCI_0_2,
    KVM_MEM_GUEST_MEMFD,
};
use kvm_ioctls::{Kvm, VcpuExit};

#[test]
fn launch() {
    let kvm = Kvm::new().unwrap();

    let code = [
        0x01, 0x00, 0x00, 0xf9, /* str x1, [x0] */
        0x00, 0x00, 0x00, 0x14, /* b <this address>; shouldn't get here, but if so loop forever */
    ];

    assert_eq!(Realm::supported(&kvm), true);

    const MEM_ADDR: u64 = 0x10000;

    const CODE_SIZE: u64 = 0x1000;

    let ipa_bits = MEM_ADDR + CODE_SIZE as u64 - 1;

    let mut realm = Realm::new(&kvm, ipa_bits.try_into().unwrap()).unwrap();

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

    let id: RawFd = realm.vm_fd().create_guest_memfd(gmem).unwrap();

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
        realm.vm_fd().set_user_memory_region2(mem_region).unwrap();
    }

    let mut vcpu_fd = realm.vm_fd().create_vcpu(0).unwrap();

    let mut kvi = kvm_vcpu_init::default();
    realm.vm_fd().get_preferred_target(&mut kvi).unwrap();

    kvi.features[0] |= 1u32 << KVM_ARM_VCPU_PSCI_0_2;

    vcpu_fd.vcpu_init(&kvi).unwrap();

    realm.vgic_initialize().unwrap();

    realm.configure_measurement(Algo::AlgoSha256).unwrap();

    realm.create_realm_descriptor().unwrap();

    realm.populate(MEM_ADDR, CODE_SIZE as u64).unwrap();

    let core_reg_base: u64 = 0x6030_0000_0010_0000;

    // set x1 to known value
    let nr_magic: u64 = 0x1987;
    vcpu_fd
        .set_one_reg(core_reg_base + 2 * 1, &(nr_magic as u128).to_le_bytes())
        .unwrap();

    // set x0 to a mmio region out of ipa
    let mmio_addr: u64 = (1 << realm.ipa_bits() - 1) + 0x1000;
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

    realm.activate().unwrap();

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
