// SPDX-License-Identifier: Apache-2.0

use std::slice::from_raw_parts_mut;

use cca::Realm;
use kvm_bindings::{kvm_userspace_memory_region, KVM_MEM_GUEST_MEMFD};
use kvm_ioctls::Kvm;

// One page of `hlt` instructions.
const CODE: &[u8; 4096] = &[0xf4; 4096];

#[test]
fn launch() {
    let kvm = Kvm::new().unwrap();

    assert_eq!(Realm::supported(&kvm), true);

    let mut realm = Realm::new(&kvm, 32).unwrap();

    let address_space = unsafe { libc::mmap(0 as _, CODE.len(), 3, 34, -1, 0) };
    if address_space == libc::MAP_FAILED {
        panic!("mmap() failed");
    }

    let address_space: &mut [u8] =
        unsafe { from_raw_parts_mut(address_space as *mut u8, CODE.len()) };

    address_space[..CODE.len()].copy_from_slice(&CODE[..]);

    const MEM_ADDR: u64 = 0x1000;
    let userspace_addr = address_space as *const [u8] as *const u8 as u64;
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: MEM_ADDR,
        memory_size: CODE.len() as _,
        userspace_addr,
        flags: KVM_MEM_GUEST_MEMFD,
    };

    unsafe {
        realm.vm_fd().set_user_memory_region(mem_region).unwrap();
    }
}
