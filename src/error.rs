// SPDX-License-Identifier: Apache-2.0

use vmm_sys_util::errno;

#[derive(Debug)]
pub enum Error {
    VmCreate(errno::Error),
}
