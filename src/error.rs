// SPDX-License-Identifier: Apache-2.0

use vmm_sys_util::errno;

#[derive(Debug)]
pub enum Error {
    VmCreate(errno::Error),
    GICCreate(errno::Error),
    GICInit(errno::Error),
    Config(errno::Error),
    RDCreate(errno::Error),
    RPopulate(errno::Error),
    RInitiate(errno::Error),
    RActivate(errno::Error),
}
