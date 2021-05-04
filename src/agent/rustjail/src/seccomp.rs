// Copyright 2021 Sony Group Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result};
use libseccomp::*;
use oci::LinuxSeccomp;
use std::str::FromStr;

pub fn get_filter_attr_from_flag(flag: &str) -> Result<ScmpFilterAttr> {
    match flag {
        "SECCOMP_FILTER_FLAG_TSYNC" => Ok(ScmpFilterAttr::CtlTsync),
        "SECCOMP_FILTER_FLAG_LOG" => Ok(ScmpFilterAttr::CtlLog),
        "SECCOMP_FILTER_FLAG_SPEC_ALLOW" => Ok(ScmpFilterAttr::CtlSsb),
        _ => Err(anyhow!("Invalid seccomp flag")),
    }
}

// init_seccomp creates a seccomp filter and loads it for the current process
// including all the child processes.
pub fn init_seccomp(scmp: &LinuxSeccomp) -> Result<()> {
    let def_action = ScmpAction::from_str(scmp.default_action.as_str(), Some(libc::EPERM as u32))?;

    // Create a new filter context
    let mut filter = ScmpFilterContext::new_filter(def_action)?;

    // Add extra architectures
    for arch in &scmp.architectures {
        let scmp_arch = ScmpArch::from_str(arch)?;
        filter.add_arch(scmp_arch)?;
    }

    // Unset no new privileges bit
    filter.set_no_new_privs_bit(false)?;

    // Add a rule for each system call
    for syscall in &scmp.syscalls {
        if syscall.names.is_empty() {
            return Err(anyhow!("syscall name is required"));
        }

        let action = ScmpAction::from_str(&syscall.action, Some(syscall.errno_ret))?;
        if action == def_action {
            continue;
        }

        for name in &syscall.names {
            let syscall_num = get_syscall_from_name(name, None)?;

            if syscall.args.is_empty() {
                filter.add_rule(action, syscall_num, None)?;
            } else {
                let mut cmps: Vec<ScmpArgCompare> = Vec::new();

                for arg in &syscall.args {
                    if arg.op.is_empty() {
                        return Err(anyhow!("seccomp opreator is required"));
                    }

                    let arg_cmp = ScmpArgCompare::new(
                        arg.index,
                        ScmpCompareOp::from_str(&arg.op)?,
                        arg.value,
                        Some(arg.value_two),
                    );

                    cmps.push(arg_cmp);
                }

                filter.add_rule(action, syscall_num, Some(&cmps))?;
            }
        }
    }

    // Set filtter attributes for each seccomp flag
    for flag in &scmp.flags {
        let scmp_attr = get_filter_attr_from_flag(flag)?;
        filter.set_filter_attr(scmp_attr, 1)?;
    }

    // Load the filter
    filter.load()?;

    Ok(())
}
