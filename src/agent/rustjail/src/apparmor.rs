// Copyright 2021 Sony Group Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, Result};
use std::fs::{read_to_string, OpenOptions};
use std::io::prelude::*;
use std::path::Path;

pub fn is_enabled() -> bool {
    match read_to_string("/sys/module/apparmor/parameters/enabled") {
        Ok(mut content) => {
            content.truncate(1);
            matches!(&*content, "Y")
        }
        Err(_) => false,
    }
}

pub fn init_apparmor(profile: &str) -> Result<()> {
    if !is_enabled() {
        return Err(anyhow!(
            "apparmor profile provided but apparmor not supported"
        ));
    }

    let exec_name = format!("exec {}", profile);

    let mut attr_path = Path::new("/proc/self/attr/apparmor/exec");
    if !attr_path.exists() {
        // Fall back to the old convention
        attr_path = Path::new("/proc/self/attr/exec");
    }

    let mut file = OpenOptions::new().write(true).open(attr_path)?;
    file.write_all(exec_name.as_str().as_bytes())?;

    Ok(())
}
