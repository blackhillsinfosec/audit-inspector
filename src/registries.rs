// This file is a part of Audit-Inspector
// Copyright (C) 2024 Kiersten Gross

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use windows_registry::{Result, LOCAL_MACHINE};

static PROCESSCREATIONINCLUDECMDLINE_BASE: &str = r#"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit"#;
static PROCESSCREATIONINCLUDECMDLINE_KEY: &str = "ProcessCreationIncludeCmdLine_Enabled";

/// Sets the HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled registry.  
/// Will create the registry if it does not exist.  
///   
/// Accepts any u32 value. However, unless the value provided is 0 (disabled), the registry will be set to 1 (enabled).  
pub fn set_command_line_logging(reg_value: u32) -> Result<u32>{
    let key = LOCAL_MACHINE.create(PROCESSCREATIONINCLUDECMDLINE_BASE)?;
    if reg_value == 0{
        key.set_u32(PROCESSCREATIONINCLUDECMDLINE_KEY, 0)?;
        Ok(0)
    } else {
        key.set_u32(PROCESSCREATIONINCLUDECMDLINE_KEY, 1)?;
        Ok(1)
    }
}

/// Returns the value of the scenoapplyregistryauditpolicy registry.  
/// Will return an error in the Result if the registry does not exist.  
pub fn get_command_line_logging() -> Result<u32> {
    let key = LOCAL_MACHINE.open(PROCESSCREATIONINCLUDECMDLINE_BASE)?;
    let reg_value = key.get_u32(PROCESSCREATIONINCLUDECMDLINE_KEY)?;
    Ok(reg_value)
}

static SCENOAPPLYLEGACYAUDITPOLICY_BASE : &str = r#"SYSTEM\\CurrentControlSet\\Control\\Lsa"#;
static SCENOAPPLYLEGACYAUDITPOLICY_KEY : &str = "scenoapplylegacyauditpolicy";

/// Sets the HKLM:\System\CurrentControlSet\Control\Lsa\scenoapplylegacyauditpolicy registry.  
/// Will create the registry if it does not exist.  
/// [Registry Reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/security-auditing-settings-not-applied-when-deploy-domain-based-policy#resolution-2-disable-the-policy-setting-by-using-registry-editor)  
/// Accepts any u32 value. However, unless the value provided is 0 (disabled), the registry will be set to 1 (enabled).  
pub fn set_no_apply_legacy_audit(reg_value: u32) -> Result<u32>{
    let key = LOCAL_MACHINE.create(SCENOAPPLYLEGACYAUDITPOLICY_BASE)?;
    if reg_value == 0 {
        key.set_u32(SCENOAPPLYLEGACYAUDITPOLICY_KEY, 0)?;
        Ok(0)
    } else {
        key.set_u32(SCENOAPPLYLEGACYAUDITPOLICY_KEY, 1)?;
        Ok(1)
    }
}

/// Returns the value of the scenoapplyregistryauditpolicy registry.  
/// Will return an error in the Result if the registry does not exist.  
pub fn get_no_apply_legacy_audit() -> Result<u32> {
    let key = LOCAL_MACHINE.open(SCENOAPPLYLEGACYAUDITPOLICY_BASE)?;
    let reg_value = key.get_u32(SCENOAPPLYLEGACYAUDITPOLICY_KEY)?;
    Ok(reg_value)
}

static SCRIPTBLOCKLOGGING_BASE: &str = r#"Software\\Policies\\Microsoft\\Windows\\Powershell\\ScriptBlockLogging"#;
static SCRIPTBLOCKLOGGING_KEY: &str = "EnableScriptBlockLogging";

/// Sets the HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging registry.
/// Will create the registry if it does not exist.
/// [Registry Reference](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1#enabling-script-block-logging)  
/// Accepts any u32 value. However, unless the value provided is 0 (disabled), the registry will be set to 1 (enabled).
pub fn set_enable_script_block_logging(reg_value: u32) -> Result<u32> {
    let key = LOCAL_MACHINE.create(SCRIPTBLOCKLOGGING_BASE)?;
    if reg_value == 0 {
        key.set_u32(SCRIPTBLOCKLOGGING_KEY, 0)?;
        Ok(0)
    } else {
        key.set_u32(SCRIPTBLOCKLOGGING_KEY, 1)?;
        Ok(1)
    }
}

/// Returns the value of the scenoapplyregistryauditpolicy registry.  
/// Will return an error in the Result if the registry does not exist.  
pub fn get_enable_script_block_logging() -> Result<u32> {
    let key = LOCAL_MACHINE.open(SCRIPTBLOCKLOGGING_BASE)?;
    let reg_value = key.get_u32(SCRIPTBLOCKLOGGING_KEY)?;
    Ok(reg_value)
}

static SCRIPTBLOCKINVOCATIONLOGGING_BASE: &str = r#"Software\\Policies\\Microsoft\\Windows\\Powershell\\ScriptBlockLogging"#;
static SCRIPTBLOCKINVOCATIONLOGGING_KEY: &str = "EnableScriptBlockInvocationLogging";

/// Sets the HKLM:\Software\Policies\Microsoft\Windows\Powershell\ScritpBlockLogging\EnableScriptBlockInvocationLogging registry.
/// Will create the registry if it does not exist.
/// Accepts any u32 value. However, unless the value provided is 1 (enabled), the registry will be set to 0 (disabled).
pub fn set_enable_script_block_invocation_logging(reg_value: u32) -> Result<u32> {
    let key = LOCAL_MACHINE.create(SCRIPTBLOCKINVOCATIONLOGGING_BASE)?;
    if reg_value == 1 {
        key.set_u32(SCRIPTBLOCKINVOCATIONLOGGING_KEY, 1)?;
        Ok(1)
    } else {
        key.set_u32(SCRIPTBLOCKINVOCATIONLOGGING_KEY, 0)?;
        Ok(0)
    }
}

/// Returns the value of the EnableScriptBlockInvocationLogging registry.
/// Will return an error in the Result if the registry does not exist.
pub fn get_enable_script_block_invocation_logging() -> Result<u32> {
    let key = LOCAL_MACHINE.open(SCRIPTBLOCKINVOCATIONLOGGING_BASE)?;
    let reg_value = key.get_u32(SCRIPTBLOCKINVOCATIONLOGGING_KEY)?;
    Ok(reg_value)
}

static MODULELOGGING_BASE: &str = r#"Software\\Policies\\Microsoft\\Windows\\Powershell\\ModuleLogging"#;
static MODULELOGGING_KEY: &str = "EnableModuleLogging";
static MODULENAMES_BASE: &str = r#"Software\\Policies\\Microsoft\\Windows\\Powershell\\ModuleLogging\\ModuleNames"#;

/// Sets the HKLM:\Software\Policies\Microsoft\Windows\Powershell\ScritpBlockLogging\EnableScriptBlockInvocationLogging registry.
/// Will create the registry if it does not exist.
/// Accepts any u32 value. However, unless the value provided is 1 (enabled), the registry will be set to 0 (disabled).
pub fn set_powershell_module_logging(modules: Vec<&String>) -> Result<u32> {
    let key = LOCAL_MACHINE.create(MODULELOGGING_BASE)?;

    if modules.len() > 0 {
        match get_powershell_module_logging() {
            Ok(module_logging) => {
                if module_logging != 1 {
                    key.set_u32(MODULELOGGING_KEY, 1)?;
                }
            } Err(e) => {
                if e.to_string().contains("The system cannot find the file specified.") {
                    key.set_u32(MODULELOGGING_KEY, 1)?;
                }
            }
        }
        
        Ok(1)
    } else {
        key.set_u32(MODULELOGGING_KEY, 0)?;
        match LOCAL_MACHINE.open(MODULENAMES_BASE) {
            Err(_) => {
                ()
            } Ok (_) => {
                LOCAL_MACHINE.remove_tree(MODULENAMES_BASE)?;
            }
        }
        Ok(0)
    }
}

/// Returns the value of the ModuleLogging registry.
/// Will return an error in the Result if the registry does not exist.
pub fn get_powershell_module_logging() -> Result<u32> {
    let key = LOCAL_MACHINE.open(MODULELOGGING_BASE)?;
    let reg_value = key.get_u32(MODULELOGGING_KEY)?;
    Ok(reg_value)
}

pub fn set_powershell_module_name(module_name: &str) -> Result<()> {
    let key = LOCAL_MACHINE.create(MODULENAMES_BASE)?;
    let module_value = key.set_string(module_name, module_name)?;
    Ok(module_value)
}

pub fn get_powershell_module_name(module_name: &str) -> Result<String> {
    let key = LOCAL_MACHINE.open(MODULENAMES_BASE)?;
    let reg_value = key.get_string(module_name)?;
    Ok(reg_value)
}

pub fn remove_powershell_module_name(module_name: &str) -> Result<()> {
    let key = LOCAL_MACHINE.create(MODULENAMES_BASE)?;
    let delete_value = key.remove_value(module_name)?;
    Ok(delete_value)
}

pub fn get_powershell_module_names() -> Result<Vec<String>> {
    let key = LOCAL_MACHINE.open(MODULENAMES_BASE)?;
    let keys = key.values()?;
    let mut module_names = Vec::new();
    for module_name in keys {
        module_names.push(module_name.0);
    }
    Ok(module_names)
}

#[cfg(debug_assertions)]
pub fn remove_audit_registries() {

    match LOCAL_MACHINE.open(PROCESSCREATIONINCLUDECMDLINE_BASE) {
        Ok(key) => {
            match key.remove_value(PROCESSCREATIONINCLUDECMDLINE_KEY) {
                Ok(_) => {
                    println!("Removed the registries for {}\\{}", PROCESSCREATIONINCLUDECMDLINE_BASE, PROCESSCREATIONINCLUDECMDLINE_KEY)
                } Err(e) => { println!("{}: {}", PROCESSCREATIONINCLUDECMDLINE_KEY, e.to_string()) }
            }
        } Err(_) => { () }
    }

    match LOCAL_MACHINE.open(SCENOAPPLYLEGACYAUDITPOLICY_BASE) {
        Ok(key) => {
            match key.remove_value(SCENOAPPLYLEGACYAUDITPOLICY_KEY){
                Ok(_) => {
                    println!("Removed the registries for {}\\{}", SCENOAPPLYLEGACYAUDITPOLICY_BASE, SCENOAPPLYLEGACYAUDITPOLICY_KEY)
                } Err(e) => { println!("{}: {}", SCENOAPPLYLEGACYAUDITPOLICY_KEY, e.to_string()) }
            };       
        } Err(_) => { () }
    }

    match LOCAL_MACHINE.remove_tree(SCRIPTBLOCKLOGGING_BASE) {
        Ok(_) => {
            println!("Removed the registries for {}", SCRIPTBLOCKLOGGING_BASE)
        } Err(e) => { println!("{}: {}", SCRIPTBLOCKLOGGING_BASE, e.to_string()) }
    };

    match LOCAL_MACHINE.remove_tree(MODULELOGGING_BASE) {
        Ok(_) => {
            println!("Removed the registries for {}", MODULELOGGING_BASE)
        } Err(e) => { println!("{}: {}", MODULELOGGING_BASE, e.to_string()) }
    };

}