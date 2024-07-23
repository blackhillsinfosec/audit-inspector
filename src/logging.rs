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

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::{policies::{self, AuditPolicy}, registries, sysmon};

/// Utility function to add all audit-related data to the supplied logging Map.
fn log_audit_configs(mut log_data: Map<String,Value>, current_audit_config: &String, pols: &Vec<AuditPolicy>) -> Map<String, Value> {
    // Log Current Audit Configurations
    let mut audit_policy = Map::new();
    match registries::get_command_line_logging() {
        Ok(v) => {
            audit_policy.insert("ProcessCreationIncludeCmdLine_Enabled".to_string(), json!(v));
        }
        Err(_) => {
            audit_policy.insert("ProcessCreationIncludeCmdLine_Enabled".to_string(), json!("Could not read the registry ProcessCreationIncludeCmdLine_Enabled."));
        }
    }
    match registries::get_no_apply_legacy_audit() {
        Ok(v) => {
            audit_policy.insert("scenoapplylegacyauditpolicy".to_string(), json!(v));
        }
        Err(_) => {
            audit_policy.insert("scenoapplylegacyauditpolicy".to_string(), json!("Could not read the registry scenoapplylegacyauditpolicy."));
        }
    }
    match registries::get_enable_script_block_logging() {
        Ok(v) => {
            audit_policy.insert("EnableScriptBlockLogging".to_string(), json!(v));
        }
        Err(_) => {
            audit_policy.insert("EnableScriptBlockLogging".to_string(), json!("Could not read the registry ScriptBlockLogging."));
        }
    }
    match registries::get_enable_script_block_invocation_logging() {
        Ok(v) => {
            audit_policy.insert("EnableScriptBlockInvocationLogging".to_string(), json!(v));
        }
        Err(_) => {
            audit_policy.insert("EnableScriptBlockInvocationLogging".to_string(), json!("Could not read the registry ScriptBlockInvocationLogging."));
        }
    }
    match registries::get_powershell_module_names() {
        Ok(v) => {
            audit_policy.insert("PowershellLoggingModuleNames".to_string(), json!(v));
        }
        Err(e) => {
            if e.to_string().contains("The system cannot find the file specified."){
                let empty_vec: Vec<String> = Vec::new();
                audit_policy.insert("PowershellLoggingModuleNames".to_string(), json!(empty_vec));
            } else {
                audit_policy.insert("PowershellLoggingModuleNames".to_string(), json!("Could not read the powershell logging module names."));
            }
        }
    }
    policies::log_current_config(&current_audit_config, &pols, &mut audit_policy);
    log_data.insert("audit_policy".to_string(), json!(audit_policy));
    log_data
}

/// Utility function to add all sysmon-related data to the supplied logging Map.
fn log_sysmon_data(mut log_data: Map<String, Value>) -> Map<String, Value> {
    // Service Fields
    let mut service = Map::new();
    let mut file = Map::new();
    match sysmon::test_sysmon_service() {
        Ok(v) => {
            match v.is_empty(){
                true => {
                    service.insert("name".to_string(), json!("No Sysmon binary is installed as a service."));
                }
                false => {
                    service.insert("name".to_string(), json!(&v.replace("\0","")));
                    
                    // Sysmon Status
                    match sysmon::get_service_status(&v) {
                        Ok(v) => { 
                            service.insert("state".to_string(), json!(&v)); 
                            if v.as_str() == "Running" {
                                
                            }
                        },
                        Err(e) => { service.insert("state".to_string(), json!(e.to_string())); }
                    };

                    // Sysmon Version
                    match sysmon::get_sysmon_version() {
                        Ok(v) => { service.insert("version".to_string(), json!(v.to_string())); },
                        Err(e) => { service.insert("version".to_string(), json!(e.to_string())); }
                    }
                    
                    // Sysmon Config
                    let sysmon_config = sysmon::get_sysmon_config(&v);
                    let mut config_file = "";
                    let mut config_hash = "";
                    for line in sysmon_config.lines() {
                        if line.contains("Config file:") {
                            let re = Regex::new(r"\s{2,}").unwrap();
                            let parts:Vec<&str> = re.split(line).collect();
                            config_file = parts[1]
                        }
                        if line.contains("Config hash:"){
                            let re = Regex::new(r"\s{2,}").unwrap();
                            let parts:Vec<&str> = re.split(line).collect();
                            let hash_part: Vec<_> = parts[1].split("=").collect();
                            config_hash = hash_part[1];
                        }
                        if !config_file.is_empty() && !config_hash.is_empty() {
                            break;
                        }
                    }
                    match config_file.is_empty() {
                        true => { 
                            file.insert("path".to_string(), json!("N/A"));
                        },
                        false => {
                            file.insert("path".to_string(), json!(config_file));
                        }
                    }
                    let mut file_hash = Map::new();
                    match config_hash.is_empty() {
                        true => { 
                            file_hash.insert("sha256".to_string(), json!("N/A"));
                            file.insert("hash".to_string(), json!(file_hash));
                        },
                        false => { 
                            file_hash.insert("sha256".to_string(), json!(config_hash)); 
                            file.insert("hash".to_string(), json!(file_hash));
                        }
                    }
                }
            }
        },
        Err(e) => {
            service.insert("name".to_string(), json!(e.to_string()));
        }
    }
    // Process Fields
    let mut process = Map::new();
    match sysmon::test_sysmon_path() {
        Ok(v) => { 
            process.insert("path".to_string(), json!(&v)); 
            let sysmon_hashes = sysmon::get_sysmon_file_hashes(&v);
            match sysmon_hashes {
                Ok(v) => {
                    let mut hash = Map::new();
                    hash.insert("sha256".to_string(), json!(v));
                    process.insert("hash".to_string(), json!(hash));
                }
                Err(e) => {
                    let mut hash = Map::new();
                    hash.insert("sha256".to_string(), json!(e.to_string()));
                    process.insert("hash".to_string(), json!(hash));
                }
            }
        },
        Err(e) => { process.insert("path".to_string(), json!(e.to_string())); }
    }
    log_data.insert("service".to_string(), json!(service));
    log_data.insert("process".to_string(), json!(process));
    if !file.is_empty(){
        log_data.insert("file".to_string(), json!(file));
    }
    log_data
}

/// Utility function that constructs and returns a Map that represents the generated log.
pub fn construct_log(current_audit_config: &String, pols: &Vec<AuditPolicy>, log_id: u32) -> Map<String, Value>{
    let mut log_data = Map::new();

    // Event Data
    let mut event = Map::new();
    event.insert("code".to_string(), json!(log_id));
    event.insert("action".to_string(), json!("audit-inspection"));

    // User Agent Data
    let mut user_agent = Map::new();
    user_agent.insert("name".to_string(), json!("Audit Inspector"));
    user_agent.insert("version".to_string(), json!(env!("CARGO_PKG_VERSION")));

    // Constructing final log
    log_data.insert("event".to_string(), json!(event));
    log_data.insert("user_agent".to_string(), json!(user_agent));
    log_data = log_audit_configs(log_data, &current_audit_config, &pols);
    log_data = log_sysmon_data(log_data);
    log_data
}