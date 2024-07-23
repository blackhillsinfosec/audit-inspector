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

use std::{
    fmt,
    process::Command
};
use console::Style;
use lazy_static::lazy_static;
use serde_json::{json, Map, Value};
use regex::Regex;

use crate::eventlog;

lazy_static!{
    static ref ERR_STYLE: console::Style = Style::new().red().bold();
}

/// Possible policies monitored and configured by this tool.
#[derive(Clone)]
pub enum AuditPolicyTypes {
    // SYSTEM
    AuditSecurityStateChange,               // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-state-change
    AuditSecuritySystemExtension,           // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-system-extension
    AuditSystemIntegrity,                   // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-system-integrity
    AuditIpsecDriver,                       // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-ipsec-driver
    AuditOtherSystemEvents,                 // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-system-events
    
    // LOGON/LOGOFF
    AuditLogon,                             // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logon
    AuditLogoff,                            // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logoff
    AuditAccountLockout,                    // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-account-lockout
    AuditIpsecMainMode,                     // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-ipsec-main-mode
    AuditIpsecQuickMode,                    // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-ipsec-quick-mode
    AuditIpsecExtendedMode,                 // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-ipsec-extended-mode
    AuditSpecialLogon,                      // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-special-logon
    AuditOtherLogonLogoffEvents,            // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-logonlogoff-events
    AuditNetworkPolicyServer,               // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-network-policy-server
    AuditUserDeviceClaims,                  // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-user-device-claims
    AuditGroupMembership,                   // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-group-membership
    
    // OBJECT ACCESS
    AuditFileSystem,                        // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-file-system
    AuditRegistry,                          // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-registry
    AuditKernelObject,                      // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-kernel-object
    AuditSam,                               // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-sam
    AuditCertificationServices,             // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services
    AuditApplicationGenerated,              // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-application-generated
    AuditHandleManipulation,                // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-handle-manipulation
    AuditFileShare,                         // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-file-share
    AuditFilteringPlatformPacketDrop,       // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-filtering-platform-packet-drop
    AuditFilteringPlatformConnection,       // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-filtering-platform-connection
    AuditOtherObjectAccessEvents,           // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-object-access-events
    AuditDetailedFileShare,                 // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-detailed-file-share
    AuditRemovableStorage,                  // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-removable-storage
    AuditCentralPolicyStaging,              // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-central-access-policy-staging

    // PRIVILEGE USE
    AuditSensitivePrivilegeUse,             // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-sensitive-privilege-use
    AuditNonSensitivePrivilegeUse,          // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-non-sensitive-privilege-use
    AuditOtherPrivilegeUseEvents,           // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-privilege-use-events

    // DETAILED TRACKING
    AuditProcessCreation,                   // https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing    
    AuditProcessTermination,                // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-process-termination
    AuditDpapiActivity,                     // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-dpapi-activity
    AuditRpcEvents,                         // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-rpc-events
    AuditPlugAndPlayEvents,                 // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-pnp-activity
    AuditTokenRightAdjustedEvents,          // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-token-right-adjusted

    // POLICY CHANGE
    AuditAuditPolicyChange,                 // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-audit-policy-change
    AuditAuthenticationPolicyChange,        // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-authentication-policy-change
    AuditAuthorizationPolicyChange,         // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-authorization-policy-change
    AuditMpssvcRulelevelPolicyChange,       // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-mpssvc-rule-level-policy-change
    AuditFilteringPlatformPolicyChange,     // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-filtering-platform-policy-change
    AuditOtherPolicyChangeEvents,           // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-policy-change-events

    // ACCOUNT MANAGEMENT
    AuditUserAccountManagement,             // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-user-account-management
    AuditComputerAccountManagement,         // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-computer-account-management
    AuditSecurityGroupManagement,           // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management
    AuditDistributionGroupManagement,       // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-distribution-group-management
    AuditApplicationGroupManagement,        // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-application-group-management
    AuditOtherAccountManagementEvents,      // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-account-management-events
    
    // DS ACCESS
    AuditDirectoryServiceAccess,            // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-directory-service-access
    AuditDirectoryServiceChanges,           // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-directory-service-changes
    AuditDirectoryServiceReplication,       // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-directory-service-replication
    AuditDetailedDirectoryServiceReplication,       // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-detailed-directory-service-replication

    // ACCOUNT LOGON
    AuditCredentialValidation,              // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-credential-validation
    AuditKerberosServiceTicketOperation,    // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-kerberos-service-ticket-operations
    AuditOtherAccountLogonEvents,            // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-account-logon-events
    AuditKerberosAuthenticationService,     // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-kerberos-authentication-service
}

impl fmt::Display for AuditPolicyTypes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self{
            // SYSTEM
            AuditPolicyTypes::AuditSecurityStateChange => write!(f, "Security State Change"),
            AuditPolicyTypes::AuditSecuritySystemExtension => write!(f, "Security System Extension"),
            AuditPolicyTypes::AuditSystemIntegrity  => write!(f, "System Integrity"),
            AuditPolicyTypes::AuditIpsecDriver => write!(f, "IPsec Driver"),
            AuditPolicyTypes::AuditOtherSystemEvents => write!(f, "Other System Events"),

            // LOGON/LOGOFF
            AuditPolicyTypes::AuditLogon => write!(f, "Logon"),
            AuditPolicyTypes::AuditLogoff => write!(f, "Logoff"),
            AuditPolicyTypes::AuditAccountLockout => write!(f, "Account Lockout"),
            AuditPolicyTypes::AuditIpsecMainMode => write!(f, "IPsec Main Mode"),
            AuditPolicyTypes::AuditIpsecQuickMode => write!(f, "IPsec Quick Mode"),
            AuditPolicyTypes::AuditIpsecExtendedMode => write!(f, "IPsec Extended Mode"),
            AuditPolicyTypes::AuditSpecialLogon => write!(f, "Special Logon"),
            AuditPolicyTypes::AuditOtherLogonLogoffEvents => write!(f, "Other Logon/Logoff Events"),
            AuditPolicyTypes::AuditNetworkPolicyServer => write!(f, "Network Policy Server"),
            AuditPolicyTypes::AuditUserDeviceClaims => write!(f, "User / Device Claims"),
            AuditPolicyTypes::AuditGroupMembership => write!(f, "Group Membership"),

            // OBJECT ACCESS
            AuditPolicyTypes::AuditFileSystem => write!(f, "File System"),
            AuditPolicyTypes::AuditRegistry => write!(f, "Registry"),
            AuditPolicyTypes::AuditKernelObject => write!(f, "Kernel Object"),
            AuditPolicyTypes::AuditSam => write!(f, "SAM"),
            AuditPolicyTypes::AuditCertificationServices => write!(f, "Certification Services"),
            AuditPolicyTypes::AuditApplicationGenerated => write!(f, "Application Generated"),
            AuditPolicyTypes::AuditHandleManipulation => write!(f, "Handle Manipulation"),
            AuditPolicyTypes::AuditFileShare => write!(f, "File Share"),
            AuditPolicyTypes::AuditFilteringPlatformPacketDrop => write!(f, "Filtering Platform Packet Drop"),
            AuditPolicyTypes::AuditFilteringPlatformConnection => write!(f, "Filtering Platform Connection"),
            AuditPolicyTypes::AuditOtherObjectAccessEvents => write!(f, "Other Object Access Events"),
            AuditPolicyTypes::AuditDetailedFileShare => write!(f, "Detailed File Share"),
            AuditPolicyTypes::AuditRemovableStorage => write!(f, "Removable Storage"),
            AuditPolicyTypes::AuditCentralPolicyStaging => write!(f, "Central Policy Staging"),

            // PRIVILEGE USE
            AuditPolicyTypes::AuditSensitivePrivilegeUse => write!(f, "Sensitive Privilege Use"),
            AuditPolicyTypes::AuditNonSensitivePrivilegeUse => write!(f, "Non Sensitive Privilege Use"),
            AuditPolicyTypes::AuditOtherPrivilegeUseEvents => write!(f, "Other Privilege Use Events"),

            // DETAILED TRACKING
            AuditPolicyTypes::AuditProcessCreation => write!(f, "Process Creation"),
            AuditPolicyTypes::AuditProcessTermination => write!(f, "Process Termination"),
            AuditPolicyTypes::AuditDpapiActivity => write!(f, "DPAPI Activity"),
            AuditPolicyTypes::AuditRpcEvents => write!(f, "RPC Events"),
            AuditPolicyTypes::AuditPlugAndPlayEvents => write!(f, "Plug and Play Events"),
            AuditPolicyTypes::AuditTokenRightAdjustedEvents => write!(f, "Token Right Adjusted Events"),

            // POLICY CHANGE
            AuditPolicyTypes::AuditAuditPolicyChange => write!(f, "Audit Policy Change"),
            AuditPolicyTypes::AuditAuthenticationPolicyChange => write!(f, "Authentication Policy Change"),
            AuditPolicyTypes::AuditAuthorizationPolicyChange => write!(f, "Authorization Policy Change"),
            AuditPolicyTypes::AuditMpssvcRulelevelPolicyChange => write!(f, "MPSSVC Rule-Level Policy Change"),
            AuditPolicyTypes::AuditFilteringPlatformPolicyChange => write!(f, "Filtering Platform Policy Change"),
            AuditPolicyTypes::AuditOtherPolicyChangeEvents => write!(f, "Other Policy Change Events"),

            // ACCOUNT MANAGEMENT
            AuditPolicyTypes::AuditUserAccountManagement => write!(f, "User Account Management"),
            AuditPolicyTypes::AuditComputerAccountManagement => write!(f, "Computer Account Management"),
            AuditPolicyTypes::AuditSecurityGroupManagement => write!(f, "Security Group Management"),
            AuditPolicyTypes::AuditDistributionGroupManagement => write!(f, "Distribution Group Management"),
            AuditPolicyTypes::AuditApplicationGroupManagement => write!(f, "Application Group Management"),
            AuditPolicyTypes::AuditOtherAccountManagementEvents => write!(f, "Other Account Management Events"),

            // DS ACCESS
            AuditPolicyTypes::AuditDirectoryServiceAccess => write!(f, "Directory Service Access"),
            AuditPolicyTypes::AuditDirectoryServiceChanges => write!(f, "Directory Service Changes"),
            AuditPolicyTypes::AuditDirectoryServiceReplication => write!(f, "Directory Service Replication"),
            AuditPolicyTypes::AuditDetailedDirectoryServiceReplication => write!(f, "Detailed Directory Service Replication"),
            
            // ACCOUNTLOGON
            AuditPolicyTypes::AuditCredentialValidation => write!(f, "Credential Validation"),
            AuditPolicyTypes::AuditKerberosServiceTicketOperation => write!(f, "Kerberos Service Ticket Operation"),
            AuditPolicyTypes::AuditOtherAccountLogonEvents => write!(f, "Other Account Logon Events"),
            AuditPolicyTypes::AuditKerberosAuthenticationService => write!(f, "Kerberos Authentication Service"),
        }
    }
}

/// Returns an array of the audit policies that apply to Domain Controllers.
fn gen_dc_policy_list() -> [AuditPolicyTypes; 10] {
    [
        AuditPolicyTypes::AuditCertificationServices,
        AuditPolicyTypes::AuditComputerAccountManagement,
        AuditPolicyTypes::AuditOtherAccountManagementEvents,
        AuditPolicyTypes::AuditDirectoryServiceAccess,
        AuditPolicyTypes::AuditDirectoryServiceChanges,
        AuditPolicyTypes::AuditDirectoryServiceReplication,
        AuditPolicyTypes::AuditDetailedDirectoryServiceReplication,
        AuditPolicyTypes::AuditKerberosAuthenticationService,
        AuditPolicyTypes::AuditOtherAccountLogonEvents,
        AuditPolicyTypes::AuditKerberosServiceTicketOperation,
    ]
}

/// Returns an array of audit policies that apply to all hosts.
fn gen_all_policy_list() -> [AuditPolicyTypes; 49] {
    [
        AuditPolicyTypes::AuditSecurityStateChange,
        AuditPolicyTypes::AuditSecuritySystemExtension,
        AuditPolicyTypes::AuditSystemIntegrity,
        AuditPolicyTypes::AuditIpsecDriver, 
        AuditPolicyTypes::AuditOtherSystemEvents,
        AuditPolicyTypes::AuditLogon,
        AuditPolicyTypes::AuditLogoff,
        AuditPolicyTypes::AuditAccountLockout,
        AuditPolicyTypes::AuditIpsecMainMode,
        AuditPolicyTypes::AuditIpsecQuickMode,
        AuditPolicyTypes::AuditIpsecExtendedMode,
        AuditPolicyTypes::AuditSpecialLogon,
        AuditPolicyTypes::AuditOtherLogonLogoffEvents,
        AuditPolicyTypes::AuditNetworkPolicyServer,
        AuditPolicyTypes::AuditUserDeviceClaims,
        AuditPolicyTypes::AuditGroupMembership,
        AuditPolicyTypes::AuditFileSystem,
        AuditPolicyTypes::AuditRegistry,
        AuditPolicyTypes::AuditKernelObject,
        AuditPolicyTypes::AuditSam,
        AuditPolicyTypes::AuditApplicationGenerated,
        AuditPolicyTypes::AuditHandleManipulation,
        AuditPolicyTypes::AuditFileShare,
        AuditPolicyTypes::AuditFilteringPlatformPacketDrop,
        AuditPolicyTypes::AuditFilteringPlatformConnection,
        AuditPolicyTypes::AuditOtherObjectAccessEvents,
        AuditPolicyTypes::AuditDetailedFileShare,
        AuditPolicyTypes::AuditRemovableStorage,
        AuditPolicyTypes::AuditCentralPolicyStaging,
        AuditPolicyTypes::AuditSensitivePrivilegeUse,
        AuditPolicyTypes::AuditNonSensitivePrivilegeUse,
        AuditPolicyTypes::AuditOtherPrivilegeUseEvents,
        AuditPolicyTypes::AuditProcessCreation,
        AuditPolicyTypes::AuditProcessTermination,
        AuditPolicyTypes::AuditDpapiActivity,
        AuditPolicyTypes::AuditRpcEvents,
        AuditPolicyTypes::AuditPlugAndPlayEvents,
        AuditPolicyTypes::AuditTokenRightAdjustedEvents,
        AuditPolicyTypes::AuditAuditPolicyChange,
        AuditPolicyTypes::AuditAuthenticationPolicyChange,
        AuditPolicyTypes::AuditAuthorizationPolicyChange,
        AuditPolicyTypes::AuditMpssvcRulelevelPolicyChange,
        AuditPolicyTypes::AuditFilteringPlatformPolicyChange,
        AuditPolicyTypes::AuditOtherPolicyChangeEvents,
        AuditPolicyTypes::AuditUserAccountManagement,
        AuditPolicyTypes::AuditSecurityGroupManagement,
        AuditPolicyTypes::AuditDistributionGroupManagement,
        AuditPolicyTypes::AuditApplicationGroupManagement,
        AuditPolicyTypes::AuditCredentialValidation,
    ]
}

/// Returns a Vector of all the applicable defined audit policies.
pub fn get_policies() -> Vec<AuditPolicy>{
    let mut pols:Vec<AuditPolicy> = Vec::new();
    for policy in gen_all_policy_list() {
        pols.push(AuditPolicy::new(policy));
    }
    let is_dc = domain_controllers::is_domain_controller();
    match is_dc {
        Ok(v) => {
            if v {
                for policy in gen_dc_policy_list() {
                    pols.push(AuditPolicy::new(policy))
                }
            }        
        },
        Err(e) => {
            println!("{}", ERR_STYLE.apply_to(format!("An error occurred trying to determine if the local host is a domain controller.\n{}", e)))
        }
    };
    pols
}

/// Returns the output of querying auditpol for the current audit configuration as a String.
pub fn get_current_audit_configurations() -> String {
    let execution = Command::new("auditpol.exe")
        .arg("/get")
        .arg("/category:*")
        .current_dir("C:\\Windows\\System32")
        .output()
        .expect("Unable to execute get command.");
    let out_put:String = String::from_utf8_lossy(&execution.stdout).to_string();
    out_put
}

/// Parses the current configuration audit to compare with the desired policy configuration.
pub fn check_policy_values(current_audit_config:&str, policies_to_compare:&Vec<AuditPolicy>) -> Vec<AuditPolicy> {
    let mut mismatched_policies:Vec<AuditPolicy> = Vec::new();
    for line in current_audit_config.lines() {
        let re = Regex::new(r"\s{2,}").unwrap();
        let parts:Vec<&str> = re.split(line).collect();
        if parts.len() > 2 {
            for pol in policies_to_compare {
                if parts[1] == &pol.policy.to_string() {
                    let mut found_value = 0;
                    if parts[2].contains("Success"){
                        found_value += 1;
                    }
                    if parts[2].contains("Failure"){
                        found_value += 2;
                    }
                    if found_value != pol.value {
                        mismatched_policies.push(pol.clone());
                    }
                }
            }
        }
    }
    mismatched_policies
}

/// Parses the current audit configuration for the policies being tracked and adds them to the supplied logging Map.
pub fn log_current_config(current_audit_config: &str, policies_to_log:&Vec<AuditPolicy>, log_data:&mut Map<String, Value>) {
    for line in current_audit_config.lines() {
        let re = Regex::new(r"\s{2,}").unwrap();
        let parts:Vec<&str> = re.split(line).collect();
        if parts.len() > 2 {
            for pol in policies_to_log {
                if parts[1] == &pol.policy.to_string() {
                    if parts[2].replace("\r", "") != "No Auditing" {
                        log_data.insert(pol.policy.to_string().chars().filter(|&c| !c.is_whitespace() && !(c == '/')).collect(), json!(parts[2].replace("\r","")));
                    }
                }
            }
        }
    }
}

/// Configures the host's audit policy to match the value attribute of the supplied AuditPolicy.  
/// _ = Do Nothing
/// 1 = success  
/// 2 = failure  
/// 3 = success and failure  
pub fn set_policy(policy: &AuditPolicy, event_id: u32){
    let success = match policy.value {
        1 => "enable",
        2 => "disable",
        3 => "enable",
        0 => "disable",
        _ => "do_nothing",
    };
    let failure = match policy.value {
        1 => "disable",
        2 => "enable",
        3 => "enable",
        0 => "disable",
        _ => "do_nothing",
    };
    if success != "do_nothing" && failure != "do_nothing" {
        let execution = Command::new("auditpol.exe")
        .arg("/set")
        .arg(format!("/subcategory:{}", policy.guid))
        .arg(format!("/success:{}", success))
        .arg(format!("/failure:{}", failure))
        .current_dir("C:\\Windows\\System32")
        .output()
        .expect("Unable to execute auditpol set command.");
        if !String::from_utf8_lossy(&execution.stderr).is_empty() {
            println!("An error occurred while setting policy configuration.\n{}", ERR_STYLE.apply_to(format!("{}", String::from_utf8_lossy(&execution.stderr))));
        } else {
            let _ = eventlog::log_config(format!("'{}' audit policy set to '/success:{} /failure:{}'.", policy.policy, success, failure), event_id);
        }
    }
}

/// Represents a Windows Audit Policy
#[derive(Clone)]
pub struct AuditPolicy {
    pub policy: AuditPolicyTypes,
    pub guid: String,
    pub value: std::os::raw::c_int,
}

/// Represents an audit policy and the desired configuration value.  
/// Desired values default to 0 (disabled), and the desired values need adjusted.  
/// It is intended for main to manipulate these desired values based on defaults and what's provided via the command line.  
impl AuditPolicy {
    /// Creates the policy to reflect the proper GUID for the Windows Audit Policy specified.
    pub fn new(policy: AuditPolicyTypes) -> Self {
        match policy {
            // SYSTEM
            AuditPolicyTypes::AuditSecurityStateChange => Self { policy, guid: "{0cce9210-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditSecuritySystemExtension => Self { policy, guid: "{0cce9211-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditSystemIntegrity => Self { policy, guid: "{0cce9212-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditIpsecDriver => Self { policy, guid: "{0cce9213-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditOtherSystemEvents => Self { policy, guid: "{0CCE9214-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            
            // LOGON/LOGOFF
            AuditPolicyTypes::AuditLogon => Self { policy, guid: "{0cce9215-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditLogoff => Self { policy, guid: "{0cce9216-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditAccountLockout => Self { policy, guid: "{0cce9217-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditIpsecMainMode => Self { policy, guid: "{0CCE9218-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditIpsecQuickMode => Self { policy, guid: "{0CCE9219-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditIpsecExtendedMode => Self { policy, guid: "{0CCE921A-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditSpecialLogon => Self { policy, guid: "{0cce921b-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditOtherLogonLogoffEvents => Self { policy, guid: "{0CCE921C-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditNetworkPolicyServer => Self { policy, guid: "{0CCE9243-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditUserDeviceClaims => Self { policy, guid: "{0CCE9247-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditGroupMembership => Self { policy, guid: "{0CCE9249-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },

            // OBJECT ACCESS
            AuditPolicyTypes::AuditFileSystem => Self { policy, guid: "{0CCE921D-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditRegistry => Self { policy, guid: "{0CCE921E-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditKernelObject => Self { policy, guid: "{0CCE921F-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditSam => Self { policy, guid: "{0CCE9220-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditCertificationServices => Self { policy, guid: "{0CCE9221-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditApplicationGenerated => Self { policy, guid: "{0CCE9222-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditHandleManipulation => Self { policy, guid: "{0CCE9223-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditFileShare => Self { policy, guid: "{0CCE9224-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditFilteringPlatformPacketDrop => Self { policy, guid: "{0CCE9225-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditFilteringPlatformConnection => Self { policy, guid: "{0CCE9226-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditOtherObjectAccessEvents => Self { policy, guid: "{0CCE9227-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditDetailedFileShare => Self { policy, guid: "{0CCE9244-69AE-11D9-BED3-505054503030}".to_owned(), value: 0},
            AuditPolicyTypes::AuditRemovableStorage => Self { policy, guid: "{0CCE9245-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditCentralPolicyStaging => Self { policy, guid: "{0CCE9246-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },

            // PRIVILEGE USE
            AuditPolicyTypes::AuditSensitivePrivilegeUse => Self { policy, guid: "{0CCE9228-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditNonSensitivePrivilegeUse => Self { policy, guid: "{0CCE9229-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditOtherPrivilegeUseEvents => Self { policy, guid: "{0CCE922A-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },

            // DETAILED TRACKING
            AuditPolicyTypes::AuditProcessCreation => Self { policy, guid: "{0cce922b-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditProcessTermination => Self { policy, guid: "{0CCE922C-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditDpapiActivity => Self { policy, guid: "{0CCE922D-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditRpcEvents => Self { policy, guid: "{0CCE922E-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditPlugAndPlayEvents => Self { policy, guid: "{0CCE9248-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditTokenRightAdjustedEvents => Self { policy, guid: "{0CCE924A-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },

            // POLICY CHANGE
            AuditPolicyTypes::AuditAuditPolicyChange => Self { policy, guid: "{0cce922f-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditAuthenticationPolicyChange => Self { policy, guid: "{0cce9230-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditAuthorizationPolicyChange => Self { policy, guid: "{0CCE9231-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditMpssvcRulelevelPolicyChange => Self { policy, guid: "{0cce9232-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditFilteringPlatformPolicyChange => Self { policy, guid: "{0CCE9233-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditOtherPolicyChangeEvents => Self { policy, guid: "{0CCE9234-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },

            // ACCOUNT MANAGEMENT
            AuditPolicyTypes::AuditUserAccountManagement => Self { policy, guid: "{0cce9235-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditComputerAccountManagement => Self { policy, guid: "{0cce9236-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditSecurityGroupManagement => Self { policy, guid: "{0cce9237-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditDistributionGroupManagement => Self { policy, guid: "{0CCE9238-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditApplicationGroupManagement => Self { policy, guid: "{0CCE9239-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditOtherAccountManagementEvents => Self { policy, guid: "{0cce923a-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },

            // DS ACCESS
            AuditPolicyTypes::AuditDirectoryServiceAccess => Self { policy, guid: "{0cce923b-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditDirectoryServiceChanges => Self { policy, guid: "{0cce923c-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditDirectoryServiceReplication => Self { policy, guid: "{0CCE923D-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditDetailedDirectoryServiceReplication => Self { policy, guid: "{0CCE923E-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },

            // ACCOUNT LOGON
            AuditPolicyTypes::AuditCredentialValidation => Self { policy, guid: "{0cce923f-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditKerberosServiceTicketOperation => Self { policy, guid: "{0cce9240-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditOtherAccountLogonEvents => Self { policy, guid: "{0CCE9241-69AE-11D9-BED3-505054503030}".to_owned(), value: 0 },
            AuditPolicyTypes::AuditKerberosAuthenticationService => Self { policy, guid: "{0cce9242-69ae-11d9-bed3-505054503030}".to_owned(), value: 0 },
        }
    }
    /// Set the desired value for the audit policy.
    pub fn set_value(&mut self, value: std::os::raw::c_int){
        self.value = value;
    }
}

impl fmt::Display for AuditPolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "policy : {}\nguid   : {}\nvalue  : {}", self.policy, self.guid, self.value.to_string())
    }
}

mod domain_controllers {
    use windows::{core::*, Win32::System::Com::*, Win32::System::Wmi::*};
    /// Returns true if the localhost is a domain controller.
    /// Uses WMI to query the host.
    pub fn is_domain_controller() -> Result<bool> {
        // WMI Template: https://github.com/microsoft/windows-rs/blob/master/crates/samples/windows/wmi/src/main.rs
        unsafe {
            // https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex
            // Initializes the COM library
            CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;

            // https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializesecurity
            CoInitializeSecurity(
                None,                           // pSecDesc
                -1,                             // cAuthSvc
                None,                           // *asAuthSvc
                None,                           // *pReserved1
                RPC_C_AUTHN_LEVEL_DEFAULT,      // dwAuthnLevel     https://learn.microsoft.com/en-us/windows/win32/rpc/authentication-level-constants
                RPC_C_IMP_LEVEL_IMPERSONATE,    // dwImpLevel       https://learn.microsoft.com/en-us/windows/win32/com/com-impersonation-level-constants
                None,                           // *pAuthList
                EOAC_NONE,                      // dwCapabilities   https://learn.microsoft.com/en-us/windows/win32/api/objidlbase/ne-objidlbase-eole_authentication_capabilities
                None,                           // *pReserved3
            )?;

            // https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance
            // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemlocator
            //
            // Creates a WMI interface to interact with Windows Management using the IWbemService
            let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;

            // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemlocator-connectserver
            //
            // Connects to WMI namespace through DCOM and returns a pointer to the IwbemService
            let server =
                locator.ConnectServer(&BSTR::from("root\\cimv2"), None, None, None, 0, None, None)?;

            // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execquery
            let query = server.ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from("select ProductType from Win32_OperatingSystem"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )?;

            let mut row = [None; 1];
            let mut returned = 0;
            // Move the first value inside the IEnumWbemClassObject (query) into row. Status of the move is stored in returned.
            query.Next(WBEM_INFINITE, &mut row, &mut returned).ok()?; // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-next
            let mut value: windows::core::VARIANT = VARIANT::default();

            let mut to_return = false;
            
            if let Some(row) = &row[0] {
                row.Get(w!("ProductType"), 0, &mut value, None, None)?;
                let str_value = value.to_string();
                match str_value == "2" {
                    true => to_return = true,
                    _ => to_return = false
                }
            }
            
            Ok(to_return)
        }
    }
}