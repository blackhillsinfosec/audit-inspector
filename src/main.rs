// Audit-Inspector
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

use policies::{AuditPolicy, AuditPolicyTypes};
mod policies;
use clap::{Parser, ArgAction};
mod registries;
mod sysmon;
mod eventlog;
mod logging;
mod install;
mod windows_errors;
use console::Style;
use lazy_static::lazy_static;
use registries::set_powershell_module_name;
use windows::Win32::{
    Foundation::HANDLE,
    Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY
    },
    System::Threading::{
        GetCurrentProcess, OpenProcessToken
    },
};
#[cfg(debug_assertions)]
use std::time::Instant;

static LONG_DESCRIPTION: &str = "This utility can be used to perform two functions:

1. Configure audit policies to a desired state.
    a. This action is logged to the event viewer.
    b. To disable this function, use the '--no-configuration' flag.
2. Log the configured audit policies to the Event Viewer.

The utility will use the default configuration unless customized on the command line.
If a policy is configured to 'No Auditing', it will be omitted from the log -- only configured policies are logged.
For Audit Policy configurations, the configuration values follow the pattern:
    - 0 = Disable
    - 1 = Success
    - 2 = Failure
    - 3 = Success and Failure
    - 4 = No Configuration Change (\"Do Nothing\")
These command line options begin with 'audit'.

For the registry configuration values, '1' is enabled and '0' is disabled.
These configuration options include 'command-line-logging', 'no-legacy-audit', 'script-block-logging', and 'script-block-invocation-logging'.

Powershell Module Logging can be controlled by listing the Powershell modules to be logged using the powershell-module-logging argument.
The default logging for Powershell Modules is 'Microsoft.Powershell.*', 'Microsoft.WSMan.Management', and 'ActiveDirectory'.
Multiple values passed to the 'powershell_module_logging' argument should be space separated.
If no Powershell Modules are listed to be logged, Powershell Module Logging will be disabled.

The install flag moves this binary to the local host and creates a scheduled task to execute the binary.
The 'install' flag accepts the following values:
  - 0 = No Installation (Default)
  - 1 = Daily
  - 2 = Weekly (Mondays)
  - 3 = Monthly (First of the Month)
The uninstall flag reverses the install action.
Any value but 0 supplied to uninstall will perform the removal.

Audit logs are JSON formatted. Config logs are string messages.

No Event Message File has been generated to match generated logs, so Message File errors will display when reading the logs in the Event Viewer.
Logs can be ingested into a SIEM for tracking changes to auditing and ensuring desired telemetry.";

static EVENT_ID: u32 = 12345;

lazy_static!{
    static ref ERR_STYLE: console::Style = Style::new().red().bold();
    static ref ABOUT: String = format!("\n{}\nThe audit event ID generated by this utility is {}.\nThe config audit event ID generated by this utility is {}.", LONG_DESCRIPTION, EVENT_ID, EVENT_ID+1);
    static ref EXECUTION_HEADER: String = format!("Audit Inspector v{}, Copyright (C) 2024 Kiersten Gross\n\nThis project is licensed under the GNU General Public License v3.0. <https://www.gnu.org/licenses/>.\nThis program comes with ABSOLUTELY NO WARRANTY.\n", env!("CARGO_PKG_VERSION").to_owned());
}

#[derive(Parser)]
#[command(name="Audit Inspector", version, long_about=ABOUT.as_str())]
struct Args {
    // All Hosts
    #[arg(short='a', long, default_value_t = 1)]
    audit_security_state_change: std::os::raw::c_int,
    #[arg(short='b', long, default_value_t = 1)]
    audit_security_system_extension: std::os::raw::c_int,
    #[arg(short='c', long, default_value_t = 3)]
    audit_system_integrity: std::os::raw::c_int,
    #[arg(short='d', long, default_value_t = 3)]
    audit_ipsec_driver: std::os::raw::c_int,
    #[arg(short='e', long, default_value_t = 3)]
    audit_other_system_events: std::os::raw::c_int,
    #[arg(short='f', long, default_value_t = 3)]
    audit_logon: std::os::raw::c_int,
    #[arg(short='g', long, default_value_t = 1)]
    audit_logoff: std::os::raw::c_int,
    #[arg(short='i', long, default_value_t = 2)]
    audit_account_lockout: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_ipsec_main_mode: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_ipsec_quick_mode: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_ipsec_extended_mode: std::os::raw::c_int,
    #[arg(short='j', long, default_value_t = 1)]
    audit_special_logon: std::os::raw::c_int,
    #[arg(short='k', long, default_value_t = 3)]
    audit_other_logon_logoff_events: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_network_policy_server: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_user_device_claims: std::os::raw::c_int,
    #[arg(short='l', long, default_value_t = 1)]
    audit_group_membership: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_file_system: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_registry: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_kernel_object: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_sam: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_application_generated: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_handle_manipulation: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_file_share: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_filtering_platform_packet_drop: std::os::raw::c_int,
    #[arg(short='m', long, default_value_t = 2)]
    audit_filtering_platform_connection: std::os::raw::c_int,
    #[arg(short='n', long, default_value_t = 3)]
    audit_other_object_access_events: std::os::raw::c_int,
    #[arg(short='o', long, default_value_t = 2)]
    audit_detailed_file_share: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_removable_storage: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_central_access_policy_staging: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_sensitive_privilege_use: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_non_sensitive_privilege_use: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_other_privilege_use_events: std::os::raw::c_int,
    #[arg(short='p', long, default_value_t = 1)]
    audit_process_creation: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_process_termination: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_dpapi_activity: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_rpc_activity: std::os::raw::c_int,
    #[arg(short='q', long, default_value_t = 1)]
    audit_plug_and_play_events: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_token_right_adjusted_events: std::os::raw::c_int,
    #[arg(short='r', long, default_value_t = 1)]
    audit_audit_policy_change: std::os::raw::c_int,
    #[arg(short='s', long, default_value_t = 1)]
    audit_authentication_policy_change: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_authorization_policy_change: std::os::raw::c_int,
    #[arg(short='t', long, default_value_t = 1)]
    audit_mpssvc_rulelevel_policy_change: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_filtering_platform_policy_change: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_other_policy_change_events: std::os::raw::c_int,
    #[arg(short='u', long, default_value_t = 3)]
    audit_user_account_management: std::os::raw::c_int,
    #[arg(short='w', long, default_value_t = 1)]
    audit_security_group_management: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_distribution_group_management: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_application_group_management: std::os::raw::c_int,
    #[arg(short='x', long, default_value_t = 3)]
    audit_credential_validation: std::os::raw::c_int,
    
    #[arg(short='y', long, default_value_t = 1)]
    command_line_logging: u32,
    #[arg(short='z', long, default_value_t = 1)]
    no_legacy_audit: u32,
    #[arg(short='A', long, default_value_t = 1)]
    script_block_logging: u32,
    #[arg(short='B', long, default_value_t = 0)]
    script_block_invocation_logging: u32,
    #[arg(short='C', long, num_args(0..), use_value_delimiter=true, value_delimiter=' ', default_value="Microsoft.Powershell.* Microsoft.WSMan.Management ActiveDirectory")]
    powershell_module_logging: Vec<String>,

    // DCs
    #[arg(short='R', long, default_value_t = 3)]
    audit_certification_services: std::os::raw::c_int,
    #[arg(short='S', long, default_value_t = 1)]
    audit_computer_account_management: std::os::raw::c_int,
    #[arg(short='T', long, default_value_t = 1)]
    audit_other_account_management_events: std::os::raw::c_int,
    #[arg(short='U', long, default_value_t = 3)]
    audit_directory_service_access: std::os::raw::c_int,
    #[arg(short='W', long, default_value_t = 1)]
    audit_directory_service_changes: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_directory_service_replication: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_detailed_directory_service_replication: std::os::raw::c_int,
    #[arg(short='X', long, default_value_t = 3)]
    audit_kerberos_service_ticket_operation: std::os::raw::c_int,
    #[arg(long, default_value_t = 4)]
    audit_other_account_logon_events: std::os::raw::c_int,
    #[arg(short='Y', long, default_value_t = 3)]
    audit_kerberos_authentication_service: std::os::raw::c_int,
    
    // Log Only
    #[arg(short='Z', long)]
    no_configuration: bool,
    // Install as a scheduled task
    #[arg(long, default_value_t = 0)]
    install: std::os::raw::c_int,
    #[arg(long)]
    uninstall: bool,
    #[cfg(debug_assertions)]
    #[arg(long)]
    #[cfg(debug_assertions)]
    remove: bool,
}

#[cfg(target_os = "windows")]
fn main() {

    println!("{}", EXECUTION_HEADER.to_string());

    if !check_admin_privileges(){
        println!("{}", ERR_STYLE.apply_to("This program requires administrator privileges."));
        std::process::exit(1);
    }

    #[cfg(debug_assertions)]
    let start = Instant::now();

    let args = Args::parse();

    #[cfg(debug_assertions)]
    if args.remove {
        remove_auditing();
        std::process::exit(0);
    }
    
    if args.install != 0 && args.uninstall {
        println!("{}", ERR_STYLE.apply_to("The 'install' and 'uninstall' flags cannot be used together."));
        std::process::exit(1);
    }
    if args.install > 0 && args.install < 5 {
        match install::install_as_a_scheduled_task(args.install) {
            Ok(_) => (),
            Err(e) => {
                println!("{}", ERR_STYLE.apply_to(format!("Error installing as a scheduled task.\n{}", e)));
                match install::cleanup_install() {
                    Ok(_) => {
                        ()
                    }
                    Err(e) => {
                        println!("{}", ERR_STYLE.apply_to(format!("Error cleaning up after failing to install.\n{}", e)));
                    }
                }
            }
        }
    } else if args.uninstall {
        match install::cleanup_install() {
            Ok(_) => {
                ()
            }
            Err(e) => {
                println!("{}", ERR_STYLE.apply_to(format!("An error occurred removing the scheduled task.\n{}", e)));
            }
        }
    } else {
        let mut pols = policies::get_policies();  
        parse_command_line(&args, &mut pols);
        let mut current_audit_config = policies::get_current_audit_configurations();
        
        // Configure Audit Policies
        if !args.no_configuration {
            let mismatched_policies = policies::check_policy_values(&current_audit_config, &pols);
            if !mismatched_policies.is_empty(){
                for pol in mismatched_policies {
                        policies::set_policy(&pol, EVENT_ID);
                    }
                // If the policies were attempted to be updated, update current config for logging.
                current_audit_config = policies::get_current_audit_configurations();
            }
            configure_registry_related_logging(args);
        }
        let log_data = logging::construct_log(&current_audit_config, &pols, EVENT_ID);
        
        match eventlog::log_audit(log_data, EVENT_ID) {
                Ok(_) => { () },
                Err(e) => { 
                        println!("{}", ERR_STYLE.apply_to(e.to_string()));
                        std::process::exit(1);
                    }
                }
    }
                            
    #[cfg(debug_assertions)]
    let elapsed = start.elapsed();
    #[cfg(debug_assertions)]
    println!("Time taken: {:?}", elapsed);

}

#[cfg(debug_assertions)]
fn remove_auditing() {
    policies::remove_audit_configurations();
    registries::remove_audit_registries();
}

/// Manipulates the policy values to match the desired values pass in via an Args struct.
fn parse_command_line(args:&Args, policies:&mut Vec<AuditPolicy>) {
    for policy in policies{
        match policy.policy {
            AuditPolicyTypes::AuditSecurityStateChange => policy.set_value(args.audit_security_state_change),
            AuditPolicyTypes::AuditSecuritySystemExtension => policy.set_value(args.audit_security_system_extension),
            AuditPolicyTypes::AuditSystemIntegrity  => policy.set_value(args.audit_system_integrity),
            AuditPolicyTypes::AuditIpsecDriver => policy.set_value(args.audit_ipsec_driver),
            AuditPolicyTypes::AuditOtherSystemEvents => policy.set_value(args.audit_other_system_events),
            AuditPolicyTypes::AuditLogon => policy.set_value(args.audit_logon),
            AuditPolicyTypes::AuditLogoff => policy.set_value(args.audit_logoff),
            AuditPolicyTypes::AuditAccountLockout => policy.set_value(args.audit_account_lockout),
            AuditPolicyTypes::AuditIpsecMainMode => policy.set_value(args.audit_ipsec_main_mode),
            AuditPolicyTypes::AuditIpsecQuickMode => policy.set_value(args.audit_ipsec_quick_mode),
            AuditPolicyTypes::AuditIpsecExtendedMode => policy.set_value(args.audit_ipsec_extended_mode),
            AuditPolicyTypes::AuditSpecialLogon => policy.set_value(args.audit_special_logon),
            AuditPolicyTypes::AuditOtherLogonLogoffEvents => policy.set_value(args.audit_other_logon_logoff_events),
            AuditPolicyTypes::AuditNetworkPolicyServer => policy.set_value(args.audit_network_policy_server),
            AuditPolicyTypes::AuditUserDeviceClaims => policy.set_value(args.audit_user_device_claims),
            AuditPolicyTypes::AuditGroupMembership => policy.set_value(args.audit_group_membership),
            AuditPolicyTypes::AuditFileSystem => policy.set_value(args.audit_file_system),
            AuditPolicyTypes::AuditRegistry => policy.set_value(args.audit_registry),
            AuditPolicyTypes::AuditKernelObject => policy.set_value(args.audit_kernel_object),
            AuditPolicyTypes::AuditSam => policy.set_value(args.audit_sam),
            AuditPolicyTypes::AuditCertificationServices => policy.set_value(args.audit_certification_services),
            AuditPolicyTypes::AuditApplicationGenerated => policy.set_value(args.audit_application_generated),
            AuditPolicyTypes::AuditHandleManipulation => policy.set_value(args.audit_handle_manipulation),
            AuditPolicyTypes::AuditFileShare => policy.set_value(args.audit_file_share),
            AuditPolicyTypes::AuditFilteringPlatformPacketDrop => policy.set_value(args.audit_filtering_platform_packet_drop),
            AuditPolicyTypes::AuditFilteringPlatformConnection => policy.set_value(args.audit_filtering_platform_connection),
            AuditPolicyTypes::AuditOtherObjectAccessEvents => policy.set_value(args.audit_other_object_access_events),
            AuditPolicyTypes::AuditDetailedFileShare => policy.set_value(args.audit_detailed_file_share),
            AuditPolicyTypes::AuditRemovableStorage => policy.set_value(args.audit_removable_storage),
            AuditPolicyTypes::AuditCentralPolicyStaging => policy.set_value(args.audit_central_access_policy_staging),
            AuditPolicyTypes::AuditSensitivePrivilegeUse => policy.set_value(args.audit_sensitive_privilege_use),
            AuditPolicyTypes::AuditNonSensitivePrivilegeUse => policy.set_value(args.audit_non_sensitive_privilege_use),
            AuditPolicyTypes::AuditOtherPrivilegeUseEvents => policy.set_value(args.audit_other_privilege_use_events),
            AuditPolicyTypes::AuditProcessCreation => policy.set_value(args.audit_process_creation),
            AuditPolicyTypes::AuditProcessTermination => policy.set_value(args.audit_process_termination),
            AuditPolicyTypes::AuditDpapiActivity => policy.set_value(args.audit_dpapi_activity),
            AuditPolicyTypes::AuditRpcEvents => policy.set_value(args.audit_rpc_activity),
            AuditPolicyTypes::AuditPlugAndPlayEvents => policy.set_value(args.audit_plug_and_play_events),
            AuditPolicyTypes::AuditTokenRightAdjustedEvents => policy.set_value(args.audit_token_right_adjusted_events),
            AuditPolicyTypes::AuditAuditPolicyChange => policy.set_value(args.audit_audit_policy_change),
            AuditPolicyTypes::AuditAuthenticationPolicyChange => policy.set_value(args.audit_authentication_policy_change),
            AuditPolicyTypes::AuditAuthorizationPolicyChange => policy.set_value(args.audit_authorization_policy_change),
            AuditPolicyTypes::AuditMpssvcRulelevelPolicyChange => policy.set_value(args.audit_mpssvc_rulelevel_policy_change),
            AuditPolicyTypes::AuditFilteringPlatformPolicyChange => policy.set_value(args.audit_filtering_platform_policy_change),
            AuditPolicyTypes::AuditOtherPolicyChangeEvents => policy.set_value(args.audit_other_policy_change_events),
            AuditPolicyTypes::AuditUserAccountManagement => policy.set_value(args.audit_user_account_management),
            AuditPolicyTypes::AuditComputerAccountManagement => policy.set_value(args.audit_computer_account_management),
            AuditPolicyTypes::AuditSecurityGroupManagement => policy.set_value(args.audit_security_group_management),
            AuditPolicyTypes::AuditDistributionGroupManagement => policy.set_value(args.audit_distribution_group_management),
            AuditPolicyTypes::AuditApplicationGroupManagement => policy.set_value(args.audit_application_group_management),
            AuditPolicyTypes::AuditOtherAccountManagementEvents => policy.set_value(args.audit_other_account_management_events),
            AuditPolicyTypes::AuditDirectoryServiceAccess => policy.set_value(args.audit_directory_service_access),
            AuditPolicyTypes::AuditDirectoryServiceChanges => policy.set_value(args.audit_directory_service_changes),
            AuditPolicyTypes::AuditDirectoryServiceReplication => policy.set_value(args.audit_directory_service_replication),
            AuditPolicyTypes::AuditDetailedDirectoryServiceReplication => policy.set_value(args.audit_detailed_directory_service_replication),
            AuditPolicyTypes::AuditCredentialValidation => policy.set_value(args.audit_credential_validation),
            AuditPolicyTypes::AuditKerberosServiceTicketOperation => policy.set_value(args.audit_kerberos_service_ticket_operation),
            AuditPolicyTypes::AuditOtherAccountLogonEvents => policy.set_value(args.audit_other_account_logon_events),
            AuditPolicyTypes::AuditKerberosAuthenticationService => policy.set_value(args.audit_kerberos_authentication_service),
        }
    }
}

/// Returns if the current program is being ran with elevated permissions.
fn check_admin_privileges() -> bool {
    unsafe {
        // Get the current process token
        let mut token_handle: HANDLE = HANDLE(0);
        match OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) {
            Ok(_) => (),
            Err(e) => {
                println!("Failed to open process token. {}", e);
                return false;
            }
        }
        // Check if the token has the elevation privilege
        let mut elevation: TOKEN_ELEVATION = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut return_length: u32 = 0;
        match GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        ) {
            Ok(_) => (),
            Err(e) => {
                println!("Failed to get token information. {}", e);
                return false;
            }
        };
        elevation.TokenIsElevated != 0
    }
}

/// Utility function that groups all the registry-related configurations.
fn configure_registry_related_logging(args:Args){
    command_line_logging_(args.command_line_logging);
    no_legacy_audit_(args.no_legacy_audit);
    script_block_logging_(args.script_block_logging);
    // If EnableScriptBlockLogging is disabled, set EnableScriptBlockInvocationLogging to disabled
    if args.script_block_logging == 0 {
        script_block_invocation_logging_(0);
    } else {
        script_block_invocation_logging_(args.script_block_invocation_logging);
    }
    // If modules exist to log, modify the necessary registries.
    let modules: Vec<&String> = args.powershell_module_logging.iter().collect();
    powershell_module_logging_(modules);
}

/// Performs the Command Line Logging registry check and set.
fn command_line_logging_ (desired_command_line_logging: u32){
    match registries::get_command_line_logging() {
        Err(e) => { 
            // If the registry doesn't exist, make it.
            if e.to_string().contains("The system cannot find the file specified."){
                command_line_registry_set(desired_command_line_logging)
            } else {
                println!("{}", ERR_STYLE.apply_to(format!("Could not access the command line logging registry value.\n{}", e))) 
            }
        },
        Ok(v) => {
            if desired_command_line_logging != v {
                command_line_registry_set(desired_command_line_logging)
            }
        }
    };
}

/// Utility function used by command_line_logging_.
fn command_line_registry_set (desired_command_line_logging: u32) {
    match registries::set_command_line_logging(desired_command_line_logging) {
        Err(e) => { println!("{}", ERR_STYLE.apply_to(format!("Could not modify command line logging registry.\n{}", e))) },
        Ok(set_value) => { 
            let _ = eventlog::log_config(format!("'ProcessCreationIncludeCmdLine_Enabled' registry set to {}.", set_value), EVENT_ID);
        }
    }
}

/// Performs the No Legacy Audit registry check and set.
fn no_legacy_audit_ (desired_no_legacy_audit: u32) {
    match registries::get_no_apply_legacy_audit() {
        Err(e) => {
            // If the registry doesn't exist, make it.
            if e.to_string().contains("The system cannot find the file specified.") {
                no_legacy_audit_set(desired_no_legacy_audit)
            } else {
                println!("{}", ERR_STYLE.apply_to(format!("Could not access the no legacy audit registry value.\n{}", e))) 
            }
        },
        Ok(v) => {
            if desired_no_legacy_audit != v {
                no_legacy_audit_set(desired_no_legacy_audit);
            }
        }
    };
}

/// Utility function used by no_legacy_audit_.
fn no_legacy_audit_set (desired_no_legacy_audit: u32) {
    match registries::set_no_apply_legacy_audit(desired_no_legacy_audit) {
        Err(e) => { println!("{}", ERR_STYLE.apply_to(format!("Could not modify no legacy audit registry.\n{}", e))) },
        Ok(set_value) => { 
            let _ = eventlog::log_config(format!("'scenoapplylegacyauditpolicy' registry set to '{}'.", set_value), EVENT_ID);
        }
    }
}

/// Performs the Powershell Block Logging check and set
fn script_block_logging_ (desired_script_block_logging: u32) {
    match registries::get_enable_script_block_logging() {
        Err(e) => {
            // If the registry doesn't exist, make it.
            if e.to_string().contains("The system cannot find the file specified.") {
                script_block_logging_set(desired_script_block_logging)
            } else {
                println!("{}", ERR_STYLE.apply_to(format!("Could not access the enable script block logging registry value.\n{}", e))) 
            }
        } Ok(v) => {
            if desired_script_block_logging != v {
                script_block_logging_set(desired_script_block_logging);
            }
        }
    }
}

/// Utility function used by script_block_logging_.
fn script_block_logging_set (desired_script_block_logging: u32) {
    match registries::set_enable_script_block_logging(desired_script_block_logging){
        Err(e) => { println!("{}", ERR_STYLE.apply_to(format!("Could not modify script block logging registry.\n{}", e))) },
        Ok(set_value) => {
            let _ = eventlog::log_config(format!("'EnableScriptBlockLogging' registry set to '{}'.", set_value), EVENT_ID);
        }
    }
}

/// Performs the Powershell Block Invocation Logging check and set.
fn script_block_invocation_logging_ (desired_script_block_invocation_logging: u32) {
    match registries::get_enable_script_block_invocation_logging() {
        Err(e) => {
            if e.to_string().contains("The system cannot find the file specified.") {
                script_block_invocation_logging_set(desired_script_block_invocation_logging)
            } else {
                println!("{}", ERR_STYLE.apply_to(format!("Could not access the enable script block invocation logging registry value.\n{}", e)))
            }
        } Ok(v) => {
            if desired_script_block_invocation_logging != v {
                script_block_invocation_logging_set(desired_script_block_invocation_logging);
            }
        }
    }
}

/// Utility function used by script_block_invocation_logging_.
fn script_block_invocation_logging_set (desired_script_block_invocation_logging: u32) {
    match registries::set_enable_script_block_invocation_logging(desired_script_block_invocation_logging) {
        Err(e) => { println!("{}", ERR_STYLE.apply_to(format!("Could not modify script block invocation logging registry.\n{}", e))) },
        Ok(set_value) => {
            let _ = eventlog::log_config(format!("'EnableScriptBlockInvoationLogging' registry set to '{}'.", set_value), EVENT_ID);
        }
    }
}

/// Performs the Powershell Module Logging check and set.
fn powershell_module_logging_ (modules: Vec<&String>) {
    match registries::get_powershell_module_logging() {
        Err(e) => {
            if e.to_string().contains("The system cannot find the file specified.") {
                powershell_module_logging_set(modules.clone())
            } else {
                println!("{}", ERR_STYLE.apply_to(format!("Could not access the powershell module logging registry value.\n{}", e)))
            }
        } Ok(v) => {
            if modules.clone().len() > 0 && v == 0 {
                powershell_module_logging_set(modules.clone())
            } else if modules.len() == 0 && v != 0 {
                powershell_module_logging_set(modules.clone())
            }
        }
    }
    powershell_module_check_and_set(modules.clone());
}

/// Utility function used by script_block_invocation_logging_.
fn powershell_module_logging_set (modules: Vec<&String>) {
    match registries::set_powershell_module_logging(modules) {
        Err(e) => { println!("{}", ERR_STYLE.apply_to(format!("Could not modify powershell module logging registry.\n{}", e))) },
        Ok(set_value) => {
            let _ = eventlog::log_config(format!("'EnableModuleLogging' registry set to '{}'.", set_value), EVENT_ID);
        }
    }
}

fn powershell_module_check_and_set (modules: Vec<&String>) {
    if modules.len() > 0 {
        match registries::get_powershell_module_names() {
            Ok(curr_modules) => {
                let mut modules_lower = Vec::new();
                for module in modules.iter() {
                    modules_lower.push(module.to_lowercase());
                }
                let mut curr_modules_lower = Vec::new();
                for curr_module in curr_modules.iter() {
                    curr_modules_lower.push(curr_module.to_lowercase());
                    if !modules_lower.contains(&curr_module.to_lowercase()) {
                        match registries::remove_powershell_module_name(curr_module) {
                            Err(e) => {
                                println!("Could not delete the existing module {}.\n{}", curr_module, e);
                            } Ok(_) => {
                                let _ = eventlog::log_config(format!("'{}' module removed from powershell logging.", curr_module), EVENT_ID);
                            }
                        }
                        
                    }
                }
                for module in modules.iter() {
                    if !curr_modules_lower.contains(&module.to_lowercase()) {
                        match set_powershell_module_name(module) {
                            Ok(_) => {
                                let _ = eventlog::log_config(format!("'{}' module added to powershell logging.", module), EVENT_ID);
                            } Err(e) => {
                                println!("Could not create the Powershell Module registry {}.\n{}", module, e);
                            }
                        }
                    }
                }
            } Err(e) => {
                if e.to_string().contains("The system cannot find the file specified.") {
                    for module in modules.iter() {
                        match set_powershell_module_name(module) {
                            Ok(_) => {
                                let _ = eventlog::log_config(format!("'{}' module added to powershell logging.", module), EVENT_ID);
                            } Err(e) => {
                                println!("Could not create the Powershell Module registry {}.\n{}", module, e);
                            }
                        }
                    }
                } else {
                    println!("Failed to access the currently configured Powershell Module Logging.\n{}", e);
                }
            }
        }
    } else {
        match registries::get_powershell_module_names() {
            Ok(modules) => {
                if modules.len() > 0 {
                    for module in modules.iter() {
                        match registries::get_powershell_module_name(module) {
                            Ok(_) => {
                                match registries::remove_powershell_module_name(module) {
                                    Err(e) => {
                                        println!("Could not delete the existing module {}.\n{}", module, e);
                                    } Ok(_) => {
                                        let _ = eventlog::log_config(format!("'{}' module removed from powershell logging.", module), EVENT_ID);
                                    }
                                }
                            } Err(e) => {
                                if e.to_string().contains("The system cannot find the file specified."){
                                    ()
                                } else {
                                    println!("Could not delete the existing module {}.\n{}", module, e);
                                }
                            }
                        }
                    }
                }
            } Err(e) => {
                if e.to_string().contains("The system cannot find the file specified."){
                    ()
                } else {
                    println!("Failed to access the currently configured Powershell Module Logging.\n{}", e);
                }
            }
        }
    }
}