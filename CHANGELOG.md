# Changelog

## [0.1.0] - 2024-06
### Initial Release 
#### Released with the following auditing policies
- AuditCredentialValidation (Default of Success and Failure)
- AuditKerberosAuthenticationService (Default of Success and Failure, Domain Controller Only)
- AuditKerberosServiceTicketOperation (Default of Success and Failure, Domain Controller Only)
- AuditDirectoryServiceAccess (Default of Failure, Domain Controller Only)
- AuditDirectoryServiceChanges (Default of Success, Domain Controller Only)
- AuditComputerAccountManagement (Default of Success, Domain Controller Only)
- AuditOtherAccountManagementEvents (Default of Success, Domain Controller Only)
- AuditSecurityGroupManagement (Default of Success)
- AuditUserAccountManagement (Default of Success and Failure)
- AuditProcessCreation (Default of Success)
- AuditAccountLockout (Default of Failure)
- AuditLogoff (Default of Success)
- AuditLogon (Default of Success and Failure)
- AuditSpecialLogon (Default of Success)
- AuditAuditPolicyChange (Default of Success)
- AuditAuthenticationPolicyChange (Default of Success)
- AuditMpssvcRulelevelPolicyChange (Default of Success)
- AuditIpsecDriver (Default of Success and Failure)
- AuditSecurityStateChange (Default of Success)
- AuditSecuritySystemExtension (Default of Success)
- AuditSystemIntegrity (Default of Success and Failure)
- AuditDetailedFileShare (Default of Failure)  
#### The following registries are tracked and set to modify audit behaviors.  
- ProcessCreationIncludeCmdLine_Enabled (Default of 1)  
- scenoapplylegacyauditpolicy (Default of 1)  
#### Functionality also includes tracking of:
- Sysmon Service Status
- Sysmon Process
- Sysmon Config

## [0.1.1] - 2024-06-14
### Added Audit Policy
- The audit policy OtherObjectAccessEvents was added (Default of Success and Failure).
- This was added for the benefit of tracking Scheduled Tasks and COM.

## [0.1.2] - 2024-06-17
### Added Audit Behavior - ScriptBlockLogging
- The registry value ScriptBlockLogging was added to be set (Default of 1) and audited.  
- This enables Powershell Script Block Logging.  
- This adds the benefit of being able to track Powershell code execution.

## [0.1.3] - 2024-06-19
### Added Audit Behavior - ScriptBlockInvocationLogging
- The registry value ScriptBlockInvocationLogging was added to be set (Default of 0) and audited.  
- This enables control over Powershell Script Block Invocation Logging.  
### Modified Sysmon Binary Path Identification
- Instead of assuming the paths `C:\Windows\Sysmon.exe`, `C:\Windows\Sysmon64.exe`, and `C:\windows\Sysmon64a.exe`, query the service for its binary path.
- It is unclear if this will help with the Service File Version bug where Windows cannot find the service binary sometimes.
    - Sometimes Windows throws an error that the file cannot be found.
- Allows for the Sysmon Binary path to be logged even if it's not installed where it's expected.
### Improved Windows Errors
- Implemented a function to use the API GetLastError and FormatMessage functions to improve error logging.

## [0.1.4] - 2024-06-25
### Added Powershell Module Logging
- ModuleLogging for Powershell was added to introduce additional Powershell auditing.
- Defaults to:
    - Microsoft.Powershell.*
    - Microsoft.WSMan.Management
    - ActiveDirectory
### Registry Static Values
- Changed registry values into static values.
- Avoids repetition and is cleaner to read.

## [0.1.5] - 2024-07-01
### Implemented the Missing Audit Policies
- Implemented an audit policy configuration for "do nothing".
    - No changes will be made to change the existing policy.
- If a policy is configured to "No Auditing", it is omitted from the log.
    - This is because 59 different policies create an unwieldy log if always generated with that much data.
- Added the following policies:
    - DC
        - AuditCertificationServices (Default: Success and Failure)
        - AuditDirectoryServiceReplication (Default: Do Nothing)
        - AuditDetailedDirectoryServiceReplication (Default: Do Nothing)
        - AuditOtherAccountLogonEvents (Default: Do Nothing)
    - All
        - AuditOtherSystemEvents (Default: Success and Failure)
        - AuditIpsecMainMode (Default: Do Nothing)
        - AuditIpsecQuickMode (Default: Do Nothing)
        - AuditIpsecExtendedMode (Default: Do Nothing)
        - AuditOtherLogonLogoffEvents (Default: Success and Failure)
        - AuditNetworkPolicyServer (Default: Do Nothing)
        - AuditUserDeviceClaims (Default: Do Nothing)
        - AuditGroupMembership (Default: Success)
        - AuditFileSystem (Default: Do Nothing)
        - AuditRegistry (Default: Do Nothing)
        - AuditKernelObject (Default: Do Nothing)
        - AuditSam (Default: Do Nothing)
        - AuditApplicationGenerated (Default: Do Nothing)
        - AuditHandleManipulation (Default: Do Nothing)
        - AuditFileShare (Default: Do Nothing)
        - AuditFilteringPlatformPacketDrop (Default: Do Nothing)
        - AuditFilteringPlatformConnection (Default: Failure)
        - AuditRemovableStorage (Default: Do Nothing)
        - AuditCentralPolicyStaging (Default: Do Nothing)
        - AuditSensitivePrivilegeUse (Default: Do Nothing)
        - AuditNonSensitivePrivlegeUse (Default: Do Nothing)
        - AuditOtherPrivilegeUseEvents (Default: Do Nothing)
        - AuditProcessTermination (Default: Do Nothing)
        - AuditDpapiActivity (Default: Do Nothing)
        - AuditRpcEvents (Default: Do Nothing)
        - AuditPlugAndPlayEvents (Default: Success)
        - AuditAuthorizationPolicyChange (Default: Do Nothing)
        - AuditFilteringPlatformPolicychange (Default: Do Nothing)
        - AuditOtherPolicyChangeEvents (Default: Do Nothing)
        - AuditDistributionGroupManagement (Default: Do Nothing)
        - AuditApplicationGroupManagement (Default: Do Nothing)

## [0.1.6] - 2024-07-10
### Applied GNU GPLv3 License
- Added license information to source files.
- Added LICENSE.txt
- Added README.md

## [0.1.7] - 2024-07-22
### Patch: Improve get_service_path
A new development of Sysmon determining audit inspector as performing process tampering led to "fishing" for what's is the source.  
Several API calls that are commonly associated with process tampering were removed from `get_service_path` in sysmon.rs.  
The code is cleaner and easier to read.  

## [0.1.8] - 2024-08-01
### Improved Error Logging
Instead of including error messages in the data fields for errors were gerenated, errors are now added to an array in the field `error.message`.  
Errors are labeled with the field for which they were generated in `error.message`.  
### Boolean Flags
The following command line items were converted to boolean flags. These items no longer accept an integer value.  
- no_configuration
- uninstall
### Feature Addition: Remove Auditing
A feature for removing audit policies was added.  
This was introduced as a debugging tool.  
This feature is only available with Rust's developer/debugging mode.  

## [0.1.9] - 2024-08-12
### Change default of Audit Directory Service Changes
- Change default configuration to Success and Failure