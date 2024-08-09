# Audit Inspector

<img src="audit-inspector.png" alt="Audit Inspector" width="200"/>

Audit Inspector is a binary tool written in Rust for Windows audit configuration and auditing.  
This tool is helpful in situations where:
- Audit policies cannot be set via Group Policy, but a remote management tool of some kind is available.
- It is desirable for a SIEM to ingest logging that shows the current audit configurations on a host.  

All configurations performed by this tool are logged to the Event Viewer. This event ID defaults to `12344`.  
Audit policies are logged in JSON format and by default use the event ID `12345`. Logs include details about the Advanced Audit Policies, specific registry-related audit policies, and Sysmon details. Sysmon does not need to be installed on the host to run audit-inspector, and the log will reflect that Sysmon is not installed.

## Build
To build Audit Inspector, the following commands can be used on hosts where Rust is installed.

### Windows
```powershell
cargo build --release
```

## Usage
### Common Options
#### Short Help
```
audit-inspector.exe -h
```
#### Long Help
```
audit-inspector.exe --help
```
#### Default Execution
Performs the default behaviors and applies all the default configurations. The resulting configuration is logged, and any failures to configure logging will be reflected in the generated log.
```
audit-inspector.exe
```
#### Audit-Only
Perform no audit configuration changes and log the current configuration.
```
audit-inspector.exe -Z
```
#### Install Audit Inspector as a Scheduled Task
The binary will copy itself to the location C:\Windows\audit-inspector.exe and create a scheduled task to execute the binary.  
  
```
audit-inspector.exe --install 1
```
Note that when the install flag is included, any other command line values passed to the binary will be included in the scheduled task. The following example shows how you could combine the install and audit-only flags.
```
audit-inspector.exe --install 1 -Z 1
```
### Full Options
When defining non-default behavior, the command line options are numerous.  
- All Advanced Audit Policy configurations begin with `audit` in their long name, and can have the possible values `0` (disabled), `1` (success), `2` (failure), `3` (success and failure), and `4` ("do nothing").  
- The registry-related audit configurations `command_line_logging`, `no_legacy_audit`, `script_block_logging`, 
 and `script_block_logging_invocation_logging`, are binary values and should only have `0` or `1` provided to them, although `audit-inspector` will default the value to `1` if the value provided is not `0`.  
- The registry-related audit configuration `powershell_module_logging` should be a space-separated list for the Powershell Modules that are desired to be logged.
- The install flag will always create a boot scheduled task. The valid values are `1` (Daily), `2` (Weekly), `3` (Monthly), or `4` (Boot Task Only). Any other values will result in the install behavior being disabled with `0` (default).
```
Usage: audit-inspector.exe [OPTIONS]

Options:
  -a, --audit-security-state-change <AUDIT_SECURITY_STATE_CHANGE>                                    [default: 1]
  -b, --audit-security-system-extension <AUDIT_SECURITY_SYSTEM_EXTENSION>                            [default: 1]
  -c, --audit-system-integrity <AUDIT_SYSTEM_INTEGRITY>                                              [default: 3]
  -d, --audit-ipsec-driver <AUDIT_IPSEC_DRIVER>                                                      [default: 3]
  -e, --audit-other-system-events <AUDIT_OTHER_SYSTEM_EVENTS>                                        [default: 3]
  -f, --audit-logon <AUDIT_LOGON>                                                                    [default: 3]
  -g, --audit-logoff <AUDIT_LOGOFF>                                                                  [default: 1]
  -i, --audit-account-lockout <AUDIT_ACCOUNT_LOCKOUT>                                                [default: 2]
      --audit-ipsec-main-mode <AUDIT_IPSEC_MAIN_MODE>                                                [default: 4]
      --audit-ipsec-quick-mode <AUDIT_IPSEC_QUICK_MODE>                                              [default: 4]
      --audit-ipsec-extended-mode <AUDIT_IPSEC_EXTENDED_MODE>                                        [default: 4]
  -j, --audit-special-logon <AUDIT_SPECIAL_LOGON>                                                    [default: 1]
  -k, --audit-other-logon-logoff-events <AUDIT_OTHER_LOGON_LOGOFF_EVENTS>                            [default: 3]
      --audit-network-policy-server <AUDIT_NETWORK_POLICY_SERVER>                                    [default: 4]
      --audit-user-device-claims <AUDIT_USER_DEVICE_CLAIMS>                                          [default: 4]
  -l, --audit-group-membership <AUDIT_GROUP_MEMBERSHIP>                                              [default: 1]
      --audit-file-system <AUDIT_FILE_SYSTEM>                                                        [default: 4]
      --audit-registry <AUDIT_REGISTRY>                                                              [default: 4]
      --audit-kernel-object <AUDIT_KERNEL_OBJECT>                                                    [default: 4]
      --audit-sam <AUDIT_SAM>                                                                        [default: 4]
      --audit-application-generated <AUDIT_APPLICATION_GENERATED>                                    [default: 4]
      --audit-handle-manipulation <AUDIT_HANDLE_MANIPULATION>                                        [default: 4]
      --audit-file-share <AUDIT_FILE_SHARE>                                                          [default: 4]
      --audit-filtering-platform-packet-drop <AUDIT_FILTERING_PLATFORM_PACKET_DROP>                  [default: 4]
  -m, --audit-filtering-platform-connection <AUDIT_FILTERING_PLATFORM_CONNECTION>                    [default: 2]
  -n, --audit-other-object-access-events <AUDIT_OTHER_OBJECT_ACCESS_EVENTS>                          [default: 3]
      --audit-removable-storage <AUDIT_REMOVABLE_STORAGE>                                            [default: 4]
      --audit-central-access-policy-staging <AUDIT_CENTRAL_ACCESS_POLICY_STAGING>                    [default: 4]
      --audit-sensitive-privilege-use <AUDIT_SENSITIVE_PRIVILEGE_USE>                                [default: 4]
      --audit-non-sensitive-privilege-use <AUDIT_NON_SENSITIVE_PRIVILEGE_USE>                        [default: 4]
      --audit-other-privilege-use-events <AUDIT_OTHER_PRIVILEGE_USE_EVENTS>                          [default: 4]
  -p, --audit-process-creation <AUDIT_PROCESS_CREATION>                                              [default: 1]
      --audit-process-termination <AUDIT_PROCESS_TERMINATION>                                        [default: 4]
      --audit-dpapi-activity <AUDIT_DPAPI_ACTIVITY>                                                  [default: 4]
      --audit-rpc-activity <AUDIT_RPC_ACTIVITY>                                                      [default: 4]
  -q, --audit-plug-and-play-events <AUDIT_PLUG_AND_PLAY_EVENTS>                                      [default: 1]
      --audit-token-right-adjusted-events <AUDIT_TOKEN_RIGHT_ADJUSTED_EVENTS>                        [default: 4]
  -r, --audit-audit-policy-change <AUDIT_AUDIT_POLICY_CHANGE>                                        [default: 1]
  -s, --audit-authentication-policy-change <AUDIT_AUTHENTICATION_POLICY_CHANGE>                      [default: 1]
      --audit-authorization-policy-change <AUDIT_AUTHORIZATION_POLICY_CHANGE>                        [default: 4]
  -t, --audit-mpssvc-rulelevel-policy-change <AUDIT_MPSSVC_RULELEVEL_POLICY_CHANGE>                  [default: 1]
      --audit-filtering-platform-policy-change <AUDIT_FILTERING_PLATFORM_POLICY_CHANGE>              [default: 4]
      --audit-other-policy-change-events <AUDIT_OTHER_POLICY_CHANGE_EVENTS>                          [default: 4]
  -u, --audit-user-account-management <AUDIT_USER_ACCOUNT_MANAGEMENT>                                [default: 3]
  -w, --audit-security-group-management <AUDIT_SECURITY_GROUP_MANAGEMENT>                            [default: 1]
      --audit-distribution-group-management <AUDIT_DISTRIBUTION_GROUP_MANAGEMENT>                    [default: 4]
      --audit-application-group-management <AUDIT_APPLICATION_GROUP_MANAGEMENT>                      [default: 4]
  -x, --audit-credential-validation <AUDIT_CREDENTIAL_VALIDATION>                                    [default: 3]
  -y, --command-line-logging <COMMAND_LINE_LOGGING>                                                  [default: 1]
  -z, --no-legacy-audit <NO_LEGACY_AUDIT>                                                            [default: 1]
  -A, --script-block-logging <SCRIPT_BLOCK_LOGGING>                                                  [default: 1]
  -B, --script-block-invocation-logging <SCRIPT_BLOCK_INVOCATION_LOGGING>                            [default: 0]
  -C, --powershell-module-logging [<POWERSHELL_MODULE_LOGGING>...]                                   [default: "Microsoft.Powershell.* Microsoft.WSMan.Management ActiveDirectory"]
  -R, --audit-certification-services <AUDIT_CERTIFICATION_SERVICES>                                  [default: 3]
  -S, --audit-computer-account-management <AUDIT_COMPUTER_ACCOUNT_MANAGEMENT>                        [default: 1]
  -T, --audit-other-account-management-events <AUDIT_OTHER_ACCOUNT_MANAGEMENT_EVENTS>                [default: 1]
  -U, --audit-directory-service-access <AUDIT_DIRECTORY_SERVICE_ACCESS>                              [default: 2]
  -W, --audit-directory-service-changes <AUDIT_DIRECTORY_SERVICE_CHANGES>                            [default: 1]
      --audit-directory-service-replication <AUDIT_DIRECTORY_SERVICE_REPLICATION>                    [default: 4]
      --audit-detailed-directory-service-replication <AUDIT_DETAILED_DIRECTORY_SERVICE_REPLICATION>  [default: 4]
  -X, --audit-kerberos-service-ticket-operation <AUDIT_KERBEROS_SERVICE_TICKET_OPERATION>            [default: 3]
      --audit-other-account-logon-events <AUDIT_OTHER_ACCOUNT_LOGON_EVENTS>                          [default: 4]
  -Y, --audit-kerberos-authentication-service <AUDIT_KERBEROS_AUTHENTICATION_SERVICE>                [default: 3]
  -Z, --no-configuration
      --install <INSTALL>                                                                            [default: 0]
      --uninstall
  -h, --help                                                                                         Print help (see more with '--help')
  -V, --version                                                                                      Print version
```
## Defaults
The default configurations made by this tool are as follows:  
### All Hosts
| Configuration Type | Name | Configuration | Event ID | Category |
| --- | --- | --- | --- | --- |
| Advanced Audit Policy | Security State Change | Success | 4608 and 4616 and 4621 | Security |
| Advanced Audit Policy | Security System Extension | Success | 4610 and 4611 and 4614 and 4622 and 4697 | Security |
| Advanced Audit Policy | System Integrity | Success and Failure | 4612 and 4615 and 4618 and 4816 and 5038 and 5056 and 5062 and 5057 and 5060 and 5061 and 6281 and 6410 | Security |
| Advanced Audit Policy | IpSec Driver | Success and Failure | 4960 and 4961 and 4962 and 4963 and 4965 and 5479 and 5479 and 5480 and 5483 and 5484 and 5485 | Security |
| Advanced Audit Policy | Other System Events | Success and Failure | 5024 and 5025 and 5027 and 5028 and 5029 and 5030 and 5032 and 5033 and 5034 and 5035 and 5037 and 5058 and 5059 and 6400 and 6401 and 6402 and 6403 and 6404 and 6405 and 6406 and 6407 and 6408 and 6409 | Security |
| Advanced Audit Policy | Logon | Success and Failure | 4624 and 4625 and 4648 and 4675 | Security |
| Advanced Audit Policy | Logoff | Success | 4634 and 4647 | Security |
| Advanced Audit Policy | Account Lockout | Failure | 4625 | Security |
| Advanced Audit Policy | Special Logon | Success | 4694 and 4672 | Security |
| Advanced Audit Policy | Other Logon/Logoff Events | Success and Failure | 4649 and 4778 and 4779 and 4800 and 4801 and 4802 and 4803 and 5378 and 5632 and 5633 | Security |
| Advanced Audit Policy | Group Memebership | Success | | |
| Advanced Audit Policy | Filtering Platform Connection | Failure | | |
| Advanced Audit Policy | Other Object Access Events | Success and Failure | | |
| Advanced Audit Policy | Process Creation | Success | | |
| Advanced Audit Policy | Plug and Play Events | Success | | |
| Advanced Audit Policy | Audit Policy Change | Success | | |
| Advanced Audit Policy | Authentication Policy Change | Success | | |
| Advanced Audit Policy | MPSSVC Rule-Level Policy Change | Success | | |
| Advanced Audit Policy | User Account Management | Success and Failure | | |
| Advanced Audit Policy | Security Group Management | Success | | |
| Advanced Audit Policy | Credential Validation | Success and Failure | | |

| Configuration Type | Name | Configuration |
| --- | --- | --- |
| Registry | HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\\ProcessCreationIncludeCmdLine_Enabled | 1 |
| Registry | HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\scenoapplylegacyauditpolicy | 1 |
| Registry | HKLM\\Software\\Policies\\Microsoft\\Windows\\Powershell\\ScriptBlockLogging\\EnableScriptBlockLogging | 1 |
| Registry | HKLM\\Software\\Policies\\Microsoft\\Windows\\Powershell\\ScriptBlockLogging\\EnableScriptBlockInvocationLogging | 0 |
| Registry | HKLM\\Software\\Policies\\Microsoft\\Windows\\Powershell\\ModuleLogging\\EnableModuleLogging | 1 |
| Registry | HKLM\\Software\\Policies\\Microsoft\\Windows\\Powershell\\ModuleLogging\\ModuleNames\\\* | Microsoft.Powershell.\* Microsoft.WSMan.Management ActiveDirectory |
### Domain Controllers
| Configuration Type | Name | Configuration |
| --- | --- | --- |
| Advanced Audit Policy | Certification Services | Sucess and Failure |
| Advanced Audit Policy | Computer Account Management | Sucess |
| Advanced Audit Policy | Other Account Management Events | Sucess |
| Advanced Audit Policy | Directory Service Access | Failure |
| Advanced Audit Policy | Directory Service Changes | Sucess |
| Advanced Audit Policy | Kerberos Service Ticket Operation | Sucess and Failure |
| Advanced Audit Policy | Kerberos Authentication Service | Sucess and Failure |
## Domain Controller Functionality
This tool can determine through WMI if the host on which it is running is a domain controller or not.  
Because of this, the tool will only apply the Domain Controller (DC) audit policies when it detects the host is a DC.
## Acknowledgements
Shout out to all the members of the Black Hills InfoSec (BHIS) SOC that have shared their knowledge and expertise.  
Special thanks to Nick Caswell, Jordan Drysdale, and Kent Ickler for their research in the BHIS SOC that was foundational for this tool.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Contributors
- Kiersten Gross
- Ashwin Balasubramanya

## License
[GPLv3](https://www.gnu.org/licenses/)
