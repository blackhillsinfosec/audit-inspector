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

use windows::{
    core::*,
    Win32::{
        Foundation::*,
        System::{
            Com::*,
            TaskScheduler::*,
            SystemServices::{
                SECURITY_BUILTIN_DOMAIN_RID,
                DOMAIN_ALIAS_RID_ADMINS,
                SECURITY_DESCRIPTOR_REVISION,
                SECURITY_LOCAL_SYSTEM_RID,
            },
        },
        Security::{
            Authorization::{
                EXPLICIT_ACCESS_W, 
                SET_ACCESS, 
                TRUSTEE_IS_SID, 
                TRUSTEE_IS_GROUP, 
                SetEntriesInAclW, 
                ConvertSecurityDescriptorToStringSecurityDescriptorW, 
                SDDL_REVISION, 
                TRUSTEE_W,
            },
            SetSecurityDescriptorDacl, 
            AllocateAndInitializeSid, 
            SECURITY_NT_AUTHORITY,
            SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            ACL,
            InitializeSecurityDescriptor,
            SECURITY_DESCRIPTOR,
            PSECURITY_DESCRIPTOR,
            DACL_SECURITY_INFORMATION,
            LABEL_SECURITY_INFORMATION,
            OWNER_SECURITY_INFORMATION,
            SetSecurityDescriptorOwner,
            SetSecurityDescriptorGroup,
        },
    },
};
use std::{
    path::Path,
    ffi::OsString,
    collections::VecDeque,
};

use crate::windows_errors::{self, WindowsError};

static NEW_EXE_PATH: &str = "C:\\Windows\\audit-inspector.exe";
static SCHEDULED_TASK_NAME: &str = "Audit Inspector";
static SCHEDULED_TASK_START_BOUNDARY: &str = "2024-01-01T9:00:00";
static SCHEDULED_TASK_BOOT_DELAY: &str = "PT30S"; // https://learn.microsoft.com/en-us/windows/win32/taskschd/boottrigger-delay

/// Function used to cleanup installation on failure or to uninstall the binary as a scheduled task.
pub fn cleanup_install() -> Result<()> {
    unsafe {
        let task_name: BSTR = BSTR::from(SCHEDULED_TASK_NAME);

        // Initialize COM library
        CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok()?;

        // Create an instance of the Task Scheduler
        let task_service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;

        // Connect to the task scheduler
        task_service.Connect(None, None, None, None)?;

        // Get the root task folder
        let root_folder: ITaskFolder = task_service.GetFolder(&BSTR::from("\\"))?;

        // If GetFolder succeeds, check for child tasks and delete the folder.
        match root_folder.GetFolder(&task_name) {
            Ok(task_folder) => {
                // If GetTask succeeds, delete the task.
                match task_folder.GetTask(&task_name){
                    Ok(_) => {
                        // Delete the Task
                        task_folder.DeleteTask(&task_name, 0)?;
                        #[cfg(debug_assertions)]
                        println!("Cleaned the task '{:#?}'", &task_name);
                    }
                    Err(_) => ()
                }
                // Delete the Task Folder
                root_folder.DeleteFolder(&task_name, 0)?;
                #[cfg(debug_assertions)]
                println!("Cleaned the task folder '{:#?}'", &task_name);
            },
            Err(_) => ()
        };        
    }

    // Check if the binary exists
    let new_exe = Path::new(NEW_EXE_PATH);
    if new_exe.exists() {
        // Delete the binary if it exists.
        match std::fs::remove_file(new_exe) {
            Ok(_) => {
                #[cfg(debug_assertions)]
                println!("Removed the file {}.", NEW_EXE_PATH);
                ()
        },
            Err(e) => {
                let windows_error:WindowsError = windows_errors::get_windows_error()?;
                return Err(Error::new(windows_error.event_code.into(), format!("Could not delete the binary during uninstall.\n{}\n{}", e, windows_error.event_message)));
            }
        }
    } 

    Ok(())
}

/// Function used to install the binary as a scheduled task.  
///   
/// The generated scheduled task has a DACL added for Full Access to Administrators and SYSTEM.  
/// The interval accepted by this function determines whether a DailyTrigger, WeeklyTrigger, or Monthly Trigger is applied to the scheduled task.  
/// The Scheduled Tasks will execute at the time of day specified by the SCHEDULED_TASK_START_BOUNDARY contant.
///   1 = Daily
///   2 = Weekly (Sundays)
///   3 = Monthly (The First Day of the Month)
///   4 = Boot Task Only
///   Any Other Value = Do Nothing
/// In addition, the scheduled task has a boot trigger, meaning the scheduled task will execute upon boot.  
///   
/// This binary copies itself to the Path specified by the NEW_EXE_PATH constant.  
/// The NEW_EXE_PATH constant should always be a location that has a DACL that requires Administrator permissions to modify.
pub fn install_as_a_scheduled_task(interval: std::os::raw::c_int) -> Result<()> {

    // Copy the binary first. If the binary fails to copy, no need to continue.
    current_to_new_exe()?;

    // Construct the command line first in case of error.
    // No need to start constructing a scheduled task if the command line construction errors.
    let command_line_arguments = construct_command_line()?;

    unsafe {
        let task_name: BSTR = BSTR::from(SCHEDULED_TASK_NAME);
        let start_boundary: BSTR = BSTR::from(SCHEDULED_TASK_START_BOUNDARY);

        // Initialize COM library
        CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok()?;

        // Create an instance of the Task Scheduler
        let task_service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;

        // Connect to the task scheduler
        task_service.Connect(None, None, None, None)?;

        // Get the root task folder
        let root_folder: ITaskFolder = task_service.GetFolder(&BSTR::from("\\"))?;

        let task_folder: ITaskFolder = match root_folder.GetFolder(&task_name) {
            Ok(folder) => folder,
            Err(_) => {
                let security_nt_authority = SECURITY_NT_AUTHORITY;
                let mut psid1: PSID = PSID(std::ptr::null_mut());
                AllocateAndInitializeSid(
                    &security_nt_authority,
                    2,
                    u32::try_from(SECURITY_BUILTIN_DOMAIN_RID)?,
                    u32::try_from(DOMAIN_ALIAS_RID_ADMINS)?,
                    0, 0, 0, 0, 0, 0,
                    &mut psid1
                )?;
                let mut trustee1 = TRUSTEE_W::default();
                trustee1.TrusteeForm = TRUSTEE_IS_SID;
                trustee1.TrusteeType = TRUSTEE_IS_GROUP;
                trustee1.ptstrName  = PWSTR(psid1.0 as _);
                let ea1: EXPLICIT_ACCESS_W = EXPLICIT_ACCESS_W {
                    grfAccessPermissions : GENERIC_ALL.0,
                    grfAccessMode : SET_ACCESS,
                    grfInheritance : SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                    Trustee : trustee1
                };
                let mut psid2: PSID = PSID(std::ptr::null_mut());
                AllocateAndInitializeSid(
                    &security_nt_authority,
                    1,
                    u32::try_from(SECURITY_LOCAL_SYSTEM_RID)?,
                    0, 0, 0, 0, 0, 0, 0,
                    &mut psid2
                )?;
                let mut trustee2 = TRUSTEE_W::default();
                trustee2.TrusteeForm = TRUSTEE_IS_SID;
                trustee2.TrusteeType = TRUSTEE_IS_GROUP;
                trustee2.ptstrName  = PWSTR(psid2.0 as _);
                let ea2: EXPLICIT_ACCESS_W = EXPLICIT_ACCESS_W {
                    grfAccessPermissions : GENERIC_ALL.0,
                    grfAccessMode : SET_ACCESS,
                    grfInheritance : SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                    Trustee : trustee2
                };
                let mut acl = std::ptr::null_mut();
                let set_res = SetEntriesInAclW(
                    Some(&[ea2, ea1]),
                    Some(std::ptr::null_mut()),
                    &mut acl
                );
                match set_res {
                    ERROR_SUCCESS => (),
                    _ => {
                        return Err(set_res.into())
                    }
                }
                let mut sd: SECURITY_DESCRIPTOR = SECURITY_DESCRIPTOR::default();
                let psd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(&mut sd as *mut _ as _);
                InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION)?;
                SetSecurityDescriptorDacl(psd, BOOL::from(true), Some(acl as *const ACL), BOOL::from(false))?;
                SetSecurityDescriptorOwner(
                    psd,
                    psid1,
                    BOOL::from(false)
                )?;
                SetSecurityDescriptorGroup(
                    psd,
                    psid1,
                    BOOL::from(false)
                )?;
                let mut buffer = PWSTR::null();
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    psd,
                    SDDL_REVISION,
                    DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                    &mut buffer,
                    None,
                )?;

                let variant_sddl = &VARIANT::from(buffer.to_string()?.as_str());
                let createdfolder: ITaskFolder = root_folder.CreateFolder(&BSTR::from(SCHEDULED_TASK_NAME), variant_sddl)?;
                #[cfg(debug_assertions)]
                println!("Scheduled Task Folder created with SDDL of: {:#?}", buffer.to_string()?);
                createdfolder
            }
        };

        // Create a new task definition
        let task_definition: ITaskDefinition = task_service.NewTask(0)?;

        // Set the registration info for the task
        let registration_info: IRegistrationInfo = task_definition.RegistrationInfo()?;
        registration_info.SetAuthor(&task_name)?;

        // Create the principal for the task
        let principal: IPrincipal = task_definition.Principal()?;
        principal.SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN)?;
        principal.SetRunLevel(TASK_RUNLEVEL_HIGHEST)?;
        principal.SetUserId(&BSTR::from("SYSTEM"))?;//"S-1-15-18"))?;

        // Create the trigger for the task
        let trigger_collection: ITriggerCollection = task_definition.Triggers()?;

        // Boot Triggers
        let trigger: ITrigger = trigger_collection.Create(TASK_TRIGGER_BOOT)?.into();
        let boot_trigger: IBootTrigger = trigger.cast()?;
        boot_trigger.SetStartBoundary(&start_boundary)?;
        let delay: BSTR = BSTR::from(SCHEDULED_TASK_BOOT_DELAY);
        boot_trigger.SetDelay(&delay)?;
        boot_trigger.SetId(&BSTR::from("Boot Trigger"))?;

        match interval {
            // A value of 0 should never trigger this code because main will only trigger install if the flag is 0.
            1 => { 
                let trigger2 = trigger_collection.Create(TASK_TRIGGER_DAILY)?;
                let daily_trigger: IDailyTrigger = trigger2.cast()?;
                daily_trigger.SetDaysInterval(1)?;
                daily_trigger.SetStartBoundary(&start_boundary)?;
                daily_trigger.SetId(&BSTR::from("Daily Trigger"))?;
            }
            2 => {
                // Weekly = Sunday
                let trigger2 = trigger_collection.Create(TASK_TRIGGER_WEEKLY)?;
                let weekly_trigger: IWeeklyTrigger = trigger2.cast()?;
                weekly_trigger.SetWeeksInterval(1)?;
                weekly_trigger.SetDaysOfWeek(1)?;
                weekly_trigger.SetStartBoundary(&start_boundary)?;
                weekly_trigger.SetId(&BSTR::from("Weekly Trigger"))?;
            }
            3 => {
                // Monthly = First day of the month
                let trigger2 = trigger_collection.Create(TASK_TRIGGER_MONTHLY)?;
                let monthly_trigger: IMonthlyTrigger = trigger2.cast()?;
                monthly_trigger.SetDaysOfMonth(1)?;
                monthly_trigger.SetStartBoundary(&start_boundary)?;
                monthly_trigger.SetId(&BSTR::from("Monthly Trigger"))?;
            },
            // From Main, only values 1-4 should be able to make it here.
            // Value 4 will still create a boot task.
            _ => {
                ()
            }
        }

        // Create the action for the task
        let action_collection: IActionCollection = task_definition.Actions()?;
        let action: IAction = action_collection.Create(TASK_ACTION_EXEC)?.into();
        let exec_action: IExecAction = action.cast()?;
        exec_action.SetPath(&BSTR::from(NEW_EXE_PATH))?;
        exec_action.SetArguments(&BSTR::from(command_line_arguments))?;

        // Register the task
        task_folder.RegisterTaskDefinition(
            &task_name,
            &task_definition,
            TASK_CREATE_OR_UPDATE.0,
            None,
            None,
            TASK_LOGON_INTERACTIVE_TOKEN,
            None,
        )?;

        #[cfg(debug_assertions)]
        println!("Scheduled Task '{}' Created!", &task_name);
    }

    Ok(())

}

/// Utility function to copy the current binary to it's location designated by the NEW_EXE_PATH constant.
fn current_to_new_exe() -> Result<()> {
    let current_exe = std::env::current_exe()?;
    let new_exe = Path::new(NEW_EXE_PATH);

    if new_exe.exists() {
        let delete_res = std::fs::remove_file(new_exe);
        match delete_res {
            Ok(_) => (),
            Err(e) => {
                let windows_error:WindowsError = windows_errors::get_windows_error()?;
                return Err(Error::new(windows_error.event_code.into(), format!("Could not overwrite the existing '{}'.\n{}\n{}", NEW_EXE_PATH, e, windows_error.event_message)));
            }
        }
    }

    std::fs::copy(current_exe, new_exe)?;

    Ok(())
}

/// Utility function that constructs the command line that will be attached to the scheduled task.  
/// This function will remove the Install flag, and it's value, before returning the new command line.
fn construct_command_line() -> Result<String> {

    let exe_path_result = std::env::current_exe()?;
    let exe_file_name = exe_path_result.file_name().ok_or("Could not get the current binary name.");
    let exe_file = match exe_file_name {
        Ok(v) => { v.to_string_lossy() },
        Err(e) => { return Err(Error::new(ERROR_INVALID_DATA.into(), e)) }
    };
    // Command line to execute without binary path.
    let mut command_line = "".to_owned();
    let mut command_line_args: VecDeque<OsString> = std::env::args_os().collect::<VecDeque<_>>();
    // Variable used to track when the install flag is detected.
    let mut install_flag_found = false;
    // For each element provided on the command line, convert it into a string and determine if it needs added to the constructed command line.
    loop {
        let curr_arg = command_line_args.pop_front();
        match curr_arg {
            None => break,
            Some(v) => {
                let converted_v = v.into_string();
                match converted_v {
                    Ok(y) => {
                        // Don't include the Install flag in the constructed command line
                        if y.contains("--install") {
                            install_flag_found = true;
                        }
                        // Don't include the Install flag's value in the constructed command line
                        else if install_flag_found {
                            install_flag_found = false;
                        }
                        // Don't include the current exe's path in the constructed command line
                        else if !y.contains(&*exe_file) {
                            command_line += " ";
                            command_line += &y;
                        }
                    }
                    Err(_) => {
                        return Err(Error::new(ERROR_INVALID_DATA.into(), "Could not convert Command Line Argument OsString to String."));
                    }
                }
            }
        }
    }

    Ok(command_line)
}