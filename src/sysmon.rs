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

use std::mem;
use windows::core::{
    Error, Result, PCSTR, PSTR};
use std::path::Path;
use std::fs::File;
use std::io::{Read, BufReader};
use std::process::Command;
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND};
use windows::Win32::Storage::FileSystem::{
    FILE_VER_GET_NEUTRAL,
    GetFileVersionInfoSizeExA,
    GetFileVersionInfoExA,
};
use windows::Win32::System::Services::{
    OpenSCManagerA, 
    SC_MANAGER_ALL_ACCESS, 
    OpenServiceA, 
    SERVICE_QUERY_STATUS,
    SERVICE_QUERY_CONFIG, 
    QueryServiceStatus,
    QueryServiceConfigA,
    QUERY_SERVICE_CONFIGA,
    SERVICE_STATUS,
    SERVICE_CONTINUE_PENDING,
    SERVICE_PAUSE_PENDING,
    SERVICE_PAUSED,
    SERVICE_RUNNING,
    SERVICE_START_PENDING,
    SERVICE_STOP_PENDING,
    SERVICE_STOPPED,
};
use sha2::{Sha256, Digest};
use crate::windows_errors::{self};

/// Returns the name of the service of the installed Sysmon Service.
///   
/// Returns and empty string if Sysmon is not installed.
pub fn test_sysmon_service() -> Result<String>{
    let mut existing_service: &str = "";
    let possible_sysmon_binaries = ["sysmon\0", "sysmon64\0", "sysmon64a\0"];
    for binary in possible_sysmon_binaries {
        let existence = get_service_status(binary);
        match existence {
            Ok(_) => { existing_service = binary; break },
            Err(e) => {
                if e.to_string().contains("Access is denied.") {
                    return Err(Error::new(ERROR_ACCESS_DENIED.into(), "Access is denied."))
                }
            }
        }
    }
    if existing_service.is_empty(){
        return Err(Error::new(ERROR_FILE_NOT_FOUND.into(), "The Sysmon service could not be found."))
    }
    Ok(existing_service.to_string())
}

/// Returns the Sha256 hash of the file provided.
pub fn get_file_hash(file_path: &str) -> Result<String> {
    let path = Path::new(file_path);
    // Open the file
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    // Create a SHA-256 object
    let mut hasher = Sha256::new();

    // Read the file content in chunks and update the hasher
    let mut buffer = [0; 1024];
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    // Get the final hash result and convert it to a hexadecimal string
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

/// Returns the Sha256 hashes of the binary paths provided to the function.  
///   
/// This function expects to receive the output from the test_sysmon_path function.
pub fn get_sysmon_file_hashes(binaries: &Vec<String>) -> Result<Vec<String>> {
    let mut sysmon_hashes = Vec::new();
    for file in binaries {
        let hash = get_file_hash(&file)?;
        sysmon_hashes.push(hash);
    }
    Ok(sysmon_hashes)
}

/// Detects if Sysmon Binaries exist at the default installation paths.
///
/// Returns a Vector of detected Sysmon binaries.
pub fn test_sysmon_path() -> Result<Vec<String>>{
    let sysmon_exists = Path::new("C:\\Windows\\Sysmon.exe").exists();
    let sysmon64_exists = Path::new("C:\\Windows\\Sysmon64.exe").exists();
    let sysmon64a_exists = Path::new("C:\\Windows\\Sysmon64a.exe").exists();
    let service_name = get_service_path(&test_sysmon_service()?)?;
    let mut existing_sysmon = Vec::new();
    if sysmon_exists {
        existing_sysmon.push("C:\\Windows\\Sysmon.exe".to_string());
    }
    if sysmon64_exists {
        existing_sysmon.push("C:\\Windows\\Sysmon64.exe".to_string());
    }
    if sysmon64a_exists {
        existing_sysmon.push("C:\\Windows\\Sysmon64a.exe".to_string());
    }
    // Log the binary if it isn't where it's expected
    if !existing_sysmon.contains(&service_name){
        existing_sysmon.push(service_name);
    }
    Ok(existing_sysmon)
}

/// Returns the current status of installed Sysmon Service.
pub fn get_service_status(sysmon_name: &str) -> Result<String>{
    unsafe{
        let scm_handle = 
            OpenSCManagerA(
                None,
                None,
                SC_MANAGER_ALL_ACCESS,
            )?;
        
        let sysmon_service = 
            OpenServiceA(
                scm_handle, 
                PCSTR::from_raw(sysmon_name.as_ptr() as *const u8), 
                SERVICE_QUERY_STATUS
            )?;

        let mut service_status: SERVICE_STATUS = mem::zeroed();

        QueryServiceStatus(sysmon_service, &mut service_status)?;

        match service_status.dwCurrentState {
            SERVICE_CONTINUE_PENDING => Ok("Continue Pending".to_owned()),
            SERVICE_PAUSE_PENDING => Ok("Pause Pending".to_owned()),
            SERVICE_PAUSED => Ok("Paused".to_owned()),
            SERVICE_RUNNING => Ok("Running".to_owned()),
            SERVICE_START_PENDING => Ok("Start Pending".to_owned()),
            SERVICE_STOP_PENDING => Ok("Stop Pending".to_owned()),
            SERVICE_STOPPED => Ok("Stopped".to_owned()),
            _ => Ok("N/A".to_owned())
        }
    }
}

/// Returns the path to the installed service's binary by using QueryServiceConfigA.
pub fn get_service_path(service_name: &str) -> Result<String> {
    unsafe{
        let scm_handle = 
            OpenSCManagerA(
                None,
                None,
                SC_MANAGER_ALL_ACCESS,
            )?;
        let sysmon_service = 
            OpenServiceA(
                scm_handle, 
                PCSTR::from_raw(service_name.as_ptr() as *const u8), 
                SERVICE_QUERY_CONFIG
            )?;
        let mut bytes_needed = 0;
        let _ = QueryServiceConfigA(
            sysmon_service,
            None,
            0,
            &mut bytes_needed 
        );
        let mut buffer = vec![0u8; bytes_needed as usize];
        let service_config: *mut QUERY_SERVICE_CONFIGA = buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGA;
        QueryServiceConfigA(
            sysmon_service,
            Some(service_config as *mut QUERY_SERVICE_CONFIGA),
            bytes_needed,
            &mut bytes_needed
        )?;
        let bin = PSTR((*service_config).lpBinaryPathName.0).to_string()?;
        Ok(bin)
    }    
}

/// Returns the version of the binary of the installed Sysmon service.
pub fn get_sysmon_version() -> Result<String>{
    unsafe {
        // Return an Error if test_sysmon_service fails
        let service_name = test_sysmon_service()?;
        let service_path = get_service_path(&service_name)?;

        let mut handle:u32 = 0;
        let info_size: u32 = GetFileVersionInfoSizeExA(FILE_VER_GET_NEUTRAL, PCSTR::from_raw(service_path.as_ptr()), &mut handle);

        if info_size == 0 {
            let windows_error: windows_errors::WindowsError = windows_errors::get_windows_error()?;
            return Err(Error::new(windows_error.event_code.into(), windows_error.event_message))
        }

        let mut buffer: Vec<u8> = (0..info_size).map(|_| 0).collect();
        
        GetFileVersionInfoExA(
            FILE_VER_GET_NEUTRAL,
            PCSTR::from_raw(service_path.as_ptr()),
            0,
            info_size,
            buffer.as_mut_ptr() as _
        )?;

        // https://github.com/RedstoneMedia/SussyLauncher/blob/872abd5a047d60b9ffd2da17c9652f80f63beae4/src-tauri/src/config.rs#L99
        let minor = (buffer[47] as u16) << 8 | (buffer[48] as u16);
        let major = (buffer[49] as u16) << 8 | (buffer[50] as u16);
        //let revision = (buffer[51] as u16) << 8 | (buffer[52] as u16);
        //let build = (buffer[53] as u16) << 8 | (buffer[54] as u16);

        Ok(format!("{}.{}", major, minor).to_string())
    }
}

/// Returns the current Sysmon config (returned by the -c flag) as a string.
pub fn get_sysmon_config (sysmon_service_path: &str) -> String {
    let execution = Command::new(sysmon_service_path.replace("\0", ""))
        .arg("-c")
        .current_dir("C:\\Windows\\System32")
        .output()
        .expect("Unable to execute sysmon config query.");
    let out_put:String = String::from_utf8_lossy(&execution.stdout).to_string();
    out_put
}