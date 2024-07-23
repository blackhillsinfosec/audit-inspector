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

use serde_json::{Map, Value};
use windows_registry::LOCAL_MACHINE;
use windows::{
    core::{
        Result,
        PCSTR
    },
    Win32::System::EventLog::{
        RegisterEventSourceA,
        ReportEventA,
        EVENTLOG_INFORMATION_TYPE
    },
};

/// Utility function that creates the Source in the EventLog Service if it doesn't exist.  
fn ensure_audit_source() -> Result<()>{
    let reg_path = format!(r#"System\\CurrentControlSet\\Services\\EventLog\\Application\\{}"#, env!("CARGO_PKG_NAME"));
    match LOCAL_MACHINE.open(reg_path) {
        Ok(_) => {
            Ok(())
        }
        Err(_) => {
            create_log_source()?;
            Ok(())
        }
    }
}

/// Adds the logs passed to it to the EventViewer using ReportEventA.
/// The created log will use the 'event_id' supplied to this function.
pub fn log_audit(log_map:Map<String,Value>, event_id: u32) -> Result<()>{
    
    ensure_audit_source()?;

    unsafe{
        let heventlog = RegisterEventSourceA(
            None,
            PCSTR::from_raw(format!("{}\0", env!("CARGO_PKG_NAME")).as_ptr() as *const u8)
        )?;
        let log = format!("{}\0", serde_json::to_string(&log_map).expect("Could not parse JSON map."));
        let log_pointer: [PCSTR; 1] = [PCSTR::from_raw(log.as_ptr())];
        ReportEventA(
            heventlog,
            EVENTLOG_INFORMATION_TYPE,
            0,
            event_id,
            None,
            0,
            Some(&log_pointer),
            None
        )?;
        #[cfg(debug_assertions)]
        println!("{}", log.to_string());
    }
    Ok(())
}

/// Function that adds informative single message logs to the EventViewer.  
/// This function is intended to be used to generate logs when this binary modifies a configuration.  
/// The event_id passed to this function is intended to be the same as passed to 'log_audit'.  
/// This function will decrement the value of 'event_id' by one to give it it's own EventID.  
pub fn log_config(message: String, event_id: u32) -> Result<()>{

    ensure_audit_source()?;

    unsafe{
        let heventlog = RegisterEventSourceA(
            None,
            PCSTR::from_raw(format!("{}\0", env!("CARGO_PKG_NAME")).as_ptr() as *const u8)
        )?;
        let log = format!("{}\0", message);
        let log_pointer: [PCSTR; 1] = [PCSTR::from_raw(log.as_ptr())];
        ReportEventA(
            heventlog,
            EVENTLOG_INFORMATION_TYPE,
            0,
            event_id-1,
            None,
            0,
            Some(&log_pointer),
            None
        )?;
        #[cfg(debug_assertions)]
        println!("{}", log.to_string());
    }
    Ok(())
}

/// Function used to create a log source.  
/// The 'EventMessageFile' used does not contain any data useful to the generated logs.  
/// When viewing logs created by this utility in the EventViewer, some errors will be reported by EventViewer because no valid EventMessageFile exists.  
/// The noted errors seen in EventViewer are not persistent and will not appear in a SIEM.  
fn create_log_source() -> Result<()>{
    let reg_path = format!(r#"System\\CurrentControlSet\\Services\\EventLog\\Application\\{}"#, env!("CARGO_PKG_NAME"));
    let key = LOCAL_MACHINE.create(reg_path)?;
    key.set_string("EventMessageFile", r#"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll"#)?;
    key.set_u32("TypesSupported", 7)?;
    Ok(())
}