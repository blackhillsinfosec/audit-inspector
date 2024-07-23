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

use windows::core::{Result, PWSTR};
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::Foundation::{GetLastError, WIN32_ERROR};

pub struct WindowsError {
    pub event_code: WIN32_ERROR,
    pub event_message: String,
}

pub fn get_windows_error() -> Result<WindowsError> {
    unsafe {
        let message: String;
        let last_error = GetLastError();
        let mut text = PWSTR::null();
        let chars = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            None, last_error.0, 
            0,
            PWSTR(&mut text.0 as *mut _ as *mut _),
            0,None);
        if chars > 0 {
            let parts = std::slice::from_raw_parts(text.0, chars as _);
            message = String::from_utf16(parts)?;
        }
        else{
            message = format!("No such error exists error: {}", last_error.0);
        }

        Ok(WindowsError {
            event_code : last_error,
            event_message: message
        })
    }
}