//! System clipboard access without third-party crates or subprocesses.
//!
//! Windows historically reached the clipboard by shelling out to
//! `powershell.exe` (`Get-Clipboard`/`Set-Clipboard`). That approach is
//! correct but slow: each invocation pays the full .NET/PowerShell startup
//! (measured 1–3 s on typical machines), which makes an interactive paste
//! feel broken. These helpers call the Win32 clipboard API directly through
//! the FFI instead — the same API PowerShell itself wraps — so a paste
//! completes in microseconds.
//!
//! Unix builds keep returning `None`/`false`: bracketed paste already
//! delivers `Event::Paste` there (`main.rs` gates `EnableBracketedPaste`
//! on unix), so no clipboard access is needed.

#[cfg(windows)]
mod imp {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    // Linker-known symbols: no clipboard crate, no extra dependencies.
    #[link(name = "user32")]
    extern "system" {
        fn OpenClipboard(hwnd_new_owner: isize) -> i32;
        fn CloseClipboard() -> i32;
        fn EmptyClipboard() -> i32;
        fn GetClipboardData(format: u32) -> isize;
        fn SetClipboardData(format: u32, data: isize) -> isize;
        fn IsClipboardFormatAvailable(format: u32) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalAlloc(flags: u32, bytes: usize) -> isize;
        fn GlobalLock(handle: isize) -> isize;
        fn GlobalUnlock(handle: isize) -> i32;
        fn GlobalFree(handle: isize) -> isize;
    }

    const CF_UNICODETEXT: u32 = 13;
    const GMEM_MOVEABLE: u32 = 0x0002;

    /// Read the clipboard text. Returns `None` when the clipboard is empty,
    /// locked by another process, or holds a non-text format.
    pub fn read() -> Option<String> {
        unsafe {
            if OpenClipboard(0) == 0 {
                return None;
            }
            let result = (|| {
                if IsClipboardFormatAvailable(CF_UNICODETEXT) == 0 {
                    return None;
                }
                // HGLOBAL from GetClipboardData belongs to the clipboard; do
                // NOT free it, only lock/copy/unlock.
                let handle = GetClipboardData(CF_UNICODETEXT);
                if handle == 0 {
                    return None;
                }
                let ptr = GlobalLock(handle) as *const u16;
                if ptr.is_null() {
                    return None;
                }
                // CF_UNICODETEXT is guaranteed NUL-terminated by the OS.
                let mut len = 0usize;
                while *ptr.add(len) != 0 {
                    len += 1;
                }
                let slice = std::slice::from_raw_parts(ptr, len);
                Some(OsString::from_wide(slice).to_string_lossy().into_owned())
            })();
            CloseClipboard();
            result
        }
    }

    /// Write text to the clipboard, returning success.
    pub fn write(text: &str) -> bool {
        // Trailing NUL is required.
        let mut wide: Vec<u16> = text.encode_utf16().collect();
        wide.push(0);
        unsafe {
            if OpenClipboard(0) == 0 {
                return false;
            }
            let ok = (|| {
                if EmptyClipboard() == 0 {
                    return false;
                }
                let handle = GlobalAlloc(GMEM_MOVEABLE, wide.len() * 2);
                if handle == 0 {
                    return false;
                }
                let ptr = GlobalLock(handle) as *mut u16;
                if ptr.is_null() {
                    GlobalFree(handle);
                    return false;
                }
                std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
                GlobalUnlock(handle);
                // Ownership transfers to the system on success; free only on
                // the failure path.
                if SetClipboardData(CF_UNICODETEXT, handle) == 0 {
                    GlobalFree(handle);
                    return false;
                }
                true
            })();
            CloseClipboard();
            ok
        }
    }
}

#[cfg(windows)]
pub use imp::{read, write};

#[cfg(not(windows))]
mod imp {
    /// Unix needs no clipboard API: bracketed paste delivers `Event::Paste`
    /// and OSC 52 covers copy. Keep the same call sites cross-platform.
    pub fn read() -> Option<String> {
        None
    }
    pub fn write(_text: &str) -> bool {
        false
    }
}

#[cfg(not(windows))]
pub use imp::{read, write};
