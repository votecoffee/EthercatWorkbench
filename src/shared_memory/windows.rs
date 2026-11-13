use super::SIZE;
use anyhow::{Result, ensure};
use std::{io, mem::size_of, ptr};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, FILETIME, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
        LocalFree, SetLastError, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, SECURITY_ATTRIBUTES,
    },
    System::{
        Memory::{
            CreateFileMappingW, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
            PAGE_READWRITE, UnmapViewOfFile,
        },
        Performance::{QueryPerformanceCounter, QueryPerformanceFrequency},
        Threading::{
            CreateMutexW, GetCurrentProcess, GetProcessTimes, ReleaseMutex, WaitForSingleObject,
        },
    },
};
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Security(*mut std::ffi::c_void);
impl Drop for Security {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}
fn exclusive(create: impl FnOnce() -> HANDLE) -> Result<Handle> {
    unsafe {
        SetLastError(0);
    }
    let value = create();
    let code = unsafe { GetLastError() };
    ensure!(
        !value.is_null(),
        "create shared memory object: {}",
        io::Error::from_raw_os_error(code as i32)
    );
    let handle = Handle(value);
    ensure!(
        code != ERROR_ALREADY_EXISTS,
        "Shared memory name already exists; close the other writer/retained reader handles or use another name"
    );
    Ok(handle)
}
pub(super) struct Mapping {
    view: MEMORY_MAPPED_VIEW_ADDRESS,
    _file: Handle,
    lock: Handle,
    pub frequency: u64,
    pub process_created: u64,
}
// Owns its view/handles; transfer before any worker access. Every view copy uses
// the named mutex. Nothing exposes a Rust pointer or reference to a reader.
unsafe impl Send for Mapping {}
impl Mapping {
    pub(super) fn new(prefix: &str) -> Result<Self> {
        let mut sd = ptr::null_mut();
        // Protected DACL: object owner and LocalSystem only. No Everyone/user-group ACE.
        ensure!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide("D:P(A;;GA;;;OW)(A;;GA;;;SY)").as_ptr(),
                    1,
                    &mut sd,
                    ptr::null_mut(),
                )
            } != 0,
            "shared memory security descriptor: {}",
            io::Error::last_os_error()
        );
        let _security = Security(sd);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let lock = exclusive(|| unsafe {
            CreateMutexW(&attributes, 0, wide(&format!("{prefix}.lock")).as_ptr())
        })?;
        let file = exclusive(|| unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                &attributes,
                PAGE_READWRITE,
                0,
                SIZE as u32,
                wide(&format!("{prefix}.data")).as_ptr(),
            )
        })?;
        let mut frequency = 0;
        ensure!(
            unsafe { QueryPerformanceFrequency(&mut frequency) } != 0 && frequency > 0,
            "QPC frequency unavailable"
        );
        let mut created = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        ensure!(
            unsafe {
                GetProcessTimes(
                    GetCurrentProcess(),
                    &mut created,
                    &mut exit,
                    &mut kernel,
                    &mut user,
                )
            } != 0,
            "publisher process creation time: {}",
            io::Error::last_os_error()
        );
        let view = unsafe { MapViewOfFile(file.0, FILE_MAP_WRITE, 0, 0, SIZE) };
        ensure!(
            !view.Value.is_null(),
            "map shared memory: {}",
            io::Error::last_os_error()
        );
        Ok(Self {
            view,
            _file: file,
            lock,
            frequency: frequency as u64,
            process_created: (u64::from(created.dwHighDateTime) << 32)
                | u64::from(created.dwLowDateTime),
        })
    }
    pub(super) fn write(&mut self, encode: impl FnOnce(u64, bool) -> [u8; SIZE]) -> Result<bool> {
        let wait = unsafe { WaitForSingleObject(self.lock.0, 0) };
        if wait == WAIT_TIMEOUT {
            return Ok(false);
        }
        ensure!(
            wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED,
            "shared memory mutex wait failed: {}",
            io::Error::last_os_error()
        );
        struct Guard(HANDLE);
        impl Drop for Guard {
            fn drop(&mut self) {
                unsafe {
                    ReleaseMutex(self.0);
                }
            }
        }
        let guard = Guard(self.lock.0);
        let mut qpc = 0;
        ensure!(
            unsafe { QueryPerformanceCounter(&mut qpc) } != 0 && qpc >= 0,
            "shared memory QPC unavailable"
        );
        let bytes = encode(qpc as u64, wait == WAIT_ABANDONED);
        // View is SIZE bytes, writable and owned by this value. The named mutex
        // protects the whole copy; readers copy into private bytes before release.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), self.view.Value.cast(), SIZE);
        }
        ensure!(
            unsafe { ReleaseMutex(guard.0) } != 0,
            "release shared memory mutex: {}",
            io::Error::last_os_error()
        );
        std::mem::forget(guard);
        Ok(true)
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe {
            UnmapViewOfFile(self.view);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, Ordering::Relaxed},
        thread,
        time::Duration,
    };
    #[test]
    fn exclusive_names_contention_and_abandoned_reader_recovery() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let prefix = format!(
            "Local\\EtherCATWorkbench.rust_test_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Relaxed)
        );
        let mut mapping = Mapping::new(&prefix).unwrap();
        assert!(Mapping::new(&prefix).is_err());
        let handle = mapping.lock.0 as usize;
        let (ready, rx) = std::sync::mpsc::channel();
        let (release, go) = std::sync::mpsc::channel();
        let reader = thread::spawn(move || {
            assert_eq!(
                unsafe { WaitForSingleObject(handle as HANDLE, 0) },
                WAIT_OBJECT_0
            );
            ready.send(()).unwrap();
            go.recv_timeout(Duration::from_secs(2)).unwrap(); /* Deliberately abandon, modelling a crashed reader. */
        });
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            !mapping
                .write(|_, _| panic!("must not encode under contention"))
                .unwrap()
        );
        release.send(()).unwrap();
        reader.join().unwrap();
        assert!(
            mapping
                .write(|_, abandoned| {
                    assert!(abandoned);
                    [0; SIZE]
                })
                .unwrap()
        );
        assert!(
            mapping
                .write(|_, abandoned| {
                    assert!(!abandoned);
                    [7; SIZE]
                })
                .unwrap()
        );
        drop(mapping);
        assert!(Mapping::new(&prefix).is_ok());
    }
}
