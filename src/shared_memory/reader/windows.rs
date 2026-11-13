use super::{Observation, ProcessState, Status};
use crate::shared_memory::SIZE;
use anyhow::{Result, ensure};
use std::{io, ptr};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    },
    System::{
        Memory::{
            FILE_MAP_READ, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile, OpenFileMappingW,
            UnmapViewOfFile,
        },
        Performance::{QueryPerformanceCounter, QueryPerformanceFrequency},
        Threading::{GetProcessTimes, OpenMutexW, OpenProcess, ReleaseMutex, WaitForSingleObject},
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
struct View(MEMORY_MAPPED_VIEW_ADDRESS);
impl Drop for View {
    fn drop(&mut self) {
        unsafe {
            UnmapViewOfFile(self.0);
        }
    }
}
struct Guard(HANDLE);
impl Drop for Guard {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
        }
    }
}
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}
fn opened(value: HANDLE, label: &str) -> Result<Handle> {
    ensure!(!value.is_null(), "{label}: {}", io::Error::last_os_error());
    Ok(Handle(value))
}
type Read = (Status, Option<Box<[u8; SIZE]>>, Option<Observation>);
pub(super) fn copy(name: &str) -> Result<Read> {
    let bytes = {
        let prefix = format!("Local\\EtherCATWorkbench.{name}");
        // Open existing objects only. Neither handle inherits and the mapping has no write access.
        let file = opened(
            unsafe { OpenFileMappingW(FILE_MAP_READ, 0, wide(&format!("{prefix}.data")).as_ptr()) },
            "open existing read-only mapping",
        )?;
        let lock = opened(
            unsafe { OpenMutexW(0x00100001, 0, wide(&format!("{prefix}.lock")).as_ptr()) },
            "open existing synchronization mutex",
        )?;
        let mapped = unsafe { MapViewOfFile(file.0, FILE_MAP_READ, 0, 0, SIZE) };
        ensure!(
            !mapped.Value.is_null(),
            "map read-only snapshot: {}",
            io::Error::last_os_error()
        );
        let view = View(mapped);
        let mut bytes = Box::new([0; SIZE]);
        let status = unsafe { WaitForSingleObject(lock.0, 0) };
        if status == WAIT_TIMEOUT {
            return Ok((Status::Busy, None, None));
        }
        ensure!(
            status == WAIT_OBJECT_0 || status == WAIT_ABANDONED,
            "snapshot mutex wait failed: {}",
            io::Error::last_os_error()
        );
        let guard = Guard(lock.0);
        if status != WAIT_ABANDONED {
            // A SIZE-byte read-only view is held under the named mutex; only private bytes escape.
            unsafe {
                ptr::copy_nonoverlapping(view.0.Value.cast::<u8>(), bytes.as_mut_ptr(), SIZE);
            }
        }
        ensure!(
            unsafe { ReleaseMutex(guard.0) } != 0,
            "release reader mutex: {}",
            io::Error::last_os_error()
        );
        std::mem::forget(guard);
        if status == WAIT_ABANDONED {
            return Ok((Status::Abandoned, None, None));
        }
        bytes
    }; // All mapping/mutex handles and the view close before validation, decoding or file output.
    let observation = if let Some(snapshot) = super::parse(bytes.as_slice())? {
        let (process, error) =
            process_state(snapshot.publisher_pid, snapshot.publisher_created_filetime);
        let mut qpc = 0;
        let mut frequency = 0;
        let reader_qpc =
            (unsafe { QueryPerformanceCounter(&mut qpc) } != 0 && qpc >= 0).then_some(qpc as u64);
        let qpc_frequency = (unsafe { QueryPerformanceFrequency(&mut frequency) } != 0
            && frequency > 0)
            .then_some(frequency as u64);
        Some(Observation {
            reader_qpc,
            qpc_frequency,
            process,
            error,
        })
    } else {
        None
    };
    Ok((Status::Ready, Some(bytes), observation))
}
fn process_state(pid: u32, created: u64) -> (ProcessState, Option<String>) {
    // SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, without VM read/write or inherited access.
    let value = unsafe { OpenProcess(0x00101000, 0, pid) };
    if value.is_null() {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            (ProcessState::Exited, None)
        } else {
            (
                ProcessState::Unavailable,
                Some(format!("publisher identity unavailable: {error}")),
            )
        };
    }
    let handle = Handle(value);
    let mut start = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe { GetProcessTimes(handle.0, &mut start, &mut exit, &mut kernel, &mut user) } == 0 {
        return (
            ProcessState::Unavailable,
            Some(format!(
                "publisher creation time unavailable: {}",
                io::Error::last_os_error()
            )),
        );
    }
    if (u64::from(start.dwHighDateTime) << 32) | u64::from(start.dwLowDateTime) != created {
        return (ProcessState::IdentityMismatch, None);
    }
    match unsafe { WaitForSingleObject(handle.0, 0) } {
        WAIT_OBJECT_0 => (ProcessState::Exited, None),
        WAIT_TIMEOUT => (ProcessState::Alive, None),
        _ => (
            ProcessState::Unavailable,
            Some(format!(
                "publisher wait unavailable: {}",
                io::Error::last_os_error()
            )),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared_memory::{Bound, Config, reader::read_once};
    use std::{thread, time::Duration};
    #[test]
    fn reader_reports_not_ready_busy_and_abandoned_without_retaining_handles() {
        let name = format!("native_reader_test_{}", std::process::id());
        let config = Config {
            name: name.clone(),
            ..Default::default()
        };
        let bound = Bound::bind(&config).unwrap();
        let capture = read_once(&name, None).unwrap();
        assert_eq!(capture.inspection.status, Status::NotReady);
        let owned_name = name.clone();
        let (ready, rx) = std::sync::mpsc::channel();
        let (release, go) = std::sync::mpsc::channel();
        let reader = thread::spawn(move || {
            let lock = opened(
                unsafe {
                    OpenMutexW(
                        0x00100001,
                        0,
                        wide(&format!("Local\\EtherCATWorkbench.{owned_name}.lock")).as_ptr(),
                    )
                },
                "test reader",
            )
            .unwrap();
            assert_eq!(unsafe { WaitForSingleObject(lock.0, 0) }, WAIT_OBJECT_0);
            ready.send(()).unwrap();
            go.recv_timeout(Duration::from_secs(2)).unwrap(); /* Exit owning the mutex to model abandonment. */
        });
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            read_once(&name, None).unwrap().inspection.status,
            Status::Busy
        );
        release.send(()).unwrap();
        reader.join().unwrap();
        let abandoned = read_once(&name, None).unwrap();
        assert_eq!(abandoned.inspection.status, Status::Abandoned);
        assert!(
            abandoned.inspection.snapshot.is_none() && abandoned.inspection.raw_sha256.is_none()
        );
        drop(bound);
        assert!(Bound::bind(&config).is_ok());
        assert!(capture.inspection.snapshot.is_none());
    }
}
