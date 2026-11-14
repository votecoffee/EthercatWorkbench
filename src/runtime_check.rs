//! Read-only Windows host prerequisites. This module never calls Npcap or owns a NIC.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
};
use windows_sys::Win32::{
    Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW},
    System::{
        LibraryLoader::GetModuleHandleW,
        Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_SUBKEY_WOW6464KEY, RegGetValueW},
        Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
            SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS,
            SERVICE_STATUS_PROCESS,
        },
        SystemInformation::GetSystemDirectoryW,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Available,
    Missing,
    Unavailable,
    Invalid,
    NotQueried,
}

#[derive(Clone, Debug, Serialize)]
pub struct Observation<T> {
    pub state: State,
    pub value: Option<T>,
    pub detail: Option<String>,
    pub os_error: Option<u32>,
}

impl<T> Observation<T> {
    fn available(value: T) -> Self {
        Self {
            state: State::Available,
            value: Some(value),
            detail: None,
            os_error: None,
        }
    }
    fn absent(state: State, detail: impl Into<String>, os_error: Option<u32>) -> Self {
        Self {
            state,
            value: None,
            detail: Some(detail.into()),
            os_error,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PeImage {
    pub machine: u16,
    pub architecture: String,
    pub pe32_plus: bool,
    pub dll: bool,
    pub bytes: u64,
}
impl PeImage {
    fn x64_dll(&self) -> bool {
        self.machine == 0x8664 && self.pe32_plus && self.dll
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Dll {
    pub name: String,
    pub path: Option<PathBuf>,
    pub image: Observation<PeImage>,
    /// Literal four-part Windows file version, not a decoded Npcap release number.
    pub file_version: Observation<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Service {
    pub state_code: u32,
    pub state: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct LoadedModules {
    pub wpcap: bool,
    pub packet: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostStatus {
    MissingPrerequisites,
    IncompatibleImage,
    ObservationUnavailable,
    ServiceNotRunning,
    PresentUnprobed,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub app_version: String,
    pub captured_at_utc: String,
    pub scope: String,
    pub application_architecture: String,
    pub pointer_bits: usize,
    pub system_directory: Observation<PathBuf>,
    pub dlls: Vec<Dll>,
    pub service_name: String,
    pub service: Observation<Service>,
    pub admin_only_registry_path: String,
    pub admin_only: Observation<bool>,
    pub host_status: HostStatus,
    pub capture_access: String,
    pub npcap_modules_before: LoadedModules,
    pub npcap_modules_after: LoadedModules,
    pub notes: Vec<String>,
}

fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain([0]).collect()
}

fn system_directory() -> Observation<PathBuf> {
    let mut buffer = [0u16; 260];
    // SAFETY: writable buffer and its actual element count are provided.
    let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if len == 0 {
        return os_failure(std::io::Error::last_os_error(), &[]);
    }
    if len >= buffer.len() {
        return Observation::absent(
            State::Unavailable,
            "system directory exceeds the supported path buffer",
            None,
        );
    }
    Observation::available(PathBuf::from(std::ffi::OsString::from_wide(&buffer[..len])))
}

fn os_failure<T>(error: std::io::Error, missing_codes: &[u32]) -> Observation<T> {
    let code = error.raw_os_error().map(|v| v as u32);
    let state = if code.is_some_and(|v| missing_codes.contains(&v)) {
        State::Missing
    } else {
        State::Unavailable
    };
    Observation::absent(state, error.to_string(), code)
}

fn read_pe(reader: &mut (impl Read + Seek), bytes: u64) -> Result<PeImage> {
    let mut dos = [0; 64];
    reader.read_exact(&mut dos).context("read DOS header")?;
    ensure!(&dos[..2] == b"MZ", "missing DOS signature");
    let offset = u64::from(u32::from_le_bytes(dos[60..64].try_into().unwrap()));
    ensure!(
        offset >= 64 && offset.checked_add(26).is_some_and(|end| end <= bytes),
        "PE header offset is outside the file"
    );
    reader.seek(SeekFrom::Start(offset))?;
    let mut header = [0; 26];
    reader.read_exact(&mut header).context("read PE header")?;
    ensure!(&header[..4] == b"PE\0\0", "missing PE signature");
    let machine = u16::from_le_bytes(header[4..6].try_into().unwrap());
    let optional_bytes = u64::from(u16::from_le_bytes(header[20..22].try_into().unwrap()));
    ensure!(
        optional_bytes >= 2 && offset + 24 + optional_bytes <= bytes,
        "optional PE header is truncated"
    );
    let magic = u16::from_le_bytes(header[24..26].try_into().unwrap());
    ensure!(
        magic == 0x10b || magic == 0x20b,
        "unknown optional PE header format"
    );
    Ok(PeImage {
        machine,
        architecture: match machine {
            0x8664 => "amd64",
            0x14c => "i386",
            0xaa64 => "arm64",
            _ => "unknown",
        }
        .into(),
        pe32_plus: magic == 0x20b,
        dll: u16::from_le_bytes(header[22..24].try_into().unwrap()) & 0x2000 != 0,
        bytes,
    })
}

fn decode_fixed_version(data: &[u8]) -> Result<String> {
    ensure!(data.len() >= 52, "truncated VS_FIXEDFILEINFO");
    let word = |offset| u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
    ensure!(word(0) == 0xfeef04bd, "invalid fixed version signature");
    let (ms, ls) = (word(8), word(12));
    Ok(format!(
        "{}.{}.{}.{}",
        ms >> 16,
        ms & 0xffff,
        ls >> 16,
        ls & 0xffff
    ))
}

fn image_failure(error: anyhow::Error) -> Observation<PeImage> {
    if let Some(io) = error.downcast_ref::<std::io::Error>()
        && io.kind() != std::io::ErrorKind::UnexpectedEof
    {
        return Observation::absent(
            State::Unavailable,
            format!("{error:#}"),
            io.raw_os_error().map(|v| v as u32),
        );
    }
    Observation::absent(State::Invalid, format!("{error:#}"), None)
}

fn file_version(path: &Path) -> Observation<String> {
    let path = wide(path.as_os_str());
    let mut unused = 0;
    // SAFETY: NUL-terminated path and writable DWORD output. This reads resources, not DLL code.
    let size = unsafe { GetFileVersionInfoSizeW(path.as_ptr(), &mut unused) };
    if size == 0 {
        return os_failure(std::io::Error::last_os_error(), &[2, 3, 1812, 1813]);
    }
    if size > 1024 * 1024 {
        return Observation::absent(State::Invalid, "version resource exceeds 1 MiB", None);
    }
    let mut buffer = vec![0u8; size as usize];
    // SAFETY: path is terminated; the buffer is writable for size bytes.
    if unsafe { GetFileVersionInfoW(path.as_ptr(), 0, size, buffer.as_mut_ptr().cast()) } == 0 {
        return os_failure(std::io::Error::last_os_error(), &[]);
    }
    let mut root = std::ptr::null_mut();
    let mut length = 0;
    // SAFETY: buffer contains the resource returned above and outputs are writable.
    if unsafe {
        VerQueryValueW(
            buffer.as_ptr().cast(),
            windows_sys::core::w!("\\"),
            &mut root,
            &mut length,
        )
    } == 0
    {
        // VerQueryValue does not promise an extended GetLastError value.
        return Observation::absent(
            State::Unavailable,
            "fixed file version block unavailable",
            None,
        );
    }
    let begin = buffer.as_ptr() as usize;
    let address = root as usize;
    if address < begin
        || address
            .checked_add(length as usize)
            .is_none_or(|end| end > begin + buffer.len())
    {
        return Observation::absent(
            State::Invalid,
            "version block lies outside the resource buffer",
            None,
        );
    }
    // SAFETY: the returned slice has just been checked to lie inside the live buffer.
    let bytes = unsafe { std::slice::from_raw_parts(root.cast::<u8>(), length as usize) };
    match decode_fixed_version(bytes) {
        Ok(version) => Observation::available(version),
        Err(error) => Observation::absent(State::Invalid, error.to_string(), None),
    }
}

fn dll(system: &Observation<PathBuf>, name: &str) -> Dll {
    let mut result = Dll {
        name: name.into(),
        path: None,
        image: Observation::absent(State::NotQueried, "system directory unavailable", None),
        file_version: Observation::absent(State::NotQueried, "PE image not available", None),
    };
    let Some(system) = &system.value else {
        return result;
    };
    let path = system.join("Npcap").join(name);
    result.path = Some(path.clone());
    result.image = match File::open(&path) {
        Err(error) => os_failure(error, &[2, 3]),
        Ok(mut file) => match file.metadata() {
            Err(error) => os_failure(error, &[]),
            Ok(meta) if !meta.is_file() => {
                Observation::absent(State::Invalid, "DLL path is not a file", None)
            }
            Ok(meta) => match read_pe(&mut file, meta.len()) {
                Ok(image) => Observation::available(image),
                Err(error) => image_failure(error),
            },
        },
    };
    if result.image.state == State::Available {
        result.file_version = file_version(&path);
    }
    result
}

struct ServiceHandle(SC_HANDLE);
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        // SAFETY: constructed only from a successful open, with single ownership.
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

fn service() -> Observation<Service> {
    // SAFETY: null names select the local SCM; only connect access is requested.
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return os_failure(std::io::Error::last_os_error(), &[]);
    }
    let manager = ServiceHandle(manager);
    // SAFETY: manager is live, name is terminated; only status-query access is requested.
    let handle = unsafe {
        OpenServiceW(
            manager.0,
            windows_sys::core::w!("npcap"),
            SERVICE_QUERY_STATUS,
        )
    };
    if handle.is_null() {
        return os_failure(std::io::Error::last_os_error(), &[1060]);
    }
    let handle = ServiceHandle(handle);
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0;
    // SAFETY: fixed structure buffer is writable and its correct byte size is passed.
    if unsafe {
        QueryServiceStatusEx(
            handle.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            std::mem::size_of_val(&status) as u32,
            &mut needed,
        )
    } == 0
    {
        return os_failure(std::io::Error::last_os_error(), &[]);
    }
    Observation::available(Service {
        state_code: status.dwCurrentState,
        state: match status.dwCurrentState {
            1 => "stopped",
            2 => "start_pending",
            3 => "stop_pending",
            4 => "running",
            5 => "continue_pending",
            6 => "pause_pending",
            7 => "paused",
            _ => "unknown",
        }
        .into(),
    })
}

fn admin_value(value: u32) -> Observation<bool> {
    match value {
        0 | 1 => Observation::available(value == 1),
        _ => Observation::absent(
            State::Invalid,
            format!("AdminOnly DWORD is {value}, expected 0 or 1"),
            None,
        ),
    }
}

fn admin_only() -> Observation<bool> {
    let mut value = 0u32;
    let mut size = 4;
    let mut kind = 0;
    // SAFETY: query-only registry API, fixed local key/value and writable DWORD outputs.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            windows_sys::core::w!("SYSTEM\\CurrentControlSet\\Services\\npcap\\Parameters"),
            windows_sys::core::w!("AdminOnly"),
            RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY,
            &mut kind,
            (&mut value as *mut u32).cast(),
            &mut size,
        )
    };
    if status == 1630 {
        return Observation::absent(State::Invalid, "AdminOnly is not a REG_DWORD", Some(status));
    }
    if status != 0 {
        return os_failure(std::io::Error::from_raw_os_error(status as i32), &[2, 3]);
    }
    if size != 4 {
        return Observation::absent(State::Invalid, "AdminOnly DWORD has an invalid size", None);
    }
    admin_value(value)
}

fn modules() -> LoadedModules {
    // SAFETY: constant terminated names; this looks up existing modules without loading them.
    unsafe {
        LoadedModules {
            wpcap: !GetModuleHandleW(windows_sys::core::w!("wpcap.dll")).is_null(),
            packet: !GetModuleHandleW(windows_sys::core::w!("Packet.dll")).is_null(),
        }
    }
}

fn host_status(
    system: &Observation<PathBuf>,
    dlls: &[Dll],
    service: &Observation<Service>,
) -> HostStatus {
    if service.state == State::Missing || dlls.iter().any(|d| d.image.state == State::Missing) {
        return HostStatus::MissingPrerequisites;
    }
    if dlls.iter().any(|d| {
        d.image.state == State::Invalid || d.image.value.as_ref().is_some_and(|i| !i.x64_dll())
    }) {
        return HostStatus::IncompatibleImage;
    }
    if system.state != State::Available
        || dlls.len() != 2
        || dlls.iter().any(|d| d.image.state != State::Available)
        || service.state != State::Available
    {
        return HostStatus::ObservationUnavailable;
    }
    match service.value.as_ref().map(|s| s.state_code) {
        Some(4) => HostStatus::PresentUnprobed,
        Some(1..=7) => HostStatus::ServiceNotRunning,
        _ => HostStatus::ObservationUnavailable,
    }
}

pub fn collect() -> Report {
    let before = modules();
    let system_directory = system_directory();
    let dlls: Vec<Dll> = [
        dll(&system_directory, "wpcap.dll"),
        dll(&system_directory, "Packet.dll"),
    ]
    .into();
    let service = service();
    let admin_only = admin_only();
    let host_status = host_status(&system_directory, &dlls, &service);
    Report {
        schema: 1, app_version: env!("CARGO_PKG_VERSION").into(),
        captured_at_utc: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        scope: "host_prerequisites_only".into(), application_architecture: std::env::consts::ARCH.into(),
        pointer_bits: usize::BITS as usize, system_directory, dlls, service_name: "npcap".into(), service,
        admin_only_registry_path: r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\npcap\Parameters\AdminOnly".into(),
        admin_only, host_status, capture_access: "not_probed".into(),
        npcap_modules_before: before, npcap_modules_after: modules(),
        notes: vec![
            "Host observations only; no NIC enumeration, adapter open, packet exchange, service control or registry writes.".into(),
            "Present prerequisites do not establish Npcap load/export compatibility, current capture permission, selected-NIC binding or EtherCAT/device acceptance.".into(),
            "AdminOnly is a recorded installer option, not an effective access test. Missing/unreadable values stay unknown; legacy registry locations are not inferred.".into(),
            "File versions are literal Windows resource values, not Npcap release identifiers or signature/authenticity checks.".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn pe(machine: u16, magic: u16, dll: bool) -> Vec<u8> {
        let mut b = vec![0; 128];
        b[..2].copy_from_slice(b"MZ");
        b[60..64].copy_from_slice(&64u32.to_le_bytes());
        b[64..68].copy_from_slice(b"PE\0\0");
        b[68..70].copy_from_slice(&machine.to_le_bytes());
        b[84..86].copy_from_slice(&2u16.to_le_bytes());
        b[86..88].copy_from_slice(&(if dll { 0x2000u16 } else { 0 }).to_le_bytes());
        b[88..90].copy_from_slice(&magic.to_le_bytes());
        b
    }
    #[test]
    fn pe_headers_distinguish_x64_x86_and_non_dll_images() {
        for (machine, magic, dll, compatible) in [
            (0x8664, 0x20b, true, true),
            (0x14c, 0x10b, true, false),
            (0xaa64, 0x20b, true, false),
            (0x8664, 0x10b, true, false),
            (0x8664, 0x20b, false, false),
        ] {
            let bytes = pe(machine, magic, dll);
            assert_eq!(
                read_pe(&mut Cursor::new(&bytes), bytes.len() as u64)
                    .unwrap()
                    .x64_dll(),
                compatible
            );
        }
    }
    #[test]
    fn pe_bounds_signatures_and_optional_headers_are_checked() {
        for fault in 0..5 {
            let mut b = pe(0x8664, 0x20b, true);
            match fault {
                0 => b.truncate(63),
                1 => b[0] = 0,
                2 => b[64] = 0,
                3 => b[60..64].copy_from_slice(&u32::MAX.to_le_bytes()),
                _ => b[84..86].copy_from_slice(&u16::MAX.to_le_bytes()),
            }
            assert!(read_pe(&mut Cursor::new(&b), b.len() as u64).is_err());
        }
    }
    #[test]
    fn fixed_file_versions_remain_literal_and_reject_truncation() {
        let mut b = vec![0; 52];
        b[..4].copy_from_slice(&0xfeef04bdu32.to_le_bytes());
        b[8..12].copy_from_slice(&0x00050001u32.to_le_bytes());
        b[12..16].copy_from_slice(&0x0056007bu32.to_le_bytes());
        assert_eq!(decode_fixed_version(&b).unwrap(), "5.1.86.123");
        assert!(decode_fixed_version(&b[..16]).is_err());
        b[0] = 0;
        assert!(decode_fixed_version(&b).is_err());
    }

    #[test]
    fn unreadable_images_preserve_os_errors_instead_of_claiming_malformed_headers() {
        let denied = image_failure(
            anyhow::Error::from(std::io::Error::from_raw_os_error(5)).context("read DOS header"),
        );
        assert_eq!(
            (denied.state, denied.os_error),
            (State::Unavailable, Some(5))
        );
        let short = image_failure(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        assert_eq!(short.state, State::Invalid);
        let malformed = image_failure(anyhow::anyhow!("missing PE signature"));
        assert_eq!(malformed.state, State::Invalid);
    }
    #[test]
    fn recorded_admin_policy_keeps_unknown_and_invalid_distinct_from_false() {
        assert_eq!(admin_value(0).value, Some(false));
        assert_eq!(admin_value(1).value, Some(true));
        assert_eq!(admin_value(2).state, State::Invalid);
        let denied: Observation<bool> = os_failure(std::io::Error::from_raw_os_error(5), &[2]);
        let missing: Observation<bool> = os_failure(std::io::Error::from_raw_os_error(2), &[2]);
        assert_eq!(
            (denied.state, denied.os_error),
            (State::Unavailable, Some(5))
        );
        assert_eq!(missing.state, State::Missing);
        assert!(missing.value.is_none());
    }
    #[test]
    fn host_status_never_claims_a_capture_access_test() {
        let system = Observation::available(PathBuf::from("fixture"));
        let image = read_pe(&mut Cursor::new(pe(0x8664, 0x20b, true)), 128).unwrap();
        let mut dlls = ["wpcap.dll", "Packet.dll"].map(|name| Dll {
            name: name.into(),
            path: None,
            image: Observation::available(image.clone()),
            file_version: Observation::absent(State::Missing, "no resource", None),
        });
        let mut service = Observation::available(Service {
            state_code: 4,
            state: "running".into(),
        });
        assert_eq!(
            host_status(&system, &dlls, &service),
            HostStatus::PresentUnprobed
        );
        service.value.as_mut().unwrap().state_code = 1;
        assert_eq!(
            host_status(&system, &dlls, &service),
            HostStatus::ServiceNotRunning
        );
        service.value.as_mut().unwrap().state_code = 99;
        assert_eq!(
            host_status(&system, &dlls, &service),
            HostStatus::ObservationUnavailable
        );
        service = Observation::absent(State::Unavailable, "denied", Some(5));
        assert_eq!(
            host_status(&system, &dlls, &service),
            HostStatus::ObservationUnavailable
        );
        dlls[0].image.value.as_mut().unwrap().machine = 0x14c;
        assert_eq!(
            host_status(&system, &dlls, &service),
            HostStatus::IncompatibleImage
        );
        dlls[0].image = Observation::absent(State::Missing, "missing", Some(2));
        assert_eq!(
            host_status(&system, &dlls, &service),
            HostStatus::MissingPrerequisites
        );
    }
}
