# Windows Npcap host check

Run this before selecting a bench adapter, or when preparing an extracted portable build:

```powershell
.\ethercat-workbench-cli.exe check-runtime
.\ethercat-workbench-cli.exe check-runtime --out .local/host-prerequisites.json
```

The command reads local host metadata. It does not enumerate/open NICs, call Npcap exports, transmit frames, change a service, edit the registry or request elevation. No selected adapter, profile or device is needed. Its JSON is a host inspection, not a capture/run report for `compare-runs`. Export requires a new `.json` path and flushes the saved file; existing paths remain protected. A successful command means observations were collected, including missing/unavailable prerequisites, rather than that capture access passed.

Npcap documents its DLL directory beneath the Windows system directory, the `npcap` service name, and installer options such as the `AdminOnly` DWORD beneath `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\npcap\Parameters`. These are the metadata locations checked here. Older registry locations are not inferred. [Npcap developer guide](https://npcap.com/guide/npcap-devguide.html)

The checker resolves the Windows system directory with the same API/path convention as the native backend, reads DOS/PE headers from `Npcap\wpcap.dll` and `Npcap\Packet.dll`, and reads their literal four-part Windows file-version resources. The version-resource buffer is limited to 1 MiB per file. File versions are not converted into Npcap release identifiers. Header inspection does not perform a full PE load, check exports/dependencies, verify a signature or establish authenticity. [Microsoft version-resource API](https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-getfileversioninfow)

Service observation requests only local SCM connect and service query-status rights; handles are closed afterward. It records the current state/code without starting or stopping the driver. The policy observation uses a query-only, DWORD-filtered registry call. [Microsoft service-query API](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex)

## Read the result

Each observation has a state, optional value/detail and an OS error code when its API provides one:

| State | Meaning |
| --- | --- |
| `available` | A value was observed; false and zero remain actual values |
| `missing` | The file, service or recorded value was not found |
| `unavailable` | A read/query failed; access-denied and other error codes remain visible |
| `invalid` | A checked header, resource or policy value has an unsupported/invalid representation |
| `not_queried` | A prerequisite observation was unavailable, so a dependent check was skipped |

`host_status` summarizes DLL header and service observations:

| Status | Meaning |
| --- | --- |
| `missing_prerequisites` | A required DLL or the service was not found |
| `incompatible_image` | A checked header is invalid, or does not describe an AMD64 PE32+ DLL |
| `observation_unavailable` | Required observations could not be completed/classified |
| `service_not_running` | The observed service is stopped, paused or pending |
| `present_unprobed` | Both headers describe x64 DLLs and the service reports running |

The summary does not require available file-version or installer-policy metadata; inspect those observations separately. `capture_access` always remains `not_probed`. An `AdminOnly` value of false does not establish effective permission, and a missing/unreadable value is not converted to false. Npcap's admin-only installation option uses a restrictive access policy; actual access still depends on the selected adapter/session and the current Windows access context. [Npcap access-policy description](https://npcap.com/guide/npcap-users-guide.html)

The report includes UTC observation time, application architecture/pointer width, resolved paths and Npcap executable-module presence before/after collection. Fresh CLI checks expect those modules to remain absent. Header/resource reads inspect files as data, without invoking Npcap code. Later installation or service changes require another observation.

## Continue commissioning

Use the [installation instructions](../README.md#install) if prerequisites need attention. Npcap remains separately installed; its runtime DLLs/driver are not bundled. After the device, ESI, isolated NIC and input are selected, follow [operations](operations.md) for discovery and the reviewed SAFEOP setup/INIT teardown scope. A host check grants no device-write authorization and does not establish NIC binding, EtherCAT compatibility, PDO meaning, SAFEOP input validity or physical timing. The [roadmap](../ROADMAP.md) and [verification record](../VERIFICATION.md) retain those pending acceptance steps.
