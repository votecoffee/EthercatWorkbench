/* SPDX-License-Identifier: MIT
 * Read-only byte format, not a function ABI. Windows x64, little endian.
 * Open existing Local\\EtherCATWorkbench.NAME.data with FILE_MAP_READ and
 * NAME.lock with SYNCHRONIZE|MUTEX_MODIFY_STATE. Hold the mutex only to copy
 * all 2560 bytes into private storage, then release before interpreting.
 * WAIT_ABANDONED: release ownership and discard. Never dereference an
 * unaligned shared struct directly or trust a stale valid/fresh flag.
 * Check schema, lengths, stream, process creation time and publication QPC.
 */
#ifndef ETHERCAT_INPUT_V1_H
#define ETHERCAT_INPUT_V1_H
#include <stdint.h>
#include <stddef.h>
#define ECW_INPUT_V1_SIZE 2560
#define ECW_INPUT_V1_HEADER 512
#define ECW_INPUT_V1_CAPACITY 1024
#define ECW_INPUT_ACTIVE 0x001u
#define ECW_INPUT_LATEST_PRESENT 0x002u
#define ECW_INPUT_VALID 0x004u
#define ECW_INPUT_LAST_VALID_PRESENT 0x008u
#define ECW_INPUT_RECEIVED 0x010u
#define ECW_INPUT_WKC_PRESENT 0x020u
#define ECW_INPUT_AL_PRESENT 0x040u
#define ECW_INPUT_EXPECTED_ID_PRESENT 0x080u
#define ECW_INPUT_FRESH_AT_PUBLICATION 0x100u
#define ECW_INPUT_PROFILE_HASH_PRESENT 0x200u
#define ECW_INPUT_OBSERVED_ID_PRESENT 0x400u
#define ECW_INPUT_CSV_PRESENT 0x800u
#pragma pack(push, 1)
typedef struct ecw_input_v1 {
    uint8_t magic[8]; /* ECWBIN01 */
    uint32_t schema, size, header_size, capacity;
    uint64_t publication_index;
    int64_t utc_start_us;
    uint64_t generation, publication_elapsed_us, offered;
    uint64_t event_index, cycle_index, elapsed_us;
    uint64_t last_valid_event_index, last_valid_cycle_index, last_valid_elapsed_us;
    uint64_t queue_drops, drained, coalesced, lock_misses, written_events, queue_pending, writes;
    uint64_t cycles, valid_exchanges, timeouts, wkc_mismatches, al_mismatches, transport_errors, missed_deadlines;
    uint64_t csv_selected, csv_written, csv_overruns;
    uint64_t publication_qpc, qpc_frequency;
    uint32_t publisher_pid, flags;
    uint16_t expected_wkc, actual_wkc, al_status, al_code;
    uint32_t issue, tx_bytes, payload_len, last_valid_len;
    uint32_t expected_vendor, expected_product, expected_revision;
    uint32_t observed_vendor, observed_product, observed_revision;
    uint32_t requested_cycle_us, freshness_ms, period_ms;
    uint16_t station, position;
    uint64_t publisher_created_filetime;
    char stream_id[64];
    uint8_t profile_sha256[32];
    char backend[64];
    uint64_t abandoned_recoveries;
    uint8_t payload[1024];
    uint8_t last_valid_payload[1024];
} ecw_input_v1;
#pragma pack(pop)
#if defined(__cplusplus)
static_assert(sizeof(ecw_input_v1) == ECW_INPUT_V1_SIZE, "snapshot size");
static_assert(offsetof(ecw_input_v1, payload) == ECW_INPUT_V1_HEADER, "payload offset");
static_assert(offsetof(ecw_input_v1, flags) == 268, "flags offset");
#else
_Static_assert(sizeof(ecw_input_v1) == ECW_INPUT_V1_SIZE, "snapshot size");
_Static_assert(offsetof(ecw_input_v1, payload) == ECW_INPUT_V1_HEADER, "payload offset");
_Static_assert(offsetof(ecw_input_v1, flags) == 268, "flags offset");
#endif
#endif
