# Eventi

## Formato

Due log JSONL append-only: `logs/host-events.jsonl` (host) e `acquired/logs/guest-events.jsonl`
(guest). Una riga = un evento:

```json
{"schema_version": 1, "seq": 42, "timestamp": "2026-09-28T09:14:03.512Z",
 "event": "CAPTURE_STARTED", "severity": "INFO", "case_id": "CASE-2026-001",
 "source": "host", "component": "orchestrator", "message": "",
 "data": {"interface": "\\Device\\NPF_{…}", "packets": 12, "verification": "process_alive+pcapng_present+idb_interface_match"},
 "prev_hash": "9f3c…", "hash": "b71e…"}
```

| Campo | Significato |
|---|---|
| `seq` | progressivo da 1, senza buchi |
| `timestamp` | UTC ISO-8601 al millisecondo (orologio della macchina che scrive: host o guest) |
| `severity` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `source` / `component` | `host`/`guest` e modulo che ha emesso l'evento |
| `data` | dettagli strutturati (percorsi, hash, PID, comandi, codici di errore) |
| `prev_hash` | `hash` dell'evento precedente (`0`×64 per il primo) |
| `hash` | SHA-256 del JSON canonico dell'evento senza il campo `hash` |

JSON canonico: chiavi ordinate, separatori `,` e `:` senza spazi, UTF-8 senza escape.
Verifica indipendente in poche righe:

```python
import hashlib, json
prev = "0" * 64
for n, line in enumerate(open("host-events.jsonl", encoding="utf-8"), 1):
    ev = json.loads(line)
    body = {k: v for k, v in ev.items() if k != "hash"}
    h = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    assert ev["seq"] == n and ev["prev_hash"] == prev and ev["hash"] == h, f"evento {n} non integro"
    prev = h
print("catena integra, hash di testa:", prev)
```

La catena rileva modifiche, cancellazioni e inserimenti **all'interno** del file; non protegge da
chi rigenera l'intero file. Per questo l'hash di testa del log host e l'hash di
`package-seal.json` vanno riportati nel verbale (vedi THREAT-MODEL). Ogni evento è scritto con
`fsync`: un'interruzione improvvisa perde al massimo l'evento in corso di scrittura.

Il log guest viene chiuso al sigillo, prima del calcolo del manifest guest: il suo hash è quindi
nel manifest e viene verificato dopo il trasferimento.

## Tipi di evento

**Caso e configurazione**: `CASE_CREATED`, `CASE_LOADED`, `CONFIG_LOADED`, `STATE_CHANGED`, `ACQUISITION_START_REQUESTED`

**Hypervisor / VM**: `HYPERVISOR_DETECTED`, `VM_IDENTITY_VERIFIED`, `NETWORK_CONFIG_VERIFIED`, `SNAPSHOT_RESTORED`, `VM_START_REQUESTED`, `VM_STARTED`, `AGENT_WAITING`, `GUEST_TOOLS_RUNNING`, `VM_READY`, `AGENT_UNREACHABLE`, `AGENT_RECONNECTED`, `CLOCK_OFFSET_MEASURED`

**Preparazione guest**: `CASE_DIRECTORY_CREATED`, `GUEST_SYSINFO_COLLECTED`, `TLS_KEYLOG_INITIALIZED`, `TLS_KEYLOG_ACTIVE`, `TLS_KEYLOG_EMPTY`

**Cattura**: `INTERFACE_SELECTED`, `WIRESHARK_START_REQUESTED`, `WIRESHARK_STARTED`, `WIRESHARK_GUI_STARTED`, `CAPTURE_STARTED`, `CAPTURE_TRAFFIC_VERIFIED`, `CAPTURE_STALLED`, `CAPTURE_PROCESS_DIED`, `CAPTURE_FILE_ROTATED`

**Browser**: `FIREFOX_PROFILE_CREATED`, `FIREFOX_STARTED`, `FIREFOX_EXITED_UNEXPECTEDLY`

**Operatore**: `SCREENSHOT_SERVICE_STARTED`, `SCREENSHOT_CREATED`, `OPERATOR_FILE_DETECTED`, `OPERATOR_FILE_MODIFIED`, `USER_ACTION`, `ACQUISITION_ACTIVE`, `HEALTH_CHECK`, `DISK_SPACE_LOW`

**Chiusura**: `STOP_REQUESTED`, `FIREFOX_STOP_REQUESTED`, `FIREFOX_STOPPED`, `CAPTURE_STOP_REQUESTED`, `CAPTURE_STOPPED`, `GUEST_SEAL_STARTED`, `GUEST_SEALED`

**Export e integrità**: `EXPORT_STARTED`, `FILE_EXPORTED`, `EXPORT_HASH_MISMATCH`, `EXPORT_COMPLETED`, `EXPORT_FAILED`, `HASH_CALCULATED`, `INTEGRITY_VERIFIED`, `INTEGRITY_FAILED`, `PCAP_SUMMARY`

**Arresto VM**: `VM_SHUTDOWN_REQUESTED`, `VM_SHUTDOWN`, `VM_FORCED_POWEROFF`, `SNAPSHOT_TAKEN`

**Output**: `MANIFEST_WRITTEN`, `REPORT_GENERATED`, `CASE_COMPLETED`, `CASE_INCOMPLETE`, `CASE_FAILED`

**Spegnimento della VM dall'interno e recupero**: `GUEST_SHUTDOWN_REQUESTED`, `GUEST_SHUTDOWN_RELEASED`, `RECOVERY_STARTED`, `RECOVERY_COMPLETED`, `RECOVERY_FAILED`

**Preparazione della VM (vmware-setup)**: `VM_SETUP_STARTED`, `VM_SETUP_STEP`, `VM_SETUP_COMPLETED`, `VM_SETUP_FAILED`

**Generici**: `WARNING`, `ERROR`

Il log di `vmware-setup` (`webcquisition.yaml.setup-<data>.events.jsonl`, `case_id` = `VM-SETUP`)
usa lo stesso formato con `VM_SETUP_STARTED`, un `VM_SETUP_STEP` per ogni passo,
`VM_SETUP_COMPLETED` o `VM_SETUP_FAILED`.

## Sequenza tipica di un'acquisizione riuscita (host)

`CASE_CREATED` → `CASE_LOADED` → `ACQUISITION_START_REQUESTED` → `CONFIG_LOADED` →
`STATE_CHANGED`(PREPARING) → `HYPERVISOR_DETECTED` → `NETWORK_CONFIG_VERIFIED` →
`SNAPSHOT_RESTORED` → `VM_START_REQUESTED` → `VM_STARTED` → `AGENT_WAITING` → (`GUEST_TOOLS_RUNNING`) → `VM_READY` →
`CLOCK_OFFSET_MEASURED` → `CASE_DIRECTORY_CREATED` → `GUEST_SYSINFO_COLLECTED` →
`TLS_KEYLOG_INITIALIZED` → `INTERFACE_SELECTED` → `WIRESHARK_START_REQUESTED` →
`WIRESHARK_STARTED` (→ `WIRESHARK_GUI_STARTED`) → `CAPTURE_STARTED` → `FIREFOX_PROFILE_CREATED` →
`FIREFOX_STARTED` → `SCREENSHOT_SERVICE_STARTED` → `STATE_CHANGED`(ACQUIRING) →
`ACQUISITION_ACTIVE` → `CAPTURE_TRAFFIC_VERIFIED` → `TLS_KEYLOG_ACTIVE` → `SCREENSHOT_CREATED`… →
`USER_ACTION` → `STOP_REQUESTED` → `STATE_CHANGED`(FINALIZING) → `FIREFOX_STOP_REQUESTED` →
`CAPTURE_STOP_REQUESTED` → `FIREFOX_STOPPED` → `CAPTURE_STOPPED` → `GUEST_SEAL_STARTED` →
`GUEST_SEALED` → `EXPORT_STARTED` → `FILE_EXPORTED`… → `EXPORT_COMPLETED` → `HASH_CALCULATED`… →
`INTEGRITY_VERIFIED` → `PCAP_SUMMARY` → `VM_SHUTDOWN_REQUESTED` → `VM_SHUTDOWN` →
`MANIFEST_WRITTEN` → `REPORT_GENERATED` → `CASE_COMPLETED`.

Il log guest contiene gli eventi prodotti nella VM: creazione della cartella, avvio di dumpcap e
della GUI, profilo e avvio di Firefox, ogni screenshot (con hash), ogni file dell'operatore
rilevato o modificato (con hash), richieste di stop dal pannello, arresti.
