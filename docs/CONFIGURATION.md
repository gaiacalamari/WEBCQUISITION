# Configurazione

## File YAML dell'host

Normalmente è **generato da `vmware-setup`** in `%ProgramData%\WEBCQUISITION\webcquisition.yaml`
(Windows) o `~/.config/webcquisition/webcquisition.yaml` e letto automaticamente. Si può indicare
un altro file con `-c/--config` o con la variabile `WEBCQUISITION_CONFIG`. Esempio commentato: [`config/webcquisition.example.yaml`](../config/webcquisition.example.yaml).
Regole: chiavi sconosciute → **errore**; tipi controllati; nessun percorso o nome di VM cablato
nel codice; configurazione effettiva e suo SHA-256 registrati in ogni caso
(`metadata/config-snapshot.yaml`, `acquisition.json`).

### `hypervisor`

| Chiave | Default | Descrizione |
|---|---|---|
| `provider` | `vmware` | `vmware` oppure `fake` (solo test / `--dry-run`) |
| `vm_name` | — (obbligatoria) | **percorso completo del file `.vmx`** |
| `vm_uuid` | `null` | `uuid.bios` atteso (spazi e trattini ignorati); **consigliato**, impostato da `vmware-setup` |
| `snapshot` | `null` | snapshot pulito da ripristinare prima di ogni acquisizione |
| `require_snapshot` | `true` | rifiuta di partire senza snapshot |
| `start_mode` | `gui` | `gui` o `headless` (`vmrun start … nogui`) |
| `boot_timeout_s` / `shutdown_timeout_s` | 300 / 180 | timeout di avvio e di arresto controllato (`vmrun stop soft`) |
| `tools_timeout_s` | 300 | attesa di VMware Tools in `check-env --live` |
| `expected_nics` | `{}` | mappa NIC → tipo; `"1"` = `ethernet0`. Valori: `nat`, `hostonly`, `bridged`, `custom:vmnetN`. **Consigliato** |
| `post_acquisition_snapshot` | `on_failure` | `never`, `on_failure`, `always` |
| `executable` | `null` | percorso di `vmrun` se non trovato automaticamente |
| `vmrun_host_type` | `ws` | `ws` (Workstation Pro) o `fusion`. Player non è supportato |

### `agent`

| Chiave | Default | Descrizione |
|---|---|---|
| `url` | `http://192.168.150.10:8765` | IP della VM sulla rete host-only e porta dell'agent |
| `token_file` | — | file con il token (≥ 32 caratteri) |
| `expected_agent_id` | `null` | deve coincidere con `agent_id` in `agent.json`; **consigliato** |
| `request_timeout_s` | 30 | timeout delle richieste ordinarie |
| `ready_timeout_s` | 300 | attesa massima della VM pronta |
| `poll_interval_s` | 5 | intervallo di monitoraggio |
| `unreachable_threshold` | 3 | tentativi falliti prima di considerare l'agent perso |
| `max_clock_offset_s` | 2.0 | soglia di WARNING per l'offset orologio guest−host |

### `capture`

| Chiave | Default | Descrizione |
|---|---|---|
| `engine` | `dumpcap` | `dumpcap` o `tshark` (produce il reperto) |
| `mode` | `dual` | `dual` = reperto + GUI Wireshark per l'operatore; `headless` = solo reperto |
| `interface` | `auto` | `vmware-setup` imposta `WEBCQ-Acquisizione`; altrimenti `auto` (unica NIC non di controllo con gateway), nome amichevole, `\Device\NPF_{GUID}` o GUID |
| `ring_filesize_mb` | 512 | dimensione di rotazione; i file non vengono mai cancellati |
| `capture_filter` | `""` | filtro BPF; vuoto consigliato |
| `snaplen` | 0 | 0 = pacchetti interi |
| `verify_timeout_s` | 30 | tempo per verificare l'avvio della cattura |
| `require_traffic` | `true` | errore se il contatore pacchetti non cresce mai |
| `stall_warning_s` | 300 | WARNING se nessun nuovo pacchetto per questo tempo |
| `min_free_disk_mb` | 2048 | soglia di WARNING per lo spazio libero nel guest |

### `tls`, `browser`, `screenshot`

| Chiave | Default | Descrizione |
|---|---|---|
| `tls.enabled` | `true` | key log TLS per il processo Firefox |
| `tls.required` | `true` | key log vuoto a fine sessione = ERROR (esito INCOMPLETE) |
| `browser.browser` | `firefox` | unico valore supportato nell'MVP |
| `browser.dedicated_profile` | `true` | obbligatorio |
| `browser.start_url` | `https://time.is` | pagina iniziale (time.is mostra l'ora di riferimento, utile negli screenshot) |
| `browser.disable_doh` / `disable_http3` / `disable_ech` | `true` | vedi TLS-KEYLOG |
| `browser.extra_prefs` | `{}` | preferenze aggiuntive (`bool`, `int`, `str`), registrate nel caso |
| `screenshot.hotkey_enabled` / `hotkey` | `true` / `ctrl+alt+s` | modificatori `ctrl`, `alt`, `shift`, `win` + lettera, cifra, `f1`–`f24`, `printscreen` |
| `screenshot.control_panel` | `true` | pannello con "Screenshot" e "Fine acquisizione" |

### `case`, `finalize`, `export`

| Chiave | Default | Descrizione |
|---|---|---|
| `case.output_directory` | `""` | radice dei casi, usata con `--case ID` |
| `case.operator` / `organization` | `null` | registrati nel caso (`--operator` ha priorità) |
| `finalize.order` | `browser_first` | oppure `capture_first` |
| `finalize.graceful_timeout_s` | 30 | attesa della chiusura pulita prima di forzare |
| `export.retries` | 3 | tentativi per file in caso di hash non corrispondente |
| `export.make_readonly` | `true` | file acquisiti resi in sola lettura sull'host |
| `finalize.block_guest_shutdown` | `true` | spegnere Windows dal menu Start termina l'acquisizione: lo spegnimento attende la copia del materiale sull'host |
| `finalize.recover_on_vm_loss` | `true` | se la VM viene spenta (Power Off, chiusura della finestra, "Arresta comunque") o sospesa prima della copia, l'host la riavvia **senza** ripristinare lo snapshot, recupera la cartella del caso e la spegne |

## Opzioni da riga di comando

- `--vm NOME`: **conferma** della VM; se diverso da `hypervisor.vm_name` l'esecuzione è rifiutata.
- `--interface X`: sovrascrive `capture.interface` per il caso (registrato nell'evento
  `INTERFACE_SELECTED`).
- `--operator`, `--output`, `--case`, `--dry-run`, `--auto-stop N` (solo test), `-v`.

## `agent.json` (nella VM)

Generato da `vmware-setup`. Percorso predefinito `C:\ProgramData\WEBCQUISITION\agent.json`. Esempio:
[`examples/agent.example.json`](../examples/agent.example.json).

| Chiave | Obbl. | Descrizione |
|---|---|---|
| `listen_host` | sì | IP della NIC host-only; `0.0.0.0` rifiutato |
| `listen_port` | no (8765) | porta |
| `token` | sì | stesso token dell'host (≥ 32 caratteri) |
| `agent_id` | sì | identificativo univoco della VM, verificato dall'host |
| `control_ip` | no | IP usato per riconoscere la NIC di controllo (default `listen_host`) |
| `dumpcap_path`, `tshark_path`, `wireshark_path`, `firefox_path` | no | percorsi degli strumenti |
| `log_dir` | no | log tecnico dell'agent (fuori dal caso) |
