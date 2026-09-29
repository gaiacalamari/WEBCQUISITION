# Test e validazione

## Test automatici

```bash
pip install -e ".[dev]"
pytest            # oltre 170 test, nessuna VM richiesta (i test PowerShell richiedono pwsh su Linux/macOS)
ruff check src tests scripts
```

| File | Copertura |
|---|---|
| `test_case.py` | creazione caso, divieto di sovrascrittura, ID non validi, lock, transizioni di stato, percorsi pericolosi |
| `test_config.py` | schema, chiavi sconosciute, valori e tipi non validi, config di esempio |
| `test_events.py` | campi, catena di hash, rilevamento di modifiche e cancellazioni, rifiuto di estendere log alterati |
| `test_hashing.py` | SHA-256, manifest, SHA256SUMS, rilevamento mismatch e file inattesi |
| `test_pcapng.py` | parser PCAPNG, lettura incrementale di file in crescita, blocchi parziali, file non validi |
| `test_vmware_provider.py` | parsing del `.vmx` (codifiche, schede, `custom`, `startConnected`), stati (accesa, sospesa, cifrata), snapshot duplicati/mancanti, VMware Tools, Player rifiutato; **acquisizione completa con il provider VMware reale** su simulatore di `vmrun`, UUID/NIC errati, arresto soft fallito |
| `test_vmware_setup.py` | lettura di `vmnetdhcp.conf`, piano degli indirizzi, correzione della rete; setup end-to-end (configurazione, snapshot, rapporto, catena eventi, **nessun segreto nei file prodotti**), rifiuti (configurazione esistente, VM accesa, rete non conforme), errore nel guest senza snapshot, UAC con esecuzione manuale, VMware Tools assenti; configurazione prodotta usata per un'acquisizione |
| `test_guest_setup_ps1.py` | **esecuzione reale di `guest-setup.ps1`** con PowerShell 7 e cmdlet Windows simulati: successo, IP e nomi delle schede, installazione, pulizia dei segreti, non elevato, Firefox mancante/Store, dumpcap mancante, Npcap solo-admin, utente inesistente, scheda non trovata, accesso automatico |
| `test_orchestrator.py` | workflow completo e ordine degli eventi; VM che non parte/non pronta, UUID/NIC/snapshot errati, VM già accesa, spegnimento bloccato, errori di preparazione, cattura (avvio, interfaccia, interruzione, nessun traffico), Firefox, key log vuoto, download corrotti (ritentati e persistenti), VM persa, agent temporaneamente irraggiungibile, stop dal pannello, snapshot post-acquisizione, selezione interfaccia |
| `test_agent_session.py` | sessione agent con componenti simulati: struttura, unicità, interfaccia di controllo, ordine cattura→Firefox, sigillo, whitelist dei download, path traversal |
| `test_agent_server.py` | server HTTP reale su loopback + client dell'host: autenticazione, download con hash, path traversal via HTTP, errori |
| `test_agent_components.py` | parsing `dumpcap -D` e adattatori, comando dumpcap (nessuna cancellazione per rotazione), preferenze e ambiente Firefox, encoder PNG, servizio screenshot, hotkey, watcher, bundle agent |
| `test_cli.py` | CLI end-to-end in `--dry-run`, `verify` con rilevamento manomissioni, start/status/stop, rifiuti di sicurezza |

La CI esegue i test su Ubuntu e Windows con Python 3.10, 3.11 e 3.12.

## Guasti simulabili

`FakeGuestClient` (host) accetta opzioni di guasto (`unreachable`, `never_ready`, `prepare_error`,
`capture_start_error`, `capture_wrong_iface`, `no_traffic`, `capture_dies`, `firefox_fail`,
`keylog_empty`, `corrupt_download`, `stop_after_status_calls`, `unreachable_after_status`);
`FakeProvider` accetta `failures` (`unavailable`, `start_fails`, `shutdown_hangs`) e `crash()`.
`tests/vmware_fakes.FakeVmrun` simula `vmrun` con stato (VM, snapshot, VMware Tools, MAC generati
all'accensione, filesystem del guest, esecuzione dello script di preparazione) e modalità di guasto
(`not_elevated`, `fail`, `no_tools`, arresto soft non riuscito).

## Protocollo di validazione in laboratorio (prima dell'uso su casi reali)

Eseguire e documentare su VMware Workstation Pro reale:

1. `vmware-setup` su una VM appena preparata: esito positivo, rapporto con tutti i passi; nella VM
   controllare IP statico della scheda `WEBCQ-Controllo` senza gateway, Scheduled Task
   "WEBCQUISITION Agent", regola firewall, assenza di file in `C:\Windows\Temp\webcq-setup` a
   parte `setup-result.json`.
2. `check-env --live` senza KO.
3. Acquisizione di prova di ~5 minuti su un sito di test noto (HTTP e HTTPS): esito COMPLETED; in
   analisi, traffico HTTPS decifrato con il key log; screenshot presenti con hash coerenti; Firefox
   in esecuzione **senza** privilegi elevati (Task Manager → colonna "Con privilegi elevati").
4. Confronto indipendente: `sha256sum -c` su `acquired/` e script di verifica della catena (EVENTS.md).
5. Arresto: negli eventi `graceful: true` per cattura e Firefox; PCAPNG apribile senza avvisi.
6. Guasti reali: scollegare la NIC1 durante la sessione (atteso `CAPTURE_STALLED`), chiudere dumpcap
   dal Task Manager (atteso `CAPTURE_PROCESS_DIED`, INCOMPLETE), spegnere la VM da Workstation
   (atteso `VM_LOST`, FAILED, snapshot post-acquisizione), rinominare lo snapshot (rifiuto prima
   dell'avvio), cambiare una scheda in Bridged (rifiuto prima dell'avvio).
7. Ripetibilità: due acquisizioni consecutive partono dallo stesso stato (stesse versioni in
   `sysinfo.json`, nessun residuo del caso precedente nella VM).
8. Conservare pacchetti e rapporto di validazione con le versioni di WEBCQUISITION, VMware, Windows,
   Firefox e Wireshark; dopo esito positivo si può marcare il provider come `stable`.
