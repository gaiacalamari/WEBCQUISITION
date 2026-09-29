# Cattura di rete

## Strategia

| Elemento | Scelta | Motivo |
|---|---|---|
| Motore del reperto | `dumpcap` (default) o `tshark` | controllabile da programma, formato PCAPNG, arresto pulito, nessuna dissezione (meno risorse, nessun crash del dissector) |
| Vista operatore | GUI Wireshark in `mode: dual` | requisito: l'operatore vede che la cattura è attiva |
| Formato | PCAPNG | conserva nome interfaccia (IDB), timestamp ad alta risoluzione, commenti |
| Rotazione | `-b filesize:N` senza `files:` | limita la dimensione dei singoli file; **nessun file viene mai eliminato** |
| Filtro | nessuno (default) | acquisire tutto; filtrare in analisi |
| Snaplen | 0 (pacchetto intero) | nessuna troncatura |

Comando registrato in `acquired/metadata/capture-command.json`, per esempio:

```
dumpcap.exe -i \Device\NPF_{GUID} -w Desktop\CASE\network\capture.pcapng -b filesize:524288
```

dumpcap aggiunge al nome numero progressivo e data: `capture_00001_20260928091402.pcapng`.

La GUI di Wireshark effettua una **propria** cattura sulla stessa interfaccia in un file
temporaneo del profilo utente, fuori dalla cartella del caso: non è un reperto e viene chiusa
forzatamente a fine sessione (per evitare il dialogo "salvare i pacchetti?"). Se la GUI non si
avvia, la cattura del reperto prosegue e viene registrato un WARNING.

## Selezione dell'interfaccia

L'agent incrocia `dumpcap -D` con `Get-NetAdapter`/`Get-NetIPAddress`/`Get-NetRoute`. L'interfaccia
che porta l'IP di controllo è marcata `is_control` ed è **rifiutata sia dall'host sia dall'agent**.
Con `interface: auto` si sceglie l'unica interfaccia non di controllo con default gateway; se ce
n'è più d'una (o nessuna) l'acquisizione non parte e si chiede una scelta esplicita.

## Verifica programmatica

1. **Processo**: dumpcap in esecuzione (`WIRESHARK_STARTED` con PID e comando).
2. **File**: almeno un PCAPNG in `network/`.
3. **Interfaccia**: gli Interface Description Block del file riportano `if_name` uguale al
   dispositivo scelto → `CAPTURE_STARTED`. Se diverso → `CAPTURE_INTERFACE_MISMATCH` (FAILED).
4. **Traffico**: il parser PCAPNG incrementale (letture solo in coda, blocchi parziali tollerati)
   conta i pacchetti; alla prima crescita → `CAPTURE_TRAFFIC_VERIFIED`. Nessuna crescita per
   `stall_warning_s` → `CAPTURE_STALLED` (WARNING); mai cresciuto → `CAPTURE_NO_TRAFFIC` (ERROR).
5. **Continuità**: il processo terminato durante la sessione → `CAPTURE_PROCESS_DIED` (ERROR,
   esito INCOMPLETE); nuovi file per rotazione → `CAPTURE_FILE_ROTATED`.
6. **Dopo l'export**: ogni PCAPNG è riletto sull'host (`PCAP_SUMMARY`: pacchetti, primo/ultimo
   timestamp, interfacce, validità, coda troncata).

Cosa **non** è verificabile automaticamente: che il traffico catturato sia *completo* (perdite
nel driver sono riportate da dumpcap in stderr e negli Interface Statistics Block, da esaminare in
analisi) e che la GUI sia effettivamente visibile a schermo.

## Arresto

dumpcap è avviato con una console propria nascosta. All'arresto, l'helper `ctrlc.py` (processo
separato) si aggancia a quella console e invia CTRL+C: dumpcap scrive gli ultimi blocchi e gli
Interface Statistics Block e chiude il file (`graceful: true`). Se non termina entro
`finalize.graceful_timeout_s`, viene terminato forzatamente (`CAPTURE_FORCED_STOP`, WARNING:
l'ultimo blocco potrebbe essere troncato; il parser lo segnala come `truncated_tail`).
