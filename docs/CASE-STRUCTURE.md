# Struttura del caso

## Sull'host (pacchetto finale)

```
CASE-2026-001/
├── acquisition.json              metadati completi dell'acquisizione (vedi sotto)
├── README.txt                    guida al contenuto
├── acquired/                     COPIA VERIFICATA della cartella Desktop\CASE-2026-001 della VM
│   ├── network/                  capture_00001_<data>.pcapng …      original.network_capture
│   ├── tls/sslkeylog.log         segreti TLS (SENSIBILE)             original.tls_secrets
│   ├── browser/firefox-profile/  profilo Firefox del caso            original.browser_profile
│   ├── screenshots/              screenshot-NNNN.png + .json          auto.screenshot(_metadata)
│   ├── operator/  (+ radice)     file salvati dall'operatore          operator.file
│   ├── metadata/                 sysinfo, comandi, prefs, manifest    guest.metadata
│   ├── logs/                     guest-events.jsonl, dumpcap-stderr   guest.log
│   └── README.txt
├── hashes/
│   ├── SHA256SUMS.txt            hash dei file in acquired/ (sha256sum -c)
│   ├── manifest.json             elenco con dimensione, hash, categoria
│   ├── guest-manifest.json       manifest dichiarato dal guest al sigillo
│   └── package-seal.json         hash di acquisition.json, report, SHA256SUMS, log eventi host
├── logs/
│   ├── host-events.jsonl         eventi host con catena di hash
│   └── host.log                  log tecnico
├── report/acquisition-report.html
└── metadata/
    ├── case.json                 stato e storia degli stati
    ├── session.json              stato di lavoro dell'orchestratore
    └── config-snapshot.yaml      configurazione effettiva
```

Separazione dei ruoli: **dati originali** (`acquired/network`, `tls`, `browser`), **file
automatici** (`screenshots`), **file dell'operatore** (`operator/` e radice), **metadati**
(`acquired/metadata`, `metadata/`, `acquisition.json`), **log** (`logs/`, `acquired/logs`),
**integrità** (`hashes/`), **report** (`report/`). La categoria di ogni file è in
`hashes/manifest.json` e in `acquisition.json`.

Per verificare con strumenti standard: `cd acquired && sha256sum -c ../hashes/SHA256SUMS.txt`.

## Nella VM (durante l'acquisizione)

`Desktop\<CASO>\` con le stesse sottocartelle di `acquired/`. Dopo il sigillo i file sono in sola
lettura. La cartella resta nella VM fino al ripristino dello snapshot; con
`post_acquisition_snapshot` può essere conservata in uno snapshot.

## `acquisition.json`

Sezioni principali:

| Sezione | Contenuto |
|---|---|
| `tool` | versione WEBCQUISITION, protocollo |
| `case` | ID, operatore, organizzazione, creazione |
| `acquisition` | `state` finale e significato, inizio/fine UTC, motivo di chiusura, fusi orari host e guest, offset orologio a inizio/fine, storia degli stati |
| `host` | nome, OS, Python |
| `hypervisor` | provider e versione, VM (nome, UUID, NIC, snapshot ripristinato, snapshot post-acquisizione) |
| `guest` | agent (id, versione), Windows, Firefox, Wireshark, account, cartella del caso |
| `network` | interfaccia selezionata, interfacce del guest, comando di cattura, riepilogo dei PCAPNG (pacchetti, primo/ultimo timestamp, interfacce, validità) |
| `tls` | percorso e dimensione del key log, avvisi |
| `browser` | versione, profilo, preferenze applicate |
| `integrity` | algoritmo, file verificati, problemi, hash del manifest guest |
| `files` | elenco completo con percorso, dimensione, SHA-256, categoria |
| `issues` | tutti i WARNING/ERROR con codice, messaggio, ora |
| `config` | configurazione effettiva e suo SHA-256 |

In `--dry-run` il file contiene `dry_run: true` e un avviso esplicito.
