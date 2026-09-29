# Threat model

## Beni da proteggere

Integrità e autenticità del pacchetto (PCAPNG, key log, screenshot, file dell'operatore, log),
riservatezza del key log e dei dati acquisiti, correttezza della documentazione (ora, ambiente,
sequenza delle azioni), isolamento della postazione dell'operatore.

## Attori e superfici

| Minaccia | Superficie | Mitigazioni | Rischio residuo |
|---|---|---|---|
| Sito/contenuto malevolo che compromette la VM | browser nella VM | VM isolata, snapshot pulito ripristinato ogni volta, nessuna cartella condivisa, NIC di controllo senza gateway | una VM compromessa può alterare i dati **prima** del sigillo; il PCAP resta una fonte indipendente da confrontare |
| VM compromessa che attacca l'host | agent/HTTP, hypervisor | l'host è client: parla solo con un endpoint noto, valida percorsi e dimensioni, scarica solo file del manifest in una cartella dedicata, non esegue nulla di ricevuto; nessuna cartella condivisa | vulnerabilità dell'hypervisor (fuori dall'ambito) |
| Terzi sulla rete che controllano l'agent | porta dell'agent | ascolto solo su IP host-only, firewall limitato all'IP dell'host, token Bearer ≥ 32 caratteri con confronto a tempo costante | HTTP non cifrato sulla rete host-only (link locale virtuale); vedi ROADMAP (TLS reciproco) |
| Uso della VM o della rete sbagliata | configurazione | verifica di UUID, NIC attese, snapshot, `agent_id`, `--vm` di conferma, sessione guest già attiva = rifiuto | configurazioni senza `vm_uuid`/`expected_nics` producono WARNING, non errori |
| Sovrascrittura/confusione tra casi | filesystem | cartelle nuove obbligatorie, nome cartella = ID caso, creazione esclusiva dei file, lock del caso, un'acquisizione per caso | — |
| Alterazione del pacchetto dopo l'acquisizione | host | SHA256SUMS, manifest guest e host, catena di hash degli eventi, `package-seal.json`, file in sola lettura, `verify` | chi controlla l'host può rigenerare tutto in modo coerente: **annotare nel verbale l'hash di `package-seal.json` e l'hash di testa del log**; firma/marca temporale in roadmap |
| Traffico di controllo nel reperto | NIC | NIC di controllo separata e mai catturata (rifiuto lato host e agent) | — |
| Fuga del key log | pacchetto | segnalato come sensibile in README/report/acquisition.json | la protezione del pacchetto è responsabilità dell'organizzazione |
| Orologio del guest errato | timestamp | offset guest−host misurato a inizio e fine; timestamp host in UTC | l'ora dell'host va verificata dall'operatore contro una fonte attendibile |
| Operatore che salva file fuori dalla cartella del caso | procedura | watcher solo sulla cartella del caso, istruzioni in README/QUICKSTART | file salvati altrove non vengono acquisiti |
| Manomissione del codice di WEBCQUISITION | installazione | versione registrata nel caso, `BUNDLE-SHA256SUMS.txt` dell'agent, hash del bundle nel rapporto di preparazione | verificare provenienza e hash delle release |
| Furto delle credenziali del guest | `vmware-setup` | usate solo durante il setup, passate a `vmrun` e mai scritte su disco o nei log (verificato dai test) | durante il setup la password è visibile, sull'host, nella riga di comando di `vmrun` a chi può elencare i processi |
| Password dell'operatore con `--autologon` | registro della VM | opzionale, segnalato come avviso nel rapporto | password in chiaro nel registro: usare un account dedicato alla VM, non riutilizzato altrove |
| Privilegi eccessivi nella VM | agent, Firefox | Scheduled Task con privilegi limitati; Firefox non elevato | l'account operatore può comunque essere amministratore: preferire un utente standard |

## Ipotesi

L'host controller è affidabile e sotto il controllo dell'organizzazione; l'hypervisor isola
correttamente la VM; lo snapshot pulito è stato preparato e documentato correttamente.
