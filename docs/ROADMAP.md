# Roadmap

## 0.2 — VMware (questa versione)

Solo VMware Workstation Pro/Fusion; preparazione automatica della VM (`vmware-setup`),
`check-env --live`, procedura guidata `wizard`, configurazione predefinita, agent con privilegi
limitati.

## 0.3 — Validazione sul campo

- Validazione documentata su Windows 10/11 e VMware Workstation Pro 17 (protocollo TESTING.md),
  correzioni, provider marcato `stable`.
- Installazione di Python embeddable e dei prerequisiti (Firefox, Wireshark; Npcap richiede la
  licenza OEM per l'installazione silenziosa) da parte di `vmware-setup`.
- Verifica della versione dell'agent contro l'hash del bundle registrato nella configurazione.

## 0.4 — Robustezza
- Ripresa dell'export interrotto; export parallelo per file grandi.
- Monitoraggio delle perdite di pacchetti (Interface Statistics Block) durante la sessione.
- Canale di controllo con TLS reciproco (certificati generati per coppia host/VM).

## 0.5 — Documentazione probatoria

- Firma del `package-seal.json` (chiave dell'organizzazione) e marca temporale RFC 3161.
- Report PDF e modello di verbale precompilato.
- Annotazioni dell'operatore con timestamp dal pannello.

## 1.0

- Formato del pacchetto e schema di `acquisition.json` dichiarati stabili e versionati.
- Registrazione video opzionale dello schermo della VM.
- Supporto a Chromium (key log) come secondo browser.
- Guida alla validazione del metodo per laboratori accreditati.
