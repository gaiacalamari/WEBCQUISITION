# Limiti noti

WEBCQUISITION è uno strumento di supporto: **non** garantisce da solo l'ammissibilità o il valore
probatorio di un'acquisizione, che dipendono da metodo, verbale, catena di custodia e contesto
giuridico.

## Tecnici

- **Validazione**: provider VMware, preparazione automatica, script PowerShell e agent sono coperti
  da test automatici con `vmrun`, cmdlet Windows e componenti simulati. Nessun test è stato ancora
  eseguito su VMware Workstation e Windows reali: le parti Win32 (cattura schermo, hotkey, CTRL+C a
  dumpcap, pannello), le guest operations e i cmdlet di rete vanno validati nel laboratorio con il
  protocollo di [TESTING.md](TESTING.md).
- **Spegnimento dall'interno della VM**: la sospensione dello spegnimento usa l'API Windows
  `ShutdownBlockReasonCreate` e non è ancora validata su Windows reale. Se l'operatore sceglie
  "Arresta comunque" o spegne la VM da Workstation, interviene il recupero: materiale salvato, ma
  esito `INCOMPLETE`, con l'ultimo blocco PCAPNG e gli ultimi eventi del guest eventualmente troncati.
- **Recupero dopo spegnimento**: la VM viene riavviata dallo stato corrente, non dallo snapshot. Il
  riavvio produce traffico di rete che **non** è catturato e non entra nel pacchetto, ma il sistema
  della VM cambia. È documentato negli eventi (`RECOVERY_*`) e in `guest-events-recovery.jsonl`.
- **Solo VMware Workstation Pro/Fusion**: Player non è supportato (niente snapshot con `vmrun`);
  VM cifrate non supportate.
- **Accesso automatico** (`--autologon`): comodo ma memorizza la password dell'operatore in chiaro
  nel registro della VM.
- **Integrità prima del sigillo**: gli hash sono calcolati al sigillo nel guest. Ciò che accade
  nella VM prima di quel momento (per esempio un malware che altera file del caso) non è
  rilevabile dagli hash; il PCAPNG e il log eventi guest aiutano a ricostruirlo.
- **Completezza della cattura**: si verificano avvio, interfaccia e crescita, non l'assenza di
  pacchetti persi dal driver (vedere Interface Statistics Block e `dumpcap-stderr.log`).
- **Decifrabilità TLS**: si verifica solo che il key log non sia vuoto. Vedi [TLS-KEYLOG.md](TLS-KEYLOG.md).
- **Solo Firefox**: altri browser e applicazioni non sono gestiti; il loro traffico può comparire
  nel PCAP ma non è decifrabile.
- **Tempo**: tutti i timestamp dipendono dagli orologi di host e guest; si misura l'offset tra i
  due, non l'esattezza rispetto a UTC reale. Nessuna marca temporale qualificata.
- **Firma**: il pacchetto non è firmato digitalmente; l'autenticità si basa sugli hash annotati nel
  verbale (firma e marca temporale RFC 3161 in roadmap).
- **Screenshot integrati**: catturano il desktop virtuale intero; contenuti protetti da DRM o
  finestre con protezione dalla cattura possono risultare neri.
- **Profilo Firefox**: acquisito come file; database SQLite potrebbero essere in uno stato
  intermedio se Firefox è stato chiuso forzatamente (WARNING `FIREFOX_FORCED_CLOSE`).
- **Modalità `start/status/stop`**: il monitoraggio avviene solo durante `status`.
- **Dimensioni**: nessun limite applicativo, ma spazio su disco della VM e dell'host va pianificato.
- **Canale di controllo HTTP**: non cifrato, protetto da isolamento di rete e token.

## Procedurali (a carico dell'operatore)

Verificare a vista che Wireshark catturi e che Firefox sia quello avviato da WEBCQUISITION;
non avviare altri browser; salvare i file solo nella cartella del caso; annotare nel verbale ora di
riferimento, esito, hash di `package-seal.json` e hash di testa del log; custodire il pacchetto
secondo le procedure dell'organizzazione.
