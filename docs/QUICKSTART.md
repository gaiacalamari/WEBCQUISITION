# Avvio rapido

## A. Prova in simulazione (nessuna VM)

```bash
pip install -e ".[dev]"
webcquisition -c examples/dry-run.yaml acquire CASE-DEMO-001 --output ./out/CASE-DEMO-001 --dry-run --auto-stop 3
webcquisition verify --output ./out/CASE-DEMO-001
```

Aprire `out/CASE-DEMO-001/report/acquisition-report.html`. I contenuti sono sintetici e marcati
come simulazione.

## B. Messa in servizio (una volta)

1. Installare WEBCQUISITION sull'host e i prerequisiti nella VM ([INSTALLATION.md](INSTALLATION.md)).
2. Spegnere la VM e chiudere la sua scheda in VMware.
3. Preparare la VM:

   ```powershell
   webcquisition vmware-setup --vmx "D:\VMs\Forensic Windows\Forensic Windows.vmx" `
       --guest-user Administrator --operator-user forensic --cases-dir D:\Cases --fix-network
   ```

   Quando richiesto, accedere nella VM come `forensic`. Con `--autologon` non serve.
4. Fare una prova completa senza creare casi:

   ```powershell
   webcquisition check-env --live
   ```

5. Fare un'acquisizione di validazione su un sito di test ([TESTING.md](TESTING.md)).

## C. Acquisizione

Doppio clic su `WEBCQUISITION.cmd`, oppure:

```powershell
webcquisition wizard
```

La procedura chiede l'ID del caso (per esempio `CASE-2026-001`) e l'operatore, mostra VM,
snapshot e destinazione, e chiede conferma. Senza domande:

```powershell
webcquisition acquire CASE-2026-001 --operator "Mario Rossi"
```

**Importante**: non aprire la VM da VMware Workstation. La apre WEBCQUISITION dopo aver ripristinato
lo snapshot pulito.

Cosa succede e cosa controllare a vista:

1. La VM riparte dallo snapshot pulito e si apre in VMware Workstation. Se non c'è l'accesso
   automatico, accedere come operatore: da quel momento parte tutto da solo.
2. Compaiono:
   - Wireshark, con la cattura in corso su `WEBCQ-Acquisizione`. **Controllare** che mostri pacchetti;
   - Firefox su **time.is**;
   - il pannello WEBCQUISITION.
3. Navigare. Per gli screenshot usare `Ctrl+Alt+S` o il pulsante del pannello. I file da conservare
   vanno salvati in `Desktop\<CASO>` o in `Desktop\<CASO>\operator`.
4. Per terminare, **spegnere Windows** (Start → Arresta). Windows mostra "WEBCQUISITION impedisce
   l'arresto": è normale, e **non** va scelto "Arresta comunque". Lo spegnimento si completa da solo
   dopo la copia del materiale. In alternativa si possono usare "Fine acquisizione" nel pannello o
   `FINE` nella console.
5. Attendere l'esito nella console dell'host. **Annotare nel verbale** l'hash di
   `package-seal.json` e l'hash di testa del log eventi.

Il pacchetto viene creato in `D:\Cases\CASE-2026-001`; la cartella `Desktop\CASE-2026-001` della VM
è in `D:\Cases\CASE-2026-001\acquired\`. Verifica indipendente, anche in seguito o
su un'altra macchina:

```powershell
webcquisition verify --output D:\Cases\CASE-2026-001
```

## D. Analisi

Lavorare su una **copia** del pacchetto. In Wireshark: Preferenze → Protocols → TLS →
*(Pre)-Master-Secret log filename* = `acquired\tls\sslkeylog.log`. Vedi [TLS-KEYLOG.md](TLS-KEYLOG.md).
