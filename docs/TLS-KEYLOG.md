# Segreti TLS (SSLKEYLOGFILE)

## Come funziona

Firefox (libreria NSS) scrive i segreti di sessione TLS nel file indicato dalla variabile
d'ambiente `SSLKEYLOGFILE`, in formato *NSS Key Log* (`CLIENT_RANDOM`, `CLIENT_TRAFFIC_SECRET_0`,
`SERVER_HANDSHAKE_TRAFFIC_SECRET`…). Wireshark usa quel file per decifrare le sessioni presenti
nel PCAPNG.

WEBCQUISITION:

1. pre-crea `tls/sslkeylog.log` vuoto nella cartella del caso (`TLS_KEYLOG_INITIALIZED`);
2. avvia Firefox con `SSLKEYLOGFILE` impostata **solo nell'ambiente di quel processo** e dei suoi
   figli; eventuali valori ereditati vengono rimossi;
3. registra quando il file inizia a crescere (`TLS_KEYLOG_ACTIVE`);
4. a fine sessione segnala un file vuoto (`TLS_KEYLOG_EMPTY`: ERROR se `tls.required`);
5. segnala una `SSLKEYLOGFILE` globale (processo, utente o sistema) come WARNING: altri programmi
   potrebbero scrivere segreti altrove, e un Firefox avviato a mano scriverebbe fuori dal caso.

Perché non globale: le specifiche chiedevano "TLS keys via SSLKEYLOGFILE"; una variabile di sistema
funzionerebbe ma farebbe scrivere segreti a qualunque applicazione NSS/OpenSSL/BoringSSL che la
rispetti, anche fuori dall'acquisizione, e renderebbe incerta l'attribuzione del file al caso.

## Uso in analisi

Su una **copia** del pacchetto: Wireshark → Preferenze → Protocols → TLS → *(Pre)-Master-Secret
log filename* = `acquired/tls/sslkeylog.log`. Oppure:

```
tshark -r capture_00001_….pcapng -o tls.keylog_file:sslkeylog.log -Y http
editcap --inject-secrets tls,sslkeylog.log capture.pcapng capture-with-keys.pcapng
```

`editcap --inject-secrets` produce un **file derivato** (con blocco DSB): non sostituisce l'originale.

## Sensibilità

Il key log consente di decifrare tutto il traffico TLS catturato, incluse credenziali e cookie di
sessione eventualmente digitati. Trattarlo come materiale riservato: accessi limitati, copie
tracciate, nessuna trasmissione in chiaro.

## Limiti (cosa può NON essere decifrabile)

| Caso | Effetto | Mitigazione in WEBCQUISITION |
|---|---|---|
| Firefox da Microsoft Store (MSIX) o build di terze parti senza supporto key log | file vuoto | usare l'installer Mozilla; errore `TLS_KEYLOG_EMPTY` |
| Applicazioni diverse da Firefox (altri browser, app, servizi Windows) | traffico cifrato non decifrabile | cattura comunque registrata; documentare |
| HTTP/3 / QUIC | decifrabile solo con Wireshark recente e segreti QUIC; comportamento variabile | `network.http.http3.enable=false` di default |
| DNS over HTTPS | nomi di dominio non visibili come DNS | `network.trr.mode=5` di default |
| Encrypted Client Hello (ECH) | SNI esterno fittizio | ECH disattivato di default |
| Certificate pinning / proxy | non pertinente al key log: la decifratura usa segreti del client, non un proxy MITM | — |
| Sessioni ripristinate / 0-RTT | i segreti possono comparire in forme diverse (`EARLY_TRAFFIC_SECRET`); verificare in analisi | nessuna |
| Service worker, preconnessioni, telemetria residua | traffico non generato direttamente dall'operatore | preferenze di riduzione del rumore, documentate |
| Traffico precedente all'avvio di Firefox | non ha segreti nel key log | Firefox parte solo a cattura attiva |
| Segreti scritti dopo l'arresto della cattura | inutili | ordine `browser_first` |
| Key log non vuoto ma incompleto | alcune sessioni non decifrabili | **da verificare dall'operatore** in analisi |

Il controllo automatico dice solo che il key log **non è vuoto**; se e quali sessioni siano
decifrabili va verificato in analisi.
