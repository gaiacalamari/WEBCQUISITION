# Security policy

## Versioni supportate

| Versione | Supportata |
|---|---|
| 0.1.x | sì |

## Segnalare una vulnerabilità

Non aprire issue pubbliche per vulnerabilità che possano compromettere l'integrità delle
acquisizioni, la riservatezza dei dati acquisiti o l'host controller. Usare la funzione
**"Report a vulnerability"** (GitHub Security Advisories) del repository, indicando:

- versione di WEBCQUISITION, hypervisor, sistema operativo di host e VM;
- descrizione, impatto (integrità del pacchetto, riservatezza del key log, esecuzione di codice,
  elusione dei controlli su VM/rete…), passi per riprodurre;
- se possibile, un caso di prova **senza dati reali**.

Obiettivi: conferma di ricezione entro 5 giorni lavorativi, valutazione entro 15, correzione e
advisory coordinati. Chi segnala viene citato, se lo desidera.

## Ambito

In ambito: agent (API, autenticazione, gestione dei percorsi), client e orchestratore dell'host,
export e verifica, formato dei log e dei manifest, script di installazione.
Fuori ambito: vulnerabilità di hypervisor, Windows, Firefox o Wireshark (segnalarle ai rispettivi
fornitori), configurazioni che ignorano le indicazioni di VM-PREPARATION e THREAT-MODEL.

## Dati sensibili

Non allegare mai pacchetti di casi reali, key log TLS o token a issue, pull request o segnalazioni.
