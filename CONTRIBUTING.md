# Contribuire a WEBCQUISITION

Grazie per l'interesse. Il progetto tratta materiale che può avere valore probatorio.

## Ambiente di sviluppo

```bash
git clone https://github.com/webcquisition/WEBCQUISITION.git
cd WEBCQUISITION
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest && ruff check src tests scripts
```

Nessuna VM è necessaria: `FakeProvider` e `FakeGuestClient` simulano hypervisor e agent, anche
con guasti (vedi docs/TESTING.md).

## Regole

1. **Agent e `webcquisition_common` usano solo la libreria standard** (devono girare nella VM
   senza installazioni aggiuntive). L'host può dipendere solo da PyYAML, salvo discussione.
2. **Nessun valore cablato** (percorsi, nomi di VM, interfacce): tutto passa dalla configurazione.
3. **Mai sovrascrivere o cancellare** file di un caso; nuove scritture in modalità esclusiva.
4. Ogni azione rilevante produce un **evento** (`EventType`) e ogni anomalia un **issue** con
   codice stabile, documentato in docs/EVENTS.md e docs/TROUBLESHOOTING.md.
5. Nuovi comportamenti e correzioni di bug arrivano **con test**; i guasti vanno simulati con i
   fake esistenti o estendendoli.
6. Distinguere nella documentazione ciò che è verificato automaticamente da ciò che va verificato
   dall'operatore.
7. Modifiche al formato del pacchetto, di `acquisition.json` o degli eventi: incrementare
   `schema_version` e annotarle in CHANGELOG.md.
8. Testi per l'utente in italiano; identificatori e codici in inglese.

## Pull request

- Un argomento per PR, descrizione del perché oltre che del cosa.
- Compilare il template (impatto forense, test, documentazione).
- La CI (ruff + pytest su Ubuntu e Windows) deve passare.
- Per l'agent: indicare se la modifica è stata provata su una VM Windows reale e con quali versioni.

## Segnalazioni

Bug e richieste tramite i template delle issue. Vulnerabilità: vedi [SECURITY.md](SECURITY.md).
Non allegare mai dati di casi reali.

Contribuendo accetti che il tuo contributo sia rilasciato con licenza Apache-2.0.
