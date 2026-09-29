# VMware: dettagli di funzionamento

WEBCQUISITION usa esclusivamente `vmrun`, la CLI fornita con VMware Workstation Pro e Fusion.

## Comandi usati

| Scopo | Comando |
|---|---|
| disponibilità e versione | `vmrun` (intestazione "vmrun version …") |
| stato | `vmrun -T ws list` (VM accesa); `.vmx` con `checkpoint.vmState` = VM sospesa |
| snapshot | `listSnapshots`, `revertToSnapshot`, `snapshot` |
| avvio e arresto | `start <vmx> gui`, `stop <vmx> soft` (richiede VMware Tools), `stop <vmx> hard` (solo se necessario, registrato) |
| VMware Tools | `checkToolsState` |
| guest operations (**solo** `vmware-setup`) | `directoryExistsInGuest`, `createDirectoryInGuest`, `copyFileFromHostToGuest`, `copyFileFromGuestToHost`, `runProgramInGuest` |

Durante un'acquisizione **non** si usano guest operations né credenziali del guest: tutto passa
dall'agent sulla rete host-only.

## Identità e rete dal file `.vmx`

- `hypervisor.vm_name` è il **percorso del `.vmx`**. Il nome mostrato in Workstation
  (`displayName`) è solo registrato.
- Identità: `uuid.bios`, normalizzato in 32 cifre esadecimali. Spazi e trattini sono ignorati sia
  nel `.vmx` sia nella configurazione.
- Schede di rete: `ethernet0` corrisponde alla NIC **"1"**, `ethernet1` alla NIC **"2"**. Il tipo
  viene da `connectionType`:
  - `nat`, `hostonly`, `bridged`;
  - `custom:vmnetN` per le reti personalizzate;
  - se la chiave manca, VMware usa `bridged`.
- `startConnected = "FALSE"` rende la scheda non conforme: una scheda di acquisizione scollegata
  darebbe un PCAP vuoto.
- Le VM **cifrate** non sono supportate, perché `vmrun` richiederebbe la password a ogni comando.
  Lo stesso vale per le VM **sospese**, che vanno spente e non riprese.

## Rete consigliata

| Scheda | Tipo VMware | Rete tipica | Uso |
|---|---|---|---|
| ethernet0 → NIC1 | NAT (VMnet8) | 192.168.x.0/24 con gateway `.2` | navigazione, **catturata** |
| ethernet1 → NIC2 | Host-only (VMnet1) | 192.168.y.0/24, host `.1`, VM `.10` statico | controllo agent, **mai catturata** |

Se si usa una rete di acquisizione diversa dalla NAT, per esempio una VMnet personalizzata con
uscita controllata, adattare `expected_nics` (`custom:vmnet3`) e usare `--fix-network` solo se va
bene lo schema predefinito.

Sull'host deve essere attiva la scheda "VMware Network Adapter VMnet1", da controllare nel Virtual
Network Editor.

## Arresto e snapshot

- Arresto controllato (`stop soft`) entro `shutdown_timeout_s`, altrimenti `stop hard`, registrato
  come `VM_FORCED_POWEROFF`.
- Snapshot post-acquisizione (`post_acquisition_snapshot: on_failure`): preso **a VM spenta** dopo
  l'export, con nome `WEBCQ-<caso>-post-<data>`. `vmrun` non registra descrizioni: il collegamento
  al caso è nel nome e in `acquisition.json`.
- Nomi di snapshot duplicati rendono ambiguo il ripristino: WEBCQUISITION rifiuta di procedere.

## Stato di validazione

Il provider è coperto da test con un simulatore di `vmrun` che riproduce stato, output ed errori.
Resta marcato `stable = False`, e ogni caso registra il warning `PROVIDER_EXPERIMENTAL`, finché non
viene completata e documentata la validazione su hardware reale ([TESTING.md](TESTING.md)).
Dopo la validazione nel proprio laboratorio si può impostare `stable = True` in
`providers/vmware.py`, annotandolo nel rapporto di validazione.
