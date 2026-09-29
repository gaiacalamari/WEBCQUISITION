"""Codice condiviso (solo standard library) tra host controller e guest agent.

Questo package NON deve avere dipendenze esterne: viene distribuito anche
all'interno della VM Windows insieme al guest agent.
"""

__version__ = "0.2.5"

#: Versione del protocollo host <-> guest. Incrementare in caso di modifiche
#: incompatibili alle API del guest agent.
PROTOCOL_VERSION = 1
