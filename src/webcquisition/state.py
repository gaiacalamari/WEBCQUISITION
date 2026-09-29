"""Macchina a stati dell'acquisizione.

    CREATED -> PREPARING -> ACQUIRING -> FINALIZING -> EXPORTING -> VERIFYING -> COMPLETED
                  |             |             |            |            |
                  +-------------+-------------+------------+------------+--> INCOMPLETE / FAILED

* COMPLETED  : tutte le verifiche automatiche superate, nessun errore.
* INCOMPLETE : pacchetto esportato e verificato, ma con errori documentati
               (es. cattura interrotta, key log vuoto, interruzione operatore).
* FAILED     : il pacchetto non costituisce un'acquisizione verificata
               (nessuna cattura valida, export o integrità falliti, VM persa...).

Uno stato terminale non può più cambiare: un caso non può essere "riaperto".
"""

from __future__ import annotations

from enum import Enum


class AcquisitionState(str, Enum):
    CREATED = "CREATED"
    PREPARING = "PREPARING"
    ACQUIRING = "ACQUIRING"
    FINALIZING = "FINALIZING"
    EXPORTING = "EXPORTING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    INCOMPLETE = "INCOMPLETE"
    FAILED = "FAILED"


S = AcquisitionState
TERMINAL = frozenset({S.COMPLETED, S.INCOMPLETE, S.FAILED})

TRANSITIONS: dict[AcquisitionState, frozenset[AcquisitionState]] = {
    S.CREATED: frozenset({S.PREPARING, S.FAILED}),
    S.PREPARING: frozenset({S.ACQUIRING, S.FINALIZING, S.FAILED}),
    S.ACQUIRING: frozenset({S.FINALIZING, S.FAILED}),
    S.FINALIZING: frozenset({S.EXPORTING, S.INCOMPLETE, S.FAILED}),
    S.EXPORTING: frozenset({S.VERIFYING, S.INCOMPLETE, S.FAILED}),
    S.VERIFYING: frozenset({S.COMPLETED, S.INCOMPLETE, S.FAILED}),
    S.COMPLETED: frozenset(),
    S.INCOMPLETE: frozenset(),
    S.FAILED: frozenset(),
}


class InvalidTransition(RuntimeError):
    pass


def check_transition(current: AcquisitionState, new: AcquisitionState) -> None:
    if new not in TRANSITIONS[current]:
        raise InvalidTransition(f"transizione non ammessa: {current.value} -> {new.value}")
