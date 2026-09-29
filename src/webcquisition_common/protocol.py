"""Costanti del protocollo HTTP host <-> guest agent (versione 1)."""

AUTH_HEADER = "Authorization"
PROTOCOL_HEADER = "X-Webcquisition-Protocol"
API_PREFIX = "/v1"

HEALTH = f"{API_PREFIX}/health"
INTERFACES = f"{API_PREFIX}/interfaces"
SESSION_PREPARE = f"{API_PREFIX}/session/prepare"
CAPTURE_START = f"{API_PREFIX}/capture/start"
CAPTURE_STATUS = f"{API_PREFIX}/capture/status"
FIREFOX_START = f"{API_PREFIX}/firefox/start"
UI_START = f"{API_PREFIX}/ui/start"
STATUS = f"{API_PREFIX}/status"
SESSION_STOP = f"{API_PREFIX}/session/stop"
SESSION_SEAL = f"{API_PREFIX}/session/seal"
SESSION_RELEASE = f"{API_PREFIX}/session/release"
SESSION_RECOVER = f"{API_PREFIX}/session/recover"
FILES = f"{API_PREFIX}/files"
FILES_CONTENT = f"{API_PREFIX}/files/content"

#: Percorsi (relativi alla cartella del caso nel guest) del manifest guest.
GUEST_MANIFEST_REL = "metadata/guest-manifest.json"
GUEST_SUMS_REL = "metadata/SHA256SUMS.txt"

#: Sottocartelle della cartella del caso sul Desktop della VM.
GUEST_SUBDIRS = ("network", "tls", "browser", "screenshots", "operator", "metadata", "logs")

MAX_REQUEST_BODY = 1024 * 1024

#: Log eventi scritto dall'agent durante il recupero dopo uno spegnimento non controllato.
GUEST_RECOVERY_EVENTS_REL = "logs/guest-events-recovery.jsonl"


def classify(rel_path: str) -> str:
    """Categoria forense di un file del pacchetto acquisito (percorso relativo POSIX)."""
    top, _, rest = rel_path.partition("/")
    if not rest:
        return "operator.file"  # file lasciati dall'operatore nella radice della cartella caso
    if top == "network":
        return "original.network_capture" if rest.endswith(".pcapng") else "original.network_other"
    if top == "tls":
        return "original.tls_secrets"
    if top == "browser":
        return "original.browser_profile"
    if top == "screenshots":
        return "auto.screenshot_metadata" if rest.endswith(".json") else "auto.screenshot"
    if top == "operator":
        return "operator.file"
    if top == "metadata":
        return "guest.metadata"
    if top == "logs":
        return "guest.log"
    return "unclassified"
