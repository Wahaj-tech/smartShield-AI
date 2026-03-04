"""
SmartShield Backend — DPI Engine TCP Client

Handles all low-level TCP communication with the C++ DPI engine
running on 127.0.0.1:9091.
"""

import json
import socket
from typing import Any, Dict

import config
from utils.logger import get_logger

log = get_logger("dpi_client")


class DPIConnectionError(Exception):
    """Raised when the DPI engine is unreachable or returns garbage."""


def send_command(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Send a JSON command to the DPI engine and return the parsed response.

    Parameters
    ----------
    data : dict
        The command payload, e.g. ``{"action": "block_domain", "domain": "youtube.com"}``.

    Returns
    -------
    dict
        Parsed JSON response from the engine.

    Raises
    ------
    DPIConnectionError
        If the engine is unreachable, times out, or returns invalid JSON.
    """
    payload = json.dumps(data)
    log.info("→ DPI  %s", payload)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(config.DPI_TIMEOUT)
            sock.connect((config.DPI_HOST, config.DPI_PORT))
            sock.sendall(payload.encode("utf-8"))

            # Shut down the write half so the engine knows the message is
            # complete (mirroring the C++ handleClient logic).
            sock.shutdown(socket.SHUT_WR)

            # Read the full response (control responses are small).
            chunks: list[bytes] = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)

            raw = b"".join(chunks).decode("utf-8")
            log.info("← DPI  %s", raw)

            if not raw:
                raise DPIConnectionError("Empty response from DPI engine")

            return json.loads(raw)

    except socket.timeout as exc:
        log.error("DPI engine timeout: %s", exc)
        raise DPIConnectionError("DPI engine timed out") from exc
    except ConnectionRefusedError as exc:
        log.error("DPI engine unreachable: %s", exc)
        raise DPIConnectionError("DPI engine unreachable (connection refused)") from exc
    except OSError as exc:
        log.error("Socket error: %s", exc)
        raise DPIConnectionError(f"Socket error: {exc}") from exc
    except json.JSONDecodeError as exc:
        log.error("Invalid JSON from DPI engine: %s", exc)
        raise DPIConnectionError(f"Invalid JSON from DPI engine: {exc}") from exc
