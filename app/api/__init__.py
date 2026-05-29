"""Pacote de API JSON — endpoints consumidos pelo frontend via fetch/AJAX."""

from datetime import timezone

from flask import Blueprint

api_bp = Blueprint("api", __name__)


def to_iso(dt) -> str | None:
    """Converte datetime para ISO 8601 com timezone UTC explícito.

    Garante que o JavaScript do frontend interprete corretamente como UTC.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


from app.api import devices, alerts, metrics, health  # noqa: E402, F401
