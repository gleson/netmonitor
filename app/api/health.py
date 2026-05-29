"""Endpoint de health-check para monitoramento externo."""

from flask import jsonify
from sqlalchemy import text

from app.api import api_bp
from app.extensions import db, limiter


@api_bp.route("/healthz")
@limiter.exempt
def healthz():
    """Retorna status da aplicação e do banco de dados.

    Não requer autenticação — destinado a load balancers e sistemas de
    monitoramento externos como Uptime Kuma, Zabbix ou Nagios.
    """
    db_ok = False
    try:
        db.session.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        pass

    status = "ok" if db_ok else "degraded"
    code = 200 if db_ok else 503
    return jsonify({"status": status, "db": "ok" if db_ok else "error"}), code
