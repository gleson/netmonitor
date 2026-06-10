"""Endpoints JSON para métricas, dados de gráficos e scan sob demanda."""

import threading
from datetime import timedelta

from flask import jsonify, request, current_app
from flask_login import login_required
from sqlalchemy import func

from app.api import api_bp, to_iso
from app.auth_utils import audit, require_role
from app.extensions import db
from app.models import (
    Device, Alert, Scan, ScanType, ScanStatus, Profile, DeviceOnlineSnapshot,
    ROLE_OPERATOR, _utcnow,
)


def _local_offset_hours() -> int:
    """Offset (em horas) UTC → fuso local configurado."""
    return int(current_app.config.get("LOCAL_TIMEZONE_OFFSET", -3))


def _local_datetime(col):
    """Expressão SQL que adiciona o offset local a uma coluna UTC.

    SQLite suporta `datetime(col, '+N hours')`. É o que usamos para
    agrupar por dia/hora no fuso local (evita o bug 21–00h BRT caindo
    no dia seguinte).
    """
    offset = _local_offset_hours()
    sign = "+" if offset >= 0 else "-"
    return func.datetime(col, f"{sign}{abs(offset)} hours")


@api_bp.route("/metrics/devices-timeline")
@login_required
def devices_timeline():
    """Retorna dados de timeline: quantos devices foram vistos ao longo do tempo.

    Útil para gráficos de linha no dashboard.
    Query params: profile_id, days (padrão 30).
    """
    profile_id = request.args.get("profile_id", type=int)
    days = request.args.get("days", 30, type=int)

    if not profile_id:
        return jsonify({"error": "profile_id é obrigatório."}), 400

    now = _utcnow()
    start = now - timedelta(days=days)

    # Agrupa devices por dia no fuso local (#6) — sem isso 21:00–23:59 BRT
    # caem no dia seguinte UTC.
    local_day = func.date(_local_datetime(Device.first_seen_at))

    results = (
        db.session.query(
            local_day.label("date"),
            func.count(Device.id).label("count"),
        )
        .filter(Device.profile_id == profile_id)
        .filter(Device.first_seen_at >= start)
        .group_by(local_day)
        .order_by(local_day)
        .all()
    )

    # Mapa dia -> novos devices
    new_by_date = {str(row.date): row.count for row in results}

    # Conta cumulativo total de devices antes do período
    total_before = Device.query.filter(
        Device.profile_id == profile_id,
        Device.first_seen_at < start,
    ).count()

    # Preenche TODOS os dias do período (contados no fuso local).
    offset_h = _local_offset_hours()
    local_start = start + timedelta(hours=offset_h)
    timeline = []
    cumulative = total_before
    for i in range(days + 1):
        day = (local_start + timedelta(days=i)).strftime("%Y-%m-%d")
        new_count = new_by_date.get(day, 0)
        cumulative += new_count
        timeline.append({
            "date": day,
            "new_devices": new_count,
            "total_devices": cumulative,
        })

    return jsonify({"timeline": timeline, "days": days})


@api_bp.route("/metrics/online-timeline")
@login_required
def online_timeline():
    """Histórico de dispositivos online e novos, com granularidade por período.

    Query params:
      - profile_id: obrigatório
      - period: 'day' (24h/hora) | 'week' (7d/hora) | '15days' (padrão, /dia) | 'month' (/dia)
    """
    profile_id = request.args.get("profile_id", type=int)
    period = request.args.get("period", "15days")

    if not profile_id:
        return jsonify({"error": "profile_id é obrigatório."}), 400

    # period → (span, granularity, delta_unit)
    period_map = {
        "day":    (24,  "hour"),
        "week":   (168, "hour"),
        "15days": (15,  "day"),
        "month":  (30,  "day"),
    }
    if period not in period_map:
        period = "15days"

    span, granularity = period_map[period]
    now = _utcnow()

    if granularity == "hour":
        start = now - timedelta(hours=span)
        fmt_sqlite = "%Y-%m-%d %H:00"
        slot_delta = timedelta(hours=1)
        total_slots = span
    else:
        start = now - timedelta(days=span)
        fmt_sqlite = "%Y-%m-%d"
        slot_delta = timedelta(days=1)
        total_slots = span

    # Buckets em fuso local (#6) — snapshots/first_seen são UTC no DB.
    snap_local = _local_datetime(DeviceOnlineSnapshot.recorded_at)
    dev_local = _local_datetime(Device.first_seen_at)

    online_rows = (
        db.session.query(
            func.strftime(fmt_sqlite, snap_local).label("slot"),
            func.max(DeviceOnlineSnapshot.online_count).label("count"),
        )
        .filter(
            DeviceOnlineSnapshot.profile_id == profile_id,
            DeviceOnlineSnapshot.recorded_at >= start,
        )
        .group_by(func.strftime(fmt_sqlite, snap_local))
        .all()
    )
    online_by_slot = {row.slot: row.count for row in online_rows}

    new_rows = (
        db.session.query(
            func.strftime(fmt_sqlite, dev_local).label("slot"),
            func.count(Device.id).label("count"),
        )
        .filter(Device.profile_id == profile_id, Device.first_seen_at >= start)
        .group_by(func.strftime(fmt_sqlite, dev_local))
        .all()
    )
    new_by_slot = {row.slot: row.count for row in new_rows}

    # Slots preenchidos no fuso local para casar com as chaves dos buckets.
    offset_h = _local_offset_hours()
    local_start = start + timedelta(hours=offset_h)
    timeline = []
    for i in range(total_slots + 1):
        slot_dt = local_start + slot_delta * i
        key = slot_dt.strftime(fmt_sqlite)
        timeline.append({
            "slot": key,
            "online_devices": online_by_slot.get(key, 0),
            "new_devices": new_by_slot.get(key, 0),
        })

    return jsonify({"timeline": timeline, "period": period, "granularity": granularity})


@api_bp.route("/metrics/alerts-summary")
@login_required
def alerts_summary():
    """Resumo de alertas por tipo e severidade.

    Query params: profile_id, days (padrão 7).
    """
    profile_id = request.args.get("profile_id", type=int)
    days = request.args.get("days", 7, type=int)

    if not profile_id:
        return jsonify({"error": "profile_id é obrigatório."}), 400

    now = _utcnow()
    start = now - timedelta(days=days)

    by_type = (
        db.session.query(
            Alert.alert_type, func.count(Alert.id)
        )
        .filter(Alert.profile_id == profile_id, Alert.created_at >= start)
        .group_by(Alert.alert_type)
        .all()
    )

    by_severity = (
        db.session.query(
            Alert.severity, func.count(Alert.id)
        )
        .filter(Alert.profile_id == profile_id, Alert.created_at >= start)
        .group_by(Alert.severity)
        .all()
    )

    return jsonify({
        "by_type": {t.value: c for t, c in by_type},
        "by_severity": {s.value: c for s, c in by_severity},
        "days": days,
    })


@api_bp.route("/metrics/dashboard-stats")
@login_required
def dashboard_stats():
    """Cartões de resumo do dashboard (atualização ao vivo, sem F5).

    Query params: profile_id (obrigatório).
    Espelha o cálculo de app/views/main.py::dashboard para que o front-end
    possa atualizar os números periodicamente via fetch.
    """
    profile_id = request.args.get("profile_id", type=int)
    if not profile_id:
        return jsonify({"error": "profile_id é obrigatório."}), 400

    from app.stats import compute_dashboard_stats

    return jsonify(compute_dashboard_stats(profile_id))


@api_bp.route("/metrics/scan-history")
@login_required
def scan_history():
    """Histórico recente de scans.

    Query params: profile_id, limit (padrão 20).
    """
    profile_id = request.args.get("profile_id", type=int)
    limit = request.args.get("limit", 20, type=int)

    if not profile_id:
        return jsonify({"error": "profile_id é obrigatório."}), 400

    scans = (
        Scan.query
        .filter_by(profile_id=profile_id)
        .order_by(Scan.started_at.desc())
        .limit(limit)
        .all()
    )

    return jsonify({
        "scans": [
            {
                "id": s.id,
                "scan_type": s.scan_type.value,
                "status": s.status.value,
                "started_at": to_iso(s.started_at),
                "finished_at": to_iso(s.finished_at),
                "hosts_found": s.hosts_found,
                "target_ip": s.target_ip,
                "error_message": s.error_message,
                "result_summary": s.result_summary,
            }
            for s in scans
        ],
    })


# ---------------------------------------------------------------------------
# Scan imediato (sob demanda) para um profile inteiro
# ---------------------------------------------------------------------------

# Controle para não disparar múltiplos scans simultâneos do mesmo tipo/profile.
# Mutações de _running_scans só acontecem sob _scans_lock para evitar race
# entre dois POSTs concorrentes ao /scan/trigger.
_running_scans: dict[str, bool] = {}
_scans_lock = threading.Lock()


@api_bp.route("/scan/trigger", methods=["POST"])
@login_required
@require_role(ROLE_OPERATOR)
def trigger_scan():
    """Dispara um scan imediato para um profile.

    Espera JSON: {"profile_id": int, "scan_type": "discovery" | "ports"}
    O scan roda em background thread para não bloquear a resposta.
    """
    data = request.get_json(silent=True) or {}
    profile_id = data.get("profile_id")
    scan_type = data.get("scan_type", "discovery")

    if not profile_id:
        return jsonify({"error": "profile_id é obrigatório."}), 400

    if scan_type not in ("discovery", "ports"):
        return jsonify({"error": "scan_type deve ser 'discovery' ou 'ports'."}), 400

    profile = db.session.get(Profile, profile_id)
    if not profile:
        return jsonify({"error": "Profile não encontrado."}), 404

    lock_key = f"{scan_type}_{profile_id}"

    # Check-and-set atômico: evita que dois requests simultâneos passem
    # pela verificação e disparem o scan duas vezes.
    with _scans_lock:
        if _running_scans.get(lock_key):
            return jsonify({
                "status": "already_running",
                "message": f"Um scan de {scan_type} já está em execução para este profile.",
            }), 409
        _running_scans[lock_key] = True

    audit("scan.trigger", "profile", profile_id, details=scan_type)
    db.session.commit()

    # Dispara em background thread
    app = current_app._get_current_object()

    def _run():
        try:
            with app.app_context():
                if scan_type == "discovery":
                    from app.scanner.scheduling import run_host_discovery
                    run_host_discovery(profile_id)
                else:
                    from app.scanner.scheduling import run_port_scan
                    run_port_scan(profile_id)
        finally:
            with _scans_lock:
                _running_scans[lock_key] = False

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    return jsonify({
        "status": "started",
        "message": f"Scan '{scan_type}' iniciado para profile '{profile.name}'.",
        "profile_id": profile_id,
        "scan_type": scan_type,
    })


@api_bp.route("/scan/status")
@login_required
def scan_status():
    """Retorna o status dos scans em execução.

    Query params: profile_id (opcional).
    """
    profile_id = request.args.get("profile_id", type=int)

    with _scans_lock:
        snapshot = list(_running_scans.items())

    running = []
    for key, is_running in snapshot:
        if not is_running:
            continue
        stype, pid = key.rsplit("_", 1)
        if profile_id and int(pid) != profile_id:
            continue
        running.append({"scan_type": stype, "profile_id": int(pid)})

    return jsonify({"running_scans": running})
