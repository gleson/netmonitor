# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**NetMonitor** (Monitor_Flask) — Flask network monitoring app with multi-profile auto-discovery, port scanning, alerts and dashboard. UI and code comments are in **Portuguese (pt-BR)**; preserve language when editing user-facing strings and docstrings.

Stack: Flask 3 + SQLAlchemy 2 + Flask-Migrate (Alembic) + APScheduler + python-nmap + scapy. SQLite (`instance/netmonitor.db`). Bootstrap 5.3 dark theme.

## Common commands

All commands assume the venv is active:

```bash
source venv/bin/activate
```

Run app:
```bash
FLASK_APP=manage.py flask run            # dev server (debug, with reloader)
gunicorn 'manage:app'                    # production
```

Tests:
```bash
pytest                                   # all tests (uses pytest.ini → tests/)
pytest tests/test_scanner.py             # single file
pytest tests/test_scanner.py::test_name  # single test
pytest -x -q --tb=short                  # fail-fast, quiet
```

Database / migrations (Flask-Migrate / Alembic):
```bash
FLASK_APP=manage.py flask db upgrade                 # apply pending migrations
FLASK_APP=manage.py flask db migrate -m "message"    # autogenerate migration
FLASK_APP=manage.py flask init-db                    # create all tables (bootstrap)
```

App CLI (defined in `manage.py`):
```bash
flask seed-admin --password '<≥10 chars, letter+digit>'
flask create-user --username X --password Y --role {viewer|operator|admin}
flask set-role --username X --role admin
flask run-scan --profile-id 1 --scan-type {discovery|ports}
flask fix-placeholder-macs                # re-resolve 02:00:* MACs via ARP
flask backup-db                           # consistent SQLite backup to BACKUP_DIR
flask generate-fernet-key                 # for SNMP community encryption
```

## Architecture

### App factory & startup (`app/__init__.py`)
- `create_app(config_name)` selects `DevelopmentConfig` / `ProductionConfig` / `TestingConfig` from `app/config.py`.
- Registers extensions (db, login, csrf, limiter, Talisman with strict CSP/HSTS), blueprints, template globals/filters, then starts APScheduler.
- **Reloader gotcha:** in dev, Werkzeug forks two processes; the scheduler is only started in the child (`WERKZEUG_RUN_MAIN=="true"`) or in production (no reloader). Don't move scheduler init outside that guard or jobs will run twice.
- `inject_globals` provides `all_profiles` and `active_profile` (from `session["active_profile_id"]`) to every template.

### Multi-profile model (`app/models.py`)
Every scan, device and alert is scoped to a `Profile`. The active profile is in the user session; most views filter by it. Core models:
- `Profile` → `IpRange` (CIDRs to scan, with per-range port config) → `Device` (unique per `(profile_id, mac)`) → `DeviceIp` (history; one `is_current=True`) → `Port`.
- `Alert` (with `is_priority` for highlighted HOST_DOWN-confirmed alerts), `Scan` (audit log of every scan run), `Vulnerability`, `Note`, `DeviceOnlineSnapshot`, `AuditLog`, `User`.
- `AppSetting` is a key/value store for runtime-editable globals (e.g. quick host-down interval) — use `AppSetting.get_int(key, default)` / `set_value(key, val)`.

Timestamps are stored as **naive UTC**. Use `_utcnow()` in `models.py` and `scheduling.py` — don't mix with `datetime.utcnow()` or tz-aware values, the columns expect naive.

### Scanner & scheduler (`app/scanner/scheduling.py`)
Three per-profile jobs are registered for each active `Profile`:
1. **`run_host_discovery`** (every `profile.host_discovery_interval_minutes`, default 45) — ARP scan via `scan_ip_range` → upserts Device/DeviceIp, emits NEW_DEVICE / NEW_IP_FOR_MAC / IP_CONFLICT / UNAUTHORIZED_DEVICE alerts, records daily online snapshot.
2. **`run_port_scan`** (every `profile.port_scan_interval_minutes`, default 4) — batched scan from `_port_scan_queues[profile_id]`. Queue is rebuilt from DB when empty using a 24h per-device cooldown (`_PORT_SCAN_COOLDOWN_HOURS`). Newly discovered devices are pushed to the front via `prepend_to_port_scan_queue`.
3. **`quick_host_down_check`** (every `HOST_DOWN_QUICK_CHECK_INTERVAL_MINUTES`, default 5; editable in `/admin/scan-settings`) — pings devices with `alert_on_down=True`. Two consecutive failures (tracked in-process via `_quick_host_down_failures`) confirm HOST_DOWN and emit a `Severity.CRITICAL` alert with `is_priority=True`.

Plus one global job: `cleanup_old_data` (daily, retention from `*_RETENTION_DAYS` config).

**Important invariants when editing scan code:**
- `scan_ports_for_host` returns `(ports, host_found)`. The caller MUST check `host_found` before marking previously open ports as closed — otherwise a transient network hiccup closes everything and re-alerts on recovery.
- "Ports vanished bug": if a device had **≥2** mapped ports and a scan returns 0 with `host_found=True`, this is treated as a bug (likely firewall blocking the probe type). `run_port_scan` does NOT close those ports; instead it calls `_requeue_with_alternate_scan`, which cycles through `-sT` / `-sT --max-retries` / `-sA` via `_next_alternate_nmap_args`, and skips updating `last_port_scanned_at` so the device is rescanned soon. A real DHCP-driven device swap is detected separately because the MAC changes too.
- Alerts: a new port in state `filtered` is recorded but does NOT emit `NEW_PORT` (only `open` does). State transitions (`filtered→open`) still emit.
- All mutations of `_port_scan_queues` must hold `_port_scan_queues_lock`.

**Nmap permissions:** SYN scan (`-sS`) requires root (`os.geteuid() == 0`); without root the scanner falls back to `-sT` (TCP connect). OS detection (`-O`) also needs root. Tests don't require root.

### Blueprints (`app/views/`, `app/api/`)
URL prefixes are set in `_register_blueprints`. RBAC enforced via `require_role` from `app/auth_utils.py` (hierarchy `viewer < operator < admin`); sensitive mutations call `audit()` before committing.

Notification fan-out for CRITICAL alerts goes through `_maybe_notify` → `app/notifications.py` (webhook / SMTP, configured per-profile).

### Templates
Single base layout `app/templates/base.html` with dark Bootstrap. Custom Jinja filters `localtime` / `localtime_short` / `localtime_full` apply `LOCAL_TIMEZONE_OFFSET` (default −3 BRT) — always use them when rendering DB timestamps.

### Tests (`tests/`)
`conftest.py` provides `app` (session-scoped, in-memory SQLite via `TestingConfig`), `db` (function-scoped, table-clean between tests), `client`, `auth_client`, `sample_profile`, `sample_range`. CSRF and rate-limit are disabled in `TestingConfig`.
