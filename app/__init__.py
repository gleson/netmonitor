"""Fábrica de aplicação Flask."""

import hashlib
import logging
import os

from flask import Flask

from app.config import config_by_name
from app.extensions import db, migrate, login_manager, csrf, limiter, talisman, scheduler


def create_app(config_name: str | None = None) -> Flask:
    """Cria e configura a instância Flask.

    Args:
        config_name: Nome do ambiente ("development", "production", "testing").
                     Se não informado, lê de FLASK_ENV ou usa "development".
    """
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    app = Flask(__name__)
    cfg_cls = config_by_name[config_name]
    cfg_cls.validate()
    app.config.from_object(cfg_cls)

    # --- Logging ---
    logging.basicConfig(
        level=logging.DEBUG if app.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    app.logger.info("Iniciando aplicação NetMonitor (env=%s)", config_name)

    # --- Extensões ---
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # --- Cabeçalhos de segurança via Talisman ---
    # CSP permissiva o suficiente para o Bootstrap/Chart.js (CDN) + handlers
    # inline existentes nos templates. Força HTTPS apenas em produção.
    csp = {
        "default-src": "'self'",
        "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
        "style-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
        "font-src": ["'self'", "https://cdn.jsdelivr.net", "data:"],
        "img-src": ["'self'", "data:"],
        "connect-src": "'self'",
        "frame-ancestors": "'none'",
        "base-uri": "'self'",
        "form-action": "'self'",
    }
    talisman.init_app(
        app,
        content_security_policy=csp,
        force_https=not app.debug and not app.config.get("TESTING"),
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        session_cookie_secure=app.config.get("SESSION_COOKIE_SECURE", False),
        frame_options="DENY",
        referrer_policy="strict-origin-when-cross-origin",
    )

    # --- Blueprints ---
    _register_blueprints(app)

    # --- Contexto de template (variáveis globais) ---
    _register_template_context(app)

    # --- Scheduler (apenas fora de testes) ---
    # Com o reloader do Flask, existem dois processos: o pai (monitor) e o filho (worker).
    # O filho tem WERKZEUG_RUN_MAIN="true". Em produção essa env não existe.
    # Só iniciamos o scheduler no filho (dev) ou quando não há reloader (prod).
    if not app.config.get("TESTING"):
        is_reloader_parent = app.debug and os.environ.get("WERKZEUG_RUN_MAIN") is None
        if not is_reloader_parent:
            _init_scheduler(app)

    return app


def _register_blueprints(app: Flask):
    """Registra todos os blueprints da aplicação."""
    from app.views.auth import auth_bp
    from app.views.main import main_bp
    from app.views.devices import devices_bp
    from app.views.alerts import alerts_bp
    from app.views.scans import scans_bp
    from app.views.admin import admin_bp
    from app.views.notes import notes_bp
    from app.views.ports_info import ports_info_bp
    from app.views.export import export_bp
    from app.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(devices_bp, url_prefix="/devices")
    app.register_blueprint(alerts_bp, url_prefix="/alerts")
    app.register_blueprint(scans_bp, url_prefix="/scans")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(notes_bp, url_prefix="/notes")
    app.register_blueprint(ports_info_bp, url_prefix="/portas")
    app.register_blueprint(export_bp, url_prefix="/export")
    app.register_blueprint(api_bp, url_prefix="/api")


def _register_template_context(app: Flask):
    """Injeta variáveis globais e filtros nos templates."""
    from datetime import datetime, timezone, timedelta

    local_tz = app.config.get("LOCAL_TIMEZONE_OFFSET", -3)  # BRT = UTC-3
    _offset = timedelta(hours=local_tz)

    @app.template_filter("localtime")
    def localtime_filter(dt, fmt="%d/%m/%Y %H:%M"):
        """Converte datetime UTC para horário local e formata."""
        if not dt:
            return "-"
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        local_dt = dt + _offset
        return local_dt.strftime(fmt)

    @app.template_filter("localtime_short")
    def localtime_short_filter(dt):
        """Formato curto: só hora e minuto."""
        return localtime_filter(dt, fmt="%H:%M")

    @app.template_filter("localtime_full")
    def localtime_full_filter(dt):
        """Formato completo com segundos."""
        return localtime_filter(dt, fmt="%d/%m/%Y %H:%M:%S")

    @app.context_processor
    def inject_globals():
        from flask import session
        from app.models import Profile
        try:
            profiles = Profile.query.filter_by(is_active=True).order_by(Profile.name).all()
        except Exception:
            profiles = []

        active_profile = None
        try:
            pid = session.get("active_profile_id")
            if pid:
                active_profile = next((p for p in profiles if p.id == pid), None)
            if active_profile is None and profiles:
                active_profile = profiles[0]
        except Exception:
            if profiles:
                active_profile = profiles[0]

        # Contagem inicial de alertas abertos para o badge do navbar (atualizada
        # ao vivo via /api/alerts/open-count no front-end).
        open_alerts_count = 0
        try:
            from app.models import Alert
            q = Alert.query.filter(Alert.acknowledged_at.is_(None))
            if active_profile:
                q = q.filter_by(profile_id=active_profile.id)
            open_alerts_count = q.count()
        except Exception:
            open_alerts_count = 0

        return dict(
            all_profiles=profiles,
            active_profile=active_profile,
            open_alerts_count=open_alerts_count,
        )


# Mantém o descritor do lock vivo pelo tempo de vida do processo. Se for
# coletado pelo GC, o flock é liberado e outro worker poderia iniciar o
# scheduler — por isso fica em escopo de módulo.
_scheduler_lock_fd = None


def _acquire_scheduler_lock(app: Flask) -> bool:
    """Garante que apenas UM processo inicie o scheduler.

    Sob Gunicorn com múltiplos workers, cada worker chama create_app e
    iniciaria seu próprio APScheduler — os jobs rodariam N vezes em paralelo
    (alertas duplicados, carga de nmap multiplicada). Um flock não-bloqueante
    em arquivo resolve: o primeiro worker pega o lock e roda os jobs; os demais
    falham silenciosamente e seguem servindo requisições sem scheduler.

    Em plataformas sem fcntl (ex.: Windows) ou em caso de erro, retorna True
    para preservar o comportamento anterior (não pior que antes).
    """
    global _scheduler_lock_fd
    try:
        import fcntl
        import tempfile
    except ImportError:
        return True

    # Lock por banco de dados para não colidir entre instâncias distintas.
    db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "default")
    digest = hashlib.sha1(db_uri.encode()).hexdigest()[:12]
    lock_path = os.path.join(tempfile.gettempdir(), f"netmonitor-scheduler-{digest}.lock")

    try:
        fd = open(lock_path, "w")
        fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError):
        app.logger.info(
            "Scheduler já iniciado por outro processo (lock %s ocupado). "
            "Este worker servirá requisições sem scheduler.", lock_path,
        )
        return False

    _scheduler_lock_fd = fd  # mantém vivo → segura o lock
    return True


def _init_scheduler(app: Flask):
    """Inicializa o APScheduler e registra os jobs de scan."""
    from sqlalchemy import inspect
    from app.scanner.scheduling import (
        register_jobs_for_all_profiles,
        register_global_jobs,
    )

    if scheduler.running:
        return

    if not _acquire_scheduler_lock(app):
        return

    app.logger.info("Inicializando APScheduler...")
    with app.app_context():
        # Verifica se as tabelas já existem antes de consultar o banco.
        # Na primeira execução (antes de init-db), as tabelas ainda não foram criadas.
        try:
            inspector = inspect(db.engine)
            if "profiles" not in inspector.get_table_names():
                app.logger.warning(
                    "Tabela 'profiles' não encontrada. Execute 'flask init-db' primeiro. "
                    "Scheduler iniciado sem jobs."
                )
                scheduler.start()
                return
            register_jobs_for_all_profiles(app)
            register_global_jobs(app)
        except Exception:
            app.logger.exception("Erro ao registrar jobs do scheduler. Iniciando sem jobs.")

    scheduler.start()
    app.logger.info("APScheduler iniciado com sucesso.")
