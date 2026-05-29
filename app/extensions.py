"""Instâncias centralizadas das extensões Flask.

Importadas e inicializadas na fábrica de app (create_app).
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from apscheduler.schedulers.background import BackgroundScheduler

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()

# Rate limiter — storage em memória por padrão. Para produção multi-worker,
# configure RATELIMIT_STORAGE_URI (ex.: "redis://localhost:6379") na Config.
limiter = Limiter(key_func=get_remote_address)

# Talisman — aplica cabeçalhos de segurança (CSP, HSTS, X-Frame-Options, etc.)
talisman = Talisman()

# Scheduler global – iniciado apenas uma vez dentro de create_app.
# timezone='UTC' garante que naive datetimes (retornados por _utcnow()) sejam
# interpretados como UTC e não como horário local — sem isso os jobs ficam
# atrasados pelo offset do sistema (ex.: BRT é 3 h atrás de UTC).
scheduler = BackgroundScheduler(daemon=True, timezone='UTC')

login_manager.login_view = "auth.login"
login_manager.login_message = "Faça login para acessar esta página."
login_manager.login_message_category = "warning"
