"""Configurações da aplicação."""

import os

basedir = os.path.abspath(os.path.dirname(__file__))

_DEV_SECRET_KEY = "dev-secret-key-troque-em-prod"


class Config:
    """Configurações base compartilhadas por todos os ambientes."""

    SECRET_KEY = os.environ.get("SECRET_KEY", _DEV_SECRET_KEY)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(basedir, '..', 'instance', 'netmonitor.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Cookies de sessão ---
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    # Duração do cookie "remember me"
    REMEMBER_COOKIE_DURATION = 60 * 60 * 24 * 14  # 14 dias

    # --- Rate limit ---
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True

    # --- Bloqueio de conta por tentativas de login falhas ---
    # Após LOGIN_MAX_FAILED_ATTEMPTS falhas (por usuário) dentro da janela
    # LOGIN_LOCKOUT_MINUTES, novas tentativas são bloqueadas até a janela expirar
    # ou um login bem-sucedido. 0 desativa o bloqueio (mantém só o rate-limit/IP).
    LOGIN_MAX_FAILED_ATTEMPTS = int(os.environ.get("LOGIN_MAX_FAILED_ATTEMPTS", 5))
    LOGIN_LOCKOUT_MINUTES = int(os.environ.get("LOGIN_LOCKOUT_MINUTES", 15))

    # --- Intervalos padrão de scan (em minutos) ---
    DEFAULT_HOST_DISCOVERY_INTERVAL = 45
    DEFAULT_PORT_SCAN_INTERVAL = 4

    # --- Portas padrão para scan ---
    DEFAULT_SCAN_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,5432,5900,8080,8443"

    # --- Limites de concorrência ---
    DEFAULT_MAX_CONCURRENT_SCANS = 3

    # --- Delay entre scans de hosts individuais (segundos) ---
    SCAN_INTER_HOST_DELAY = 0.3

    # --- Threshold para considerar host "online" (minutos) ---
    # Deve ser >= 2× o host_discovery_interval_minutes do perfil (padrão 45 min)
    # para tolerar reinicios do app e falhas pontuais de discovery sem falso-offline.
    HOST_ONLINE_THRESHOLD_MINUTES = 70

    # --- Paginação ---
    ITEMS_PER_PAGE = 25

    # --- Fuso horário local (offset em horas relativo a UTC) ---
    # BRT (Brasília) = -3
    LOCAL_TIMEZONE_OFFSET = -3

    # --- APScheduler ---
    SCHEDULER_API_ENABLED = False

    # --- Alertas HOST_DOWN ---
    # Quick check: ping leve (ICMP/ARP/TCP) em hosts com alert_on_down=True.
    # Default 5 min. Editável em /admin/scan-settings (chave 'host_down_quick_check_interval').
    # Após 2 falhas consecutivas, gera alerta CRITICAL is_priority=True.
    HOST_DOWN_QUICK_CHECK_INTERVAL_MINUTES = 5

    # --- Retenção de dados ---
    # 0 = sem limpeza automática. Job roda diariamente.
    SCAN_RETENTION_DAYS = int(os.environ.get("SCAN_RETENTION_DAYS", 30))
    ALERT_RETENTION_DAYS = int(os.environ.get("ALERT_RETENTION_DAYS", 90))
    SNAPSHOT_RETENTION_DAYS = int(os.environ.get("SNAPSHOT_RETENTION_DAYS", 180))
    AUDIT_LOG_RETENTION_DAYS = int(os.environ.get("AUDIT_LOG_RETENTION_DAYS", 365))

    # --- Notificações (webhook / SMTP) ---
    NOTIFICATIONS_ENABLED = os.environ.get("NOTIFICATIONS_ENABLED", "1") == "1"
    SMTP_HOST = os.environ.get("SMTP_HOST", "")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
    SMTP_USER = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    SMTP_FROM = os.environ.get("SMTP_FROM", "netmonitor@localhost")
    SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "1") == "1"

    # --- Backup ---
    # Diretório onde `flask backup-db` grava os arquivos. Padrão: ./backups
    BACKUP_DIR = os.environ.get("BACKUP_DIR", os.path.join(basedir, "..", "backups"))
    # Backup automático agendado. 0 = desativado (use cron/`flask backup-db`).
    BACKUP_INTERVAL_HOURS = int(os.environ.get("BACKUP_INTERVAL_HOURS", 24))
    # Remove backups .db.gz mais antigos que N dias. 0 = mantém todos.
    BACKUP_RETENTION_DAYS = int(os.environ.get("BACKUP_RETENTION_DAYS", 30))

    # --- Criptografia de credenciais SNMP (Fernet) ---
    # Gere com: flask generate-fernet-key
    # Sem esta variável, a community é armazenada em texto puro.
    FERNET_KEY = os.environ.get("FERNET_KEY", "")

    # --- Correlação CVE (NVD) ---
    # Job diário que correlaciona service_name/service_version das portas
    # abertas com CVEs conhecidos via API do NVD. Não gera tráfego na rede
    # local (só consultas HTTPS externas, com cache em cve_cache).
    CVE_LOOKUP_ENABLED = os.environ.get("CVE_LOOKUP_ENABLED", "1") == "1"
    CVE_LOOKUP_INTERVAL_HOURS = int(os.environ.get("CVE_LOOKUP_INTERVAL_HOURS", 24))
    CVE_CACHE_TTL_DAYS = int(os.environ.get("CVE_CACHE_TTL_DAYS", 7))
    # CVSS mínimo para registrar Vulnerability + alerta (>=9.0 vira CRITICAL).
    CVE_MIN_CVSS_ALERT = float(os.environ.get("CVE_MIN_CVSS_ALERT", 7.0))
    # Máximo de consultas não-cacheadas à API por execução (rate-limit NVD).
    CVE_MAX_LOOKUPS_PER_RUN = int(os.environ.get("CVE_MAX_LOOKUPS_PER_RUN", 30))
    # API key do NVD (opcional). Com chave o limite sobe de ~5 para ~50 req/30s
    # e a pausa entre consultas cai de 6.5s para 0.7s. Solicite em
    # https://nvd.nist.gov/developers/request-an-api-key
    NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
    # Catálogo CISA KEV (vulnerabilidades sob exploração ativa) — feed público,
    # sem LLM nem API key. CVEs em KEV viram alerta CRITICAL is_priority=True.
    CVE_KEV_ENABLED = os.environ.get("CVE_KEV_ENABLED", "1") == "1"
    CVE_KEV_REFRESH_HOURS = int(os.environ.get("CVE_KEV_REFRESH_HOURS", 24))

    # --- Check rápido de portas críticas ---
    # Escaneia apenas CRITICAL_PORTS (~11 portas) nos devices online a cada
    # N minutos — detecta exposição grave em horas em vez de 24h, com tráfego
    # mínimo. 0 desativa.
    CRITICAL_PORTS_CHECK_INTERVAL_MINUTES = int(
        os.environ.get("CRITICAL_PORTS_CHECK_INTERVAL_MINUTES", 120)
    )

    # --- Scan UDP ---
    # Scan semanal de um conjunto pequeno de portas UDP (DNS, SNMP, NTP,
    # NetBIOS, SSDP...). Requer root (-sU usa raw sockets). 0 desativa.
    UDP_SCAN_INTERVAL_HOURS = int(os.environ.get("UDP_SCAN_INTERVAL_HOURS", 168))

    # --- Verificação de certificados TLS ---
    # Checa expiração de certificados em portas HTTPS abertas. 0 desativa.
    TLS_CHECK_INTERVAL_HOURS = int(os.environ.get("TLS_CHECK_INTERVAL_HOURS", 24))
    TLS_CERT_WARN_DAYS = int(os.environ.get("TLS_CERT_WARN_DAYS", 15))

    # --- Dedupe de alertas de porta ---
    # Não re-emite o mesmo alerta (device+porta) dentro desta janela, evitando
    # spam quando o estado oscila (flapping filtered<->open).
    PORT_ALERT_DEDUP_HOURS = int(os.environ.get("PORT_ALERT_DEDUP_HOURS", 6))

    @classmethod
    def validate(cls):
        """Hook para validação específica por ambiente. Override em subclasses."""
        return


class DevelopmentConfig(Config):
    DEBUG = True
    # Em dev, HTTP é ok — não forçar HTTPS nem cookies secure.
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False


class ProductionConfig(Config):
    DEBUG = False
    # Cookies só trafegam sobre HTTPS em produção.
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True

    @classmethod
    def validate(cls):
        if not os.environ.get("SECRET_KEY") or os.environ.get("SECRET_KEY") == _DEV_SECRET_KEY:
            raise RuntimeError(
                "SECRET_KEY deve ser definida via variável de ambiente em produção. "
                "Gere uma chave forte com `python -c 'import secrets; print(secrets.token_hex(32))'`."
            )


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    # Desativa rate-limit e HTTPS forçado nos testes.
    RATELIMIT_ENABLED = False
    SESSION_COOKIE_SECURE = False
    # Sem chamadas de rede externas em testes.
    CVE_LOOKUP_ENABLED = False
    CVE_KEV_ENABLED = False


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}
