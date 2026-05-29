# NetMonitor

Aplicação Flask de **monitoramento de rede** com descoberta automática de hosts
multi-perfil, varredura de portas, detecção de dispositivos móveis, alertas e
dashboard em tempo real.

> Interface e comentários em **pt-BR**.

---

## Recursos

- **Multi-perfil**: cada perfil de rede tem suas próprias faixas (CIDRs), intervalos
  de scan e configurações. Todo scan, dispositivo e alerta é escopado por perfil.
- **Descoberta de hosts** (ARP scan) com histórico de IP por MAC e detecção de:
  novos dispositivos, mudança de IP, conflito de IP e dispositivos não autorizados.
- **Varredura de portas** em fila, com cooldown por dispositivo (24h), detecção de
  serviços/versões e contorno automático de firewall (alterna `-sT`/`-sS`/`-sA`).
- **Quick host-down check**: ping leve (ICMP/ARP/TCP) com confirmação por dupla
  falha antes de gerar alerta CRITICAL prioritário.
- **Dashboard ao vivo**: cartões, gráficos (Chart.js) e histórico de scans que se
  atualizam sozinhos (sem F5); badge de alertas abertos em todas as páginas.
- **Alertas** com severidade (INFO/WARNING/CRITICAL) e **notificações** externas
  (webhook e e-mail/SMTP), com nível mínimo configurável por perfil.
- **RBAC**: `viewer < operator < admin`, com **audit log** de ações sensíveis.
- **Backup automático** do SQLite (agendado) + comando CLI.
- **Segurança**: CSP/HSTS via Talisman, CSRF, rate-limit no login, **bloqueio de
  conta** por excesso de tentativas, criptografia Fernet das communities SNMP.
- Scans sob demanda: ping, portas, detecção de SO, scan de vulnerabilidades
  (`nmap --script=vuln`), SNMP e identificação de dispositivos móveis.

## Stack

Flask 3 · SQLAlchemy 2 · Flask-Migrate (Alembic) · APScheduler · python-nmap ·
scapy · Bootstrap 5.3 (tema escuro) · Chart.js. Banco padrão: **SQLite**
(`instance/netmonitor.db`); compatível com PostgreSQL.

---

## Instalação

Requer Python 3.11+ e o **nmap** instalado no sistema.

```bash
git clone git@github.com:gleson/netmonitor.git
cd netmonitor

python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env        # ajuste SECRET_KEY, DATABASE_URL, etc.
```

### Banco de dados

```bash
export FLASK_APP=manage.py
flask db upgrade            # aplica as migrations
# (ou, num banco novo sem migrations: flask init-db)
```

### Primeiro usuário admin

```bash
flask seed-admin --password 'umaSenhaForte123'   # mín. 10 chars, letra + dígito
```

---

## Executando

```bash
source venv/bin/activate

# Desenvolvimento (debug + reloader)
FLASK_APP=manage.py flask run

# Produção
gunicorn 'manage:app'
```

Acesse `http://localhost:5000` e faça login.

> **Permissões de root:** SYN scan (`-sS`) e detecção de SO (`-O`) exigem root.
> Sem root, o scanner cai automaticamente para TCP connect (`-sT`).

> **Gunicorn multi-worker:** o scheduler é iniciado por **um único** processo,
> garantido por um lock de arquivo (`flock`) — os scans não são duplicados.

---

## Comandos CLI

```bash
flask db upgrade                                   # aplica migrations
flask init-db                                      # cria tabelas (bootstrap)
flask seed-admin --password '<senha>'              # cria/promove admin
flask create-user --username X --password Y --role {viewer|operator|admin}
flask set-role --username X --role admin
flask run-scan --profile-id 1 --scan-type {discovery|ports}
flask fix-placeholder-macs                         # re-resolve MACs 02:00:* via ARP
flask backup-db                                    # backup consistente do SQLite
flask generate-fernet-key                          # chave p/ cifrar community SNMP
```

## Testes

```bash
pytest                          # todos
pytest tests/test_scanner.py    # um arquivo
pytest -x -q --tb=short         # fail-fast
```

---

## Configuração (variáveis de ambiente)

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `SECRET_KEY` | *(obrigatória em prod)* | Chave de sessão. |
| `DATABASE_URL` | SQLite local | URI do banco. |
| `FERNET_KEY` | — | Cifra as communities SNMP (`flask generate-fernet-key`). |
| `LOGIN_MAX_FAILED_ATTEMPTS` | `5` | Falhas antes de bloquear a conta (0 desativa). |
| `LOGIN_LOCKOUT_MINUTES` | `15` | Janela do bloqueio de login. |
| `BACKUP_INTERVAL_HOURS` | `24` | Intervalo do backup automático (0 desativa). |
| `BACKUP_RETENTION_DAYS` | `30` | Remove backups mais antigos (0 mantém todos). |
| `BACKUP_DIR` | `./backups` | Destino dos backups. |
| `SCAN_RETENTION_DAYS` / `ALERT_RETENTION_DAYS` / `SNAPSHOT_RETENTION_DAYS` / `AUDIT_LOG_RETENTION_DAYS` | `30/90/180/365` | Retenção de dados (0 desativa a limpeza). |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_FROM` / `SMTP_USE_TLS` | — | Envio de e-mail para alertas. |
| `NOTIFICATIONS_ENABLED` | `1` | Liga/desliga notificações externas. |

Ajustes adicionais em `app/config.py` e, em runtime, no painel **Admin → Configurações de Scan**.

---

## Arquitetura (visão geral)

- **`app/__init__.py`** — fábrica `create_app`, extensões, CSP/HSTS, blueprints e
  inicialização do scheduler (guardado contra reloader/multi-worker).
- **`app/models.py`** — modelos: `Profile → IpRange → Device → DeviceIp/Port`,
  além de `Alert`, `Scan`, `Vulnerability`, `Note`, `User`, `AuditLog`, `AppSetting`,
  `DeviceOnlineSnapshot`. Timestamps em **UTC naive**.
- **`app/scanner/scheduling.py`** — jobs por perfil (host discovery, port scan,
  quick host-down) + jobs globais (limpeza e backup).
- **`app/views/`, `app/api/`** — páginas e endpoints JSON (consumidos pelo dashboard).
- **`app/templates/`** — layout único `base.html` (Bootstrap escuro).

---

## Segurança

Ferramenta destinada a **monitoramento de redes próprias/autorizadas**. A varredura
de IPs é restrita aos ranges configurados em cada perfil. Use de acordo com as
políticas da sua organização e a legislação aplicável.
