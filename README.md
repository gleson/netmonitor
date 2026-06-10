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
- **Correlação de CVEs**: serviços/versões detectados são cruzados com a API do
  **NVD** (com cache e filtragem por versão CPE para reduzir falsos-positivos);
  CVEs no catálogo **CISA KEV** (exploração ativa) viram alerta CRITICAL
  prioritário. Sem tráfego na rede local — só consultas HTTPS externas.
- **Catálogo de referência de portas** (82 fichas em pt-BR): riscos, quando
  alertar, análise e comandos comentados (nmap, tcpdump, etc.), incluindo portas
  de adversários (Metasploit, ADB, Back Orifice), ICS/SCADA e roteadores.
- **Verificação de certificados TLS** (expiração) e baseline de portas
  (`is_authorized`) para suprimir reincidência de alertas conhecidos.
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
flask db upgrade            # cria/atualiza o schema (funciona em banco novo)
```

> A primeira migration (`00000000base`) cria o schema base, então `flask db upgrade`
> basta para um banco do zero — não é preciso rodar `flask init-db` antes.
> O comando `flask init-db` ainda existe como atalho de bootstrap (`db.create_all`),
> mas nesse caso rode `flask db stamp head` em seguida para registrar as migrations.

### Primeiro usuário admin

Num banco novo, o `flask db upgrade` **já cria o admin padrão** automaticamente:

```
usuário: admin
senha:   umaSenhaForte123
```

> ⚠️ **Troque essa senha após o primeiro acesso** — ela é pública (está aqui no
> repositório). Use **Admin → Usuários** na interface ou
> `flask seed-admin --password '<novaSenha>'`.

O seed só ocorre quando **não há nenhum usuário** (não sobrescreve deploys
existentes). Para definir credenciais diferentes já na criação, exporte as
variáveis antes do upgrade:

```bash
SEED_ADMIN_USERNAME=meuadmin SEED_ADMIN_PASSWORD='outraSenhaForte123' flask db upgrade
```

Para criar/promover um admin manualmente a qualquer momento:

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
flask db upgrade                                   # cria/atualiza o schema (banco novo ou existente)
flask init-db                                      # bootstrap alternativo via db.create_all (depois: flask db stamp head)
flask seed-admin --password '<senha>'              # cria/promove admin
flask create-user --username X --password Y --role {viewer|operator|admin}
flask set-role --username X --role admin
flask run-scan --profile-id 1 --scan-type {discovery|ports}
flask fix-placeholder-macs                         # re-resolve MACs 02:00:* via ARP
flask backup-db                                    # backup consistente do SQLite
flask generate-fernet-key                          # chave p/ cifrar community SNMP
flask update-kev                                   # atualiza o catálogo CISA KEV (sem LLM)
flask run-cve-scan                                 # roda a correlação de CVEs sob demanda
```

### Atualização de bases sem LLM

As bases técnicas podem ser atualizadas por scripts/cron, **sem depender de um
modelo de LLM** — útil para quem clona o repositório sem acesso a um:

```bash
flask update-kev                          # CISA KEV (exploração ativa) — feed público
python scripts/update_iana_ports.py       # nomes de serviço de portas (registro IANA)
sudo nmap --script-updatedb               # reindexa scripts NSE (atualizam com o nmap)
```

Detalhes (o que é/não é automatizável) em [`docs/atualizacao-bases.md`](docs/atualizacao-bases.md).

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
| `NVD_API_KEY` | — | API key do NVD (opcional): ~10× mais consultas de CVE/30s. |
| `CVE_LOOKUP_ENABLED` / `CVE_KEV_ENABLED` | `1` / `1` | Liga correlação de CVE / catálogo CISA KEV. |
| `CVE_MIN_CVSS_ALERT` | `7.0` | CVSS mínimo p/ gerar alerta de CVE (≥9.0 vira CRITICAL). |
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
  `CveCache`, `DeviceOnlineSnapshot`. Timestamps em **UTC naive**.
- **`app/scanner/scheduling.py`** — jobs por perfil (host discovery, port scan,
  quick host-down) + jobs globais (limpeza e backup).
- **`app/views/`, `app/api/`** — páginas e endpoints JSON (consumidos pelo dashboard).
- **`app/templates/`** — layout único `base.html` (Bootstrap escuro).

---

## Segurança

Ferramenta destinada a **monitoramento de redes próprias/autorizadas**. A varredura
de IPs é restrita aos ranges configurados em cada perfil. Use de acordo com as
políticas da sua organização e a legislação aplicável.
