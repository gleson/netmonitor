#!/usr/bin/env python3
"""Ponto de entrada principal para rodar a aplicação e tarefas CLI."""

import os

import click
from app import create_app, db

app = create_app()


@app.cli.command("init-db")
def init_db():
    """Cria todas as tabelas no banco de dados."""
    with app.app_context():
        db.create_all()
        click.echo("Banco de dados inicializado.")


@app.cli.command("seed-admin")
@click.option("--username", default="admin", help="Nome do usuário admin.")
@click.option("--password", required=True, help="Senha do usuário admin (mín 10, letras+dígitos).")
def seed_admin(username, password):
    """Cria o usuário administrador padrão."""
    from app.models import User, ROLE_ADMIN

    err = User.validate_password(password)
    if err:
        raise click.ClickException(err)

    with app.app_context():
        existing = User.query.filter_by(username=username).first()
        if existing:
            if existing.role != ROLE_ADMIN:
                existing.role = ROLE_ADMIN
                db.session.commit()
                click.echo(f"Usuário '{username}' promovido a admin.")
            else:
                click.echo(f"Usuário '{username}' já existe.")
            return
        user = User(username=username, role=ROLE_ADMIN)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"Usuário '{username}' criado com sucesso (role=admin).")


@app.cli.command("set-role")
@click.option("--username", required=True, help="Usuário alvo.")
@click.option(
    "--role",
    type=click.Choice(["viewer", "operator", "admin"]),
    required=True,
    help="Novo role.",
)
def set_role(username, role):
    """Altera o role de um usuário existente."""
    from app.models import User

    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if not user:
            click.echo(f"Usuário '{username}' não encontrado.")
            return
        old = user.role
        user.role = role
        db.session.commit()
        click.echo(f"Role de '{username}' alterado: {old} -> {role}.")


@app.cli.command("create-user")
@click.option("--username", required=True)
@click.option("--password", required=True)
@click.option(
    "--role",
    type=click.Choice(["viewer", "operator", "admin"]),
    default="viewer",
)
def create_user(username, password, role):
    """Cria um novo usuário."""
    from app.models import User

    err = User.validate_password(password)
    if err:
        raise click.ClickException(err)

    with app.app_context():
        if User.query.filter_by(username=username).first():
            click.echo(f"Usuário '{username}' já existe.")
            return
        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f"Usuário '{username}' criado com role='{role}'.")


@app.cli.command("run-scan")
@click.option("--profile-id", type=int, required=True, help="ID do perfil de rede.")
@click.option("--scan-type", type=click.Choice(["discovery", "ports"]), default="discovery")
def run_scan(profile_id, scan_type):
    """Executa um scan manualmente para um perfil específico."""
    from app.scanner.scheduling import run_host_discovery, run_port_scan

    with app.app_context():
        if scan_type == "discovery":
            click.echo(f"Iniciando host discovery para profile {profile_id}...")
            run_host_discovery(profile_id)
        else:
            click.echo(f"Iniciando port scan para profile {profile_id}...")
            run_port_scan(profile_id)
        click.echo("Scan concluído.")


@app.cli.command("fix-placeholder-macs")
@click.option("--profile-id", type=int, default=None, help="Limita a um perfil.")
@click.option("--prefix", default="02:00:", help="Prefixo de MAC placeholder.")
def fix_placeholder_macs(profile_id, prefix):
    """Re-resolve MACs placeholder para os devices online via tabela ARP."""
    from app.scanner.scheduling import refresh_placeholder_macs

    with app.app_context():
        stats = refresh_placeholder_macs(profile_id=profile_id, prefix=prefix)
        click.echo(
            f"Verificados: {stats['checked']} | "
            f"Atualizados: {stats['updated']} | "
            f"Offline: {stats['offline']} | "
            f"Online sem ARP: {stats['online_not_resolved']} | "
            f"Conflitos: {stats['conflicts']}"
        )
        for d in stats["details"]:
            if d["result"] == "atualizado":
                click.echo(f"  [OK] {d['ip']:<16} {d['old_mac']} -> {d['new_mac']}")
            elif d["result"] == "conflito":
                click.echo(
                    f"  [CONFLITO] {d['ip']:<16} {d['old_mac']} -> {d['new_mac']} "
                    f"(MAC já em uso pelo device #{d['conflict_device_id']})"
                )


@app.cli.command("backup-db")
@click.option("--dest", default=None, help="Diretório de destino (padrão: BACKUP_DIR do config).")
@click.option("--compress/--no-compress", default=True, help="Comprime o backup com gzip.")
def backup_db(dest, compress):
    """Copia o banco SQLite para um arquivo de backup com timestamp.

    Usa sqlite3.connect().backup() para garantir consistência mesmo com a
    aplicação em execução. Aplica a retenção de BACKUP_RETENTION_DAYS.
    O mesmo backup roda automaticamente via scheduler (BACKUP_INTERVAL_HOURS).

    Exemplo de agendamento via cron (diário às 02:00):
        0 2 * * * /caminho/para/venv/bin/flask --app manage backup-db >> /var/log/netmonitor-backup.log 2>&1
    """
    from app.scanner.scheduling import perform_backup

    with app.app_context():
        try:
            dest_path = perform_backup(dest=dest, compress=compress)
        except RuntimeError as exc:
            raise click.ClickException(str(exc))

    size_kb = os.path.getsize(dest_path) // 1024
    click.echo(f"Backup salvo em: {dest_path} ({size_kb} KB)")


@app.cli.command("update-kev")
def update_kev():
    """Atualiza o catálogo CISA KEV (vulnerabilidades sob exploração ativa).

    Feed público, sem LLM nem API key — ideal para agendar em cron:
        0 6 * * *  cd /caminho && FLASK_APP=manage.py flask update-kev
    """
    from app.scanner.cve import update_kev_catalog
    with app.app_context():
        count = update_kev_catalog()
    if count is None:
        raise click.ClickException("Falha ao baixar o catálogo CISA KEV (rede?).")
    click.echo(f"Catálogo CISA KEV atualizado: {count} CVEs.")


@app.cli.command("run-cve-scan")
def run_cve_scan():
    """Roda a correlação de CVEs sob demanda (mesmo job do scheduler)."""
    from app.scanner.cve import correlate_cves
    with app.app_context():
        stats = correlate_cves()
    click.echo(
        f"Correlação CVE: {stats['combos']} combinações, "
        f"{stats['lookups']} consultas, {stats['vulns_created']} vulnerabilidades, "
        f"{stats['alerts']} alertas."
    )


@app.cli.command("generate-fernet-key")
def generate_fernet_key():
    """Gera uma nova chave Fernet para cifrar credenciais SNMP."""
    from cryptography.fernet import Fernet as _Fernet
    key = _Fernet.generate_key().decode()
    click.echo("Chave gerada. Adicione ao seu ambiente:")
    click.echo(f"\n  export FERNET_KEY={key}\n")
    click.echo("Aviso: guarde esta chave com segurança. Sem ela os dados cifrados não podem ser recuperados.")


if __name__ == "__main__":
    app.run()
