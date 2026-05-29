"""Utilitário para gerenciar o perfil ativo via sessão Flask."""

from flask import request, session


def get_active_profile_id() -> int | None:
    """Retorna o profile_id ativo.

    Prioridade: parâmetro de URL > sessão > None.
    Quando o parâmetro de URL está presente, sincroniza com a sessão para
    que as páginas subsequentes usem o mesmo perfil automaticamente.
    """
    pid = request.args.get("profile_id", type=int)
    if pid:
        session["active_profile_id"] = pid
        return pid
    return session.get("active_profile_id")
