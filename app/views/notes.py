"""Blueprint de anotações — guia de notas por perfil."""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required

from app.auth_utils import audit, require_role
from app.extensions import db
from app.models import Note, ROLE_OPERATOR, _utcnow

notes_bp = Blueprint("notes", __name__, template_folder="../templates/notes")


@notes_bp.route("/")
@login_required
def note_list():
    from app.profile_utils import get_active_profile_id
    from sqlalchemy import or_
    profile_id = get_active_profile_id()
    query = Note.query
    if profile_id:
        # Exibe notas do perfil ativo E notas globais (profile_id=NULL)
        query = query.filter(
            or_(Note.profile_id == profile_id, Note.profile_id.is_(None))
        )
    notes = query.order_by(Note.updated_at.desc()).all()
    return render_template(
        "notes/list.html",
        notes=notes,
        selected_profile_id=profile_id,
    )


@notes_bp.route("/new", methods=["GET", "POST"])
@login_required
@require_role(ROLE_OPERATOR)
def note_new():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        profile_id = request.form.get("profile_id", type=int) or None
        if not title:
            flash("O título é obrigatório.", "danger")
            return render_template("notes/form.html", profiles=profiles, note=None)
        note = Note(title=title, content=content, profile_id=profile_id)
        db.session.add(note)
        db.session.flush()
        audit("note.create", "note", note.id, details=note.title)
        db.session.commit()
        flash("Anotação criada.", "success")
        return redirect(url_for("notes.note_list"))
    return render_template("notes/form.html", note=None)


@notes_bp.route("/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
@require_role(ROLE_OPERATOR)
def note_edit(note_id):
    note = db.session.get(Note, note_id) or _abort(404)
    if request.method == "POST":
        note.title = request.form.get("title", "").strip() or note.title
        note.content = request.form.get("content", "").strip()
        note.profile_id = request.form.get("profile_id", type=int) or None
        note.updated_at = _utcnow()
        audit("note.update", "note", note.id, details=note.title)
        db.session.commit()
        flash("Anotação atualizada.", "success")
        return redirect(url_for("notes.note_list"))
    return render_template("notes/form.html", note=note)


@notes_bp.route("/<int:note_id>/delete", methods=["POST"])
@login_required
@require_role(ROLE_OPERATOR)
def note_delete(note_id):
    note = db.session.get(Note, note_id) or _abort(404)
    profile_id = note.profile_id
    audit("note.delete", "note", note.id, details=note.title)
    db.session.delete(note)
    db.session.commit()
    flash("Anotação excluída.", "warning")
    return redirect(url_for("notes.note_list"))


def _abort(code):
    from flask import abort
    abort(code)
