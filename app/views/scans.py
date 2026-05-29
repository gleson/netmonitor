"""Blueprint da página de histórico de scans."""

from flask import Blueprint, render_template, request
from flask_login import login_required

from app.models import Scan, ScanType, ScanStatus

scans_bp = Blueprint("scans", __name__, template_folder="../templates/scans")


@scans_bp.route("/")
@login_required
def scan_list():
    """Lista paginada de scans com filtros."""
    from app.profile_utils import get_active_profile_id
    profile_id = get_active_profile_id()
    scan_type = request.args.get("type", "")
    status = request.args.get("status", "")
    page = request.args.get("page", 1, type=int)

    query = Scan.query

    if profile_id:
        query = query.filter_by(profile_id=profile_id)
    if scan_type:
        try:
            query = query.filter_by(scan_type=ScanType(scan_type))
        except ValueError:
            pass
    if status:
        try:
            query = query.filter_by(status=ScanStatus(status))
        except ValueError:
            pass

    query = query.order_by(Scan.started_at.desc())
    pagination = query.paginate(page=page, per_page=50, error_out=False)

    return render_template(
        "scans/list.html",
        scans=pagination.items,
        pagination=pagination,
        selected_profile_id=profile_id,
        selected_type=scan_type,
        selected_status=status,
        scan_types=ScanType,
        scan_statuses=ScanStatus,
    )
