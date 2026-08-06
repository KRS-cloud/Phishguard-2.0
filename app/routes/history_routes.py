import csv
import io
from io import BytesIO
import json
from xml.sax.saxutils import escape

from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.extensions import db
from app.models import ScanHistory

history_bp = Blueprint(
    "history",
    __name__,
    url_prefix="/history",
)


def pdf_text(value):
    """Escape untrusted text before ReportLab parses its markup."""

    return escape(str(value)).replace("\n", "<br/>")


def safe_csv_cell(value):
    """Prevent spreadsheet applications from executing CSV formulas."""

    if value is None:
        return ""

    text = str(value)
    trimmed = text.lstrip()

    if (
        text.startswith(("\t", "\r"))
        or trimmed.startswith(("=", "+", "-", "@"))
    ):
        return f"'{text}"

    return text


def prediction_label(prediction):
    """Return a cautious user-facing label for stored predictions."""

    if prediction == "Safe":
        return "Low Risk Indicators"

    return prediction


@history_bp.route("/")
@login_required
def history():
    """
    Display the current user's scan history.
    """

    search_query = request.args.get(
        "search",
        "",
    ).strip()

    scan_type = request.args.get(
        "scan_type",
        "",
    ).strip()

    prediction = request.args.get(
        "prediction",
        "",
    ).strip()

    page = request.args.get(
        "page",
        1,
        type=int,
    )

    if page < 1:
        page = 1

    per_page = 10

    query = db.select(ScanHistory).where(
        ScanHistory.user_id == current_user.id
    )

    if search_query:
        query = query.where(
            ScanHistory.input_value.ilike(
                f"%{search_query}%"
            )
        )

    if scan_type in {"URL", "Email", "QR"}:
        query = query.where(
            ScanHistory.scan_type == scan_type
        )

    if prediction in {"Safe", "Suspicious", "Phishing"}:
        query = query.where(
            ScanHistory.prediction == prediction
        )

    query = query.order_by(
        ScanHistory.created_at.desc()
    )

    pagination = db.paginate(
        query,
        page=page,
        per_page=per_page,
        error_out=False,
    )

    total_scans = db.session.scalar(
        db.select(
            db.func.count(ScanHistory.id)
        ).where(
            ScanHistory.user_id == current_user.id
        )
    ) or 0

    safe_scans = db.session.scalar(
        db.select(
            db.func.count(ScanHistory.id)
        ).where(
            ScanHistory.user_id == current_user.id,
            ScanHistory.prediction == "Safe",
        )
    ) or 0

    suspicious_scans = db.session.scalar(
        db.select(
            db.func.count(ScanHistory.id)
        ).where(
            ScanHistory.user_id == current_user.id,
            ScanHistory.prediction == "Suspicious",
        )
    ) or 0

    phishing_scans = db.session.scalar(
        db.select(
            db.func.count(ScanHistory.id)
        ).where(
            ScanHistory.user_id == current_user.id,
            ScanHistory.prediction == "Phishing",
        )
    ) or 0

    return render_template(
        "history/history.html",
        scans=pagination.items,
        pagination=pagination,
        search_query=search_query,
        selected_scan_type=scan_type,
        selected_prediction=prediction,
        total_scans=total_scans,
        safe_scans=safe_scans,
        suspicious_scans=suspicious_scans,
        phishing_scans=phishing_scans,
    )


@history_bp.route("/<int:scan_id>")
@login_required
def scan_details(scan_id):
    """
    Display one detailed scan report.
    """

    scan = db.session.get(
        ScanHistory,
        scan_id,
    )

    if scan is None:
        abort(404)

    if scan.user_id != current_user.id:
        abort(403)

    recommendations = []

    if scan.recommendations:
        try:
            recommendations = json.loads(
                scan.recommendations
            )

        except (json.JSONDecodeError, TypeError):
            recommendations = [
                scan.recommendations
            ]

    return render_template(
        "history/scan_details.html",
        scan=scan,
        recommendations=recommendations,
    )


@history_bp.route("/<int:scan_id>/pdf")
@login_required
def download_scan_pdf(scan_id):
    """
    Download one scan report as a PDF.
    """

    scan = db.session.get(
        ScanHistory,
        scan_id,
    )

    if scan is None:
        abort(404)

    if scan.user_id != current_user.id:
        abort(403)

    recommendations = []

    if scan.recommendations:
        try:
            recommendations = json.loads(
                scan.recommendations
            )

        except (
            json.JSONDecodeError,
            TypeError,
        ):
            recommendations = [
                scan.recommendations
            ]

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"PhishGuard Scan Report #{scan.id}",
        author="PhishGuard AI & ML",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=9,
        textColor=colors.grey,
        spaceAfter=18,
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=12,
        spaceBefore=12,
        spaceAfter=8,
    )

    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=9.5,
        leading=14,
    )

    story = []

    story.append(
        Paragraph(
            "PhishGuard AI & ML",
            title_style,
        )
    )

    story.append(
        Paragraph(
            "Security Analysis Report",
            subtitle_style,
        )
    )

    summary_data = [
        [
            "Report ID",
            str(scan.id),
        ],
        [
            "Scan Type",
            scan.scan_type,
        ],
        [
            "Prediction",
            prediction_label(scan.prediction),
        ],
        [
            "Risk Level",
            scan.risk_level,
        ],
        [
            "Risk Score",
            f"{scan.risk_score:.1f}%",
        ],
        [
            "Confidence",
            (
                f"{scan.confidence:.1f}%"
                if scan.confidence is not None
                else "Not available"
            ),
        ],
        [
            "Created At",
            (
                scan.created_at.strftime(
                    "%d %b %Y, %I:%M %p"
                )
                if scan.created_at
                else "Unknown"
            ),
        ],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[
            45 * mm,
            105 * mm,
        ],
    )

    summary_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#E8F5E9"),
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (0, -1),
                colors.HexColor("#1B5E20"),
            ),
            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold",
            ),
            (
                "FONTNAME",
                (1, 0),
                (1, -1),
                "Helvetica",
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                9,
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.HexColor("#CCCCCC"),
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP",
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),
        ])
    )

    story.append(summary_table)

    story.append(
        Spacer(
            1,
            12,
        )
    )

    story.append(
        Paragraph(
            "Analyzed Input",
            heading_style,
        )
    )

    story.append(
        Paragraph(
            pdf_text(scan.input_value),
            body_style,
        )
    )

    if scan.explanation:
        story.append(
            Paragraph(
                "Explanation",
                heading_style,
            )
        )

        story.append(
            Paragraph(
                pdf_text(scan.explanation),
                body_style,
            )
        )

    if recommendations:
        story.append(
            Paragraph(
                "Recommendations",
                heading_style,
            )
        )

        for index, recommendation in enumerate(
            recommendations,
            start=1,
        ):
            story.append(
                Paragraph(
                    pdf_text(f"{index}. {recommendation}"),
                    body_style,
                )
            )

            story.append(
                Spacer(
                    1,
                    5,
                )
            )

    story.append(
        Spacer(
            1,
            18,
        )
    )

    story.append(
        Paragraph(
            (
                "This report was generated automatically by "
                "PhishGuard AI & ML Security Platform."
            ),
            subtitle_style,
        )
    )

    story.append(
        Paragraph(
            (
                "Developed by Pankaj Pawar - "
                "B.Tech CSE (AI & ML) Project"
            ),
            subtitle_style,
        )
    )

    document.build(story)

    buffer.seek(0)

    return Response(
        buffer.getvalue(),
        mimetype="application/pdf",
        headers={
            "Content-Disposition": (
                f"attachment; "
                f"filename=phishguard_report_{scan.id}.pdf"
            )
        },
    )


@history_bp.route("/export/csv")
@login_required
def export_csv():
    """
    Export the current user's scan history as a CSV file.
    """

    query = (
        db.select(ScanHistory)
        .where(
            ScanHistory.user_id == current_user.id
        )
        .order_by(
            ScanHistory.created_at.desc()
        )
    )

    scans = db.session.scalars(
        query
    ).all()

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Scan Type",
        "Input",
        "Prediction",
        "Risk Level",
        "Risk Score",
        "Confidence",
        "Explanation",
        "Recommendations",
        "Created At",
    ])

    for scan in scans:

        writer.writerow([
            safe_csv_cell(scan.id),
            safe_csv_cell(scan.scan_type),
            safe_csv_cell(scan.input_value),
            safe_csv_cell(prediction_label(scan.prediction)),
            safe_csv_cell(scan.risk_level),
            safe_csv_cell(scan.risk_score),
            safe_csv_cell(scan.confidence),
            safe_csv_cell(scan.explanation),
            safe_csv_cell(scan.recommendations),
            (
                scan.created_at.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                if scan.created_at
                else ""
            ),
        ])

    csv_data = output.getvalue()

    output.close()

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                "attachment; filename=phishguard_scan_history.csv"
        },
    )


@history_bp.route(
    "/<int:scan_id>/delete",
    methods=["POST"],
)
@login_required
def delete_scan(scan_id):
    """
    Delete one scan owned by the current user.
    """

    scan = db.session.get(
        ScanHistory,
        scan_id,
    )

    if scan is None:
        abort(404)

    if scan.user_id != current_user.id:
        abort(403)

    try:
        db.session.delete(scan)
        db.session.commit()

        flash(
            "The scan record was deleted successfully.",
            "success",
        )

    except Exception:
        db.session.rollback()

        flash(
            "The scan record could not be deleted.",
            "error",
        )

    return redirect(
        url_for("history.history")
    )
