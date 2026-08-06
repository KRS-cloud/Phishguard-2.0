from datetime import datetime

from app.extensions import db


class ScanHistory(db.Model):
    """
    Stores security analysis results for registered users.
    """

    __tablename__ = "scan_history"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    scan_type = db.Column(
        db.String(30),
        nullable=False,
    )

    input_value = db.Column(
        db.Text,
        nullable=False,
    )

    prediction = db.Column(
        db.String(50),
        nullable=False,
    )

    risk_level = db.Column(
        db.String(30),
        nullable=False,
    )

    risk_score = db.Column(
        db.Float,
        nullable=False,
        default=0.0,
    )

    confidence = db.Column(
        db.Float,
        nullable=True,
    )

    explanation = db.Column(
        db.Text,
        nullable=True,
    )

    recommendations = db.Column(
        db.Text,
        nullable=True,
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False,
        index=True,
    )

    user = db.relationship(
        "User",
        back_populates="scans",
    )

    def __repr__(self):
        return (
            f"<ScanHistory id={self.id} "
            f"type={self.scan_type} "
            f"risk={self.risk_level}>"
        )