from app import create_app
from app.extensions import db


app = create_app()


def create_database():
    """
    Create missing database tables.

    This runs for local development and when Gunicorn imports
    the application during deployment.
    """

    with app.app_context():
        db.create_all()


create_database()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )