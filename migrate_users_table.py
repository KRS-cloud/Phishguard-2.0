from sqlalchemy import inspect, text

from app import create_app
from app.extensions import db


app = create_app()


with app.app_context():
    inspector = inspect(db.engine)

    columns = {
        column["name"]
        for column in inspector.get_columns("users")
    }

    print("Existing user columns:")
    print(sorted(columns))

    statements = []

    if "last_seen" not in columns:
        statements.append(
            """
            ALTER TABLE users
            ADD COLUMN last_seen DATETIME
            """
        )

    if "login_count" not in columns:
        statements.append(
            """
            ALTER TABLE users
            ADD COLUMN login_count INTEGER
            NOT NULL DEFAULT 0
            """
        )

    if "is_admin" not in columns:
        statements.append(
            """
            ALTER TABLE users
            ADD COLUMN is_admin BOOLEAN
            NOT NULL DEFAULT 0
            """
        )

    if not statements:
        print(
            "\nNo migration needed. "
            "The users table is already updated."
        )

    else:
        for statement in statements:
            db.session.execute(
                text(statement)
            )

        db.session.commit()

        print(
            f"\nMigration complete. "
            f"Added {len(statements)} column(s)."
        )

    updated_columns = {
        column["name"]
        for column in inspect(
            db.engine
        ).get_columns("users")
    }

    print("\nUpdated user columns:")
    print(sorted(updated_columns))