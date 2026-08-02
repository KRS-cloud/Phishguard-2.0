from flask import (
    Blueprint,
    jsonify,
    render_template,
    request,
)

from flask_login import login_required

from app.services.password_service import (
    check_password_strength,
    generate_password,
)


password_bp = Blueprint(
    "password",
    __name__,
    url_prefix="/password",
)


@password_bp.route("/")
@login_required
def password_tools():
    return render_template(
        "password/password_tools.html"
    )


@password_bp.route(
    "/generate",
    methods=["POST"],
)
@login_required
def generate():

    data = request.get_json(
        silent=True
    ) or {}

    try:

        password = generate_password(
            length=data.get("length", 16),
            use_uppercase=data.get(
                "uppercase",
                True,
            ),
            use_lowercase=data.get(
                "lowercase",
                True,
            ),
            use_numbers=data.get(
                "numbers",
                True,
            ),
            use_symbols=data.get(
                "symbols",
                True,
            ),
            exclude_ambiguous=data.get(
                "exclude_ambiguous",
                False,
            ),
        )

        return jsonify({
            "success": True,
            "password": password,
        })

    except ValueError as error:

        return jsonify({
            "success": False,
            "error": str(error),
        }), 400


@password_bp.route(
    "/check",
    methods=["POST"],
)
@login_required
def check():

    data = request.get_json(
        silent=True
    ) or {}

    password = data.get(
        "password",
        "",
    )

    result = check_password_strength(
        password
    )

    return jsonify(result)