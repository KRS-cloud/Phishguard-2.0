import math
import secrets
import string


AMBIGUOUS_CHARACTERS = "Il1O0o"


def generate_password(
    length=16,
    use_uppercase=True,
    use_lowercase=True,
    use_numbers=True,
    use_symbols=True,
    exclude_ambiguous=False,
):
    """
    Generate a secure random password.
    """

    try:
        length = int(length)
    except (TypeError, ValueError):
        length = 16

    length = max(8, min(length, 64))

    character_groups = []

    if use_lowercase:
        character_groups.append(
            string.ascii_lowercase
        )

    if use_uppercase:
        character_groups.append(
            string.ascii_uppercase
        )

    if use_numbers:
        character_groups.append(
            string.digits
        )

    if use_symbols:
        character_groups.append(
            "!@#$%^&*()-_=+[]{}?"
        )

    if not character_groups:
        raise ValueError(
            "Select at least one character type."
        )

    if exclude_ambiguous:
        character_groups = [
            "".join(
                char
                for char in group
                if char not in AMBIGUOUS_CHARACTERS
            )
            for group in character_groups
        ]

    if length < len(character_groups):
        raise ValueError(
            "Password length is too short."
        )

    password_chars = [
        secrets.choice(group)
        for group in character_groups
    ]

    combined_characters = "".join(
        character_groups
    )

    while len(password_chars) < length:
        password_chars.append(
            secrets.choice(
                combined_characters
            )
        )

    # Secure shuffle
    for index in range(
        len(password_chars) - 1,
        0,
        -1,
    ):
        random_index = secrets.randbelow(
            index + 1
        )

        password_chars[index], password_chars[random_index] = (
            password_chars[random_index],
            password_chars[index],
        )

    return "".join(password_chars)


def estimate_entropy(password):
    """
    Estimate password entropy.
    """

    pool_size = 0

    if any(char.islower() for char in password):
        pool_size += 26

    if any(char.isupper() for char in password):
        pool_size += 26

    if any(char.isdigit() for char in password):
        pool_size += 10

    if any(
        not char.isalnum()
        for char in password
    ):
        pool_size += 32

    if not password or pool_size == 0:
        return 0.0

    entropy = len(password) * math.log2(
        pool_size
    )

    return round(entropy, 2)


def format_crack_time(seconds):
    """
    Convert seconds into readable time.
    """

    if seconds < 1:
        return "Less than 1 second"

    minute = 60
    hour = minute * 60
    day = hour * 24
    year = day * 365

    if seconds < minute:
        return f"{round(seconds)} seconds"

    if seconds < hour:
        return (
            f"{round(seconds / minute)} minutes"
        )

    if seconds < day:
        return (
            f"{round(seconds / hour)} hours"
        )

    if seconds < year:
        return (
            f"{round(seconds / day)} days"
        )

    years = seconds / year

    if years < 1000:
        return f"{round(years)} years"

    if years < 1_000_000:
        return (
            f"{round(years / 1000, 1)} thousand years"
        )

    if years < 1_000_000_000:
        return (
            f"{round(years / 1_000_000, 1)} million years"
        )

    return "Billions of years"


def check_password_strength(password):
    """
    Analyze password strength.
    """

    if not password:
        return {
            "score": 0,
            "strength": "Very Weak",
            "entropy": 0,
            "crack_time": "Instant",
            "warnings": [
                "Enter a password to analyze."
            ],
            "suggestions": [],
        }

    length = len(password)

    has_lowercase = any(
        char.islower()
        for char in password
    )

    has_uppercase = any(
        char.isupper()
        for char in password
    )

    has_number = any(
        char.isdigit()
        for char in password
    )

    has_symbol = any(
        not char.isalnum()
        for char in password
    )

    score = 0

    if length >= 8:
        score += 15

    if length >= 12:
        score += 15

    if length >= 16:
        score += 10

    if has_lowercase:
        score += 10

    if has_uppercase:
        score += 10

    if has_number:
        score += 10

    if has_symbol:
        score += 15

    unique_ratio = (
        len(set(password)) / length
    )

    if unique_ratio >= 0.7:
        score += 10

    warnings = []
    suggestions = []

    common_patterns = [
        "password",
        "qwerty",
        "123456",
        "admin",
        "welcome",
        "letmein",
        "abc123",
    ]

    password_lower = password.lower()

    if any(
        pattern in password_lower
        for pattern in common_patterns
    ):
        score -= 30

        warnings.append(
            "The password contains a common or predictable pattern."
        )

    if unique_ratio < 0.5:
        score -= 10

        warnings.append(
            "The password contains many repeated characters."
        )

    if length < 12:
        suggestions.append(
            "Use at least 12 characters."
        )

    if not has_lowercase:
        suggestions.append(
            "Add lowercase letters."
        )

    if not has_uppercase:
        suggestions.append(
            "Add uppercase letters."
        )

    if not has_number:
        suggestions.append(
            "Add numbers."
        )

    if not has_symbol:
        suggestions.append(
            "Add symbols."
        )

    score = max(
        0,
        min(score, 100),
    )

    if score < 30:
        strength = "Very Weak"

    elif score < 50:
        strength = "Weak"

    elif score < 70:
        strength = "Moderate"

    elif score < 85:
        strength = "Strong"

    else:
        strength = "Very Strong"

    entropy = estimate_entropy(
        password
    )

    guesses = 2 ** entropy

    guesses_per_second = (
        10_000_000_000
    )

    seconds = (
        guesses
        / guesses_per_second
        / 2
    )

    return {
        "score": score,
        "strength": strength,
        "entropy": entropy,
        "crack_time": format_crack_time(
            seconds
        ),
        "warnings": warnings,
        "suggestions": suggestions,
    }