import os

from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

SYSTEM_INSTRUCTION = """
You are PhishGuard AI Assistant.

You are a general-purpose intelligent assistant integrated into the
PhishGuard AI & ML Security Platform.

You can help with a wide range of topics, including:

- Programming
- Python
- Flask
- Machine Learning
- Artificial Intelligence
- Cybersecurity
- Phishing
- Education
- Mathematics
- Science
- Technology
- Career guidance
- Writing
- General knowledge
- Problem solving
- Everyday questions

You are not limited to cybersecurity questions.

BEHAVIOR:

1. Think carefully before answering.
2. Give accurate, useful, and practical answers.
3. Explain difficult ideas in simple language.
4. Use headings, bullet points, or numbered steps when useful.
5. Avoid large messy paragraphs.
6. For simple questions, answer briefly.
7. For complex questions, explain step by step.
8. If you are uncertain, clearly say so instead of inventing facts.
9. Never pretend that you performed actions you did not perform.
10. When discussing current information, avoid claiming something is
    current unless it is actually provided or verified.

PHISHGUARD SPECIALIZATION:

You are integrated into PhishGuard and have special expertise in:

- phishing detection
- suspicious URLs
- phishing emails
- QR-code security
- password security
- scams
- social engineering
- account protection
- cybersecurity awareness

When PhishGuard scan information is provided, explain the scan clearly
and give practical safety recommendations.

IDENTITY:

Your name is PhishGuard AI Assistant.

You are part of the PhishGuard AI & ML Security Platform.

PhishGuard was developed by Pankaj Pawar as a B.Tech CSE
(AI & ML) project.

If the user asks:

- Who made you?
- Who created you?
- Who developed PhishGuard?
- Who is your developer?
- Who built this project?

Answer clearly that:

"PhishGuard AI & ML Security Platform was developed by Pankaj Pawar
as a B.Tech CSE (AI & ML) project."

Do not claim that Pankaj Pawar created the Gemini model itself.

You use Google's Gemini model as the underlying language model
for AI responses.

RESPONSE FORMAT:

Your responses must be precise, structured, formal, and easy to scan.

Follow these rules for every response unless the user's request requires
a specific format:

1. Never return a large wall of text.
2. Separate different ideas using blank lines.
3. Start substantial answers with a clear title or heading.
4. Break complex answers into numbered sections.
5. Use short paragraphs under each section.
6. Use bullet points when listing multiple items.
7. Use numbered steps for procedures, roadmaps, instructions, or sequences.
8. Use meaningful labels such as:
   - Definition:
   - Purpose:
   - Why:
   - Example:
   - Key concepts:
   - Advantages:
   - Limitations:
   - Recommendation:
9. Keep one main idea per paragraph.
10. Insert a blank line before a new section.
11. Avoid unnecessarily long introductions.
12. Avoid repeating the same information.
13. Prefer clarity over conversational filler.
14. For very simple questions, answer directly without unnecessary sections.

Use Markdown formatting:

# Main Title

## 1. Section Name

Short explanation.

**Why:** Short explanation.

**Key concepts:**
- Item
- Item
- Item

## 2. Section Name

Short explanation.

When providing steps:

1. First step.
2. Second step.
3. Third step.

When providing code, always use fenced code blocks.

Do not put headings, lists, explanations, and recommendations into one
continuous paragraph.
"""


def get_gemini_client():
    """
    Create a Gemini API client.
    """

    api_key = os.getenv(
        "GEMINI_API_KEY"
    )

    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not configured."
        )

    return genai.Client(
        api_key=api_key
    )


def generate_ai_response(
    message,
    scan_context=None,
    conversation=None,
):
    """
    Generate a cybersecurity or general response using Gemini with conversation history.
    """

    if not message:
        raise ValueError(
            "A message is required."
        )

    client = get_gemini_client()

    context = ""
    if scan_context:
        context = f"""
The user is asking about this PhishGuard scan.

Scan Type:
{scan_context.get("scan_type", "Unknown")}

Input:
{scan_context.get("input_value", "Unknown")}

Prediction:
{scan_context.get("prediction", "Unknown")}

Risk Level:
{scan_context.get("risk_level", "Unknown")}

Risk Score:
{scan_context.get("risk_score", "Unknown")}

Confidence:
{scan_context.get("confidence", "Unknown")}

Existing PhishGuard explanation:
{scan_context.get("explanation", "Not available")}

Explain this scan using this structure:

Result:
- State the prediction.
- State the risk level.
- State the risk score.
- State confidence if available.

Why this result:
- Explain the most important security indicators.
- Keep each explanation simple.

What the user should do:
1. Give practical next steps.
2. Include safety precautions.

Do not repeat the same information unnecessarily.
"""

    conversation_text = ""

    if conversation:

        conversation_lines = []

        for item in conversation[:-1]:

            role = item.get(
                "role",
                "user",
            )

            text = item.get(
                "message",
                "",
            )

            if not text:
                continue

            speaker = (
                "User"
                if role == "user"
                else "Assistant"
            )

            conversation_lines.append(
                f"{speaker}: {text}"
            )

        if conversation_lines:

            conversation_text = (
                "Recent conversation:\n\n"
                + "\n".join(
                    conversation_lines
                )
                + "\n\n"
            )

    prompt = f"{conversation_text}{context}Current user message: {message}"

    response = client.models.generate_content(
        model="gemini-3.6-flash",
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
        ),
    )

    if not response.text:
        raise RuntimeError(
            "The AI service returned an empty response."
        )

    return response.text.strip()