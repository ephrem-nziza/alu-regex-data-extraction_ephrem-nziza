"""
main.py

This program reads a text file and finds useful information inside it,
like emails, card numbers, phone numbers, links, hashtags, and times.

It also checks the text for unsafe patterns before it trusts anything,
and it hides sensitive data (emails, card numbers) in the output.

How to run it:
    cd src
    python main.py

It reads from ../input/raw-text.txt
It writes the result to ../output/sample-output.json
"""

import re
import json
import os


# PART 1: Safety checks

# Before we look for emails, cards, etc, we first check every line
# of the text for patterns that look unsafe. If a line has one of
# these patterns, we skip that whole line completely. We do not try
# to keep the "safe part" of a bad line, we just drop the whole line.
# This is a simple and safe way to handle text we do not fully trust.

UNSAFE_PATTERNS = {
    # a script tag, like <script ...>
    "script_tag": re.compile(r"<\s*script[^>]*>", re.IGNORECASE),

    # common SQL command words used to attack databases
    "sql_command": re.compile(
        r"\b(DROP\s+TABLE|SELECT\s+\*\s+FROM|UNION\s+SELECT|OR\s+1\s*=\s*1)",
        re.IGNORECASE,
    ),

    # code inside double curly braces or ${ }, used in some template systems
    "template_code": re.compile(r"\{\{.*?\}\}|\$\{.*?\}"),

    # repeated "../" used to escape a folder and reach system files
    "folder_escape": re.compile(r"(\.\./){2,}"),

    # a null byte marker, sometimes used to break old, unsafe programs
    "null_byte": re.compile(r"%00|\x00"),
}


def check_line_for_unsafe_patterns(line):
    """Look at one line of text and return a list of problems found."""
    problems_found = []
    for name, pattern in UNSAFE_PATTERNS.items():
        if pattern.search(line):
            problems_found.append(name)
    return problems_found


# PART 2: Patterns for the data we want to find

# EMAIL ADDRESS
# Example: grace.uwimana@alueducation.com
#   [A-Za-z0-9._%+-]+   the part before the @ (name, dots, plus sign, etc)
#   @                   the @ symbol
#   [A-Za-z0-9.-]+      the domain name (can have dots, like si.alueducation)
#   \.[A-Za-z]{2,}      a dot followed by the ending, like .com or .rw
EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# ALU email endings. The $ sign means "end of the text", so an address
# like fake@alueducation.com.badsite.com will NOT be treated as a real
# ALU address, because it does not actually end with @alueducation.com.
ENDS_WITH_ALU_OFFICIAL = re.compile(r"@alueducation\.com$", re.IGNORECASE)
ENDS_WITH_ALU_ALUMNI = re.compile(
    r"@alumni\.alueducation\.com$", re.IGNORECASE
)
ENDS_WITH_ALU_SI = re.compile(r"@si\.alueducation\.com$", re.IGNORECASE)


def classify_email(email):
    """Decide which ALU group an email belongs to, or say it's external."""
    if ENDS_WITH_ALU_ALUMNI.search(email):
        return "alu_alumni"
    if ENDS_WITH_ALU_SI.search(email):
        return "alu_si"
    if ENDS_WITH_ALU_OFFICIAL.search(email):
        return "alu_official"
    return "external"


# CREDIT CARD NUMBER
# This pattern only checks the SHAPE of a number (13 to 19 digits,
# with spaces or dashes allowed between them). It does NOT check if
# the number is a real, working card. That is what the Luhn check
# below is for.
CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def luhn_check(number):
    """
    The Luhn check is a simple math test used by real payment systems
    to catch mistyped card numbers. A number can look right (13-19
    digits) but still fail this test, which means it is not a valid
    card number.
    """
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False

    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    return total % 10 == 0


def mask_card(number):
    """Hide most of the card number, keep only the last 4 digits."""
    digits = re.sub(r"\D", "", number)
    if len(digits) >= 4:
        return f"**** **** **** {digits[-4:]}"
    return "****"


def mask_email(email):
    """Hide most of an email address, keep the first and last letter."""
    local_part, _, domain = email.partition("@")
    if len(local_part) <= 2:
        hidden = local_part[0] + "*"
    else:
        hidden = local_part[0] + "*" * (len(local_part) - 2) + local_part[-1]
    return f"{hidden}@{domain}"


# PHONE NUMBER
# Real phone numbers come in many shapes: with a country code, with
# brackets around the area code, with spaces or dashes. This pattern
# is wide on purpose, and we filter out bad matches afterward by
# counting the digits.
PHONE_PATTERN = re.compile(
    r"\b(?:\+\d{1,3}[ -]?)?(?:\(\d{2,4}\)[ -]?)?\d{2,4}(?:[ -]?\d{2,4}){1,3}\b"
)


def looks_like_a_real_phone_number(text):
    """A real phone number usually has 7 to 15 digits in total."""
    digit_count = len(re.sub(r"\D", "", text))
    return 7 <= digit_count <= 15


# URL / LINK
# Matches links starting with http://, https://, or www.
# Stops at a space, quote mark, or angle bracket, so it does not
# accidentally grab extra text sitting next to the link.
URL_PATTERN = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)

# HASHTAG
# Must start with a # followed by a LETTER (not a number). This stops
# things like "Ticket #10234" from being wrongly picked up as a hashtag.
HASHTAG_PATTERN = re.compile(r"#[A-Za-z]\w*")

# TIME
# Covers both 12-hour time (9:30 AM) and 24-hour time (21:00), since
# real messages often use both styles without warning.
TIME_12H_PATTERN = re.compile(r"\b(1[0-2]|0?[1-9]):[0-5][0-9]\s?[APap][Mm]\b")
TIME_24H_PATTERN = re.compile(r"\b([01][0-9]|2[0-3]):[0-5][0-9]\b")


# PART 3: Put it all together

def process_text(raw_text):
    lines = raw_text.splitlines()

    unsafe_lines_report = []
    safe_lines = []

    for line_number, line in enumerate(lines, start=1):
        problems = check_line_for_unsafe_patterns(line)
        if problems:
            unsafe_lines_report.append({
                "line_number": line_number,
                "problems": problems,
            })
            # skip this line, do not use it for extraction
        else:
            safe_lines.append(line)

    safe_text = "\n".join(safe_lines)

    # find emails
    found_emails = sorted(set(EMAIL_PATTERN.findall(safe_text)))
    email_results = [
        {"masked": mask_email(e), "category": classify_email(e)}
        for e in found_emails
    ]

    # find credit cards
    card_results = []
    already_seen = set()
    for match in CREDIT_CARD_PATTERN.findall(safe_text):
        digits_only = re.sub(r"\D", "", match)
        if digits_only in already_seen:
            continue
        already_seen.add(digits_only)
        card_results.append({
            "masked": mask_card(match),
            "luhn_valid": luhn_check(digits_only),
        })

    # find phone numbers
    phone_results = sorted({
        m.group(0).strip()
        for m in PHONE_PATTERN.finditer(safe_text)
        if looks_like_a_real_phone_number(m.group(0))
    })

    # find URLs
    url_results = sorted(set(URL_PATTERN.findall(safe_text)))

    # find hashtags
    hashtag_results = sorted(set(HASHTAG_PATTERN.findall(safe_text)))

    # find times
    time_12h_results = sorted(set(
        m.group(0) for m in TIME_12H_PATTERN.finditer(safe_text)
    ))
    time_24h_results = sorted(set(
        m.group(0) for m in TIME_24H_PATTERN.finditer(safe_text)
    ))

    return {
        "summary": {
            "total_lines": len(lines),
            "unsafe_lines_found": len(unsafe_lines_report),
            "emails_found": len(email_results),
            "credit_cards_found": len(card_results),
            "credit_cards_that_pass_luhn_check": sum(
                1 for c in card_results if c["luhn_valid"]
            ),
            "phone_numbers_found": len(phone_results),
            "urls_found": len(url_results),
            "hashtags_found": len(hashtag_results),
        },
        "safety_report": {
            "note": (
                "Lines listed here were removed before extraction. "
                "Only the line number and the type of problem is kept, "
                "not the actual unsafe text."
            ),
            "unsafe_lines": unsafe_lines_report,
        },
        "emails": email_results,
        "credit_cards": card_results,
        "phone_numbers": phone_results,
        "urls": url_results,
        "hashtags": hashtag_results,
        "time_12_hour_format": time_12h_results,
        "time_24_hour_format": time_24h_results,
    }


def main():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_path = os.path.join(project_root, "input", "raw-text.txt")
    output_path = os.path.join(project_root, "output", "sample-output.json")

    with open(input_path, "r", encoding="utf-8") as f:
        raw_text = f.read()

    result = process_text(raw_text)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    # Print only counts and safety info, never the raw email/card data,
    # so nothing sensitive ends up in the terminal or in log files.
    print("=== Summary ===")
    for key, value in result["summary"].items():
        print(f"{key}: {value}")

    print(f"\nUnsafe lines found: "
          f"{len(result['safety_report']['unsafe_lines'])}")
    for item in result["safety_report"]["unsafe_lines"]:
        print(f"  line {item['line_number']}: {item['problems']}")

    print(f"\nFull result saved to: {output_path}")


if __name__ == "__main__":
    main()
