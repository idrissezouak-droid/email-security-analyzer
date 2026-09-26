from project import (
    read_email,
    parse_email,
    analyze_headers,
    analyze_body,
    calculate_risk,
    extract_domain,
    extract_urls
)


def test_read_email(tmp_path):
    email_file = tmp_path / "email.txt"
    email_file.write_text("hello idriss")

    result = read_email(str(email_file))

    assert result == "hello idriss"


def test_parse_email():
    email_content = """From: security@company.com
To: idriss@example.com
Subject: Test email

Hello Idriss,
This is a test email.
"""

    result = parse_email(email_content)

    assert result["From"] == "security@company.com"
    assert result["To"] == "idriss@example.com"
    assert result["Subject"] == "Test email"


def test_analyze_headers():
    email_content = """From: attacker@example.com
To: idriss@example.com
Subject: Urgent
Reply-To: fake@example.com
Return-Path: attacker@example.com
Authentication-Results: spf=fail; dkim=fail; dmarc=fail

Hello Idriss,
Your account requires immediate verification.
"""

    msg = parse_email(email_content)
    result = analyze_headers(msg)

    assert result["From"] == msg["From"]
    assert result["To"] == msg["To"]
    assert result["Subject"] == msg["Subject"]
    assert result["Reply-To"] == msg["Reply-To"]
    assert result["Return-Path"] == msg["Return-Path"]
    assert result["Authentication-Results"] == msg["Authentication-Results"]


def test_analyze_body():
    email_content = """Hello Idriss,
Your account requires immediate verification."""

    msg = parse_email(email_content)
    result = analyze_body(msg)

    assert result == email_content


def test_calculate_risk():
    email_content = """From: security@company.com
To: idriss@example.com
Subject: Security notification
Reply-To: attacker@gmail.com
Return-Path: security@company.com
Authentication-Results: spf=fail; dkim=fail; dmarc=pass

Hello Idriss,

This is a normal security notification.
Please review the information when you have time."""

    msg = parse_email(email_content)
    headers = analyze_headers(msg)
    body = analyze_body(msg)

    score, reasons = calculate_risk(headers, body)

    assert score == 7


def test_extract_domain():
    result = extract_domain("security@microsoft.com")

    assert result == "microsoft.com"


def test_extract_urls():
    body = "Visit https://google.com and https://paypal.com"

    result = extract_urls(body)

    assert result == ["https://google.com", "https://paypal.com"]