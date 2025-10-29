
from pii_redactor_lite.redactor import redact_text

def test_email_masking():
    content = "Contact me at person@example.com"
    redacted, findings = redact_text(content, mode="mask")
    assert "***@example.com" in redacted
    assert any(f["type"] == "email" for f in findings)
