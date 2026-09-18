"""
Tests for secret_patterns pure functions (Module 10a).
"""

from __future__ import annotations

import pytest

from app.plugins.installed.secrets_detection.secret_patterns import scan_text


def test_detects_aws_access_key():
    text = 'String key = "AKIAIOSFODNN7EXAMPLE";'
    matches = scan_text(text)
    assert any(m.pattern_name == "AWS Access Key ID" for m in matches)
    aws_match = next(m for m in matches if m.pattern_name == "AWS Access Key ID")
    assert aws_match.severity == "critical"


def test_detects_google_api_key():
    text = 'val apiKey = "AIzaSyD-1234567890abcdefghijklmnopqrstuv"'
    matches = scan_text(text)
    assert any(m.pattern_name == "Google API Key" for m in matches)


def test_detects_private_key_block():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"
    matches = scan_text(text)
    assert any(m.pattern_name == "Private Key Block" for m in matches)
    key_match = next(m for m in matches if m.pattern_name == "Private Key Block")
    assert key_match.severity == "critical"


def test_detects_jwt_token():
    text = 'String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ_abc123";'
    matches = scan_text(text)
    assert any(m.pattern_name == "JWT Token" for m in matches)


def test_detects_hardcoded_password():
    text = 'config.password = "SuperSecret123";'
    matches = scan_text(text)
    assert any(m.pattern_name == "Hardcoded Password" for m in matches)


def test_detects_hardcoded_generic_secret():
    text = 'private static final String SECRET = "sk_live_abcdef1234567890";'
    matches = scan_text(text)
    assert any(m.pattern_name == "Hardcoded API Key/Secret/Token" for m in matches)


def test_no_false_positive_on_clean_code():
    text = """
    public class MainActivity extends Activity {
        private String username;
        public void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_main);
        }
    }
    """
    matches = scan_text(text)
    assert matches == []


def test_redaction_never_exposes_full_secret():
    text = 'String key = "AKIAIOSFODNN7EXAMPLE";'
    matches = scan_text(text)
    aws_match = next(m for m in matches if m.pattern_name == "AWS Access Key ID")
    assert "AKIAIOSFODNN7EXAMPLE" not in aws_match.redacted_snippet
    assert "*" in aws_match.redacted_snippet


def test_line_numbers_are_correct():
    text = "line one\nline two\nAKIAIOSFODNN7EXAMPLE\nline four"
    matches = scan_text(text)
    aws_match = next(m for m in matches if m.pattern_name == "AWS Access Key ID")
    assert aws_match.line_number == 3


def test_matches_capped_per_pattern():
    # 25 AWS-shaped keys on separate lines -- should cap at 20 per the module's limit
    lines = [f"AKIA{str(i).zfill(16)}" for i in range(25)]
    text = "\n".join(lines)
    matches = scan_text(text)
    aws_matches = [m for m in matches if m.pattern_name == "AWS Access Key ID"]
    assert len(aws_matches) == 20


def test_multiple_different_secrets_all_detected():
    text = (
        'String aws = "AKIAIOSFODNN7EXAMPLE";\n'
        'String pw = "password" ;\n'  # too short/malformed, shouldn't match password pattern strictly
        'config.password = "hunter22";\n'
    )
    matches = scan_text(text)
    names = {m.pattern_name for m in matches}
    assert "AWS Access Key ID" in names
    assert "Hardcoded Password" in names


# --------------------------------------------------------------------------- #
# Entropy-based generic detection -- thresholds calibrated against real
# computed entropy values (see conversation/dev notes), not guessed.
# --------------------------------------------------------------------------- #
def test_shannon_entropy_of_empty_string_is_zero():
    from app.plugins.installed.secrets_detection.secret_patterns import shannon_entropy
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_of_repeated_char_is_zero():
    from app.plugins.installed.secrets_detection.secret_patterns import shannon_entropy
    assert shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == pytest.approx(0.0, abs=1e-9)


def test_high_entropy_random_looking_string_detected():
    text = 'String key = "aB3xR9kL2mZ8pQ7vN4wT6yU1sD5fG0hJ";'  # genuinely random-looking, mixed case
    matches = scan_text(text)
    assert any(m.pattern_name == "High-Entropy String (possible secret)" for m in matches)
    entropy_match = next(m for m in matches if m.pattern_name == "High-Entropy String (possible secret)")
    assert entropy_match.severity == "low"  # advisory, not a confirmed finding


def test_camelcase_variable_name_not_flagged_by_entropy():
    """A long but linguistically-structured name has lower entropy than real random data -- must not trip the check."""
    text = 'String x = "ThisIsJustAVeryLongVariableNameNotASecretAtAll";'
    matches = scan_text(text)
    assert not any("High-Entropy" in m.pattern_name for m in matches)


def test_repeated_characters_not_flagged_by_entropy():
    text = 'String x = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";'
    matches = scan_text(text)
    assert not any("High-Entropy" in m.pattern_name for m in matches)


def test_short_string_below_min_length_not_flagged():
    text = 'String x = "short";'
    matches = scan_text(text)
    assert not any("High-Entropy" in m.pattern_name for m in matches)


def test_entropy_matches_capped():
    # 30 random base64-shaped strings, seeded -- empirically verified (not assumed) that at
    # least 11 exceed the entropy threshold, so the cap of _MAX_ENTROPY_MATCHES (10) is
    # actually exercised rather than the test passing by accident.
    import random
    random.seed(42)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    lines = ['String s{} = "{}";'.format(i, "".join(random.choices(alphabet, k=30))) for i in range(30)]
    text = "\n".join(lines)
    matches = scan_text(text)
    entropy_matches = [m for m in matches if "High-Entropy" in m.pattern_name]
    assert len(entropy_matches) == 10


def test_entropy_redaction_never_exposes_full_value():
    text = 'String key = "aB3xR9kL2mZ8pQ7vN4wT6yU1sD5fG0hJ";'
    matches = scan_text(text)
    entropy_match = next(m for m in matches if "High-Entropy" in m.pattern_name)
    assert "aB3xR9kL2mZ8pQ7vN4wT6yU1sD5fG0hJ" not in entropy_match.redacted_snippet
