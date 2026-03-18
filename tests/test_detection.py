"""
Offline tests for the PhishNet detection algorithm (V8 heuristics).
Run: cd apps/api && python -m pytest ../../tests/test_detection.py -v
Or:  cd PhishNet && python tests/test_detection.py
"""

import sys
import os

# Add the API app to the path so we can import directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.main import _heuristic_detect_fallback, _registrable_domain, _is_third_party_domain


class FakeEmail:
    """Lightweight stand-in for the ORM Email model, used for testing heuristics."""
    def __init__(self, subject="", from_addr="", body_text="", extracted_urls=None):
        self.subject = subject
        self.from_addr = from_addr
        self.body_text = body_text
        self.extracted_urls = extracted_urls or []


def make_email(subject="", from_addr="", body_text="", urls=None):
    return FakeEmail(subject=subject, from_addr=from_addr, body_text=body_text, extracted_urls=urls or [])


# ============================================================================
# PHISHING EMAILS — should score HIGH (>=65)
# ============================================================================

def test_nigerian_scam():
    e = make_email(
        subject="URGENT: Unclaimed Fund Notification",
        from_addr="Dr. James <drjames@random-domain.ng>",
        body_text="Dear beneficiary, you have been selected to receive a compensation fund "
                  "of 5.5 million USD from the United Nations. Contact us via Western Union.",
        urls=["http://192.168.1.100/claim"]
    )
    score, label, reasons = _heuristic_detect_fallback(e)
    print(f"[Nigerian scam] score={score}, label={label}, reasons={reasons}")
    assert label == "phishing", f"Expected phishing, got {label} (score={score})"
    assert score >= 65


def test_brand_spoof_with_ip():
    e = make_email(
        subject="Your PayPal account has been limited",
        from_addr="PayPal Security <security@random-mailer.com>",
        body_text="Your account has been limited due to suspicious activity. Verify your identity now.",
        urls=["http://45.33.32.156/verify-paypal"]
    )
    score, label, reasons = _heuristic_detect_fallback(e)
    print(f"[Brand spoof + IP] score={score}, label={label}, reasons={reasons}")
    assert score >= 65, f"Expected >=65, got {score}"


def test_punycode_domain():
    e = make_email(
        subject="Confirm your Apple ID",
        from_addr="Apple <noreply@xn--pple-43d.com>",
        body_text="Your Apple ID was used to sign in. If this wasn't you, verify immediately.",
        urls=["https://xn--pple-43d.com/verify"]
    )
    score, label, reasons = _heuristic_detect_fallback(e)
    print(f"[Punycode] score={score}, label={label}, reasons={reasons}")
    assert score >= 35, f"Expected >=35, got {score}"


def test_coinbase_spoof():
    """Simulates sample-1001.eml pattern: coinbase spoof from medisept.com.au"""
    e = make_email(
        subject="[Alert] Confirm your info is required [Case ID 153465]",
        from_addr='"support@mail.coinbase.com" <mssggeauthencti-cbspprt@medisept.com.au>',
        body_text="Your Coinbase account requires verification. Confirm your identity to avoid suspension.",
        urls=["https://medisept.com.au/coinbase-verify", "https://medisept.com.au/login"]
    )
    score, label, reasons = _heuristic_detect_fallback(e)
    print(f"[Coinbase spoof] score={score}, label={label}, reasons={reasons}")
    assert score >= 30, f"Expected >=30 (suspicious+), got {score}"


# ============================================================================
# LEGITIMATE EMAILS — should score LOW (<30, ideally <15)
# ============================================================================

def test_legit_newsletter():
    e = make_email(
        subject="This week in tech: AI breakthroughs",
        from_addr="TechCrunch <newsletter@techcrunch.com>",
        body_text="Here are the top stories this week. Read more on our site.",
        urls=[
            "https://techcrunch.com/2024/03/15/article",
            "https://techcrunch.com/unsubscribe?id=123",
            "https://list-manage.com/track/click?u=abc"
        ]
    )
    score, label, reasons = _heuristic_detect_fallback(e)
    print(f"[Legit newsletter] score={score}, label={label}, reasons={reasons}")
    assert label == "benign", f"Expected benign, got {label} (score={score})"
    assert score < 30


def test_legit_bank_notification():
    e = make_email(
        subject="Your monthly statement is ready",
        from_addr="Chase <no-reply@chase.com>",
        body_text="Your January statement is now available. Log in to view your account details.",
        urls=["https://chase.com/statements", "https://chase.com/unsubscribe"]
    )
    score, label, reasons = _heuristic_detect_fallback(e)
    print(f"[Legit bank] score={score}, label={label}, reasons={reasons}")
    assert label == "benign", f"Expected benign, got {label} (score={score})"
    assert score < 15


def test_legit_password_reset():
    e = make_email(
        subject="Password reset request",
        from_addr="GitHub <noreply@github.com>",
        body_text="We received a request to reset your password. If you didn't make this request, ignore this email.",
        urls=["https://github.com/password_reset?token=abc123"]
    )
    score, label, reasons = _heuristic_detect_fallback(e)
    print(f"[Legit password reset] score={score}, label={label}, reasons={reasons}")
    assert label == "benign", f"Expected benign, got {label} (score={score})"
    assert score < 20


def test_legit_ecommerce_receipt():
    e = make_email(
        subject="Your order has shipped!",
        from_addr="Amazon <shipment-tracking@amazon.com>",
        body_text="Your package is on its way. Track your delivery with the link below.",
        urls=[
            "https://amazon.com/track/123",
            "https://s3.amazonaws.com/images/logo.png",
            "https://amazon.com/unsubscribe"
        ]
    )
    score, label, reasons = _heuristic_detect_fallback(e)
    print(f"[Legit ecommerce] score={score}, label={label}, reasons={reasons}")
    assert label == "benign", f"Expected benign, got {label} (score={score})"
    assert score < 15


def test_legit_marketing_with_tracking():
    """Marketing emails have many third-party tracking links — should NOT be flagged."""
    e = make_email(
        subject="50% off this weekend only!",
        from_addr="Nike <offers@nike.com>",
        body_text="Shop our biggest sale of the year. Limited time offer.",
        urls=[
            "https://nike.com/sale",
            "https://sendgrid.net/track/click?id=abc",
            "https://doubleclick.net/impression",
            "https://nike.com/unsubscribe",
        ]
    )
    score, label, reasons = _heuristic_detect_fallback(e)
    print(f"[Legit marketing] score={score}, label={label}, reasons={reasons}")
    assert label == "benign", f"Expected benign, got {label} (score={score})"
    assert score < 20


def test_legit_plain_text_no_urls():
    e = make_email(
        subject="Meeting tomorrow at 3pm",
        from_addr="John Smith <john@company.com>",
        body_text="Hey, just a reminder about our meeting tomorrow. See you there.",
        urls=[]
    )
    score, label, reasons = _heuristic_detect_fallback(e)
    print(f"[Legit plain text] score={score}, label={label}, reasons={reasons}")
    assert label == "benign", f"Expected benign, got {label} (score={score})"
    assert score == 0


def test_legit_gmail_sender():
    """Emails from generic domains (gmail) should not flag link mismatches."""
    e = make_email(
        subject="Check out this article",
        from_addr="friend@gmail.com",
        body_text="I found this interesting article about Python.",
        urls=["https://realpython.com/python-tips", "https://youtube.com/watch?v=abc"]
    )
    score, label, reasons = _heuristic_detect_fallback(e)
    print(f"[Legit gmail] score={score}, label={label}, reasons={reasons}")
    assert label == "benign", f"Expected benign, got {label} (score={score})"
    assert score < 15


# ============================================================================
# EDGE CASES — should be suspicious but not necessarily phishing
# ============================================================================

def test_urgency_only():
    """Urgency language alone should NOT trigger phishing — many legit emails are urgent."""
    e = make_email(
        subject="Action required: verify your account",
        from_addr="Dropbox <no-reply@dropbox.com>",
        body_text="Please verify your identity to continue using Dropbox. Your account has been limited.",
        urls=["https://dropbox.com/verify"]
    )
    score, label, reasons = _heuristic_detect_fallback(e)
    print(f"[Urgency only] score={score}, label={label}, reasons={reasons}")
    assert score < 30, f"Expected <30 (urgency alone shouldn't trigger phishing), got {score}"


def test_single_mismatch_link():
    """A single mismatched link in an otherwise normal email = low score."""
    e = make_email(
        subject="Your invoice",
        from_addr="billing@company.com",
        body_text="Please find your invoice attached.",
        urls=["https://random-cdn.com/invoice.pdf"]
    )
    score, label, reasons = _heuristic_detect_fallback(e)
    print(f"[Single mismatch] score={score}, label={label}, reasons={reasons}")
    # Single mismatch with 1 total URL → ratio 1.0, so it'll add 25
    # But that alone shouldn't be phishing
    assert score < 65, f"Expected <65, got {score}"


# ============================================================================
# HELPER TESTS
# ============================================================================

def test_registrable_domain():
    assert _registrable_domain("www.google.com") == "google.com"
    assert _registrable_domain("mail.google.co.uk") == "google.co.uk"
    assert _registrable_domain("example.com") == "example.com"
    assert _registrable_domain("sub.deep.example.com") == "example.com"
    assert _registrable_domain("") == ""


def test_third_party_detection():
    assert _is_third_party_domain("sendgrid.net") is True
    assert _is_third_party_domain("tracking.sendgrid.net") is True
    assert _is_third_party_domain("evil-phishing.com") is False
    assert _is_third_party_domain("doubleclick.net") is True


if __name__ == "__main__":
    tests = [
        # Phishing tests
        test_nigerian_scam,
        test_brand_spoof_with_ip,
        test_punycode_domain,
        test_coinbase_spoof,
        # Legitimate tests
        test_legit_newsletter,
        test_legit_bank_notification,
        test_legit_password_reset,
        test_legit_ecommerce_receipt,
        test_legit_marketing_with_tracking,
        test_legit_plain_text_no_urls,
        test_legit_gmail_sender,
        # Edge cases
        test_urgency_only,
        test_single_mismatch_link,
        # Helpers
        test_registrable_domain,
        test_third_party_detection,
    ]

    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
            print(f"  > PASS\n")
        except AssertionError as ex:
            failed += 1
            print(f"  X FAIL: {ex}\n")
        except Exception as ex:
            failed += 1
            print(f"  X ERROR: {ex}\n")

    print(f"\n{'='*60}")
    print(f"Results: {passed} passed, {failed} failed out of {passed + failed}")
    if failed == 0:
        print("All tests passed!")
    sys.exit(1 if failed else 0)
