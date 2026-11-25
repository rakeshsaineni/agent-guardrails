from agentguard.pii import Tokenizer, find_pii, iban_ok, luhn_ok, npi_ok, redact, ssn_ok


def test_validators():
    assert luhn_ok("4111111111111111") and not luhn_ok("4111111111111112")
    assert ssn_ok("123456789") and not ssn_ok("000123456") and not ssn_ok("666123456") and not ssn_ok("912345678")
    assert iban_ok("GB82 WEST 1234 5698 7654 32") and not iban_ok("GB82 WEST 1234 5698 7654 33")
    assert npi_ok("1234567893") and not npi_ok("1234567890")


def test_find_and_redact_mixed_text():
    text = ("Patient DOB: 04/12/1988, MRN 00482913, NPI 1234567893. Card 4111 1111 1111 1111, "
            "call (313) 555-0142 or jane.doe@example.com. Key AKIAABCDEFGHIJKLMNOP.")
    kinds = [f.kind for f in find_pii(text)]
    assert kinds == ["DOB", "MRN", "NPI", "CARD", "PHONE", "EMAIL", "AWS_KEY"]
    assert "4111" not in redact(text) and "[CARD]" in redact(text)


def test_no_false_positive_on_order_numbers():
    assert not [f for f in find_pii("Order 4111111111111112 shipped; ticket 000-12-3456 closed") if f.kind != "PHONE"]


def test_tokenization_round_trip_is_stable():
    tok = Tokenizer(b"k")
    a = tok.tokenize("Email jane@example.com about SSN 123-45-6789")
    b = tok.tokenize("Remind jane@example.com again")
    assert "jane@" not in a and a.split()[1] == b.split()[1]  # same person -> same token
    assert tok.detokenize(a) == "Email jane@example.com about SSN 123-45-6789"
