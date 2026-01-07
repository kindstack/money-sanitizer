#!/usr/bin/env python3
"""Exhaustive test suite for sanitize-ofx.py covering MS Money OFX and QIF formats."""

import pytest
import tempfile
from pathlib import Path

from sanitize_ofx import (
    _ascii,
    _sanitize_date,
    _sanitize_amount,
    _trim,
    _format_qif_record,
    sanitize_qif,
    sanitize_ofx,
    sanitize_file,
    _escape_ampersands,
    _sanitize_ofx_value,
)


# =============================================================================
# Helper Functions Tests
# =============================================================================

class TestAscii:
    """Tests for _ascii() function."""

    def test_plain_ascii(self):
        assert _ascii("Hello World") == "Hello World"

    def test_unicode_normalization(self):
        # Accented characters should be normalized
        assert _ascii("café") == "cafe"
        assert _ascii("naïve") == "naive"
        assert _ascii("résumé") == "resume"

    def test_special_unicode(self):
        # Em dash is normalized and stripped (not converted to hyphen)
        assert _ascii("test\u2014dash") == "testdash"
        assert _ascii("\u201cquoted\u201d") == "quoted"

    def test_newlines_and_carriage_returns(self):
        assert _ascii("line1\nline2") == "line1 line2"
        assert _ascii("line1\rline2") == "line1 line2"
        assert _ascii("line1\r\nline2") == "line1 line2"

    def test_caret_replacement(self):
        # Caret is QIF record separator
        assert _ascii("test^value") == "test value"

    def test_multiple_spaces(self):
        assert _ascii("too    many   spaces") == "too many spaces"

    def test_leading_trailing_spaces(self):
        assert _ascii("  trimmed  ") == "trimmed"

    def test_empty_string(self):
        assert _ascii("") == ""

    def test_only_unicode(self):
        # Non-ASCII only
        assert _ascii("中文") == ""

    def test_mixed_unicode_ascii(self):
        assert _ascii("Price: €50") == "Price: 50"


class TestSanitizeDate:
    """Tests for _sanitize_date() function."""

    def test_mm_dd_yyyy(self):
        assert _sanitize_date("12/25/2023") == "12/25'23"

    def test_mm_dd_yy(self):
        assert _sanitize_date("12/25/23") == "12/25'23"

    def test_yyyy_mm_dd(self):
        assert _sanitize_date("2023-12-25") == "12/25'23"

    def test_dd_mm_yyyy_slash(self):
        assert _sanitize_date("25/12/2023") == "12/25'23"

    def test_dd_mm_yyyy_dash(self):
        assert _sanitize_date("25-12-2023") == "12/25'23"

    def test_whitespace_handling(self):
        assert _sanitize_date("  12/25/2023  ") == "12/25'23"

    def test_unrecognized_format(self):
        # Should return as-is with warning
        assert _sanitize_date("invalid-date") == "invalid-date"

    def test_edge_case_dates(self):
        assert _sanitize_date("01/01/2000") == "01/01'00"
        assert _sanitize_date("12/31/1999") == "12/31'99"


class TestSanitizeAmount:
    """Tests for _sanitize_amount() function."""

    def test_simple_positive(self):
        assert _sanitize_amount("100.50") == "100.50"

    def test_simple_negative(self):
        assert _sanitize_amount("-50.25") == "-50.25"

    def test_with_comma_thousands(self):
        assert _sanitize_amount("1,234.56") == "1234.56"
        assert _sanitize_amount("1,000,000.00") == "1000000.00"

    def test_with_plus_sign(self):
        assert _sanitize_amount("+100.00") == "100.00"

    def test_whitespace(self):
        assert _sanitize_amount("  100.50  ") == "100.50"

    def test_empty_string(self):
        assert _sanitize_amount("") == "0.00"

    def test_only_minus(self):
        assert _sanitize_amount("-") == "0.00"

    def test_integer_value(self):
        assert _sanitize_amount("100") == "100.00"

    def test_stray_characters(self):
        # Currency symbols, etc.
        assert _sanitize_amount("$100.00") == "100.00"

    def test_negative_with_comma(self):
        assert _sanitize_amount("-1,234.56") == "-1234.56"


class TestTrim:
    """Tests for _trim() function."""

    def test_within_limit(self):
        assert _trim("short", 10) == "short"

    def test_at_limit(self):
        assert _trim("exactly10!", 10) == "exactly10!"

    def test_over_limit(self):
        assert _trim("this is too long", 10) == "this is to"

    def test_empty_string(self):
        assert _trim("", 10) == ""


class TestEscapeAmpersands:
    """Tests for _escape_ampersands() function."""

    def test_plain_ampersand(self):
        assert _escape_ampersands("A & B") == "A &amp; B"

    def test_already_escaped(self):
        assert _escape_ampersands("&amp;") == "&amp;"
        assert _escape_ampersands("&lt;") == "&lt;"
        assert _escape_ampersands("&gt;") == "&gt;"
        assert _escape_ampersands("&apos;") == "&apos;"
        assert _escape_ampersands("&quot;") == "&quot;"

    def test_mixed(self):
        assert _escape_ampersands("A & B &amp; C") == "A &amp; B &amp; C"


class TestSanitizeOfxValue:
    """Tests for _sanitize_ofx_value() function."""

    def test_trnamt(self):
        assert _sanitize_ofx_value("TRNAMT", "1,234.56") == "1234.56"

    def test_date_tags(self):
        assert _sanitize_ofx_value("DTPOSTED", "2023-12-25") == "20231225"
        assert _sanitize_ofx_value("DTSTART", "20231201") == "20231201"

    def test_name_truncation(self):
        long_name = "A" * 50
        result = _sanitize_ofx_value("NAME", long_name)
        assert len(result) == 32

    def test_memo_truncation(self):
        long_memo = "B" * 300
        result = _sanitize_ofx_value("MEMO", long_memo)
        assert len(result) == 255

    def test_fitid_truncation(self):
        long_fitid = "C" * 50
        result = _sanitize_ofx_value("FITID", long_fitid)
        assert len(result) == 32

    def test_empty_value(self):
        assert _sanitize_ofx_value("NAME", "") == ""
        assert _sanitize_ofx_value("NAME", "   ") == ""


# =============================================================================
# QIF Format Tests
# =============================================================================

class TestQifBasic:
    """Basic QIF parsing and formatting tests."""

    def test_minimal_transaction(self):
        qif = "!Type:Bank\nD01/15/2023\nT100.00\n^"
        result = sanitize_qif(qif)
        assert "!Type:BANK" in result
        assert "D01/15'23" in result
        assert "T100.00" in result
        assert "^" in result

    def test_crlf_endings(self):
        qif = "!Type:Bank\nD01/15/2023\nT100.00\n^"
        result = sanitize_qif(qif)
        assert "\r\n" in result
        assert result.endswith("\r\n")

    def test_preserves_type_header(self):
        for account_type in ["Bank", "CCard", "Cash", "Oth A", "Oth L", "Invst"]:
            qif = f"!Type:{account_type}\nD01/15/2023\nT100.00\n^"
            result = sanitize_qif(qif)
            assert f"!Type:{account_type.upper()}" in result


class TestQifTransactionFields:
    """Tests for various QIF transaction fields."""

    def test_payee_field(self):
        qif = "!Type:Bank\nD01/15/2023\nT100.00\nPAcme Corporation\n^"
        result = sanitize_qif(qif)
        assert "PAcme Corporation" in result

    def test_payee_truncation(self):
        long_payee = "P" + "X" * 100
        qif = f"!Type:Bank\nD01/15/2023\nT100.00\n{long_payee}\n^"
        result = sanitize_qif(qif)
        # Payee limit is 80
        lines = result.split("\r\n")
        payee_line = [l for l in lines if l.startswith("P")][0]
        assert len(payee_line) <= 81  # P + 80 chars

    def test_memo_field(self):
        qif = "!Type:Bank\nD01/15/2023\nT100.00\nMThis is a memo\n^"
        result = sanitize_qif(qif)
        assert "MThis is a memo" in result

    def test_memo_truncation(self):
        long_memo = "M" + "Y" * 150
        qif = f"!Type:Bank\nD01/15/2023\nT100.00\n{long_memo}\n^"
        result = sanitize_qif(qif)
        lines = result.split("\r\n")
        memo_line = [l for l in lines if l.startswith("M")][0]
        assert len(memo_line) <= 121  # M + 120 chars

    def test_category_field(self):
        qif = "!Type:Bank\nD01/15/2023\nT100.00\nLFood:Groceries\n^"
        result = sanitize_qif(qif)
        assert "LFood:Groceries" in result

    def test_check_number_field(self):
        qif = "!Type:Bank\nD01/15/2023\nT100.00\nN1234\n^"
        result = sanitize_qif(qif)
        assert "N1234" in result

    def test_address_field(self):
        qif = "!Type:Bank\nD01/15/2023\nT100.00\nA123 Main St\nANew York, NY 10001\n^"
        result = sanitize_qif(qif)
        assert "A123 Main St" in result
        assert "ANew York, NY 10001" in result

    def test_address_truncation(self):
        long_address = "A" + "Z" * 50
        qif = f"!Type:Bank\nD01/15/2023\nT100.00\n{long_address}\n^"
        result = sanitize_qif(qif)
        lines = result.split("\r\n")
        addr_lines = [l for l in lines if l.startswith("A")]
        for addr in addr_lines:
            assert len(addr) <= 36  # A + 35 chars


class TestQifSplitTransactions:
    """Tests for QIF split transactions."""

    def test_basic_split(self):
        qif = """!Type:Bank
D01/15/2023
T300.00
PGrocery Store
SFood:Groceries
$100.00
SFood:Dining
$200.00
^"""
        result = sanitize_qif(qif)
        assert "SFood:Groceries" in result
        assert "$100.00" in result
        assert "SFood:Dining" in result
        assert "$200.00" in result

    def test_split_with_memo(self):
        qif = """!Type:Bank
D01/15/2023
T300.00
SFood
EMeat and vegetables
$100.00
SHousehold
ECleaning supplies
$200.00
^"""
        result = sanitize_qif(qif)
        assert "SFood" in result
        assert "EMeat and vegetables" in result
        assert "SHousehold" in result
        assert "ECleaning supplies" in result

    def test_split_ordering_preserved(self):
        qif = """!Type:Bank
D01/15/2023
T200.00
SFirst
$100.00
SSecond
$100.00
^"""
        result = sanitize_qif(qif)
        first_pos = result.find("SFirst")
        second_pos = result.find("SSecond")
        assert first_pos < second_pos


class TestQifMultipleTransactions:
    """Tests for multiple QIF transactions."""

    def test_multiple_records(self):
        qif = """!Type:Bank
D01/15/2023
T100.00
PPurchase 1
^
D01/16/2023
T200.00
PPurchase 2
^
D01/17/2023
T300.00
PPurchase 3
^"""
        result = sanitize_qif(qif)
        assert result.count("^") == 3
        assert "PPurchase 1" in result
        assert "PPurchase 2" in result
        assert "PPurchase 3" in result

    def test_mixed_transactions(self):
        qif = """!Type:Bank
D01/15/2023
T-50.00
PWithdrawal
^
D01/16/2023
T1000.00
PDeposit
^"""
        result = sanitize_qif(qif)
        assert "T-50.00" in result
        assert "T1000.00" in result


class TestQifEdgeCases:
    """Edge cases and error handling for QIF."""

    def test_missing_type_header(self):
        qif = "D01/15/2023\nT100.00\n^"
        result = sanitize_qif(qif)
        # Should still process
        assert "D01/15'23" in result

    def test_missing_date(self):
        qif = "!Type:Bank\nT100.00\nPPayee\n^"
        result = sanitize_qif(qif)
        # Should still process
        assert "T100.00" in result

    def test_missing_amount(self):
        qif = "!Type:Bank\nD01/15/2023\nPPayee\n^"
        result = sanitize_qif(qif)
        # Should still process
        assert "D01/15'23" in result

    def test_empty_record(self):
        qif = "!Type:Bank\n^\n^"
        result = sanitize_qif(qif)
        # Empty records should be handled

    def test_unsupported_tags_dropped(self):
        qif = "!Type:Bank\nD01/15/2023\nT100.00\nXUnsupported\n^"
        result = sanitize_qif(qif)
        assert "XUnsupported" not in result

    def test_unicode_in_payee(self):
        qif = "!Type:Bank\nD01/15/2023\nT100.00\nPCafé Française\n^"
        result = sanitize_qif(qif)
        assert "PCafe Francaise" in result

    def test_various_line_endings(self):
        # Unix
        qif1 = "!Type:Bank\nD01/15/2023\nT100.00\n^"
        # Windows
        qif2 = "!Type:Bank\r\nD01/15/2023\r\nT100.00\r\n^"
        # Old Mac
        qif3 = "!Type:Bank\rD01/15/2023\rT100.00\r^"

        for qif in [qif1, qif2, qif3]:
            result = sanitize_qif(qif)
            assert "D01/15'23" in result


# =============================================================================
# OFX Format Tests
# =============================================================================

class TestOfxBasic:
    """Basic OFX parsing tests."""

    def test_minimal_ofx(self):
        ofx = """<?xml version="1.0"?>
<OFX>
<SIGNONMSGSRSV1>
<SONRS>
<STATUS><CODE>0</CODE></STATUS>
<DTSERVER>20231215</DTSERVER>
</SONRS>
</SIGNONMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        assert "OFXHEADER:100" in result
        assert "<OFX>" in result

    def test_header_format(self):
        ofx = "<OFX></OFX>"
        result = sanitize_ofx(ofx)
        assert "OFXHEADER:100" in result
        assert "DATA:OFXSGML" in result
        assert "VERSION:102" in result
        assert "SECURITY:NONE" in result
        assert "ENCODING:USASCII" in result
        assert "CHARSET:1252" in result

    def test_crlf_endings(self):
        ofx = "<OFX></OFX>"
        result = sanitize_ofx(ofx)
        assert "\r\n" in result
        assert result.endswith("\r\n")


class TestOfxTransactions:
    """Tests for OFX transaction handling."""

    def test_single_transaction(self):
        ofx = """<OFX>
<BANKMSGSRSV1>
<STMTTRNRS>
<TRNUID>12345</TRNUID>
<STMTRS>
<BANKACCTFROM>
<BANKID>123456789</BANKID>
<ACCTID>987654321</ACCTID>
<ACCTTYPE>CHECKING</ACCTTYPE>
</BANKACCTFROM>
<BANKTRANLIST>
<DTSTART>20231201</DTSTART>
<DTEND>20231231</DTEND>
<STMTTRN>
<TRNTYPE>DEBIT</TRNTYPE>
<DTPOSTED>20231215</DTPOSTED>
<TRNAMT>-50.00</TRNAMT>
<FITID>TXN123</FITID>
<NAME>Grocery Store</NAME>
</STMTTRN>
</BANKTRANLIST>
</STMTRS>
</STMTTRNRS>
</BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        assert "<STMTTRN>" in result
        assert "<TRNTYPE>DEBIT" in result
        assert "<DTPOSTED>20231215" in result
        assert "<TRNAMT>-50.00" in result
        assert "<FITID>TXN123" in result
        assert "<NAME>Grocery Store" in result

    def test_multiple_transactions(self):
        ofx = """<OFX>
<BANKMSGSRSV1>
<STMTTRNRS>
<TRNUID>12345</TRNUID>
<STMTRS>
<BANKACCTFROM>
<BANKID>123456789</BANKID>
<ACCTID>987654321</ACCTID>
</BANKACCTFROM>
<BANKTRANLIST>
<DTSTART>20231201</DTSTART>
<DTEND>20231231</DTEND>
<STMTTRN>
<TRNTYPE>CREDIT</TRNTYPE>
<DTPOSTED>20231201</DTPOSTED>
<TRNAMT>1000.00</TRNAMT>
<FITID>TXN001</FITID>
</STMTTRN>
<STMTTRN>
<TRNTYPE>DEBIT</TRNTYPE>
<DTPOSTED>20231215</DTPOSTED>
<TRNAMT>-250.00</TRNAMT>
<FITID>TXN002</FITID>
</STMTTRN>
<STMTTRN>
<TRNTYPE>DEBIT</TRNTYPE>
<DTPOSTED>20231220</DTPOSTED>
<TRNAMT>-100.00</TRNAMT>
<FITID>TXN003</FITID>
</STMTTRN>
</BANKTRANLIST>
</STMTRS>
</STMTTRNRS>
</BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        assert result.count("<STMTTRN>") == 3
        assert "<FITID>TXN001" in result
        assert "<FITID>TXN002" in result
        assert "<FITID>TXN003" in result


class TestOfxTransactionTypes:
    """Tests for various OFX transaction types."""

    @pytest.mark.parametrize("trntype", [
        "CREDIT", "DEBIT", "INT", "DIV", "FEE", "SRVCHG", "DEP",
        "ATM", "POS", "XFER", "CHECK", "PAYMENT", "CASH", "DIRECTDEP",
        "DIRECTDEBIT", "REPEATPMT", "OTHER"
    ])
    def test_transaction_types(self, trntype):
        ofx = f"""<OFX>
<BANKMSGSRSV1><STMTTRNRS><TRNUID>1</TRNUID><STMTRS>
<BANKTRANLIST><STMTTRN>
<TRNTYPE>{trntype}</TRNTYPE>
<DTPOSTED>20231215</DTPOSTED>
<TRNAMT>100.00</TRNAMT>
<FITID>T1</FITID>
</STMTTRN></BANKTRANLIST>
</STMTRS></STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        assert f"<TRNTYPE>{trntype}" in result


class TestOfxBalances:
    """Tests for OFX balance handling."""

    def test_balance_generation(self):
        ofx = """<OFX>
<BANKMSGSRSV1><STMTTRNRS><TRNUID>1</TRNUID><STMTRS>
<BANKACCTFROM><BANKID>123</BANKID><ACCTID>456</ACCTID></BANKACCTFROM>
<BANKTRANLIST>
<DTSTART>20231201</DTSTART>
<DTEND>20231231</DTEND>
<STMTTRN>
<TRNTYPE>CREDIT</TRNTYPE>
<DTPOSTED>20231215</DTPOSTED>
<TRNAMT>500.00</TRNAMT>
<FITID>T1</FITID>
</STMTTRN>
</BANKTRANLIST>
</STMTRS></STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        assert "<LEDGERBAL>" in result
        assert "<AVAILBAL>" in result
        assert "<BALAMT>500.00" in result

    def test_balance_with_multiple_transactions(self):
        ofx = """<OFX>
<BANKMSGSRSV1><STMTTRNRS><TRNUID>1</TRNUID><STMTRS>
<BANKTRANLIST>
<DTEND>20231231</DTEND>
<STMTTRN><TRNTYPE>CREDIT</TRNTYPE><DTPOSTED>20231201</DTPOSTED><TRNAMT>1000.00</TRNAMT><FITID>T1</FITID></STMTTRN>
<STMTTRN><TRNTYPE>DEBIT</TRNTYPE><DTPOSTED>20231215</DTPOSTED><TRNAMT>-300.00</TRNAMT><FITID>T2</FITID></STMTTRN>
<STMTTRN><TRNTYPE>DEBIT</TRNTYPE><DTPOSTED>20231220</DTPOSTED><TRNAMT>-200.00</TRNAMT><FITID>T3</FITID></STMTTRN>
</BANKTRANLIST>
</STMTRS></STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        # Balance should be 1000 - 300 - 200 = 500
        assert "<BALAMT>500.00" in result


class TestOfxFinancialInstitution:
    """Tests for OFX financial institution info."""

    def test_fi_info_generation(self):
        ofx = """<OFX>
<SIGNONMSGSRSV1>
<SONRS>
<STATUS><CODE>0</CODE></STATUS>
<DTSERVER>20231215</DTSERVER>
</SONRS>
</SIGNONMSGSRSV1>
<BANKMSGSRSV1><STMTTRNRS><TRNUID>1</TRNUID><STMTRS>
<BANKACCTFROM><BANKID>123456789</BANKID><ACCTID>456</ACCTID></BANKACCTFROM>
</STMTRS></STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        assert "<FI>" in result
        assert "<ORG>123456789" in result
        assert "<FID>123456789" in result
        assert "<INTU.BID>123456789" in result


class TestOfxTrnuid:
    """Tests for OFX TRNUID handling."""

    def test_empty_trnuid_filled(self):
        ofx = """<OFX>
<BANKMSGSRSV1><STMTTRNRS>
<TRNUID></TRNUID>
<STMTRS>
<BANKTRANLIST>
<STMTTRN>
<DTPOSTED>20231215</DTPOSTED>
<TRNAMT>100.00</TRNAMT>
<FITID>TXN123</FITID>
</STMTTRN>
</BANKTRANLIST>
</STMTRS>
</STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        # TRNUID should be filled with FITID or timestamp
        assert "<TRNUID>" in result

    def test_existing_trnuid_preserved(self):
        ofx = """<OFX>
<BANKMSGSRSV1><STMTTRNRS>
<TRNUID>EXISTING123</TRNUID>
<STMTRS></STMTRS>
</STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        assert "<TRNUID>EXISTING123" in result


class TestOfxFieldTruncation:
    """Tests for OFX field length limits."""

    def test_name_truncation(self):
        long_name = "A" * 50
        ofx = f"""<OFX>
<BANKMSGSRSV1><STMTTRNRS><TRNUID>1</TRNUID><STMTRS>
<BANKTRANLIST>
<STMTTRN>
<TRNTYPE>DEBIT</TRNTYPE>
<DTPOSTED>20231215</DTPOSTED>
<TRNAMT>100.00</TRNAMT>
<FITID>T1</FITID>
<NAME>{long_name}</NAME>
</STMTTRN>
</BANKTRANLIST>
</STMTRS></STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        # NAME limit is 32
        assert f"<NAME>{'A' * 32}" in result

    def test_memo_truncation(self):
        long_memo = "B" * 300
        ofx = f"""<OFX>
<BANKMSGSRSV1><STMTTRNRS><TRNUID>1</TRNUID><STMTRS>
<BANKTRANLIST>
<STMTTRN>
<TRNTYPE>DEBIT</TRNTYPE>
<DTPOSTED>20231215</DTPOSTED>
<TRNAMT>100.00</TRNAMT>
<FITID>T1</FITID>
<MEMO>{long_memo}</MEMO>
</STMTTRN>
</BANKTRANLIST>
</STMTRS></STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        # MEMO limit is 255
        assert f"<MEMO>{'B' * 255}" in result

    def test_fitid_truncation(self):
        long_fitid = "C" * 50
        ofx = f"""<OFX>
<BANKMSGSRSV1><STMTTRNRS><TRNUID>1</TRNUID><STMTRS>
<BANKTRANLIST>
<STMTTRN>
<TRNTYPE>DEBIT</TRNTYPE>
<DTPOSTED>20231215</DTPOSTED>
<TRNAMT>100.00</TRNAMT>
<FITID>{long_fitid}</FITID>
</STMTTRN>
</BANKTRANLIST>
</STMTRS></STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        # FITID limit is 32
        assert f"<FITID>{'C' * 32}" in result


class TestOfxAmountHandling:
    """Tests for OFX amount formatting."""

    def test_positive_amount(self):
        ofx = """<OFX>
<BANKMSGSRSV1><STMTTRNRS><TRNUID>1</TRNUID><STMTRS>
<BANKTRANLIST>
<STMTTRN>
<TRNTYPE>CREDIT</TRNTYPE>
<DTPOSTED>20231215</DTPOSTED>
<TRNAMT>1234.56</TRNAMT>
<FITID>T1</FITID>
</STMTTRN>
</BANKTRANLIST>
</STMTRS></STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        assert "<TRNAMT>1234.56" in result

    def test_negative_amount(self):
        ofx = """<OFX>
<BANKMSGSRSV1><STMTTRNRS><TRNUID>1</TRNUID><STMTRS>
<BANKTRANLIST>
<STMTTRN>
<TRNTYPE>DEBIT</TRNTYPE>
<DTPOSTED>20231215</DTPOSTED>
<TRNAMT>-500.00</TRNAMT>
<FITID>T1</FITID>
</STMTTRN>
</BANKTRANLIST>
</STMTRS></STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        assert "<TRNAMT>-500.00" in result

    def test_amount_with_commas(self):
        ofx = """<OFX>
<BANKMSGSRSV1><STMTTRNRS><TRNUID>1</TRNUID><STMTRS>
<BANKTRANLIST>
<STMTTRN>
<TRNTYPE>CREDIT</TRNTYPE>
<DTPOSTED>20231215</DTPOSTED>
<TRNAMT>1,234.56</TRNAMT>
<FITID>T1</FITID>
</STMTTRN>
</BANKTRANLIST>
</STMTRS></STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        assert "<TRNAMT>1234.56" in result


class TestOfxDateHandling:
    """Tests for OFX date formatting."""

    def test_date_normalization(self):
        ofx = """<OFX>
<BANKMSGSRSV1><STMTTRNRS><TRNUID>1</TRNUID><STMTRS>
<BANKTRANLIST>
<DTSTART>2023-12-01</DTSTART>
<DTEND>2023-12-31</DTEND>
<STMTTRN>
<TRNTYPE>DEBIT</TRNTYPE>
<DTPOSTED>2023-12-15</DTPOSTED>
<TRNAMT>100.00</TRNAMT>
<FITID>T1</FITID>
</STMTTRN>
</BANKTRANLIST>
</STMTRS></STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        # Dates should be numeric only
        assert "<DTSTART>20231201" in result
        assert "<DTEND>20231231" in result
        assert "<DTPOSTED>20231215" in result


class TestOfxSgmlConversion:
    """Tests for OFX SGML format conversion."""

    def test_tags_uppercase(self):
        ofx = """<ofx>
<bankmsgsrsv1><stmttrnrs><trnuid>1</trnuid><stmtrs>
<banktranlist>
<stmttrn>
<trntype>debit</trntype>
<dtposted>20231215</dtposted>
<trnamt>100.00</trnamt>
<fitid>T1</fitid>
</stmttrn>
</banktranlist>
</stmtrs></stmttrnrs></bankmsgsrsv1>
</ofx>"""
        result = sanitize_ofx(ofx)
        assert "<BANKMSGSRSV1>" in result
        assert "<STMTTRN>" in result
        assert "<TRNTYPE>" in result

    def test_ampersand_escaping(self):
        ofx = """<OFX>
<BANKMSGSRSV1><STMTTRNRS><TRNUID>1</TRNUID><STMTRS>
<BANKTRANLIST>
<STMTTRN>
<TRNTYPE>DEBIT</TRNTYPE>
<DTPOSTED>20231215</DTPOSTED>
<TRNAMT>100.00</TRNAMT>
<FITID>T1</FITID>
<NAME>Smith & Jones</NAME>
</STMTTRN>
</BANKTRANLIST>
</STMTRS></STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        assert "Smith" in result
        assert "Jones" in result


class TestOfxEdgeCases:
    """Edge cases and error handling for OFX."""

    def test_no_ofx_root(self):
        with pytest.raises(ValueError, match="does not contain an <OFX>"):
            sanitize_ofx("<INVALID></INVALID>")

    def test_unicode_handling(self):
        ofx = """<OFX>
<BANKMSGSRSV1><STMTTRNRS><TRNUID>1</TRNUID><STMTRS>
<BANKTRANLIST>
<STMTTRN>
<TRNTYPE>DEBIT</TRNTYPE>
<DTPOSTED>20231215</DTPOSTED>
<TRNAMT>100.00</TRNAMT>
<FITID>T1</FITID>
<NAME>Café Française</NAME>
</STMTTRN>
</BANKTRANLIST>
</STMTRS></STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        assert "Cafe Francaise" in result

    def test_mixed_case_tags(self):
        ofx = """<OFX>
<BankMsgsRsV1><StmtTrnRs><TrnUid>1</TrnUid><StmtRs>
<BankTranList>
<StmtTrn>
<TrnType>DEBIT</TrnType>
<DtPosted>20231215</DtPosted>
<TrnAmt>100.00</TrnAmt>
<FitId>T1</FitId>
</StmtTrn>
</BankTranList>
</StmtRs></StmtTrnRs></BankMsgsRsV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        # All tags should be uppercase
        assert "<BANKMSGSRSV1>" in result
        assert "<STMTTRN>" in result

    def test_sgml_without_closing_tags(self):
        # SGML style without closing tags for leaf elements
        ofx = """OFXHEADER:100
DATA:OFXSGML
VERSION:102

<OFX>
<BANKMSGSRSV1>
<STMTTRNRS>
<TRNUID>1
<STMTRS>
<BANKTRANLIST>
<STMTTRN>
<TRNTYPE>DEBIT
<DTPOSTED>20231215
<TRNAMT>100.00
<FITID>T1
</STMTTRN>
</BANKTRANLIST>
</STMTRS>
</STMTTRNRS>
</BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        assert "<TRNTYPE>DEBIT" in result
        assert "<DTPOSTED>20231215" in result

    def test_empty_elements_dropped(self):
        ofx = """<OFX>
<BANKMSGSRSV1><STMTTRNRS><TRNUID>1</TRNUID><STMTRS>
<BANKTRANLIST>
<STMTTRN>
<TRNTYPE>DEBIT</TRNTYPE>
<DTPOSTED>20231215</DTPOSTED>
<TRNAMT>100.00</TRNAMT>
<FITID>T1</FITID>
<NAME></NAME>
<MEMO></MEMO>
</STMTTRN>
</BANKTRANLIST>
</STMTRS></STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        # Empty NAME and MEMO should be dropped
        lines = result.split("\r\n")
        name_lines = [l for l in lines if "<NAME>" in l]
        memo_lines = [l for l in lines if "<MEMO>" in l]
        assert len(name_lines) == 0
        assert len(memo_lines) == 0


class TestOfxCreditCard:
    """Tests for OFX credit card statements."""

    def test_credit_card_statement(self):
        ofx = """<OFX>
<SIGNONMSGSRSV1>
<SONRS>
<STATUS><CODE>0</CODE></STATUS>
<DTSERVER>20231215</DTSERVER>
</SONRS>
</SIGNONMSGSRSV1>
<CREDITCARDMSGSRSV1>
<CCSTMTTRNRS>
<TRNUID>CC123</TRNUID>
<CCSTMTRS>
<CCACCTFROM>
<ACCTID>4111111111111111</ACCTID>
</CCACCTFROM>
<BANKTRANLIST>
<DTSTART>20231201</DTSTART>
<DTEND>20231231</DTEND>
<STMTTRN>
<TRNTYPE>DEBIT</TRNTYPE>
<DTPOSTED>20231215</DTPOSTED>
<TRNAMT>-75.00</TRNAMT>
<FITID>CC001</FITID>
<NAME>Restaurant Purchase</NAME>
</STMTTRN>
</BANKTRANLIST>
</CCSTMTRS>
</CCSTMTTRNRS>
</CREDITCARDMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        assert "<CREDITCARDMSGSRSV1>" in result
        assert "<CCSTMTTRNRS>" in result
        assert "<CCSTMTRS>" in result
        assert "<CCACCTFROM>" in result


class TestOfxInvestment:
    """Tests for OFX investment statements."""

    def test_investment_statement_structure(self):
        ofx = """<OFX>
<SIGNONMSGSRSV1>
<SONRS>
<STATUS><CODE>0</CODE></STATUS>
<DTSERVER>20231215</DTSERVER>
</SONRS>
</SIGNONMSGSRSV1>
<INVSTMTMSGSRSV1>
<INVSTMTTRNRS>
<TRNUID>INV123</TRNUID>
<INVSTMTRS>
<DTASOF>20231231</DTASOF>
<INVACCTFROM>
<BROKERID>Broker123</BROKERID>
<ACCTID>ACCT456</ACCTID>
</INVACCTFROM>
<INVTRANLIST>
<DTSTART>20231201</DTSTART>
<DTEND>20231231</DTEND>
</INVTRANLIST>
</INVSTMTRS>
</INVSTMTTRNRS>
</INVSTMTMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        assert "<INVSTMTMSGSRSV1>" in result
        assert "<INVSTMTTRNRS>" in result
        assert "<INVACCTFROM>" in result


# =============================================================================
# File Processing Tests
# =============================================================================

class TestSanitizeFile:
    """Tests for file-level processing."""

    def test_qif_detection(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.qif', delete=False) as f:
            f.write("!Type:Bank\nD01/15/2023\nT100.00\n^")
            f.flush()
            result = sanitize_file(Path(f.name))
            assert "!Type:BANK" in result
            Path(f.name).unlink()

    def test_ofx_detection(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ofx', delete=False) as f:
            f.write("<OFX></OFX>")
            f.flush()
            result = sanitize_file(Path(f.name))
            assert "OFXHEADER:100" in result
            Path(f.name).unlink()

    def test_qfx_detection(self):
        # QFX files are OFX format
        with tempfile.NamedTemporaryFile(mode='w', suffix='.qfx', delete=False) as f:
            f.write("<OFX></OFX>")
            f.flush()
            result = sanitize_file(Path(f.name))
            assert "OFXHEADER:100" in result
            Path(f.name).unlink()


# =============================================================================
# MS Money Specific Format Tests
# =============================================================================

class TestMsMoneyQifCompatibility:
    """Tests specifically for MS Money QIF compatibility."""

    def test_date_format_money_style(self):
        # MS Money expects MM/DD'YY format
        qif = "!Type:Bank\nD12/25/2023\nT100.00\n^"
        result = sanitize_qif(qif)
        assert "D12/25'23" in result

    def test_credit_card_type(self):
        qif = "!Type:CCard\nD01/15/2023\nT-50.00\nPAmazon\n^"
        result = sanitize_qif(qif)
        assert "!Type:CCARD" in result

    def test_investment_type(self):
        qif = "!Type:Invst\nD01/15/2023\nT1000.00\n^"
        result = sanitize_qif(qif)
        assert "!Type:INVST" in result

    def test_windows_line_endings(self):
        qif = "!Type:Bank\nD01/15/2023\nT100.00\n^"
        result = sanitize_qif(qif)
        # All line endings should be CRLF
        assert "\r\n" in result
        assert result.count("\n") == result.count("\r\n")


class TestMsMoneyOfxCompatibility:
    """Tests specifically for MS Money OFX compatibility."""

    def test_sgml_format_no_xml_declaration(self):
        ofx = """<?xml version="1.0"?>
<OFX></OFX>"""
        result = sanitize_ofx(ofx)
        # MS Money expects SGML header, not XML declaration
        assert "<?xml" not in result
        assert "OFXHEADER:100" in result

    def test_version_102(self):
        ofx = "<OFX></OFX>"
        result = sanitize_ofx(ofx)
        assert "VERSION:102" in result

    def test_encoding_usascii(self):
        ofx = "<OFX></OFX>"
        result = sanitize_ofx(ofx)
        assert "ENCODING:USASCII" in result

    def test_charset_1252(self):
        ofx = "<OFX></OFX>"
        result = sanitize_ofx(ofx)
        assert "CHARSET:1252" in result

    def test_required_fi_block(self):
        ofx = """<OFX>
<SIGNONMSGSRSV1>
<SONRS>
<STATUS><CODE>0</CODE></STATUS>
</SONRS>
</SIGNONMSGSRSV1>
<BANKMSGSRSV1><STMTTRNRS><TRNUID>1</TRNUID><STMTRS>
<BANKACCTFROM><BANKID>123456789</BANKID><ACCTID>456</ACCTID></BANKACCTFROM>
</STMTRS></STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        # MS Money requires FI block
        assert "<FI>" in result
        assert "</FI>" in result

    def test_intu_bid_for_quicken_import(self):
        ofx = """<OFX>
<SIGNONMSGSRSV1>
<SONRS>
<STATUS><CODE>0</CODE></STATUS>
</SONRS>
</SIGNONMSGSRSV1>
<BANKMSGSRSV1><STMTTRNRS><TRNUID>1</TRNUID><STMTRS>
<BANKACCTFROM><BANKID>123456789</BANKID><ACCTID>456</ACCTID></BANKACCTFROM>
</STMTRS></STMTTRNRS></BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        # INTU.BID is needed for some imports
        assert "<INTU.BID>" in result


class TestMsMoneyRealWorldScenarios:
    """Real-world scenarios for MS Money import."""

    def test_typical_bank_download(self):
        ofx = """OFXHEADER:100
DATA:OFXSGML
VERSION:102
SECURITY:NONE
ENCODING:USASCII
CHARSET:1252
COMPRESSION:NONE
OLDFILEUID:NONE
NEWFILEUID:NONE

<OFX>
<SIGNONMSGSRSV1>
<SONRS>
<STATUS>
<CODE>0
<SEVERITY>INFO
</STATUS>
<DTSERVER>20231215120000
<LANGUAGE>ENG
</SONRS>
</SIGNONMSGSRSV1>
<BANKMSGSRSV1>
<STMTTRNRS>
<TRNUID>1001
<STATUS>
<CODE>0
<SEVERITY>INFO
</STATUS>
<STMTRS>
<CURDEF>USD
<BANKACCTFROM>
<BANKID>123456789
<ACCTID>9876543210
<ACCTTYPE>CHECKING
</BANKACCTFROM>
<BANKTRANLIST>
<DTSTART>20231201
<DTEND>20231215
<STMTTRN>
<TRNTYPE>DEBIT
<DTPOSTED>20231205
<TRNAMT>-42.50
<FITID>20231205001
<NAME>GROCERY STORE
<MEMO>Card Purchase
</STMTTRN>
<STMTTRN>
<TRNTYPE>CREDIT
<DTPOSTED>20231210
<TRNAMT>2500.00
<FITID>20231210001
<NAME>EMPLOYER INC
<MEMO>Direct Deposit
</STMTTRN>
</BANKTRANLIST>
<LEDGERBAL>
<BALAMT>5432.10
<DTASOF>20231215
</LEDGERBAL>
</STMTRS>
</STMTTRNRS>
</BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(ofx)
        assert "OFXHEADER:100" in result
        assert "<OFX>" in result
        assert "<STMTTRN>" in result
        assert "<TRNAMT>-42.50" in result
        assert "<TRNAMT>2500.00" in result

    def test_credit_card_download(self):
        qif = """!Type:CCard
D12/01/2023
T-125.00
PAMAZON.COM
MOnline Purchase
^
D12/05/2023
T-45.99
PNETFLIX
MMonthly Subscription
^
D12/10/2023
T500.00
PPAYMENT - THANK YOU
^"""
        result = sanitize_qif(qif)
        assert "!Type:CCARD" in result
        assert "PAMAZON.COM" in result
        assert "PNETFLIX" in result
        assert "T-125.00" in result
        assert "T500.00" in result

    def test_bank_statement_with_special_chars(self):
        qif = """!Type:Bank
D12/15/2023
T-50.00
PO'Reilly's Auto Parts
MBrake pads & rotors
^"""
        result = sanitize_qif(qif)
        assert "PO'Reilly's Auto Parts" in result
        # Ampersand in memo should be handled
        assert "MBrake pads" in result
        assert "rotors" in result


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests using temporary files."""

    def test_round_trip_qif(self):
        original = """!Type:Bank
D01/15/2023
T-100.00
PTest Payee
MTest Memo
^"""
        result = sanitize_qif(original)
        # Result should be valid and parseable
        assert "!Type:BANK" in result
        assert "^" in result

    def test_round_trip_ofx(self):
        original = """<OFX>
<BANKMSGSRSV1>
<STMTTRNRS>
<TRNUID>1</TRNUID>
<STMTRS>
<BANKTRANLIST>
<STMTTRN>
<TRNTYPE>DEBIT</TRNTYPE>
<DTPOSTED>20231215</DTPOSTED>
<TRNAMT>-100.00</TRNAMT>
<FITID>T1</FITID>
<NAME>Test</NAME>
</STMTTRN>
</BANKTRANLIST>
</STMTRS>
</STMTTRNRS>
</BANKMSGSRSV1>
</OFX>"""
        result = sanitize_ofx(original)
        assert "OFXHEADER:100" in result
        assert "<OFX>" in result
        assert "</OFX>" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
