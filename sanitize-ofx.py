#!/usr/bin/env python3
"""Sanitize QIF or OFX files so Microsoft Money Sunset Edition accepts them."""

from __future__ import annotations

import argparse
import datetime as _dt
import logging
import re
import sys
import unicodedata
from pathlib import Path
from typing import Dict, Iterable, List
import xml.etree.ElementTree as ET

_LOG = logging.getLogger(__name__)

_HEADER_TEMPLATE = [
    "OFXHEADER:100",
    "DATA:OFXSGML",
    "VERSION:102",
    "SECURITY:NONE",
    "ENCODING:USASCII",
    "CHARSET:1252",
    "COMPRESSION:NONE",
    "OLDFILEUID:NONE",
    "NEWFILEUID:NONE",
    "",
]

_ALLOWED_QIF_TAGS = {
    "D",
    "T",
    "P",
    "M",
    "L",
    "N",
    "A",
    "S",
    "E",
    "O",
    "$",
    "^",
}

_PAYEE_LIMIT = 80
_MEMO_LIMIT = 120
_ADDRESS_LIMIT = 35

_OFX_TAG_LIMITS = {
    "NAME": 32,
    "MEMO": 255,
    "FITID": 32,
    "TRNUID": 36,
    "ORG": 32,
    "FID": 32,
}


def _ascii(text: str) -> str:
    """Return a Money-safe ASCII string."""
    normalized = unicodedata.normalize("NFKD", text)
    ascii_bytes = normalized.encode("ascii", "ignore")
    cleaned = ascii_bytes.decode("ascii", "ignore")
    cleaned = cleaned.replace("\r", " ").replace("\n", " ")
    cleaned = cleaned.replace("^", " ")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def _sanitize_date(raw: str) -> str:
    candidates = ["%m/%d/%Y", "%m/%d/%y", "%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"]
    for pattern in candidates:
        try:
            parsed = _dt.datetime.strptime(raw.strip(), pattern)
            return parsed.strftime("%m/%d'%y")
        except ValueError:
            continue
    _LOG.warning("Unrecognized date '%s'; leaving as-is", raw)
    return raw.strip()


def _sanitize_amount(raw: str) -> str:
    cleaned = raw.strip().replace(",", "")
    cleaned = cleaned.replace("+", "")
    if cleaned in {"", "-"}:
        return "0.00"
    try:
        value = float(cleaned)
    except ValueError:  # fallback for stray characters
        cleaned = re.sub(r"[^0-9.-]", "", cleaned)
        value = float(cleaned or 0.0)
        _LOG.warning("Amount needed coercion from '%s'", raw)
    return f"{value:.2f}"


def _trim(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    _LOG.warning("Truncating field '%s' to %d characters", text, limit)
    return text[:limit]


def _format_qif_record(lines: Iterable[str]) -> List[str]:
    record: Dict[str, List[str]] = {}
    for entry in lines:
        if not entry:
            continue
        tag = entry[0]
        value = entry[1:]
        if tag not in _ALLOWED_QIF_TAGS:
            _LOG.warning("Dropping unsupported QIF tag '%s'", tag)
            continue
        record.setdefault(tag, []).append(value)

    formatted: List[str] = []
    if "D" in record:
        formatted.append("D" + _sanitize_date(record["D"][0]))
    else:
        _LOG.warning("QIF record missing date; Money may reject it")
    if "T" in record:
        formatted.append("T" + _sanitize_amount(record["T"][0]))
    else:
        _LOG.warning("QIF record missing amount; Money may reject it")
    if "P" in record:
        payee = _trim(_ascii(record["P"][0]), _PAYEE_LIMIT)
        formatted.append("P" + payee)
    if "M" in record:
        memo = _trim(_ascii(record["M"][0]), _MEMO_LIMIT)
        formatted.append("M" + memo)
    if "L" in record:
        formatted.append("L" + _ascii(record["L"][0]))
    if "N" in record:
        formatted.append("N" + _ascii(record["N"][0]))

    for tag in ("A",):
        for value in record.get(tag, []):
            formatted.append(tag + _trim(_ascii(value), _ADDRESS_LIMIT))

    # Split details (S,E,O,$) must stay grouped and ordered
    splits = []
    split_tags = ("S", "E", "O", "$")
    max_len = max(len(record.get(t, [])) for t in split_tags) if any(record.get(t) for t in split_tags) else 0
    for index in range(max_len):
        for tag in split_tags:
            values = record.get(tag, [])
            if index < len(values):
                cleaned = _ascii(values[index])
                if tag == "$":
                    cleaned = _sanitize_amount(cleaned)
                splits.append(tag + cleaned)
    formatted.extend(splits)

    return formatted


def sanitize_qif(text: str) -> str:
    content = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.strip() for line in content.split("\n")]
    output: List[str] = []
    buffer: List[str] = []
    header = None

    for line in lines:
        if not line:
            continue
        if line.startswith("!Type"):
            if buffer:
                output.extend(_format_qif_record(buffer))
                output.append("^")
                buffer.clear()
            header_value = line.split(":", 1)[1].strip().upper() if ":" in line else "BANK"
            header = f"!Type:{header_value or 'BANK'}"
            output.append(header)
            continue
        if line == "^":
            if buffer:
                output.extend(_format_qif_record(buffer))
            else:
                _LOG.warning("Empty QIF record encountered")
            output.append("^")
            buffer.clear()
            continue
        buffer.append(line)

    if buffer:
        output.extend(_format_qif_record(buffer))
        output.append("^")

    if header is None:
        _LOG.warning("No QIF !Type header found; Money may refuse the file")

    # Ensure CRLF endings as Money expects Windows line endings
    return "\r\n".join(output) + "\r\n"


def _escape_ampersands(text: str) -> str:
    return re.sub(r"&(?!amp;|lt;|gt;|apos;|quot;)", "&amp;", text)


def _ensure_trnuid(root: ET.Element) -> None:
    fallback = None
    for fit in root.findall(".//FITID"):
        if fit.text and fit.text.strip():
            fallback = fit.text.strip()
            break
    if fallback is None:
        fallback = _dt.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    for node in root.findall(".//TRNUID"):
        if not node.text or not node.text.strip():
            node.text = fallback


def _ensure_balances(root: ET.Element) -> None:
    stmtrs = root.find(".//STMTRS")
    if stmtrs is None:
        return

    dtend = stmtrs.findtext(".//DTEND")
    if not dtend:
        dtend = _dt.datetime.utcnow().strftime("%Y%m%d")

    total = 0.0
    for trn in stmtrs.findall(".//STMTTRN"):
        amount_text = (trn.findtext("TRNAMT") or "0").replace(",", "")
        try:
            total += float(amount_text)
        except ValueError:
            continue

    def _make_balance(tag: str) -> ET.Element:
        existing = stmtrs.find(tag)
        if existing is not None:
            return existing
        return ET.SubElement(stmtrs, tag)

    for balance_tag in ("LEDGERBAL", "AVAILBAL"):
        balance = _make_balance(balance_tag)
        balamt = balance.find("BALAMT")
        if balamt is None:
            balamt = ET.SubElement(balance, "BALAMT")
        balamt.text = f"{total:.2f}"

        dtasof = balance.find("DTASOF")
        if dtasof is None:
            dtasof = ET.SubElement(balance, "DTASOF")
        dtasof.text = dtend


def _ensure_fi_info(root: ET.Element) -> None:
    sonrs = root.find(".//SONRS")
    if sonrs is None:
        return

    bank_id = root.findtext(".//BANKACCTFROM/BANKID", default="000000000").strip() or "000000000"
    org = bank_id

    fi = sonrs.find("FI")
    if fi is None:
        fi = ET.SubElement(sonrs, "FI")

    if fi.find("ORG") is None:
        ET.SubElement(fi, "ORG").text = org
    if fi.find("FID") is None:
        ET.SubElement(fi, "FID").text = bank_id

    intu_bid = sonrs.find("INTU.BID")
    if intu_bid is None:
        intu_bid = ET.SubElement(sonrs, "INTU.BID")
    intu_bid.text = bank_id


def _sanitize_ofx_value(tag: str, value: str) -> str:
    raw = value.strip()
    if not raw:
        return ""

    upper_tag = tag.upper()
    if upper_tag == "TRNAMT":
        return _sanitize_amount(raw)
    if upper_tag in {"DTPOSTED", "DTSTART", "DTEND", "DTASOF"}:
        digits = re.sub(r"[^0-9]", "", raw)
        if len(digits) < 8:
            _LOG.warning("Date-like tag %s has unexpected value '%s'", upper_tag, raw)
        return digits or raw

    sanitized = _ascii(raw)
    limit = _OFX_TAG_LIMITS.get(upper_tag)
    if limit:
        sanitized = _trim(sanitized, limit)
    return sanitized


def _ofx_element_to_sgml(elem: ET.Element) -> List[str]:
    lines: List[str] = []

    def _walk(node: ET.Element) -> None:
        tag = node.tag.upper()
        children = list(node)
        text = _sanitize_ofx_value(tag, node.text or "")

        if children:
            lines.append(f"<{tag}>")
            if text:
                lines.append(text)
            for child in children:
                _walk(child)
            lines.append(f"</{tag}>")
        else:
            if text:
                lines.append(f"<{tag}>{text}")
            else:
                # Drop empty leaf nodes; Money prefers them omitted entirely
                return

    _walk(elem)
    return lines


def sanitize_ofx(text: str) -> str:
    body_start = text.upper().find("<OFX")
    if body_start == -1:
        raise ValueError("Input does not contain an <OFX> root element")

    body = text[body_start:]
    body = body.replace("\r\n", "\n").replace("\r", "\n")
    body = _escape_ampersands(body)

    def _upper_tag(match: re.Match[str]) -> str:
        prefix = match.group(1)
        tag = match.group(2).upper()
        suffix = match.group(3)
        return f"<{prefix}{tag}{suffix}>"

    body = re.sub(r"<(/?)([A-Za-z0-9_.+-]+)([^>]*)>", _upper_tag, body)

    # Fix SGML: Close leaf tags that have text content but no closing tag
    # Matches <TAG>Content<... where Content is not whitespace and next char is < but not </TAG>
    # Content must not contain <. \S matches < so we use [^<\s] to ensure we don't match start of next tag.
    body = re.sub(
        r"<([A-Z0-9_.+-]+)>([^<]*[^<\s][^<]*)(?=<(?!/\1>))",
        r"<\1>\2</\1>",
        body,
        flags=re.IGNORECASE,
    )

    body = unicodedata.normalize("NFKD", body).encode("ascii", "ignore").decode("ascii", "ignore")
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:  # noqa: B904 - include context
        raise ValueError(f"Unable to parse OFX XML: {exc}") from exc

    _ensure_trnuid(root)
    _ensure_balances(root)
    _ensure_fi_info(root)
    lines = _ofx_element_to_sgml(root)
    sanitized = _HEADER_TEMPLATE + lines
    return "\r\n".join(sanitized) + "\r\n"


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        _LOG.info("Falling back to latin-1 decoding for %s", path)
        return path.read_text(encoding="latin-1")


def sanitize_file(input_path: Path) -> str:
    text = _read_text(input_path)
    
    # Detect OFX/QFX by content signature
    if "<OFX" in text.upper():
        return sanitize_ofx(text)
        
    # Default to QIF processing
    return sanitize_qif(text)


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-i", "--input", type=Path, required=True, help="Path to source QIF or OFX file")
    parser.add_argument("-o", "--output", type=Path, help="Destination file path")
    parser.add_argument("--in-place", action="store_true", help="Overwrite the source file in place")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args(argv)

    if args.in_place and args.output is not None:
        parser.error("--in-place and --output are mutually exclusive")
    if not args.input.exists():
        parser.error(f"Input file '{args.input}' does not exist")
    if args.output and args.output.is_dir():
        parser.error("--output must be a file, not a directory")
    if args.in_place:
        args.output = args.input
    if not args.output:
        suffix = args.input.suffix or ""
        stem = args.input.stem
        new_name = f"{stem}.sanitized{suffix}"
        args.output = args.input.with_name(new_name)
    return args


def main(argv: List[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    _configure_logging(args.verbose)
    try:
        sanitized = sanitize_file(args.input)
    except Exception as exc:  # noqa: BLE001 - surface to CLI
        _LOG.error("Failed to sanitize %s: %s", args.input, exc)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="ascii", newline="") as handle:
        handle.write(sanitized)
    _LOG.info("Sanitized file written to %s", args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
