#!/usr/bin/env python3

'''
Copyright (c) 2024-2026 Johann N. Löfflmann

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


This adapter reads exported TOTP secrets and stores those by calling
the interface of a target authenticator that is running on your personal computer,
or converts them into another export format.

See also https://github.com/jonelo/totp-secrets-adapter

Supported sources:
- https://github.com/scito/extract_otp_secrets (json, csv)
- Apple Passwords (csv)
- https://docs.2fauth.app (json)
- otpauth URIs, one per line (e.g. the otpauth export of 2FAuth)

Supported targets:
- https://github.com/JeNeSuisPasDave/authenticator (cli+stdin)
- all formats of the supported sources
'''

import argparse
import contextlib
import csv
import json
import glob
import os
import re
import shutil
import sys
import subprocess
import tempfile
from collections import namedtuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from getpass import getpass
from typing import Optional
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

__version__ = "2.0.0"

DEFAULT_AUTHENTICATOR = "authenticator"
AUTHENTICATOR_URL = "https://github.com/JeNeSuisPasDave/authenticator"
SUPPORTED_MAJOR_VERSION = 1
VERSION_PATTERN = re.compile(r"^authenticator version (\d+)\.(\d+)\.(\d+)")
DUMMY_ID = "dummy:dummy"
NO_DATA_FILE = "No data file was found"
# the authenticator always exits with 0, success can only be told by its output
ADD_OK = "OK"
DELETE_OK = "Deleted 1 configuration."
WRONG_PASSPHRASE = "Passphrase is incorrect"
PROMPTS = re.compile(r"(Enter|Confirm) (passphrase|shared secret): ")

SOURCE_APPLE = "apple-passwords"
SOURCE_EXTRACT_JSON = "extract-otp-secrets-json"
SOURCE_EXTRACT_CSV = "extract-otp-secrets-csv"
SOURCE_2FAUTH_JSON = "2fauth-json"
SOURCE_OTPAUTH = "otpauth-uris"
TARGET_AUTHENTICATOR = "authenticator"
SOURCES = (SOURCE_APPLE, SOURCE_EXTRACT_JSON, SOURCE_EXTRACT_CSV,
           SOURCE_2FAUTH_JSON, SOURCE_OTPAUTH)
TARGETS = (TARGET_AUTHENTICATOR,) + SOURCES

EXTRACT_FIELDS = ("name", "secret", "issuer", "type", "counter", "url")
EXTRACT_REQUIRED = ("issuer", "name", "secret")
APPLE_FIELDS = ("Title", "URL", "Username", "Password", "Notes", "OTPAuth")
APPLE_REQUIRED = ("Title", "OTPAuth")
APPLE_PASS_THROUGH = APPLE_FIELDS[:-1]   # everything except OTPAuth
# 2FAuth only recognizes an export whose "app" starts with "2fauth_"
TWOFAUTH_APP_PREFIX = "2fauth_"
TWOFAUTH_APP = TWOFAUTH_APP_PREFIX + "totp-secrets-adapter"
TWOFAUTH_REQUIRED = ("otp_type", "account", "service", "secret")
TWOFAUTH_TYPES = {"totp": "totp", "hotp": "hotp", "steamtotp": "steam"}
TWOFAUTH_PASS_THROUGH = ("icon", "icon_mime", "icon_file", "legacy_uri")
# 2FAuth only imports a text file if every line starts like this
OTPAUTH_LINE = re.compile(r"^otpauth://(totp|hotp|steam)/", re.IGNORECASE)

OTP_TYPES = ("totp", "hotp", "steam")
EXTRACT_TYPES = ("totp", "hotp")
TYPE_NAMES = {"totp": "time-based (TOTP)", "hotp": "counter-based (HOTP)",
              "steam": "Steam Guard"}
SUPPORTED_TYPES = {
    TARGET_AUTHENTICATOR: ("totp", "hotp"),
    SOURCE_APPLE: ("totp",),
    SOURCE_EXTRACT_JSON: EXTRACT_TYPES,
    SOURCE_EXTRACT_CSV: EXTRACT_TYPES,
    SOURCE_2FAUTH_JSON: OTP_TYPES,
    SOURCE_OTPAUTH: OTP_TYPES,
}
DEFAULT_DIGITS = 6
STEAM_DIGITS = 5
DEFAULT_PERIOD = 30
DEFAULT_ALGORITHM = "SHA1"


class InputError(Exception):
    '''Invalid input; the message describes the problem.'''


@dataclass
class OtpRecord:
    '''One OTP secret in the normalized form that all readers produce and all
    writers consume.

    Attributes:
        issuer: name of the service, may be empty.
        name: account name.
        secret: base32 encoded shared secret.
        type: one of OTP_TYPES ("totp", "hotp", "steam").
        counter: counter of a HOTP record, None for the other types.
        digits: number of digits of a password.
        period: validity of a TOTP password in seconds.
        algorithm: hash algorithm in upper case, e.g. "SHA1".
        otpauth: the original otpauth URL of the source, written back verbatim
            by the writers; None if the source had none.
        apple: the columns APPLE_PASS_THROUGH of an Apple Passwords entry,
            None for other sources.
        twofauth: the fields TWOFAUTH_PASS_THROUGH of a 2FAuth entry, None for
            other sources.
    '''
    issuer: str
    name: str
    secret: str
    type: str = "totp"
    counter: Optional[int] = None
    digits: int = DEFAULT_DIGITS
    period: int = DEFAULT_PERIOD
    algorithm: str = DEFAULT_ALGORITHM
    # data of the source that is written back unchanged if the target has a
    # place for it; not part of the OTP data, so not compared
    otpauth: Optional[str] = field(default=None, compare=False)
    apple: Optional[dict] = field(default=None, compare=False)
    twofauth: Optional[dict] = field(default=None, compare=False)

    @property
    def id(self):
        '''The identifier of the record in messages and in the authenticator.

        Returns:
            "issuer:name" as str.
        '''
        return f"{self.issuer}:{self.name}"


def parse_args():
    '''Parses and checks the command line arguments.

    Returns:
        argparse.Namespace with files, source (None if not given), target,
        output (the file of --output or --output-overwrite, None for target
        authenticator), overwrite (True for --output-overwrite) and
        authenticator (None if not given).

    Raises:
        SystemExit: exit code 0 after --help or --version; exit code 2 if no
            file is given or the options are invalid or do not fit the target.
    '''
    parser = argparse.ArgumentParser(
        description="Reads exported TOTP secrets and stores them in Dave's "
                    "authenticator,\nor converts them into another format.",
        epilog="examples:\n"
               "  %(prog)s *.json\n"
               "  %(prog)s --authenticator "
               "~/.venvs/authenticator/bin/authenticator *.json\n"
               "  %(prog)s --target apple-passwords --output apple.csv *.json\n"
               "  %(prog)s --source apple-passwords --target "
               "extract-otp-secrets-json --output otp.json Passwords.csv\n"
               "  %(prog)s -s apple-passwords -t extract-otp-secrets-csv "
               "-o otp.csv Passwords.csv\n"
               "  %(prog)s -t 2fauth-json -O 2fauth_import.json 2fauth_export_otpauth.txt",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "files", nargs="*", metavar="file",
        help="exported secrets; wildcards (* and ?) are expanded "
             "by the script if the shell does not do it")
    parser.add_argument(
        "-s", "--source", choices=SOURCES, metavar="FORMAT",
        help=f"format of the input files: {', '.join(SOURCES)} (default: "
             "detected from the file extension and the CSV header)")
    parser.add_argument(
        "-t", "--target", choices=TARGETS, metavar="TARGET", default=TARGET_AUTHENTICATOR,
        help=f"where the secrets go: {', '.join(TARGETS)} "
             f"(default: {TARGET_AUTHENTICATOR})")
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "-o", "--output", metavar="FILE",
        help="output file for the targets other than authenticator; "
             "an existing file is never overwritten")
    output.add_argument(
        "-O", "--output-overwrite", metavar="FILE",
        help="like --output, but an existing file is overwritten")
    parser.add_argument(
        "-a", "--authenticator", metavar="PATH",
        help="path or name of Dave's authenticator executable "
             f"(default: {DEFAULT_AUTHENTICATOR} from PATH)")
    args = parser.parse_args()
    if not args.files:
        parser.print_usage()
        sys.exit(2)
    args.overwrite = args.output_overwrite is not None
    args.output = args.output or args.output_overwrite
    if args.target == TARGET_AUTHENTICATOR:
        if args.output is not None:
            parser.error("--output and --output-overwrite are not allowed with "
                         f"--target {TARGET_AUTHENTICATOR}")
    else:
        if args.output is None:
            parser.error(f"--output or --output-overwrite is required with --target {args.target}")
        if args.authenticator is not None:
            parser.error(f"--authenticator is only allowed with --target {TARGET_AUTHENTICATOR}")
    return args


def collect_files(args):
    '''Returns the input files and expands wildcards.

    The script expands wildcards itself, because not all shells perform
    globbing before they pass the arguments to the script. A pattern that
    matches no file is reported with a warning.

    Args:
        args: list of file names and patterns with * or ?, as given on the
            command line.

    Returns:
        list of file names; entries without wildcards are passed unchanged,
        even if the file does not exist. Empty if only non-matching patterns
        were given.
    '''
    secret_files = []
    for entry in args:
        if "*" in entry or "?" in entry:
            files = glob.glob(entry)
            if not files:
                print(f"Warning: {entry} does not match any file.")
            secret_files.extend(files)
        else:
            secret_files.append(entry)
    return secret_files


# ---------------------------------------------------------------- otpauth URLs

def default_digits(otp_type):
    '''Returns the default number of digits of an OTP type.

    Args:
        otp_type: one of OTP_TYPES.

    Returns:
        STEAM_DIGITS (5) for "steam", DEFAULT_DIGITS (6) otherwise.
    '''
    return STEAM_DIGITS if otp_type == "steam" else DEFAULT_DIGITS


def parse_int(value, what, minimum):
    '''Converts a value to an int with a lower bound.

    Args:
        value: str or int to convert; None is reported as not a number.
        what: name of the value for the error messages, e.g. "counter".
        minimum: smallest allowed number.

    Returns:
        The number as int.

    Raises:
        InputError: value is not a number or is smaller than minimum.
    '''
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise InputError(f"{what} is not a number: {value}")
    if number < minimum:
        raise InputError(f"{what} must be at least {minimum}: {value}")
    return number


def parse_otpauth(url):
    '''Splits an otpauth URL (Key Uri Format) into its parts.

    Missing optional parameters get their defaults (digits depend on the type).

    Args:
        url: otpauth URL as str, e.g. "otpauth://totp/Issuer:alice?secret=...".

    Returns:
        dict with the keys type (lower case), label_issuer (issuer part of the
        label, "" if there is none), account, secret, issuer (the issuer
        parameter, "" if missing), counter (int for HOTP, None otherwise),
        digits, period and algorithm (upper case).

    Raises:
        InputError: the URL is not an otpauth URL of a type in OTP_TYPES, has
            no secret, a HOTP URL has no valid counter, or digits or period are
            not positive numbers.
    '''
    parsed = urlparse(url)
    otp_type = parsed.netloc.lower()
    if parsed.scheme.lower() != "otpauth" or otp_type not in OTP_TYPES:
        raise InputError(f"not an otpauth URL: {url}")
    label = unquote(parsed.path.lstrip("/"))
    label_issuer, account = label.split(":", 1) if ":" in label else ("", label)
    params = {key.lower(): values[0] for key, values in parse_qs(parsed.query).items()}
    if not params.get("secret"):
        raise InputError("the otpauth URL has no secret")
    parts = {
        "type": otp_type,
        "label_issuer": label_issuer.strip(),
        "account": account.strip(),
        "secret": params["secret"],
        "issuer": params.get("issuer", ""),
        "counter": None,
        "digits": parse_int(params.get("digits", default_digits(otp_type)), "digits", 1),
        "period": parse_int(params.get("period", DEFAULT_PERIOD), "period", 1),
        "algorithm": params.get("algorithm", DEFAULT_ALGORITHM).upper(),
    }
    if otp_type == "hotp":
        parts["counter"] = parse_int(params.get("counter"), "counter", 0)
    return parts


def build_otpauth(record):
    '''Builds the otpauth URL of a record.

    Optional parameters are only included if they differ from their defaults;
    the counter is always included for HOTP, the period never.

    Args:
        record: OtpRecord.

    Returns:
        otpauth URL as str, e.g. "otpauth://totp/Issuer:alice?secret=...&issuer=Issuer".
    '''
    label = quote(record.name, safe="@")
    if record.issuer:
        label = f"{quote(record.issuer, safe='@')}:{label}"
    params = {"secret": record.secret}
    if record.issuer:
        params["issuer"] = record.issuer
    if record.type == "hotp":
        params["counter"] = record.counter
    if record.algorithm != DEFAULT_ALGORITHM:
        params["algorithm"] = record.algorithm
    if record.digits != default_digits(record.type):
        params["digits"] = record.digits
    if record.type != "hotp" and record.period != DEFAULT_PERIOD:
        params["period"] = record.period
    return f"otpauth://{record.type}/{label}?{urlencode(params, quote_via=quote)}"


# ---------------------------------------------------------------- sources

def record_from_extract(fields):
    '''Creates a record from the fields of extract_otp_secrets (json or csv).

    Digits, period and algorithm are only part of the otpauth URL in the field
    url; an invalid url is ignored with a warning and the defaults are used.

    Args:
        fields: dict with the keys of EXTRACT_FIELDS; issuer, name and secret
            are required, type defaults to "totp".

    Returns:
        OtpRecord; otpauth is set to the url if it is valid.

    Raises:
        InputError: a required field is missing or None, the type is not in
            EXTRACT_TYPES, or a HOTP record has no valid counter.
    '''
    missing = [key for key in EXTRACT_REQUIRED if key not in fields or fields[key] is None]
    if missing:
        raise InputError(f"lacks {', '.join(missing)}")
    otp_type = str(fields.get("type") or "totp").lower()
    if otp_type not in EXTRACT_TYPES:
        raise InputError(f"type {otp_type} is not supported")
    record = OtpRecord(issuer=str(fields["issuer"]), name=str(fields["name"]),
                       secret=str(fields["secret"]), type=otp_type)
    if otp_type == "hotp":
        record.counter = parse_int(fields.get("counter"), "counter", 0)
    # digits, period and algorithm are only part of the otpauth URL
    url = fields.get("url")
    if url:
        try:
            parts = parse_otpauth(str(url))
        except InputError as e:
            print(f"Warning: {record.id}: url ignored ({e})")
        else:
            record.digits = parts["digits"]
            record.period = parts["period"]
            record.algorithm = parts["algorithm"]
            record.otpauth = str(url)
    return record


def read_json(secret_file):
    '''Reads a JSON file (UTF-8, with or without BOM).

    Args:
        secret_file: path of the file.

    Returns:
        The decoded JSON value (list, dict, ...).

    Raises:
        InputError: the file is not valid UTF-8 or not valid JSON.
        OSError: the file cannot be opened or read.
    '''
    try:
        with open(secret_file, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise InputError(f"not a valid JSON file ({e})")


def is_2fauth_export(data):
    '''Tells whether decoded JSON data looks like a 2FAuth export.

    Args:
        data: the decoded JSON value of a file.

    Returns:
        True if data is a dict whose "app" starts with "2fauth_" and whose
        "data" is a list, False otherwise.
    '''
    return (isinstance(data, dict) and isinstance(data.get("data"), list)
            and str(data.get("app", "")).startswith(TWOFAUTH_APP_PREFIX))


def read_extract_json(secret_file, errors):
    '''Reads the JSON export of extract_otp_secrets (a list of objects).

    Args:
        secret_file: path of the file.
        errors: list that a message "<file>: record #<n> <problem>" is appended
            to for each invalid record; the other records are still read.

    Returns:
        list of OtpRecord of the valid records.

    Raises:
        InputError: the file is no valid JSON or does not contain a list.
        OSError: the file cannot be opened or read.
    '''
    data = read_json(secret_file)
    if not isinstance(data, list):
        raise InputError("expected a list of records")
    records = []
    for index, fields in enumerate(data, start=1):
        try:
            if not isinstance(fields, dict):
                raise InputError("is not an object")
            records.append(record_from_extract(fields))
        except InputError as e:
            errors.append(f"{secret_file}: record #{index} {e}")
    return records


def read_csv_rows(secret_file):
    '''Reads a CSV file (UTF-8, with or without BOM) with a header line.

    Args:
        secret_file: path of the file.

    Returns:
        tuple (header, rows): header is the list of column names (empty for an
        empty file), rows is a list of dicts that map the column names to the
        values of a line.

    Raises:
        InputError: the file is not valid UTF-8 or not valid CSV.
        OSError: the file cannot be opened or read.
    '''
    try:
        with open(secret_file, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            return reader.fieldnames or [], list(reader)
    except (csv.Error, UnicodeDecodeError) as e:
        raise InputError(f"not a valid CSV file ({e})")


def read_extract_csv(secret_file, errors):
    '''Reads the CSV export of extract_otp_secrets.

    Args:
        secret_file: path of the file.
        errors: list that a message "<file>: line <n> <problem>" is appended to
            for each invalid line; the other lines are still read.

    Returns:
        list of OtpRecord of the valid lines.

    Raises:
        InputError: the file is no valid CSV or its header is not exactly
            EXTRACT_FIELDS.
        OSError: the file cannot be opened or read.
    '''
    header, rows = read_csv_rows(secret_file)
    if tuple(header) != EXTRACT_FIELDS:
        raise InputError(f"the first line must be {','.join(EXTRACT_FIELDS)}")
    records = []
    for row_number, fields in enumerate(rows, start=2):
        try:
            records.append(record_from_extract(fields))
        except InputError as e:
            errors.append(f"{secret_file}: line {row_number} {e}")
    return records


def read_apple_passwords(secret_file, errors):
    '''Reads a CSV export of Apple Passwords.

    Entries without OTPAuth are skipped and only counted in a message. Title
    and Username are the fallbacks for issuer and name if the otpauth URL has
    none; the columns APPLE_PASS_THROUGH are kept in OtpRecord.apple.

    Args:
        secret_file: path of the file.
        errors: list that a message "<file>: line <n> <problem>" is appended to
            for each invalid otpauth URL; the other lines are still read.

    Returns:
        list of OtpRecord of the entries with a valid one-time password.

    Raises:
        InputError: the file is no valid CSV or lacks a column of APPLE_REQUIRED.
        OSError: the file cannot be opened or read.
    '''
    header, rows = read_csv_rows(secret_file)
    missing = [key for key in APPLE_REQUIRED if key not in header]
    if missing:
        raise InputError(f"not an Apple Passwords export (column {', '.join(missing)} missing)")
    records = []
    without_otp = 0
    for row_number, fields in enumerate(rows, start=2):
        url = (fields.get("OTPAuth") or "").strip()
        if not url:
            without_otp += 1
            continue
        try:
            parts = parse_otpauth(url)
        except InputError as e:
            errors.append(f"{secret_file}: line {row_number} {e}")
            continue
        records.append(record_from_otpauth(
            parts, fields["OTPAuth"], fields.get("Title") or "", fields.get("Username") or "",
            apple={key: fields.get(key) or "" for key in APPLE_PASS_THROUGH}))
    if without_otp:
        entries = "entry" if without_otp == 1 else "entries"
        print(f"{secret_file}: {without_otp} {entries} without a one-time password skipped")
    return records


def read_2fauth_json(secret_file, errors):
    '''Reads the JSON export of 2FAuth.

    Args:
        secret_file: path of the file.
        errors: list that a message "<file>: record #<n> <problem>" is appended
            to for each invalid item of "data"; the other items are still read.

    Returns:
        list of OtpRecord of the valid items.

    Raises:
        InputError: the file is no valid JSON or no 2FAuth export
            (see is_2fauth_export()).
        OSError: the file cannot be opened or read.
    '''
    data = read_json(secret_file)
    if not is_2fauth_export(data):
        raise InputError(f"not a 2FAuth export (an object with \"app\": "
                         f"\"{TWOFAUTH_APP_PREFIX}...\" and \"data\" is expected)")
    records = []
    for index, item in enumerate(data["data"], start=1):
        try:
            records.append(record_from_2fauth(item))
        except InputError as e:
            errors.append(f"{secret_file}: record #{index} {e}")
    return records


def record_from_2fauth(item):
    '''Creates a record from an item of the "data" list of a 2FAuth export.

    The fields TWOFAUTH_PASS_THROUGH (icon data and legacy_uri) are kept in
    OtpRecord.twofauth; legacy_uri may be stale and is therefore not used for
    the OTP data.

    Args:
        item: dict with at least the keys of TWOFAUTH_REQUIRED; digits,
            algorithm, period and counter are optional.

    Returns:
        OtpRecord; missing digits, period and algorithm get their defaults, a
        missing HOTP counter becomes 0.

    Raises:
        InputError: item is no dict, a required field is missing or None, the
            otp_type is not in TWOFAUTH_TYPES, or digits, period or counter
            are invalid.
    '''
    if not isinstance(item, dict):
        raise InputError("is not an object")
    missing = [key for key in TWOFAUTH_REQUIRED if item.get(key) is None]
    if missing:
        raise InputError(f"lacks {', '.join(missing)}")
    otp_type = TWOFAUTH_TYPES.get(str(item["otp_type"]).lower())
    if otp_type is None:
        raise InputError(f"otp_type {item['otp_type']} is not supported")
    record = OtpRecord(
        issuer=str(item["service"]), name=str(item["account"]),
        secret=str(item["secret"]), type=otp_type,
        digits=default_digits(otp_type),
        algorithm=str(item.get("algorithm") or DEFAULT_ALGORITHM).upper(),
        twofauth={key: item.get(key) for key in TWOFAUTH_PASS_THROUGH})
    if item.get("digits") is not None:
        record.digits = parse_int(item["digits"], "digits", 1)
    if otp_type == "hotp":
        record.counter = parse_int(item.get("counter") or 0, "counter", 0)
    elif item.get("period") is not None:
        record.period = parse_int(item["period"], "period", 1)
    return record


def read_otpauth_uris(secret_file, errors):
    '''Reads a text file with one otpauth URI per line; empty lines are ignored.

    Args:
        secret_file: path of the file.
        errors: list that a message "<file>: line <n> <problem>" is appended to
            for each invalid URI; the other lines are still read.

    Returns:
        list of OtpRecord of the valid URIs.

    Raises:
        InputError: the file is not valid UTF-8.
        OSError: the file cannot be opened or read.
    '''
    try:
        with open(secret_file, "r", encoding="utf-8-sig", newline="") as f:
            lines = f.read().splitlines()
    except UnicodeDecodeError as e:
        raise InputError(f"not a text file ({e})")
    records = []
    for line_number, line in enumerate(lines, start=1):
        uri = line.strip()
        if not uri:
            continue
        try:
            records.append(record_from_otpauth(parse_otpauth(uri), uri))
        except InputError as e:
            errors.append(f"{secret_file}: line {line_number} {e}")
    return records


def record_from_otpauth(parts, otpauth, issuer_fallback="", name_fallback="", **pass_through):
    '''Creates a record from the parts of an otpauth URL.

    The URL itself is kept to be written back unchanged.

    Args:
        parts: dict returned by parse_otpauth().
        otpauth: the otpauth URL the parts come from, stored in OtpRecord.otpauth.
        issuer_fallback: issuer if the URL has neither an issuer parameter nor
            an issuer in its label.
        name_fallback: name if the URL has no account in its label.
        **pass_through: further OtpRecord fields, i.e. apple or twofauth.

    Returns:
        OtpRecord.
    '''
    return OtpRecord(
        issuer=parts["issuer"] or parts["label_issuer"] or issuer_fallback,
        name=parts["account"] or name_fallback,
        secret=parts["secret"], type=parts["type"], counter=parts["counter"],
        digits=parts["digits"], period=parts["period"],
        algorithm=parts["algorithm"], otpauth=otpauth, **pass_through)


READERS = {
    SOURCE_APPLE: read_apple_passwords,
    SOURCE_EXTRACT_JSON: read_extract_json,
    SOURCE_EXTRACT_CSV: read_extract_csv,
    SOURCE_2FAUTH_JSON: read_2fauth_json,
    SOURCE_OTPAUTH: read_otpauth_uris,
}


def detect_source(secret_file):
    '''Detects the format of a file by its extension and its content.

    .json: a list is extract_otp_secrets, a 2FAuth export is 2FAuth; .txt:
    otpauth URIs; .csv: the header decides between extract_otp_secrets and
    Apple Passwords.

    Args:
        secret_file: path of the file.

    Returns:
        one of SOURCES.

    Raises:
        InputError: the format cannot be detected, or the JSON or CSV content
            is invalid.
        OSError: the file cannot be opened or read.
    '''
    with open(secret_file, "rb"):
        pass  # reports a missing or unreadable file as such
    extension = os.path.splitext(secret_file)[1].lower()
    if extension == ".json":
        data = read_json(secret_file)
        if isinstance(data, list):
            return SOURCE_EXTRACT_JSON
        if is_2fauth_export(data):
            return SOURCE_2FAUTH_JSON
    if extension == ".txt":
        return SOURCE_OTPAUTH
    if extension == ".csv":
        header, _ = read_csv_rows(secret_file)
        if tuple(header) == EXTRACT_FIELDS:
            return SOURCE_EXTRACT_CSV
        if all(key in header for key in APPLE_REQUIRED):
            return SOURCE_APPLE
    raise InputError("cannot detect the format, please use --source")


def load_records(secret_files, source):
    '''Reads and validates all files.

    This happens before anything is written or the authenticator is touched;
    all problems of all files are collected and printed to stderr at once.

    Args:
        secret_files: list of file paths.
        source: one of SOURCES for all files, or None to detect the format of
            each file with detect_source().

    Returns:
        list of (file, records) tuples in the order of secret_files; records
        is a list of OtpRecord.

    Raises:
        SystemExit: exit code 1 if a file cannot be read or contains invalid
            input.
    '''
    loaded = []
    errors = []
    for secret_file in secret_files:
        try:
            file_source = source or detect_source(secret_file)
            loaded.append((secret_file, READERS[file_source](secret_file, errors)))
        except OSError as e:
            errors.append(f"{secret_file}: {e.strerror}")
        except InputError as e:
            errors.append(f"{secret_file}: {e}")
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        sys.exit(1)
    return loaded


# ---------------------------------------------------------------- file targets

def cannot_create(path, error):
    '''Reports that the output file cannot be created and exits.

    Args:
        path: path of the output file.
        error: the OSError that occurred.

    Raises:
        SystemExit: always, exit code 1.
    '''
    print(f"Error: {path} cannot be created ({error.strerror}).", file=sys.stderr)
    sys.exit(1)


@contextlib.contextmanager
def open_output(path, overwrite=False):
    '''Creates the output file, readable by the user only (mode 0600).

    Without overwrite the file is created with O_EXCL. With overwrite the data
    is written into a temporary file in the same directory that replaces the
    old one when it is complete, so the old file survives a failure and never
    keeps more permissive access rights.

    Args:
        path: path of the output file.
        overwrite: True to replace an existing file.

    Yields:
        the file opened for writing text (UTF-8, newline="" so that the writers
        control the line endings).

    Raises:
        SystemExit: exit code 1 if the file already exists and overwrite is
            False, or if it cannot be created or replaced; the temporary file
            is removed in that case.
    '''
    if not overwrite:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            print(f"Error: {path} already exists, it is not overwritten "
                  f"(use --output-overwrite to replace it).", file=sys.stderr)
            sys.exit(1)
        except OSError as e:
            cannot_create(path, e)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            yield f
        return
    directory, name = os.path.split(path)
    try:
        fd, temp_path = tempfile.mkstemp(dir=directory or ".", prefix=f".{name}.", suffix=".tmp")
    except OSError as e:
        cannot_create(path, e)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            yield f
        os.replace(temp_path, path)
    except OSError as e:
        os.unlink(temp_path)
        cannot_create(path, e)
    except BaseException:
        os.unlink(temp_path)
        raise


def extract_fields(record):
    '''Converts a record into the fields of extract_otp_secrets.

    Args:
        record: OtpRecord.

    Returns:
        dict with the keys of EXTRACT_FIELDS; counter is "" for non-HOTP
        records, url is the original otpauth URL or a newly built one.
    '''
    return {
        "name": record.name,
        "secret": record.secret,
        "issuer": record.issuer,
        "type": record.type,
        "counter": record.counter if record.type == "hotp" else "",
        "url": record.otpauth or build_otpauth(record),
    }


Layout = namedtuple("Layout", "line_ending final_newline")


def detect_layout(path):
    '''Detects the line ending of a file and whether it ends with a line break.

    Args:
        path: path of the file.

    Returns:
        Layout(line_ending, final_newline): line_ending is the line ending of
        the first line, "\\r\\n" or "\\n" ("\\n" if the file has no line break);
        final_newline is True if the file ends with "\\n".

    Raises:
        OSError: the file cannot be opened or read.
    '''
    with open(path, "rb") as f:
        data = f.read()
    first_line_end = data.find(b"\n")
    crlf = first_line_end > 0 and data[first_line_end - 1:first_line_end] == b"\r"
    return Layout("\r\n" if crlf else "\n", data.endswith(b"\n"))


def write_extract_json(records, f, layout):
    '''Writes records in the JSON format of extract_otp_secrets.

    Args:
        records: list of OtpRecord.
        f: text file opened for writing.
        layout: Layout of the first input file; unused, JSON always uses "\\n".
    '''
    # json.dump always uses "\n", JSON is not line-based
    json.dump([extract_fields(record) for record in records], f,
              indent=2, ensure_ascii=False)
    f.write("\n")


def write_extract_csv(records, f, layout):
    '''Writes records in the CSV format of extract_otp_secrets.

    Args:
        records: list of OtpRecord.
        f: text file opened for writing with newline="".
        layout: Layout of the first input file; its line ending is used.
    '''
    writer = csv.DictWriter(f, fieldnames=EXTRACT_FIELDS, lineterminator=layout.line_ending)
    writer.writeheader()
    for record in records:
        writer.writerow(extract_fields(record))


def write_apple_passwords(records, f, layout):
    '''Writes records as an Apple Passwords import file.

    Records from Apple Passwords get their original columns back; for the
    others Title is the issuer (or the name if there is no issuer) and
    Username is the name.

    Args:
        records: list of OtpRecord.
        f: text file opened for writing with newline="".
        layout: Layout of the first input file; its line ending is used.
    '''
    writer = csv.writer(f, lineterminator=layout.line_ending)
    writer.writerow(APPLE_FIELDS)
    for record in records:
        apple = record.apple or {"Title": record.issuer or record.name,
                                 "Username": record.name}
        writer.writerow([apple.get(key, "") for key in APPLE_PASS_THROUGH]
                        + [record.otpauth or build_otpauth(record)])


def twofauth_item(record):
    '''Converts a record into an item of the "data" list of a 2FAuth export.

    Args:
        record: OtpRecord; the fields in OtpRecord.twofauth are written back.

    Returns:
        dict with all fields 2FAuth requires; period is None for HOTP, counter
        is None for the other types, legacy_uri is the original one, else the
        original otpauth URL, else a newly built one.
    '''
    pass_through = record.twofauth or {}
    legacy_uri = pass_through.get("legacy_uri")
    return {
        "otp_type": {"steam": "steamtotp"}.get(record.type, record.type),
        "account": record.name,
        "service": record.issuer,
        "icon": pass_through.get("icon"),
        "icon_mime": pass_through.get("icon_mime"),
        "icon_file": pass_through.get("icon_file"),
        "secret": record.secret,
        "digits": record.digits,
        "algorithm": record.algorithm.lower(),
        "period": None if record.type == "hotp" else record.period,
        "counter": record.counter if record.type == "hotp" else None,
        "legacy_uri": legacy_uri if legacy_uri is not None
                      else record.otpauth or build_otpauth(record),
    }


def write_2fauth_json(records, f, layout):
    '''Writes records as a 2FAuth JSON export with the current time (UTC).

    Args:
        records: list of OtpRecord.
        f: text file opened for writing.
        layout: Layout of the first input file; unused, JSON always uses "\\n".
    '''
    # json.dump always uses "\n", JSON is not line-based
    export = {
        "app": TWOFAUTH_APP,
        "schema": 1,
        "datetime": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "data": [twofauth_item(record) for record in records],
    }
    json.dump(export, f, indent=4, ensure_ascii=False)
    f.write("\n")


def describes(uri, record):
    '''Tells whether an otpauth URI alone contains all data of a record.

    The issuer of an Apple Passwords entry, for example, may come from its
    title. 2FAuth rejects the whole file if a URI has no label
    (otpauth://totp?...).

    Args:
        uri: otpauth URI as str, or None.
        record: OtpRecord.

    Returns:
        True if uri has a label and a supported type and parses to a record
        with the same OTP data, False otherwise (also for None or an invalid URI).
    '''
    if not uri or not OTPAUTH_LINE.match(uri):
        return False
    try:
        return record_from_otpauth(parse_otpauth(uri), uri) == record
    except InputError:
        return False


def write_otpauth_uris(records, f, layout):
    '''Writes records as otpauth URIs, one per line.

    The original URI is written if it is complete (see describes()), a newly
    built one otherwise.

    Args:
        records: list of OtpRecord.
        f: text file opened for writing with newline="".
        layout: Layout of the first input file; its line ending is used, and a
            final line break is only written if the input file has one.
    '''
    # the URI is the only place for the data, so it must be complete
    uris = [record.otpauth if describes(record.otpauth, record)
            else build_otpauth(record) for record in records]
    f.write(layout.line_ending.join(uris))
    if uris and layout.final_newline:
        f.write(layout.line_ending)


WRITERS = {
    SOURCE_APPLE: write_apple_passwords,
    SOURCE_EXTRACT_JSON: write_extract_json,
    SOURCE_EXTRACT_CSV: write_extract_csv,
    SOURCE_2FAUTH_JSON: write_2fauth_json,
    SOURCE_OTPAUTH: write_otpauth_uris,
}


def supported_by(target, record):
    '''Tells whether a target can store the type of a record.

    Args:
        target: one of TARGETS.
        record: OtpRecord.

    Returns:
        True if the target supports the type of the record; False otherwise,
        after printing that the record is skipped.
    '''
    if record.type in SUPPORTED_TYPES[target]:
        return True
    print(f"skipping record {record.id}: {target} does not support "
          f"{TYPE_NAMES[record.type]} one-time passwords")
    return False


def warn_about_dropped_data(records, target):
    '''Warns if pass-through data of the records has no place in the target.

    Covers the extra columns of Apple Passwords entries and the icons of
    2FAuth entries.

    Args:
        records: list of OtpRecord that are written.
        target: one of SOURCES (a file target).
    '''
    if target != SOURCE_APPLE:
        from_apple = sum(1 for record in records if record.apple)
        if from_apple:
            print(f"Warning: the columns {', '.join(APPLE_PASS_THROUGH)} of "
                  f"{from_apple} Apple Passwords entries are not part of {target} "
                  f"and are not written.")
    if target != SOURCE_2FAUTH_JSON:
        with_icon = sum(1 for record in records
                        if record.twofauth and record.twofauth.get("icon_file"))
        if with_icon:
            print(f"Warning: the icons of {with_icon} 2FAuth entries are not part "
                  f"of {target} and are not written.")


def export_records(loaded, target, output, overwrite):
    '''Writes the records of all files into one output file of a file target.

    Records whose type the target does not support are skipped. The output
    uses the line ending of the first input file. Ends with a warning that the
    file contains unencrypted secrets.

    Args:
        loaded: list of (file, records) tuples returned by load_records().
        target: one of SOURCES (a file target).
        output: path of the output file.
        overwrite: True to replace an existing output file.

    Raises:
        SystemExit: exit code 1 if the output file cannot be created (see
            open_output()).
        OSError: the first input file cannot be read again.
    '''
    records = [record for _, records in loaded for record in records
               if supported_by(target, record)]
    warn_about_dropped_data(records, target)
    # the output uses the line ending of the first input file
    layout = detect_layout(loaded[0][0])
    with open_output(output, overwrite) as f:
        WRITERS[target](records, f, layout)
    print(f"{len(records)} record(s) written to {output}.")
    print(f"Warning: {output} contains unencrypted secrets, "
          f"delete it as soon as you do not need it anymore.")


# ---------------------------------------------------------------- authenticator

def run_authenticator(exe, args, stdin_text):
    '''Calls the authenticator CLI and feeds stdin_text to its prompts.

    stdin is always a pipe, the CLI never reads from the terminal.

    Args:
        exe: path of the authenticator executable.
        args: list of command line arguments, e.g. ["add", "issuer:name"];
            must never contain secrets or the passphrase.
        stdin_text: str with the answers to the prompts, one per line; "" for
            none.

    Returns:
        subprocess.CompletedProcess with returncode and stdout and stderr as str.

    Raises:
        SystemExit: exit code 1 if exe cannot be executed.
    '''
    try:
        return subprocess.run([exe, *args], input=stdin_text,
                              capture_output=True, text=True)
    except OSError as e:
        print(f"Error: {exe} cannot be executed ({e.strerror}).", file=sys.stderr)
        sys.exit(1)


def resolve_authenticator(path):
    '''Finds the authenticator executable.

    Args:
        path: name (searched in PATH) or path of the executable; a leading ~
            is expanded.

    Returns:
        the full path of the executable as str.

    Raises:
        SystemExit: exit code 1 if the executable cannot be found or is not
            executable.
    '''
    exe = shutil.which(os.path.expanduser(path))
    if exe is None:
        print(f"Error: {path} not found or not executable, please install it "
              f"first (pip install authenticator) or pass its path with "
              f"--authenticator.", file=sys.stderr)
        sys.exit(1)
    return exe


def check_authenticator(exe):
    '''Makes sure that exe is a supported version of Dave's authenticator.

    This is checked before any secret is sent to it; the found version is
    printed.

    Args:
        exe: full path of the executable (see resolve_authenticator()).

    Raises:
        SystemExit: exit code 1 if "exe --version" fails or does not print
            "authenticator version 1.x.y".
    '''
    result = run_authenticator(exe, ["--version"], "")
    output = result.stdout.strip()
    match = VERSION_PATTERN.match(output)
    if (result.returncode != 0 or match is None
            or int(match.group(1)) != SUPPORTED_MAJOR_VERSION):
        found = (output or result.stderr.strip() or "no output").splitlines()[0]
        print(f"Error: {exe} is not a supported authenticator (found: {found}). "
              f"Supported: {AUTHENTICATOR_URL} version "
              f"{SUPPORTED_MAJOR_VERSION}.x", file=sys.stderr)
        sys.exit(1)
    print(f"Using authenticator {'.'.join(match.groups())} ({exe})")


def succeeded(result, marker):
    '''Tells whether a call of the authenticator succeeded.

    The authenticator always exits with 0, so success can only be told by its
    output, e.g. "Enter passphrase: Enter shared secret: OK".

    Args:
        result: subprocess.CompletedProcess of run_authenticator().
        marker: expected end of the last output line, e.g. ADD_OK or DELETE_OK.

    Returns:
        True if the exit code is 0 and the last line of stdout ends with
        marker, False otherwise.
    '''
    lines = result.stdout.rstrip().splitlines()
    return result.returncode == 0 and bool(lines) and lines[-1].endswith(marker)


def without_prompts(output):
    '''Removes the prompts of the authenticator from its output.

    Args:
        output: stdout or stderr of the authenticator as str.

    Returns:
        output without the prompts and without leading and trailing whitespace.
    '''
    return PROMPTS.sub("", output).strip()


def print_failure(result):
    '''Prints stdout and stderr of a failed authenticator call without the
    prompts; empty outputs are omitted.

    Args:
        result: subprocess.CompletedProcess of run_authenticator().
    '''
    for output in (result.stdout, result.stderr):
        if without_prompts(output):
            print(without_prompts(output))


def data_file_exists(exe):
    '''Tells whether the authenticator already has a data file.

    Calls "list" with empty stdin, so no passphrase is needed.

    Args:
        exe: full path of the authenticator executable.

    Returns:
        False if the output starts with "No data file was found", True otherwise.
    '''
    return not run_authenticator(exe, ["list"], "").stdout.startswith(NO_DATA_FILE)


def ask_passphrase(new_data_file):
    '''Asks for the passphrase of the data file without echoing it.

    Args:
        new_data_file: True if the data file is created, then the passphrase
            has to be confirmed.

    Returns:
        the passphrase as str.

    Raises:
        SystemExit: exit code 1 if the passphrase is empty (the authenticator
            would silently cancel) or the confirmation does not match.
    '''
    passphrase = getpass("Enter passphrase: ")
    # the authenticator silently cancels on an empty passphrase
    if not passphrase.strip():
        print("Error: the passphrase must not be empty.", file=sys.stderr)
        sys.exit(1)
    if new_data_file and getpass("Confirm passphrase: ") != passphrase:
        print("Error: the passphrases do not match.", file=sys.stderr)
        sys.exit(1)
    return passphrase


def verify_passphrase(exe, passphrase):
    '''Checks the passphrase of an existing data file with a read-only
    "list" before any record is added.

    Args:
        exe: full path of the authenticator executable.
        passphrase: passphrase to check, passed via stdin.

    Raises:
        SystemExit: exit code 1 if the passphrase is incorrect.
    '''
    if WRONG_PASSPHRASE in run_authenticator(exe, ["list"], f"{passphrase}\n").stdout:
        print("Error: the passphrase is incorrect.", file=sys.stderr)
        sys.exit(1)


def create_data_file(exe, passphrase):
    '''Initializes the data file by adding a dummy record.

    The record DUMMY_ID has to be removed with delete_dummy_record() later.

    Args:
        exe: full path of the authenticator executable.
        passphrase: passphrase of the new data file, passed via stdin.

    Raises:
        SystemExit: exit code 1 if the data file could not be initialized; the
            output of the authenticator is printed.
    '''
    result = run_authenticator(exe, ["add", DUMMY_ID],
                               f"yes\n{passphrase}\n{passphrase}\nAA\n")
    if not succeeded(result, ADD_OK):
        print("Error: the data file could not be initialized.", file=sys.stderr)
        print_failure(result)
        sys.exit(1)


def add_options(record):
    '''Returns the options of "authenticator add" for the non-default
    parameters of a record.

    Args:
        record: OtpRecord.

    Returns:
        list of str, e.g. ["--counter", "0"] for HOTP, ["--period", "60"] for a
        non-default TOTP period, plus ["--length", "8"] for non-default digits;
        empty if all parameters are defaults.
    '''
    options = []
    if record.type == "hotp":
        options += ["--counter", str(record.counter)]
    elif record.period != DEFAULT_PERIOD:
        options += ["--period", str(record.period)]
    if record.digits != DEFAULT_DIGITS:
        options += ["--length", str(record.digits)]
    return options


def add_record(exe, record, passphrase):
    '''Adds one record to the authenticator; the passphrase and the secret are
    passed via stdin.

    Args:
        exe: full path of the authenticator executable.
        record: OtpRecord to add.
        passphrase: passphrase of the data file.

    Returns:
        True if the record was added; False otherwise, after printing the
        output of the authenticator.
    '''
    result = run_authenticator(exe, ["add", record.id, *add_options(record)],
                               f"{passphrase}\n{record.secret}\n")
    if not succeeded(result, ADD_OK):
        print(f"failed to add {record.id}")
        print_failure(result)
        return False
    return True


def delete_dummy_record(exe, passphrase):
    '''Removes the record DUMMY_ID that create_data_file() added.

    A failure is only reported as a warning with the output of the
    authenticator.

    Args:
        exe: full path of the authenticator executable.
        passphrase: passphrase of the data file.
    '''
    result = run_authenticator(exe, ["delete", DUMMY_ID], f"{passphrase}\nyes\n")
    if not succeeded(result, DELETE_OK):
        print(f"Warning: the record {DUMMY_ID} could not be removed, "
              f"please delete it manually.")
        print_failure(result)


def import_records(exe, loaded, passphrase):
    '''Adds all records to the authenticator.

    Records of unsupported types and records with an algorithm other than
    SHA1 are skipped.

    Args:
        exe: full path of the authenticator executable.
        loaded: list of (file, records) tuples returned by load_records().
        passphrase: passphrase of the data file.

    Returns:
        tuple (imported, failed, skipped) with the numbers of records.
    '''
    imported = failed = skipped = 0
    for secret_file, records in loaded:
        print(f"\nProcessing file {secret_file} ...")
        for record in records:
            if not supported_by(TARGET_AUTHENTICATOR, record):
                skipped += 1
                continue
            if record.algorithm != DEFAULT_ALGORITHM:
                print(f"skipping record {record.id}: the authenticator does not "
                      f"support {record.algorithm}")
                skipped += 1
                continue
            print(f"processing record {record.id}")
            if add_record(exe, record, passphrase):
                imported += 1
            else:
                failed += 1
    return imported, failed, skipped


def list_records(exe, passphrase):
    '''Prints the records of the data file (without the prompts); stderr of
    the authenticator goes to stderr.

    Args:
        exe: full path of the authenticator executable.
        passphrase: passphrase of the data file.
    '''
    result = run_authenticator(exe, ["list"], f"{passphrase}\n")
    print(without_prompts(result.stdout))
    if result.stderr.strip():
        print(result.stderr.rstrip(), file=sys.stderr)


def import_into_authenticator(loaded, authenticator):
    '''Imports the records of all files into Dave's authenticator.

    Checks the executable, asks for the passphrase, creates the data file if
    needed (the dummy record is removed again even if the import fails) or
    verifies the passphrase of the existing one, adds the records and finally
    lists the content of the data file.

    Args:
        loaded: list of (file, records) tuples returned by load_records().
        authenticator: name or path of the authenticator executable.

    Raises:
        SystemExit: exit code 1 if the authenticator is missing or not
            supported, the passphrase is empty, incorrect or not confirmed,
            the data file cannot be created, or at least one record could not
            be added.
    '''
    exe = resolve_authenticator(authenticator)
    check_authenticator(exe)

    new_data_file = not data_file_exists(exe)
    passphrase = ask_passphrase(new_data_file)

    if new_data_file:
        print("Data file not found, initializing data file ...")
        create_data_file(exe, passphrase)
    else:
        print("Data file is already there.")
        verify_passphrase(exe, passphrase)

    try:
        imported, failed, skipped = import_records(exe, loaded, passphrase)
    finally:
        if new_data_file:
            delete_dummy_record(exe, passphrase)

    print(f"\n{imported} record(s) imported, {failed} failed, {skipped} skipped.\n")
    list_records(exe, passphrase)
    if failed:
        sys.exit(1)


def main():
    '''Entry point: parses the arguments, reads all input files and imports
    the records into the authenticator or writes them into the output file.

    Raises:
        SystemExit: exit code 2 for missing or invalid arguments, 1 if no input
            file was found or a later step fails (see load_records(),
            import_into_authenticator(), export_records()).
    '''
    args = parse_args()

    secret_files = collect_files(args.files)
    if not secret_files:
        print("No input files found.")
        sys.exit(1)
    loaded = load_records(secret_files, args.source)

    if args.target == TARGET_AUTHENTICATOR:
        import_into_authenticator(loaded, args.authenticator or DEFAULT_AUTHENTICATOR)
    else:
        export_records(loaded, args.target, args.output, args.overwrite)


if __name__ == "__main__":
    main()
