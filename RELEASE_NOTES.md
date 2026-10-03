# Release Notes

## version 2.0.0, Oct 3, 2026

### new features

- new option -h/--help prints the help

- new option -v/--version prints the version of totpsa.py

- new option --authenticator PATH selects the authenticator executable
  (default: "authenticator" from PATH); a leading ~ is expanded. This allows you
  to use an authenticator installed in a virtual environment without activating it

- before any secret is sent, the script checks with "authenticator --version"
  that the selected program is Dave's authenticator in a supported version (1.x)
  and stops with an error otherwise

- support for Apple Passwords (issue #1): the CSV export of the Passwords app
  (Title,URL,Username,Password,Notes,OTPAuth) can be read, and a CSV file for
  the import into Passwords can be written; entries without a one-time password
  are ignored. When converting Apple Passwords to Apple Passwords, all columns of
  an entry are copied unchanged; when converting it into a format without these
  columns, a warning names the columns that are not written

- support for 2FAuth (issue #2): its JSON export and its otpauth export (a text
  file with one otpauth URI per line) can be read and written (--source and
  --target 2fauth-json, otpauth-uris). The JSON output starts with
  "app": "2fauth_totp-secrets-adapter", because 2FAuth only recognizes its
  format by this prefix; icons of 2FAuth entries are kept between 2FAuth JSON
  files. URIs without a label, which 2FAuth rejects, are replaced by complete ones.

- Steam Guard one-time passwords of 2FAuth are kept between the two 2FAuth
  formats and skipped with a warning for all other targets

- support for the CSV format of extract_otp_secrets
  (name,secret,issuer,type,counter,url)

- new option --source {apple-passwords,extract-otp-secrets-json,
  extract-otp-secrets-csv} specifies the format of the input files; without it,
  the format is detected by the file extension and the CSV header

- new options --target {authenticator,apple-passwords,extract-otp-secrets-json,
  extract-otp-secrets-csv} and --output FILE: besides the import into Dave's
  authenticator (default), every supported format can be converted into every
  other one. The output file is created readable by the user only and an
  existing file is never overwritten. The original otpauth URL of the source
  (Apple Passwords "OTPAuth", extract_otp_secrets "url") is kept verbatim in all
  conversions. CSV output files use the line ending of the first input file (LF
  if it cannot be determined), so that the export of Apple Passwords (LF) is
  reproduced byte by byte; line breaks inside values are kept unchanged

- new option -O/--output-overwrite FILE: like --output, but an existing file is
  replaced. The data is written into a temporary file first that replaces the
  old file when it is complete, so the old file survives a failure and the new
  one is always readable by the user only

- short forms of the options: -s (--source), -t (--target), -o (--output),
  -a (--authenticator)

- counter-based (HOTP) records are imported into Dave's authenticator with
  "add --counter N"

- a number of digits other than 6 and a period other than 30 seconds (taken from
  the otpauth URL) are passed to Dave's authenticator with "--length" and
  "--period"

- the passphrase of an existing data file is checked (read-only "list") before
  any record is added

### bug fixes

- the list of records shown at the end is now printed as the authenticator's
  output; previously the raw (stdout, stderr) pair of the call was printed

- when a new data file is created, the passphrase must now be entered twice;
  previously it was asked only once, so a typo created a data file with a
  passphrase nobody knew

- the temporary record "dummy:dummy", which is used to initialize a new data
  file, is now always removed, even if the import is aborted by an error

- all input files are read and validated before the authenticator is called; a
  missing file, an invalid JSON file or a record without "issuer", "name" or
  "secret" is reported with the file name, and the script stops before the
  passphrase is asked and before the data file is touched. Previously the script
  crashed with a traceback, possibly after the data file had been initialized

- records that the authenticator refuses to add (e.g. because the id already
  exists) are now reported as failed, including the authenticator's message,
  instead of being silently ignored; the remaining records are still imported.
  Dave's authenticator always exits with 0, so success is recognized by its
  output ("OK", "Deleted 1 configuration.")

- a missing authenticator installation is reported with a clear message instead
  of a traceback

- HOTP (counter-based) records were imported as TOTP records, which produced
  wrong codes; they are now imported with their counter. Records without a
  "type" field are imported as TOTP records as before

- records with an algorithm other than SHA1 are skipped with a warning when
  importing into Dave's authenticator, which only supports SHA1

- an empty passphrase is rejected; the authenticator silently cancels on an
  empty passphrase, so the records were reported as imported although they were
  not

### changes

- exit codes: 2 if no arguments are given, 1 if no input file was found, if the
  input is invalid, if the authenticator is missing or not supported, if the
  passphrase is empty, incorrect or the passphrases do not match, if the output
  file already exists, or if at least one record could not be imported; 2 for
  invalid options; 0 otherwise. Previously the script always exited with 0

- the command line is parsed with argparse; calling the script without files
  prints the argparse usage line instead of "Usage: totpsa.py [json file]..."

- a wildcard pattern that does not match any file now prints a warning

- a summary ("n record(s) imported, m failed, k skipped") is printed after the
  import

- the "debug:" output of every authenticator call was removed; the
  authenticator's output is only shown if a call fails

- the commands and the input sent to the authenticator are unchanged, except
  for the additional "--version" call at the start, the read-only "list" that
  checks the passphrase of an existing data file, and the options --counter,
  --length and --period for records with non-default values

- the prompts of the authenticator ("Enter passphrase: ", ...) are removed from
  the output that is shown

- README: lists Aegis, Ente Auth, FreeOTP+ and OTPClient as targets, because
  they import the otpauth-uris output, and describes the import into them

### code quality

- the script is structured into functions with a main() function and can be
  imported without side effects

- all calls of the authenticator go through a single helper based on
  subprocess.run(); its input is always passed through a pipe, never through the
  terminal

- removed the shadowing of the built-in id(), redundant f-strings and redundant
  wait() calls; quit() was replaced by sys.exit()

- every function has a docstring (Google style) that describes what it does,
  its parameters, its return values and the errors it raises or the exits it
  causes

- new .gitignore excludes the __pycache__ directories, the .DS_Store files of
  macOS, the .idea/ directory of JetBrains IDEs and a .venv/ virtual environment


## version 1.0.0

- initial release
