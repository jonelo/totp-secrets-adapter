#!/usr/bin/env python3

'''
Copyright (c) 2024 Johann N. Löfflmann

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
the interface of a target authenticator that is running on your personal computer.

See also https://github.com/jonelo/totp-secrets-adapter

Supported TOTP extractors:
- https://github.com/scito/extract_otp_secrets (json)

Supported target authenticators:
- https://github.com/JeNeSuisPasDave/authenticator (cli+stdin)
'''

import json
import glob
import sys
from subprocess import Popen, PIPE, STDOUT
from getpass import getpass
from pathlib import Path

def usage():
    print(f"Usage: {Path(sys.argv[0]).name} [json file]...")

if len(sys.argv) == 1:
    usage()
    quit()

# Gather all secret files
# (not all shells perform globbing before they pass it to the script)
secret_files = []
for entry in sys.argv[1:]:
    if "*" in entry or "?" in entry:
        files = glob.glob(entry)
        for file in files:
            secret_files.append(file)
    else:
        secret_files.append(entry)

if len(secret_files) == 0:
    print(f"No input files found.")
    quit()

# Initialize global variables
dummy_record_created = False
passphrase = getpass("Enter passphrase: ")

# Initialize the data file if it is not there yet
p = Popen(["authenticator", "list"], stdout=PIPE, stdin=PIPE, stderr=PIPE, text=True)
stdout_data = p.communicate()[0]
p.wait()
if stdout_data.startswith("No data file was found"):
    print("Data file not found, initializing data file ...")
    # Create a dummy record to initialize the data file
    p = Popen(["authenticator", "add", f"dummy:dummy"], stdout=PIPE, stdin=PIPE, stderr=PIPE, text=True)
    stdout_data = p.communicate(input=f"yes\n{passphrase}\n{passphrase}\nAA\n")
    p.wait()
    dummy_record_created = True
    print("debug: ", stdout_data)
else:
    print("Data file is already there.")

# Process all *.json files
for secret_file in secret_files:
    print(f"\ndebug: Processing file {secret_file} ...")
    with open(secret_file, 'r') as f:
        data = json.load(f)
        for record in data:
            id = f"{record['issuer']}:{record['name']}"
            print (f"\nprocessing record {id}")
            p = Popen(["authenticator", "add", f"{id}"],
                stdout=PIPE, stdin=PIPE, stderr=PIPE, text=True)
            stdout_data = p.communicate(input=f"{passphrase}\n{record['secret']}\n")
            p.wait()
            print ("debug: ", stdout_data)

# Housekeeping, remove the dummy record again
if dummy_record_created:
    id = "dummy:dummy"
    print (id)
    p = Popen(["authenticator", "delete", f"{id}"],
        stdout=PIPE, stdin=PIPE, stderr=PIPE, text=True)
    stdout_data = p.communicate(input=f"{passphrase}\nyes\n")
    p.wait()
    print ("debug: ", stdout_data)

# Show what records are in the data file
p = Popen(["authenticator", "list"],
    stdout=PIPE, stdin=PIPE, stderr=PIPE, text=True)
stdout_data = p.communicate(input=f"{passphrase}\n")
p.wait()
for line in stdout_data:
    print (line)
