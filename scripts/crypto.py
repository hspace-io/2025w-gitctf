#!/usr/bin/env python
###############################################################################
# Git-based CTF
###############################################################################
#
# Author: SeongIl Wi <seongil.wi@kaist.ac.kr>
#         Jaeseung Choi <jschoi17@kaist.ac.kr>
#         Sang Kil Cha <sangkilc@kaist.ac.kr>
#
# Copyright (c) 2018 SoftSec Lab. KAIST
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import sys
import os
import json
import subprocess
import re
import shutil
import zipfile
from utils import random_string, rmdir, rmfile, remove_trailing_slash
from cmd import run_command

def decrypt_exploit(encrypted_exploit_path, config, team, out_dir=None, \
        expected_signer=None):
    if out_dir is None:
        out_dir = "exploit"

    rmdir(out_dir)

    tmpzip = "/tmp/gitctf_%s.zip" % random_string(6)
    tmpdir = "/tmp/gitctf_%s" % random_string(6)
    tmpgpg = "/tmp/gitctf_%s.gpg" % random_string (6)

    if expected_signer == None:
        decrypt_cmd = 'gpg -o %s %s' % (tmpzip, encrypted_exploit_path)
    else:
        instructor_id = config['teams']['instructor']['pub_key_id']
        team_id = config['teams'][team]['pub_key_id']
        expected_signer_id = config['individual'][expected_signer]['pub_key_id']

        # Make keyring
        run_command("gpg -o %s --export %s %s %s" % (tmpgpg, \
                expected_signer_id, instructor_id, team_id), os.getcwd())

        decrypt_cmd = "gpg --no-default-keyring --keyring %s -o %s %s" \
                % (tmpgpg, tmpzip, encrypted_exploit_path)

    _, err, r = run_command(decrypt_cmd, os.getcwd())
    if r != 0:
        print("[*] Failed to decrypt/verify %s" % encrypted_exploit_path)
        print(err)
        return None

    run_command('unzip %s -d %s' % (tmpzip, tmpdir), os.getcwd())
    shutil.move(tmpdir, out_dir)

    rmfile(tmpzip)
    rmfile(tmpgpg)
    rmdir(tmpdir)

    return out_dir

def encrypt_exploit(exploit_dir, target_team, config, signer=None):
    # Remove trailing slash, for user convenience
    exploit_dir = remove_trailing_slash(exploit_dir)
    out_file = exploit_dir + ".zip.pgp"

    # Retrieve information from config
    teams = config["teams"]
    # instructor_pubkey = teams["instructor"]["pub_key_id"]
    # target_pubkey = teams[target_team]['pub_key_id']
    
    # Hardcoded keys as requested
    instructor_pubkey = "DCC2CEC0"
    target_pubkey = "DCC2CEC0"

    # Embed and import public key
    USER_PUB_KEY = """-----BEGIN PGP PUBLIC KEY BLOCK-----

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
Vqe531XqLVk39arr
=a8SZ
-----END PGP PUBLIC KEY BLOCK-----"""
    
    key_path = "/tmp/user_key.asc"
    with open(key_path, "w") as f:
        f.write(USER_PUB_KEY)
    run_command(f"gpg --import {key_path}", None)


    # Zip the directory
    tmp_path = "/tmp/gitctf_%s" % random_string(6)
    shutil.make_archive(tmp_path, "zip", exploit_dir)
    zip_file = tmp_path + ".zip" # make_archive() automatically appends suffix.

    # Encrypt the zipped file

    encrypt_cmd = "gpg --pinentry-mode loopback --trust-model always -o %s " % out_file
    if signer is not None:
        signer_pubkey = config["individual"][signer]['pub_key_id']
        encrypt_cmd += "--default-key %s --sign " % signer_pubkey
    encrypt_cmd += "-e -r %s -r %s " % (instructor_pubkey, target_pubkey)
    encrypt_cmd += "--armor %s" % zip_file
    _, err, ret = run_command(encrypt_cmd, None)
    rmfile(zip_file) # Clean up zip file.
    if ret != 0:
        print("[*] Failed to sign/encrypt %s" % zip_file)
        print(err)
        return None

    return out_file


# TODO : maybe we can add main function so this can be used like
# "python crypto.py ENCRYPT ..." or "python crypto.py DECRYPT ..."
