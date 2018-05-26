# Copyright (C) 2018 - Chenfeng Bao
#
# This program is free software; you can redistribute it and/or modify it 
# under the terms of the GNU General Public License; either version 3 of 
# the License, or (at your option) any later version.
# You should have received a copy of the GNU General Public License 
# along with this program; if not, see <http://www.gnu.org/licenses>.

import argparse
import os
import struct
import csv
import sys
import getpass
import sqlite3
import re
import json
import binascii
from binascii import a2b_base64, b2a_base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import asymmetric
backend = default_backend()
recordFields = {
    'ACCT': ('aid', 'Name', 'Folder', 'URL', 'Notes', 'Favorite', 'sharedfromaid', 'Username', 'Password', 
        'Require Password Repromt', 'Generated Password', 'Secure Notes', 'Last Used', 'AutoLogin', 'Disable AutoFill', 'realm_data', 'fiid', 
        'custom_js', 'submit_id', 'captcha_id', 'urid', 'basic_auth', 'method', 'action', 'groupid', 'deleted', 'attachkey', 
        'attachpresent', 'individualshare', 'Note Type', 'noalert', 'Last Modified', 'Shared with Others', 'Last Password Changed', 
        'Created', 'vulnerable', 'Auto Change Password supported', 'breached', 'Custom Template', 'Form Fields'),
    'ACFL': ('aid', 'Site Name', 'Field Name', 'Field Type', 'Field Value', 'checked', 'Form Name', 'urid', 'otherlogin', 
        'url', 'otherfield'),
    'LPFF': ('ffid', 'Type', 'Name', 'Language', 'First Name', 'Middle Name', 'Last Name', 'Email', 'Company', 
        'Social Security Number', 'Birthday', 'Address 1', 'Address 2', 'City / Town', 'state', 'State / Province', 
        'ZIP / Postal Code', 'country', 'country_cc3l', 'Country', 'Mobile Number', 'Mobile Number country', 'Mobile Number ext.', 
        'Evening Number', 'Evening Number country', 'Evening Number ext.', 'Phone Number', 'Phone Number country', 
        'Phone Number ext.', 'Fax Number', 'Fax Number country', 'Fax Number ext.', 'Credit Card Number', 
        'Credit Card Expiration Date', 'Credit Card Security Code', 'username', 'Address 3', 'Title', 'Gender', 'driverlicensenum', 
        'taxid', 'Require Password Reprompt', 'Bank Name', 'Bank Account Number', 'Bank Routing Number', 'Time Zone', 'County', 
        'Credit Card Start Date', 'Name on Card', 'Credit Card Issue Number', 'Notes', 'lastname2', 'mobileemail', 'firstname2', 
        'firstname3', 'lastname3', 'Enable Free Credit Monitoring', 'Custom Fields'),
    'FFCF': ('cfid', 'text', 'value', 'alttext'),
    'AACT': ('appaid', 'Application', 'Notes', 'Name', 'Folder', 'last_touch', 'fiid', 'Require Password Reprompt', 'Favorite', 
        'script', 'wintitle', 'wininfo', 'exeversion', 'AutoLogin', 'warnversion', 'exehash'),
    'AACF': ('appaid', 'App Name', 'id', 'Field Value', 'Field Type'),
    'ATTA': ('id', 'parent', 'mimetype', 'storagekey', 'size', 'filename'),
    'EQDN': ('edid', 'domain'),
    'URUL': ('url', 'exacthost', 'exactport', 'case_insensitive')
}
fileNames = {
    'ACCT': 'Sites_and_SecureNotes.csv',
    'ACFL': 'SitesFormFields.csv',
    'LPFF': 'FormFills.csv',
    'AACT': 'Applications.csv',
    'AACF': 'ApplicationsFields.csv',
    'ATTA': 'Attachments.csv',
    'EQDN': 'EquivalentDomains.csv',
    'URUL': 'UrlRules.csv'
}
DEBUG = False

def main():
    flags = parse_cmdl()
    vaultAsc, iterations = read_vault_from_file(flags.input, flags.user, flags.iterations)
    passwordBin = getpass.getpass().encode('utf-8')
    key = p2k(flags.user.encode('utf-8'), passwordBin, iterations)
    vaultBin = pre_dec_vault(vaultAsc, key)
    vaultDict = parse_vault_bin(vaultBin, key)
    for code in recordFields:
        if vaultDict.get(code) and fileNames.get(code):
            export_to_csv(vaultDict[code], recordFields[code], flags.outdir, fileNames[code])
    print()
    print('Data exported to {}'.format(os.path.abspath(flags.outdir)))
    input('Press ENTER to exit')

class LpDecryptionError(Exception):
    pass

def parse_cmdl():
    parser = argparse.ArgumentParser(description='Export information from LastPass vault')
    parser.add_argument('-i', '--input', action='store', metavar='DB', help='Path of LastPass vault file.')
    parser.add_argument('-o', '--outdir', action='store', metavar='DIR', help='Output directory')
    parser.add_argument('-u', '--user', action='store', metavar='EMAIL', help='User email')
    parser.add_argument('--iterations', action='store', metavar='#', type=int, help='Password iterations.')
    flags = parser.parse_args()
    flags.input = request_filepath(flags.input, 'Path of LastPass vault file: ')
    flags.outdir = request_dirpath(flags.outdir, 'Output directory: ', makenew=True)
    if not flags.outdir.endswith(os.sep):
        flags.outdir += os.sep
    if flags.user is None:
        flags.user = input('Email: ')
    flags.user = re.sub(r'\s*', '', flags.user.lower())
    return flags

def read_vault_from_file(path, email, iterations):
    with open(path, 'br') as f:
        head = f.read(15)
    if head == b'SQLite format 3':
        vaultAscRaw = read_from_db(path, email)
    else:
        with open(path, 'r', encoding='utf-8') as f:
            vaultAscRaw = f.read()
    match = re.match(r'iterations=(\d+);(.*)', vaultAscRaw)
    if match:
        if not iterations:
            iterations = int(match[1])
        vaultAsc = match[2]
    else:
        if not iterations:
            iterations = input_int('Password iterations: ', 'Error: not a positive integer', validator=lambda x: x>0)
        vaultAsc = vaultAscRaw
    return vaultAsc, iterations

def read_from_db(path, email):
    cursor = sqlite3.connect(path).cursor()
    cursor.execute("SELECT data FROM LastPassData WHERE type='accts' AND username_hash=?", (sha256(email.encode('utf-8')).hex(),))
    res = cursor.fetchone()
    cursor.close()
    if res:
        return res[0]
    else:
        fail("ERROR: vault not found in database", 1)

def pre_dec_vault(vaultAsc, key):
    try:
        vaultAsc = aes_decrypt_soft(vaultAsc, key, raiseCond=('format','padding','unicode'))
    except LpDecryptionError as e:
        if e.args[0] == 'format':
            pass
        else:
            fail('Error: failed to decrypt the vault', 1)
    if vaultAsc.startswith('LPB64'):
        vaultAsc = vaultAsc[5:]
    try:
        vaultBin = a2b_base64(vaultAsc)
    except binascii.Error:
        fail('Error: failed to decrypt the vault', 1)
    return vaultBin

def parse_vault_bin(vault, key):
    vaultDict = {'ACCT':[], 'ACFL':[], 'LPFF':[], 'AACT':[], 'AACF':[], 'ATTA':[], 'EQDN':[], 'URUL':[]}
    pos = 0
    codePrev, shareKey, sharedFolderName, aid, siteName, attachKey, appaid, appName = (None,)*8
    collection = []
    regex = re.compile(b'[A-Z]{4}')
    while pos < len(vault):
        match = regex.match(vault[pos:])
        if not match:
            fail('ERROR: corrupted vault', 1)
        code = match[0].decode('utf-8')
        pos += 4
        chunk, pos = read_chunk(vault, pos)
        if code == 'ACCT':
            record = parse_generic(chunk, shareKey if shareKey else key, recordFields[code], hexFields=('URL', 'action'))
            aid = record['aid']
            siteName = record['Name']
            attachKey, record['attachkey'] = get_attach_key(record['attachkey'], shareKey if shareKey else key)
            if sharedFolderName:
                if record['Folder']:
                    record['Folder'] = sharedFolderName + '\\' + record['Folder']
                else:
                    record['Folder'] = sharedFolderName
            vaultDict[code].append(record)
        elif code in ('ACFL', 'ACOF'):
            record = parse_generic(chunk, key, recordFields['ACFL'], 
                prepend=[aid, siteName], append=[str(int(code=='ACOF'))], hexFields=('url',))
            vaultDict['ACFL'].append(record)
            collection.append({field: record[field] for field in ('Field Name', 'Field Type', 'Field Value', 'checked')})
        elif code == 'LPFF':
            record = parse_generic(chunk, key, recordFields[code])
            record['Type'] = 'Credit Card' if record['Type']=='1' else 'Generic'
            vaultDict[code].append(record)
        elif code == 'FFCF':
            record = parse_generic(chunk, key, recordFields[code])
            collection.append(record)
        elif code == 'AACT':
            record = parse_generic(chunk, key, recordFields[code], hexFields=('Application',))
            appaid  = record['appaid']
            appName = record['Name']
            vaultDict[code].append(record)
        elif code == 'AACF':
            record = parse_generic(chunk, key, recordFields[code], prepend=[appaid, appName])
            vaultDict[code].append(record)
        elif code == 'ATTA':
            record = parse_generic(chunk, attachKey if attachKey else key, recordFields[code])
            if attachKey:
                record['filename'] = aes_decrypt_soft(record['filename'], attachKey)
            vaultDict[code].append(record)
        elif code == 'EQDN':
            record = parse_generic(chunk, key, recordFields[code], hexFields=('domain',))
            vaultDict[code].append(record)
        elif code == 'URUL':
            record = parse_generic(chunk, key, recordFields[code], hexFields=('url',))
            vaultDict[code].append(record)
        elif code == 'SHAR':
            shareKey, sharedFolderName = parse_shar(chunk, key)
        if code != 'FFCF' and codePrev == 'FFCF' and vaultDict['LPFF']:
            vaultDict['LPFF'][-1]['Custom Fields'] = json.dumps(collection, ensure_ascii=False)
            collection = []
        elif code not in ('ACFL', 'ACOF') and codePrev in ('ACFL', 'ACOF') and vaultDict['ACCT']:
            vaultDict['ACCT'][-1]['Form Fields'] = json.dumps(collection, ensure_ascii=False)
            collection = []
        codePrev = code
    return vaultDict

def parse_generic(chunk, key, headers, prepend=None, append=None, hexFields=None):
    chunks = read_chunks(chunk)
    for i in range(len(chunks)):
        chunks[i] = decrypt_or_decode(chunks[i], key)
    prepend = list(prepend) if prepend else []
    append = list(append) if append else []
    expectedChunksNum = len(headers) - len(prepend) - len(append)
    expectedChunks = chunks[:expectedChunksNum]
    if expectedChunksNum-len(chunks) > 0:
        missingChunks = [''] * (expectedChunksNum-len(chunks))
    else:
        missingChunks = []
    extraChunks = chunks[expectedChunksNum:]
    record = dict(zip(headers, prepend + expectedChunks + missingChunks + append))
    for i, t in enumerate(extraChunks):
        record['?'*(i+1)] = t
    if hexFields:
        for field in hexFields:
            if field not in record: continue
            try:
                record[field] = bytes.fromhex(record[field]).decode('utf-8')
            except ValueError:
                fail('ERROR: corrupted vault', 1)
    return record

def parse_shar(chunk, key):
    pos = 0
    id, pos = read_chunk(chunk, pos)
    shareKeyHexEnc, pos = read_chunk(chunk, pos)
    nameEnc, pos = read_chunk(chunk, pos)
    pos = read_chunk(chunk, pos)[1]
    pos = read_chunk(chunk, pos)[1]
    shareKeyHexEnc, pos = read_chunk(chunk, pos)
    try:
        shareKeyHex = aes_decrypt_soft(shareKeyHexEnc, key, raiseCond=('format', 'padding', 'unicode'))
    except LpDecryptionError:
        return None, None
    shareKey = bytes.fromhex(shareKeyHex)
    name = aes_decrypt_soft(nameEnc.decode('utf-8'), shareKey, terminateCond=('format',))
    return shareKey, name

def export_to_csv(vaultSec, headers, dir, filename):
    if vaultSec:
        extra = tuple(field for field in vaultSec[0].keys() if field not in headers)
    with open(os.path.join(dir, filename), 'w', newline='', encoding='utf_8_sig') as csvfile:
        writer = csv.DictWriter(csvfile, headers+extra, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(vaultSec)

def decrypt_or_decode(data, key):
    try:
        dataDec = data.decode('utf-8')
    except UnicodeDecodeError:
        try:
            dataDec = aes_decrypt_soft(data, key, raiseCond=('format',))
        except LpDecryptionError as e:
            assert e.args[0] == 'format'
            fail('ERROR: corrupted vault', 1)
    return dataDec

def get_attach_key(attachKeyHexEncB64, key):
    if not attachKeyHexEncB64:
        return None, ''
    try:
        attachKeyHex = aes_decrypt_soft(attachKeyHexEncB64, key, 
            raiseCond=('unicode', 'padding'), terminateCond=('format',))
    except LpDecryptionError as e:
        assert e.args[0] in ('unicode', 'padding')
        return None, attachKeyHexEncB64
    try:
        attachKey = bytes.fromhex(attachKeyHex)
    except ValueError:
        fail('ERROR: corrupted vault', 1)
    return attachKey, attachKeyHex

def read_chunks(data):
    pos = 0
    chunks = []
    while pos < len(data):
        chunk, pos = read_chunk(data, pos)
        chunks.append(chunk)
    return chunks

def read_chunk(data, start=0):
    try:
        size = struct.unpack('>I', data[start:start+4])[0]
    except struct.error:
        fail('ERROR: corrupted vault', 1)
    start += 4
    data = data[start:start+size]
    if len(data) != size:
        fail('ERROR: corrupted vault', 1)
    return data, start+size

def request_filepath(path, msg, makenew=False):
    while True:
        if not path:
            path = input(msg).strip().strip('"')
        if makenew:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            return path
        elif os.path.isfile(path):
            return path
        else:
            print('Invalid filepath!')
            path = None

def request_dirpath(path, msg, makenew=False):
    while True:
        if not path:
            path = input(msg).strip().strip('"')
        if makenew:
            os.makedirs(path, exist_ok=True)
            return path
        elif os.path.isdir(path):
            return path
        else:
            print('Invalid directory path!')
            path = None

def p2k(salt, password, iterations):
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=backend
    ).derive(password)

def aes_decrypt_soft(dataRaw, key, raiseCond=None, terminateCond=None):
    """Decrypt data in standard LP storage form. 
    By default, if decryption fails and dataRaw conforms to standard LP encrypted data format, 
        return the base64 representation of the original data.
    if decryption fails and dataRaw does not conform to standard form,
        return the hex representation of the original data.
    Specify the following two parameters to change the default soft exit:
    riaseCond:      List of LpDecryptionError messages that would cause the exception to be raised
    terminateCond:  List of LpDecryptionError messages that would cause termination of script
    """
    if not dataRaw:
        return ''
    raiseCond = raiseCond if raiseCond else tuple()
    terminateCond = terminateCond if terminateCond else tuple()
    try:
        dataEnc, mode = format_enc_data(dataRaw)
        res = aes_decrypt_str(dataEnc, key, mode)
    except LpDecryptionError as e:
        if e.args[0] in raiseCond:
            raise e
        if e.args[0] in terminateCond:
            fail('ERROR: corrupted vault', 1)
        if e.args[0] != 'format':
            if mode.name == 'CBC':
                res = '!' + b2a_base64(mode.initialization_vector).decode('utf-8').strip() \
                    + '|' + b2a_base64(dataEnc).decode('utf-8').strip()
            elif mode.name == 'ECB':
                res = b2a_base64(dataEnc).decode('utf-8').strip()
            else:
                fail('ERROR: Impossible scenario!!! Contact developer!', 999)
        else:
            res = dataRaw.hex()
    return res

def format_enc_data(dataRaw):
    try:
        memoryview(dataRaw)
    except TypeError:
        try:
            getattr(dataRaw, 'encode') and getattr(dataRaw, 'capitalize')
        except AttributeError:
            raise TypeError('ERROR: Encrypted data must be either str or bytes')
        else:
            dataType = 'b64'
    else:
        dataType = 'bytes'
    if dataType == 'b64':
        if dataRaw[0] == '!' and dataRaw[25] == '|':
        # CBC candidate
            ivB64, dataEncB64 = dataRaw[1:25], dataRaw[26:]
            try:
                iv = a2b_base64(ivB64)
                dataEnc = a2b_base64(dataEncB64)
            except binascii.Error:
                raise LpDecryptionError('format')
            if len(iv) != 16 or len(dataEnc) % 16 !=0:
                raise LpDecryptionError('format')
            return dataEnc, modes.CBC(iv)
        else:
        # ECB candidate
            try:
                dataEnc = a2b_base64(dataRaw)
            except binascii.Error:
                raise LpDecryptionError('format')
            if len(dataEnc) % 16 != 0:
                raise LpDecryptionError('format')
            return dataEnc, modes.ECB()
    else:
        lenMod = len(dataRaw) % 16
        if lenMod == 1 and dataRaw[0:1] == b'!':
            iv = dataRaw[1:17]
            dataEnc = dataRaw[17:]
            return dataEnc, modes.CBC(iv)
        elif lenMod == 0:
            return dataRaw, modes.ECB()
        else:
            raise LpDecryptionError('format')

def aes_decrypt_str(textEnc, key, mode):
    try:
        text = aes_decrypt_raw(textEnc, key, mode).decode('utf-8')
    except UnicodeDecodeError:
        raise LpDecryptionError('unicode')
    except ValueError as e:
        if not e.args[0] == 'Invalid padding bytes.':
            raise e
        raise LpDecryptionError('padding')
    else:
        return text

def aes_decrypt_raw(ciphertext, key, mode):
    cipher = Cipher(algorithms.AES(key), mode, backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = decryptor.update(ciphertext)+decryptor.finalize()
    return unpadder.update(plaintext) + unpadder.finalize()

def sha256(data):
    digest = hashes.Hash(hashes.SHA256(), backend=backend)
    digest.update(data)
    return digest.finalize()

def input_int(msg, errMsg, validator=None):
    while True:
        try:
            i = int(input(msg))
        except ValueError:
            pass
        else:
            if (validator is None) or validator(i):
                return i
        if errMsg:
            print(errMsg)

def fail(msg, errCode=1):
    print(msg, file=sys.stderr)
    if DEBUG:
        raise RuntimeError
    else:
        input('press ENTER to exit')
        sys.exit(errCode)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print()
