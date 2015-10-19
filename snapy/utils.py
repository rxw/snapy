# -*- coding: utf-8 -*-

"""
    This module contains methods for creating request tokens and
    encryption/decryption of snaps
"""

import json
import os
from hashlib import sha256, sha1, md5
from time import time
from datetime import datetime
from uuid import uuid4, uuid1
from base64 import b64encode, b64decode
from binascii import unhexlify
from zipfile import is_zipfile, ZipFile

from urllib import urlencode
import requests
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.PublicKey import RSA

SECRET = b'iEk21fuwZApXlz93750dmW22pw389dPwOk'
STATIC_TOKEN = 'm198sOkJEn37DjqZ32lpRu76xmw288xSQ9'
BLOB_ENCRYPTION_KEY = 'M02cnQ51Ji97vwT4'
HASH_PATTERN = ('00011101111011100011110101011110'
                '11010001001110011000110001000110')


def make_request_token(a, b):
    hash_a = sha256(SECRET + a.encode('utf-8')).hexdigest()
    hash_b = sha256(b.encode('utf-8') + SECRET).hexdigest()
    return ''.join((hash_b[i] if c == '1' else hash_a[i]
                    for i, c in enumerate(HASH_PATTERN)))

def get_token(auth_token=None):
    return STATIC_TOKEN if auth_token is None else auth_token


def pkcs5_pad(data, blocksize=16):
    pad_count = blocksize - len(data) % blocksize
    return data + (chr(pad_count) * pad_count).encode('utf-8')


def decrypt(data):
    cipher = AES.new(BLOB_ENCRYPTION_KEY, AES.MODE_ECB)
    return cipher.decrypt(pkcs5_pad(data))


def decrypt_story(data, key, iv):
    akey = b64decode(key)
    aiv = b64decode(iv)
    cipher = AES.new(akey, AES.MODE_CBC, aiv)
    return cipher.decrypt(pkcs5_pad(data))

def timestamp():
    return int(round(time() * 1000))

def encrypt(data):
    cipher = AES.new(BLOB_ENCRYPTION_KEY, AES.MODE_ECB)
    return cipher.encrypt(pkcs5_pad(data))

def get_attestation(username, password, timestamp):
    binary = requests.get('https://api.casper.io/droidguard/create/binary').json()
    tosend = b64decode(binary['binary'])

    headers = {
        'User-Agent': 'DroidGuard/7329000 (A116 _Quad KOT49H); gzip',
        'Content-type': 'application/x-protobuf'
    }

    url = 'https://www.googleapis.com/androidantiabuse/v1/x/create?alt=PROTO&key=AIzaSyBofcZsgLSS7BOnBjZPEkk4rYwzOIz-lTI'
    androidantiabuse = requests.post(url, tosend, headers=headers)

    if androidantiabuse.status_code != 200:
        print('Attestation androidantiabuse HTTP status code != 200')
        return

    hashString = username + "|" + password + "|" + timestamp + "|/loq/login"
    url = 'https://api.casper.io/droidguard/attest/binary'
    tosend = {
        'bytecode_proto': b64encode(androidantiabuse.content),
        'nonce': b64encode(sha256(hashString).digest()),
        'apk_digest': '5O40Rllov9V8PpwD5zPmmp+GQi7UMIWz2A0LWZA7UX0='
    }

    droidguard = requests.post(url, tosend)

    if droidguard.status_code != 200:
        print('Attestation droidguard HTTP status code != 200')
        return

    if 'binary' not in droidguard.json():
        print('Attestation error: Invalid droidguard JSON / no signedAttestation')
        return

    url = 'https://www.googleapis.com/androidcheck/v1/attestations/attest?alt=JSON&key=AIzaSyDqVnJBjE5ymo--oBJt3On7HQx9xNm1RHA'
    tosend = b64decode(droidguard.json()['binary'])

    headers = {
        'User-Agent': 'SafetyNet/7899000 (WIKO JZO54K); gzip',
        'Content-Type': 'application/x-protobuf'
    }

    androidcheck = requests.post(url, tosend, headers=headers)

    if androidcheck.status_code != 200:
        print('Attestation androidcheck HTTP status code != 200')
        return

    if 'signedAttestation' not in androidcheck.json():
        print('Attestation error: Invalid androidcheck JSON / no signedAttestation')
        return

    return androidcheck.json()['signedAttestation']

def get_client_auth_token(username, password, timestamp):
    url = 'https://api.casper.io/security/login/signrequest/'
    tosend = {
            'username': username,
            'password': password,
            'timestamp': timestamp
            }
    r = requests.post(url, data=tosend)
    result = r.json()
    return result


def encryptPassword(email, password):
    gdpk = "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ=="
    binaryKey = b64decode(gdpk).encode('hex')
    
    half = binaryKey[8:264]
    modulus = long(half, 16)
    
    half = binaryKey[272:278]
    exponent = long(half, 16)
    
    sha1hash = sha1(b64decode(gdpk)).digest()
    signature = "00" + sha1hash[:4].encode('hex')
    
    key = RSA.construct((modulus, exponent))
    cipher = PKCS1_OAEP.new(key)
    plain = email + "\x00" + password
    encrypted = cipher.encrypt(plain).encode('hex')
    ste = signature + encrypted
    output = unhexlify(ste)
    
    encryptedPassword = b64encode(output).encode('ascii').replace("+","-").replace("/","_")
    return encryptedPassword

def get_auth_token(email, password):
    encryptedPasswd = encryptPassword(email, password)
    
    postfields = {
        'device_country': 'us',
        'operatorCountry': 'us',
        'lang': 'en_US',
        'sdk_version': '19',
        'google_play_services_version': '7097038',
        'accountType': 'HOSTED_OR_GOOGLE',
        'Email': email,
        'service': 'audience:server:client_id:694893979329-l59f3phl42et9clpoo296d8raqoljl6p.apps.googleusercontent.com',
        'source': 'android',
        'androidId': '378c184c6070c26c',
        'app': 'com.snapchat.android',
        'client_sig': '49f6badb81d89a9e38d65de76f09355071bd67e7',
        'callerPkg': 'com.snapchat.android',
        'callerSig': '49f6badb81d89a9e38d65de76f09355071bd67e7',
        'EncryptedPasswd': encryptedPasswd
    }
    
    headers = {
        'device': '378c184c6070c26c',
        'app': 'com.snapchat.android',
        'User-Agent': 'GoogleAuth/1.4 (mako JDQ39)',
        'Accept-Encoding': 'gzip'
    }
    
    r = requests.post("https://android.clients.google.com/auth", headers=headers, data=postfields, verify=False)
    
    if r.status_code == 200:
        splitted = r.text.split('\n')
        expiry = datetime.fromtimestamp(int(splitted[2].split('=')[1]))
        return (splitted[0][5:], expiry)

    else:
        print "Invalid gmail address"

def request(endpoint, auth_token, data=None, params=None, files=None,
            raise_for_status=True, req_type='post', moreheaders={}):
    """Wrapper method for calling Snapchat API which adds the required auth
    token before sending the request.

    :param endpoint: URL for API endpoint
    :param data: Dictionary containing form data
    :param raise_for_status: Raise exception for 4xx and 5xx status codes
    :param req_type: The request type (GET, POST). Defaults to POST
    """
    if params is not None:
        if 'now' in params:
            now = params['now']
        else:
            now = str(timestamp())

        if 'gauth' in params:
            gauth = params['gauth']
        else:
            gauth = ""
    else:
        now = str(timestamp())
        gauth = ""

    if data is None:
        data = {}
    
    headers = {
        'User-Agent': 'Snapchat/9.16.2.0 (HTC One; Android 5.0.2#482424.2#21; gzip)',
        'Accept-Language': 'en',
        'Accept-Locale': 'en_US',
        'X-Snapchat-Client-Auth-Token': "Bearer " + gauth
    }

    headers.update(moreheaders) 

    URL = 'https://feelinsonice-hrd.appspot.com'
    
    if endpoint == '/loq/login':
        headers.update({
            'Accept-Encoding': 'gzip'
            })

    if endpoint == '/bq/blob':
        headers.update({
            'X-Timestamp': now
            })

    if endpoint == '/loq/login' or endpoint == '/loq/device_id':
        req_token = make_request_token(STATIC_TOKEN, now)
    else:
        req_token = make_request_token(auth_token, now)

    if endpoint != '/bq/story_blob':
        data.update({
            'timestamp': now,
            'req_token': req_token
        })

    if req_type == 'post':
        r = requests.post(URL + endpoint, data=data, files=files,
                          headers=headers, verify=False)
    else:
        if gauth == "": headers = None
        r = requests.get(URL + endpoint, params=data, headers=headers, verify=False)
    if raise_for_status:
        r.raise_for_status()
    return r


def make_media_id(username):
    """Create a unique media identifier. Used when uploading media"""
    #partial = md5(str(uuid1())).hexdigest()
    #uuid = "%s-%s-%s-%s-%s" % (partial[:8], partial[8:12], partial[12:16], partial[16:20], partial[20:32])
    #print uuid
    return '{username}~{uuid}'.format(username=username.upper(),uuid=str(uuid1()))


def unzip_snap_mp4(abspath, quiet=False):
    zipped_snap = ZipFile(abspath)

    # unzip /path/to/zipfile.mp4 to /path/to/zipfile
    unzip_dir = os.path.splitext(abspath)[0]
    zipped_snap.extractall(unzip_dir)

    # move /path/to/zipfile.mp4 to /path/to/zipfile.zip
    os.rename(abspath, unzip_dir + '.zip')

    for f in os.listdir(unzip_dir):
        # mv /path/to/zipfile/media~* /path/to/zipfile.mp4
        if f.split('~')[0] == 'media':
            os.rename(os.path.join(unzip_dir, f), unzip_dir + '.mp4')

        # mv /path/to/zipfile/overlay~* /path/to/zipfile_overlay.png
        elif f.split('~')[0] == 'overlay':
            os.rename(os.path.join(unzip_dir, f),
                      unzip_dir + '_overlay.png')

    try:
        os.rmdir(unzip_dir)
    except OSError:
        print('Something other than a video or overlay was in {0}. \
               Cannot remove directory, not empty.'
              .format(unzip_dir + '.zip'))

    if not quiet:
        print('Unzipped {0}'.format(abspath))
