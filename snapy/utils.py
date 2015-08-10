# -*- coding: utf-8 -*-

"""
    This module contains methods for creating request tokens and
    encryption/decryption of snaps
"""

import json
from hashlib import sha256, sha1, md5
from time import time
from uuid import uuid4, uuid1
from base64 import b64encode, b64decode
from binascii import unhexlify

from urllib import urlencode
import requests
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.PublicKey import RSA

boundary = "Boundary+0xAbCdEfGbOuNdArY"
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
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(pkcs5_pad(data))

def timestamp():
    return int(round(time() * 1000))

def encrypt(data):
    cipher = AES.new(BLOB_ENCRYPTION_KEY, AES.MODE_ECB)
    return cipher.encrypt(pkcs5_pad(data))

def get_attestation(username, password, timestamp):
    hashString = username + "|" + password + "|" + timestamp + "|/loq/login"
    nonce = b64encode(sha256(hashString).digest())
    authentication = "cp4craTcEr82Pdf5j8mwFKyb8FNZbcel"
    apkDigest      = "JJShKOLH4YYjWZlJQ71A2dPTcmxbaMboyfo0nsKYayE"
    
    url = 'http://attest.casper.io/attestation' 
    tosend = {
            'nonce': nonce,
            'authentication': authentication,
            'apk_digest': apkDigest,
            'timestamp': timestamp
            }
    headers = {
            'Content-type': 'application/x-www-form-urlencoded'
            }
    r = requests.post(url, data=tosend, headers=headers)

    result = r.json()
    return result['signedAttestation']

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
        return splitted[0][5:]
    else:
        print "Invalid gmail address"

def request(endpoint, auth_token, data=None, params=None, files=None,
            raise_for_status=True, req_type='post'):
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
        now = str(timestamp())

    if data is None:
        data = {}
    
    headers = {
        'User-Agent': 'Snapchat/9.10.0.0 (HTC One; Android 4.4.2#302626.7#19; gzip)',
        'Accept-Language': 'en',
        'Accept-Locale': 'en_US',
        'X-Snapchat-Client-Auth-Token': "Bearer " + gauth
    }

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

    data.update({
        'timestamp': now,
        'req_token': req_token
    })

    if req_type == 'post':
        r = requests.post(URL + endpoint, data=data, files=files,
                          headers=headers)
    else:
        """
        boundary = "Boundary+0xAbCdEfGbOuNdArY"
        datas = "--" + boundary + "\r\n" + 'Content-Disposition: form-data; name="req_token"' + "\r\n\r\n" + req_token + "\r\n"
        for key, value in data.iteritems():
            if key == "req_token": continue

            if key is not 'data':
                datas += "--" + boundary + "\r\n" + 'Content-Disposition: form-data; name="' + key + '"' + "\r\n\r\n" + str(value) + "\r\n"
            else:
                datas += "--" + boundary + "\r\n" + 'Content-Disposition: form-data; name="data"; filename="data"' + "\r\n" 
                + 'Content-Type: application/octet-stream' + "\r\n\r\n" + str(value) + "\r\n"
        
        data = "?" + datas + "--" + boundary + "--"
        """
        r = requests.get(URL + endpoint, params=data, headers=headers)
    if raise_for_status:
        r.raise_for_status()
    return r


def make_media_id(username):
    """Create a unique media identifier. Used when uploading media"""
    #partial = md5(str(uuid1())).hexdigest()
    #uuid = "%s-%s-%s-%s-%s" % (partial[:8], partial[8:12], partial[12:16], partial[16:20], partial[20:32])
    #print uuid
    return '{username}~{uuid}'.format(username=username.upper(),uuid=str(uuid1()))
