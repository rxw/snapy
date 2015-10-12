import hmac
import requests
from base64 import b64encode, b64decode
from hashlib import sha256
from time import time

class CasperAPI(object):
    API_KEY = ''
    API_SECRET = ''
    USER_AGENT = 'Casper-API-PHP/1.0.0'
    URL = 'https://api.casper.io'
    SNAPCHAT_VERSION = '9.16.2.0'

    def setAPIKey(self, api_key = None):
        self.API_KEY = api_key

    def setAPISecret(self, api_secret = None):
        self.API_SECRET = api_secret

    def timestamp(self):
        return int(round(time() * 1000))

    def generate_request_signature(self, params, secret):
        string = ''
        for key, value in sorted(params.items()):
            string += key+value
        hexdigest = hmac.new(secret, string, sha256).hexdigest()
        signature = "v1:" + hexdigest
        return signature

    def _request(self, endpoint, moreheaders = [], data = [], post = False):
        headers = {
                "X-Casper-API-Key": self.API_KEY,
                "X-Casper-Signature": self.generate_request_signature(data, self.API_SECRET),
                "User-Agent": self.USER_AGENT,
                "Encoding": "gzip"
                }

        if moreheaders is not None:
            headers.update(moreheaders)

        if post:
            r = requests.post(self.URL + endpoint, headers=headers, data=data)
        else:
            r = requests.get(self.URL + endpoint, headers=headers, params=data)
        return r

    def _external_request(self, url, moreheaders, data, post):
        headers = moreheaders
        if post:
            r = requests.post(url, headers=headers, data=data)
        else:
            r = requests.get(url, headers=headers, params=data)
        return r

    def _get(self, endpoint, headers):
        return self._request(endpoint, headers, {}, False)

    def _post(self, endpoint, headers, data):
        return self._request(endpoint, headers, data, True)

    def _generate_snapchat_nonce(self, username, password, timestamp, endpoint = "/loq/login"):
        nonce = b64encode(sha256(username+"|"+password+"|"+timestamp+"|"+endpoint).digest())


    def get_snapchat_client_auth(self, username, password, timestamp):
        result = self._post("/snapchat/clientauth/signrequest", None, {
            "username": username,
            "password": password,
            "timestamp": timestamp,
            "snapchat_version": self.SNAPCHAT_VERSION})
        return result.json()

    def get_attestation(self, username, password, timestamp):
        binary = self._get("/snapchat/attestation/create", None).json()
        tosend = b64decode(binary['binary'])

        headers = {
                'User-Agent': 'SafetyNet/7899000 (klte KOT49H); gzip',
                'Content-Type': 'application/x-protobuf'
                }
        
        url = "https://www.googleapis.com/androidantiabuse/v1/x/create?alt=PROTO&key=AIzaSyBofcZsgLSS7BOnBjZPEkk4rYwzOIz-lTI"
        androidantiabuse = self._external_request(url, headers, tosend, True)

        if androidantiabuse.status_code != 200:
            print('Attestation androidantiabuse HTTP status code != 200')
            return

        nonce = self._generate_snapchat_nonce(username, password, timestamp)

        response = self._post("/snapchat/attestation/attest", None, {
            "protobuf": b64encode(androidantiabuse.content),
            "nonce": nonce,
            "snapchat_version": self.SNAPCHAT_VERSION
            })

        binary = b64decode(response.json()['binary'])

        headers = {
                'Content-Type': 'application/x-protobuf',
                'User-Agent': 'SafetyNet/7899000 (klte KOT49H); gzip'
                }
        url = "https://www.googleapis.com/androidcheck/v1/attestations/attest?alt=JSON&key=AIzaSyDqVnJBjE5ymo--oBJt3On7HQx9xNm1RHA"
        response = self._external_request(url, headers, binary, True)

        json = response.json()
        return json['signedAttestation']