from Agent import CasperAgent
from Exception import CasperException
import hashlib, base64, json

class CasperAPI(CasperAgent):
	SNAPCHAT_VERSION = "9.16.2.0"

	def __init__(self, apiKey = None, apiSecret = None):
		super(CasperAPI, self).__init__(apiKey, apiSecret)

		self.apiKey = apiKey
		self.apiSecret = apiSecret

	def getSnapchatInfo(self):
		return self.get("/snapchat")

	def getSnapchatClientAuth(self, username, password, timestamp):
		res = self.post(endpoint = "/snapchat/clientauth/signrequest",
		                params = {
			                "username": username,
			                "password": password,
			                "timestamp": timestamp,
			                "snapchat_version": self.SNAPCHAT_VERSION
		                })

		if "signature" not in res:
			raise CasperException("Signature not found in response!")

		return res["signature"]

	def getSnapchatAttestation(self, nonce):
		res = self.get("/snapchat/attestation/create")

		if "binary" not in res:
			raise CasperException("Binary not found in response!")

		binary = base64.b64decode(res["binary"])
		res = self.externalRequest(url = "https://www.googleapis.com/androidantiabuse/v1/x/create?alt=PROTO&key=AIzaSyBofcZsgLSS7BOnBjZPEkk4rYwzOIz-lTI",
		                           headers = {
			                           "Content-Type": "application/x-protobuf",
			                           "User-Agent": "SafetyNet/7899000 (klte KOT49H); gzip"
		                           },
		                           params = binary,
		                           post = True)

		protobuf = base64.b64encode(res)
		res = self.post(endpoint = "/snapchat/attestation/attest",
		                params = {
			                "protobuf": protobuf,
			                "nonce": nonce,
			                "snapchat_version": self.SNAPCHAT_VERSION
		                })

		if "binary" not in res:
			raise CasperException("Binary not found in response!")

		binary = base64.b64decode(res["binary"])
		res = self.externalRequest(url = "https://www.googleapis.com/androidcheck/v1/attestations/attest?alt=JSON&key=AIzaSyDqVnJBjE5ymo--oBJt3On7HQx9xNm1RHA",
		                           headers = {
			                           "Content-Type": "application/x-protobuf",
			                           "User-Agent": "SafetyNet/7899000 (klte KOT49H); gzip"
		                           },
		                           params = binary,
		                           post = True)

		try:
			rJSON = json.loads(res)
		except ValueError:
			raise CasperException("Failed to decode response!")

		if "signedAttestation" not in rJSON:
			raise CasperException("Attestation not found in response!")

		return rJSON["signedAttestation"]

	@staticmethod
	def generateSnapchatNonce(username, password, timestamp, endpoint = "/loq/login"):
		return base64.b64encode(hashlib.sha256("{0}|{1}|{2}|{3}".format(username, password, timestamp, endpoint)).digest())