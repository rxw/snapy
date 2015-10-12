import requests, base64, hmac, hashlib
from Exception import CasperException

requests.packages.urllib3.disable_warnings()
class CasperAgent(object):
	USER_AGENT = "Casper-API-Python/1.0.0"
	URL = "https://api.casper.io"

	def __init__(self, apiKey = None, apiSecret = None):
		self.apiKey = apiKey
		self.apiSecret = apiSecret

	def get(self, endpoint, headers = None):
		return self.request(endpoint = endpoint,
		                    headers = headers)

	def post(self, endpoint, headers = None, params = None):
		return self.request(endpoint = endpoint,
		                    headers = headers,
		                    params = params,
		                    post = True)

	def request(self, endpoint, headers = None, params = None, post = False):
		s = requests.Session()

		if headers is None: headers = {}
		headers.update({
			"X-Casper-API-Key": self.apiKey,
			"X-Casper-Signature": self.generateRequestSignature(params),
			"User-Agent": self.USER_AGENT
		})
		s.headers = headers

		requestURL = "{0}{1}".format(self.URL, endpoint)
		if post:
			res = s.post(requestURL, data = params, timeout = 10, verify = False)
		else:
			res = s.get(requestURL, timeout = 10, verify = False)

		try:
			rJSON = res.json()
		except ValueError:
			raise CasperException("Failed to decode response!")

		if res.status_code != 200:
			if "code" in rJSON and "message" in rJSON:
				raise CasperException("API Response: [{0}] {1}".format(rJSON["code"], rJSON["message"]))
			else:
				raise CasperException("API Response: [{0}] Unknown Error Message".format(res.status_code))

		return rJSON

	@staticmethod
	def externalRequest(url, headers = None, params = None, post = False):
		s = requests.Session()
		s.headers = headers

		if post:
			res = s.post(url, data = params, timeout = 10, verify = False)
		else:
			res = s.get(url, timeout = 10, verify = False)

		if not res:
			raise CasperException("Request failed!")

		if res.status_code != 200:
			raise CasperException("External request failed!")

		return res.content

	def generateRequestSignature(self, params):
		if params is None: params = {}
		sortedData = "".join("{0}{1}".format(key, value) for key, value in sorted(params.items()))
		signature = hmac.new(key = self.apiSecret, msg = sortedData, digestmod = hashlib.sha256).hexdigest()
		return "v1:{0}".format(signature)