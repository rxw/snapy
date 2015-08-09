from pysnap import Snapchat
from pprint import pprint

snapchat = Snapchat()
snapchat.login("snapbotnet", "pa55w0rd3", "snapbotnet@gmail.com", "pa55w0rd3")
snaps = snapchat.get_snaps()
