#!/usr/bin/env python

import json
import os.path
import hmac
from time import time
from uuid import uuid1
from datetime import datetime
from hashlib import sha256, md5

from snapy.utils import (encrypt, decrypt, decrypt_story,
                          make_media_id, request, get_auth_token, 
                          make_request_token, get_attestation, 
                          timestamp, STATIC_TOKEN, get_client_auth_token)

from snapy.API import CasperAPI

MEDIA_IMAGE = 0
MEDIA_VIDEO = 1
MEDIA_VIDEO_NOAUDIO = 2

FRIEND_CONFIRMED = 0
FRIEND_UNCONFIRMED = 1
FRIEND_BLOCKED = 2
PRIVACY_EVERYONE = 0
PRIVACY_FRIENDS = 1


def is_video(data):
    return True if data[0:2] == b'\x00\x00' else False


def is_image(data):
    return True if data[0:2] == b'\xFF\xD8' else False


def is_zip(data):
    return True if data[0:2] == b'PK' else False


def get_file_extension(media_type):
    if media_type in (MEDIA_VIDEO, MEDIA_VIDEO_NOAUDIO):
        return 'mp4'
    if media_type == MEDIA_IMAGE:
        return 'jpg'
    return ''


def get_media_type(data):
    if is_video(data):
        return MEDIA_VIDEO
    if is_image(data):
        return MEDIA_IMAGE
    if is_zip(data):
        return MEDIA_VIDEO
    return None


def _map_keys(snap):
    return {
        u'id': snap.get('id', None),
        u'media_id': snap.get('c_id', None),
        u'media_type': snap.get('m', None),
        u'time': snap.get('t', None),
        u'sender': snap.get('sn', None),
        u'recipient': snap.get('rp', None),
        u'status': snap.get('st', None),
        u'screenshot_count': snap.get('c', None),
        u'sent': snap.get('sts', None),
        u'opened': snap.get('ts', None)
    }

class Snapchat(object):
    """Construct a :class:`Snapchat` object used for communicating
    with the Snapchat API.

    Usage:

        from snapy import Snapchat
        snapchat = Snapchat()
        snapchat.login('username', 'password', 'gmail_addr', 'gmail_passwd')
        ...

    """
    def __init__(self):
        self.username = None
        self.auth_token = None
        self.gmail = None
        self.gpasswd = None
        self.gauth = None
        self.expiry = datetime.fromtimestamp(0)

    def _request(self, endpoint, data=None, params=None, files=None,
                 raise_for_status=True, req_type='post', moreheaders={}):
        return request(endpoint, self.auth_token, data, params, files,
                       raise_for_status, req_type, moreheaders)

    def _get_device_token(self):
        r = self._request('/loq/device_id',params={'gauth': self._get_gauth()})
        return r.json()
        
    def _unset_auth(self):
        self.username = None
        self.auth_token = None

    def _get_gauth(self):
        """This is the proper way to access self.gauth when using it for an
        API request. This first checks to see if the Bearer token is expired,
        renewing it if needed.
        """
        if datetime.now() >= self.expiry:
            gauth_token = get_auth_token(self.gmail, self.gpasswd)
            self.gauth = gauth_token[0]
            self.expiry = gauth_token[1]

        return self.gauth

    def _get_conversation_auth(self, to):
        """Gets conversation auth for a certain user.
           Only takes in one user, returns a dict.
        """
        now = str(timestamp())
        r = self._request('/loq/conversation_auth_token',{
            'username': self.username,
            'timestamp': now,
            'conversation_id': self.username + "~" + to
            }, {'now': now, 'gauth': self._get_gauth()})
        return r.json()

    def restore_token(self, username, auth_token, gmail, gpasswd):
        """Restore a Snapchat session from an auth_token parameter
        returned in the response of a login request. Useful for when
        Snapchat breaks the login API.

        :param username     Snapchat username
        :param auth_token   Snapchat auth_token
        :param gmail        Gmail address
        :param gpasswd      Gmail password
        """
        self.username = username
        self.auth_token = auth_token
        self.gmail = gmail
        self.gpasswd = gpasswd
        gauth_token = get_auth_token(gmail, gpasswd)
        self.gauth = gauth_token[0]
        self.expiry = gauth_token[1]

    def login(self, username, password, gmail, gpasswd, ckey, csecret):
        """Login to Snapchat account
        Returns a dict containing user information on successful login, the
        data returned is similar to get_updates.

        :param username Snapchat username
        :param password Snapchat password
        :param gmail    Gmail address
        :param gpasswd  Gmail password
        """
        self.gmail = gmail
        self.gpasswd = gpasswd

        casper = CasperAPI(ckey, csecret)
        i = 0
        logged_in = False
        while i < 4 and logged_in == False:
            i += 1
            now = str(timestamp())
            req_token = make_request_token(STATIC_TOKEN, now)
            gauth_token = get_auth_token(gmail, gpasswd)
            self.gauth = gauth_token[0]
            self.expiry = gauth_token[1]
            string = username + "|" + password + "|" + now + "|" + req_token
            dtoken = self._get_device_token()
            self._unset_auth()
            nonce = casper.generateSnapchatNonce(username, password, now)
            attestation = casper.getSnapchatAttestation(nonce)
            r = self._request('/loq/login', {
                'username': username,
                'password': password,
                'height': 1280,
                'width': 720,
                'max_video_height': 640,
                'max_video_width': 480,
                'dsig': hmac.new(str(dtoken['dtoken1v']),string,sha256).hexdigest()[:20],
                'dtoken1i': dtoken['dtoken1i'],
                'ptoken': "ie",
                'attestation': attestation,
                'sflag': 1,
                'application_id': 'com.snapchat.android',
                'req_token': req_token
            }, {
                'now': now, 
                'gauth': self._get_gauth()
            }, None, True, 'post', {
            'X-Snapchat-Client-Auth': casper.getSnapchatClientAuth(username, password, now)
            })

            result = r.json()

            if 'updates_response' in result:
                logged_in = True
                if 'auth_token' in result['updates_response']:
                    self.auth_token = result['updates_response']['auth_token']

                if 'username' in result['updates_response']:
                    self.username = username

        if self.username is None and self.auth_token is None:
            raise Exception(result.get('message', 'unknown error'))

        return result

    def logout(self):
        """Logout of Snapchat account
        Returns true if logout was successful.
        """
        r = self._request('logout', {'username': self.username})
        return len(r.content) == 0

    def get_updates(self, update_timestamp=0):
        """Get user, friend and snap updates
        Returns a dict containing user, friends and snap information.

        :param update_timestamp: Optional timestamp (epoch in seconds) to limit
                                 updates
        """
        now = str(timestamp())
        r = self._request('/loq/all_updates', {
            'timestamp': now,
            'username': self.username,
            'height': 1280,
            'width': 720,
            'max_video_height': 640,
            'max_video_width': 480
        }, {
            'now': now,
            'gauth': self._get_gauth()
            })
        result = r.json()
        if 'auth_token' in result:
            self.auth_token = result['auth_token']
        return result
    
    def get_conversations(self):
        """Returns a list of conversations
        with other users.
        """
        offset = None
        updates = self.get_updates()
        try:
            last = updates['conversations_response'][-2]
            offset = last['iter_token']
        except IndexError:
            print "No conversations except TeamSnapchat"
        
        
        convos = updates['conversations_response']
        """
        while len(offset) > 0:
            now = str(timestamp())
            result = self._request('conversations', {
                'username': self.username,
                'timestamp': now,
                'checksum': md5(self.username).hexdigest(),
                'offset': offset,
                'features_map': '{}'
                }, {
                'now': now,
                'gauth': self.gauth
                })
            print result.json()
            convos += result.json()['conversations_response']
            last = result.json()['conversations_response'][-1]
            offset = last['iter_token'] if 'iter_token' in last else ""
        """
        return convos

    def get_snaps(self):
        """Get snaps
        Returns a list containing metadata for snaps

        :param update_timestamp: Optional timestamp (epoch in seconds) to limit
                                 updates
        """
        snaps = []
        conversations = self.get_conversations()
        
        for conversation in conversations:
            num_pending = len(conversation['pending_received_snaps'])
            for i in range(0, num_pending):
                snap = (_map_keys(conversation['pending_received_snaps'][i]))
                snaps.append(snap)

        return snaps

    def get_friend_stories(self, update_timestamp=0):
        """Get stories
        Returns a dict containing metadata for stories

        :param update_timestamp: Optional timestamp (epoch in seconds) to limit
                                 updates
        """
        result = self.get_updates()
        stories = []
        fstories = []
        story_groups = result['stories_response']['friend_stories']
        for group in story_groups:
            sender = group['username']
            for story in group['stories']:
                obj = story['story']
                if obj['is_shared'] == False and obj['username'] != 'teamsnapchat':
                    stories.append(obj)
        return stories

    def get_story_blob(self, story_id, story_key, story_iv):
        """Get the image or video of a given snap
        Returns the decrypted image or a video of the given snap or None if
        data is invalid.

        :param story_id: Media id to fetch
        :param story_key: Encryption key of the story
        :param story_iv: Encryption IV of the story
        """
        now = str(timestamp())
        r = self._request('/bq/story_blob', {'story_id': story_id},
                          raise_for_status=False, req_type='get')
        data = decrypt_story(r.content, story_key, story_iv)
        return data

    def get_blob(self, snap_id):
        """Get the image or video of a given snap
        Returns the image or a video of the given snap or None if
        data is invalid.

        :param snap_id: Snap id to fetch
        """
        now = str(timestamp())
        
        r = self._request('/bq/blob', {'id': snap_id, 'timestamp':now, 'username': self.username}, 
                {'now': now, 'gauth': self._get_gauth()}, req_type='get')
        
        return r.content
        

    def send_events(self, events, data=None):
        """Send event data
        Returns true on success.

        :param events: List of events to send
        :param data: Additional data to send
        """
        now = str(timestamp())
        if data is None:
            data = {}
        r = self._request('/bq/update_snaps', {
            'events': json.dumps(events),
            'json': json.dumps(data),
            'username': self.username
            }, {'now': now,'gauth': self._get_gauth()})
        return len(r.content) == 0

    def mark_viewed(self, snap_id, view_duration=1):
        """Mark a snap as viewed
        Returns true on success.

        :param snap_id: Snap id to mark as viewed
        :param view_duration: Number of seconds snap was viewed
        """
        now = time()
        data = {snap_id: {u't': now, u'sv': view_duration}}
        events = [
            {
                u'eventName': u'SNAP_VIEW', u'params': {u'id': snap_id},
                u'ts': int(round(now)) - view_duration
            },
            {
                u'eventName': u'SNAP_EXPIRED', u'params': {u'id': snap_id},
                u'ts': int(round(now))
            }
        ]
        return self.send_events(events, data)

    def mark_screenshot(self, snap_id, view_duration=1):
        """Mark a snap as screenshotted
        Returns true on success.

        :param snap_id: Snap id to mark as viewed
        :param view_duration: Number of seconds snap was viewed
        """
        now = time()
        data = {snap_id: {u't': now, u'sv': view_duration, u'c': 3}}
        events = [
            {
                u'eventName': u'SNAP_SCREENSHOT', u'params': {u'id': snap_id},
                u'ts': int(round(now)) - view_duration
            }
        ]
        return self.send_events(events, data)

    def update_privacy(self, friends_only):
        """Set privacy settings
        Returns true on success.

        :param friends_only: True to allow snaps from friends only
        """
        setting = lambda f: PRIVACY_FRIENDS if f else PRIVACY_EVERYONE
        r = self._request('settings', {
            'username': self.username,
            'action': 'updatePrivacy',
            'privacySetting': setting(friends_only)
        })
        return r.json().get('param') == str(setting(friends_only))

    def get_friends(self):
        """Get friends
        Returns a list of friends.
        """
        friends = []
        for friend in self.get_updates().get('friends_response', [])['friends']:
            friends.append(friend['name'])
        return friends

    def get_best_friends(self):
        """Get best friends
        Returns a list of best friends.
        """
        return self.get_updates().get('bests', [])

    def add_friend(self, username):
        """Add user as friend
        Returns JSON response.
        Expected messages:
            Success: '{username} is now your friend!'
            Pending: '{username} is private. Friend request sent.'
            Failure: 'Sorry! Couldn't find {username}'

        :param username: Username to add as a friend
        """
        now = str(timestamp())
        r = self._request('/bq/friend', {
            'action': 'add',
            'friend': username,
            'timestamp': now,
            'username': self.username,
            'added_by': 'ADDED_BY_USERNAME'
            }, {'now': now, 'gauth': self._get_gauth()})
        return r.json()

    def delete_friend(self, username):
        """Remove user from friends
        Returns true on success.

        :param username: Username to remove from friends
        """
        now = str(timestamp())
        r = self._request('/bq/friend', {
            'action': 'delete',
            'friend': username,
            'timestamp': now,
            'username': self.username
            }, {'now': now, 'gauth': self._get_gauth()})
        return r.json()

    def block(self, username):
        """Block a user
        Returns true on success.

        :param username: Username to block
        """
        now = (str(timestamp()))
        r = self._request('/bq/friend', {
            'action': 'block',
            'friend': username,
            'username': self.username,
            'features_map': '{}',
            'timestamp': now
            }, {'gauth': self._get_gauth()})
        return r.json().get('message') == '{0} was blocked'.format(username)

    def unblock(self, username):
        """Unblock a user
        Returns true on success.

        :param username: Username to unblock
        """
        r = self._request('friend', {
            'action': 'unblock',
            'friend': username,
            'username': self.username
        })
        return r.json().get('message') == '{0} was unblocked'.format(username)

    def get_blocked(self):
        """Find blocked users
        Returns a list of currently blocked users.
        """
        return [f for f in self.get_friends() if f['type'] == FRIEND_BLOCKED]

    def get_requested(self):
        """Find friend requests
        Returns a list of users requests a friendship.
        """
        requests = []
        for request in self.get_updates().get('friends_response', [])['added_friends']:
            requests.append(request)
        return requests

    def upload(self, path):
        """Upload media
        Returns the media ID on success. The media ID is used when sending
        the snap.
        """
        if not os.path.exists(path):
            raise ValueError('No such file: {0}'.format(path))

        with open(path, 'rb') as f:
            data = f.read()

        media_type = get_media_type(data)
        if media_type is None:
            raise ValueError('Could not determine media type for given data')

        media_id = make_media_id(self.username)
        now = str(timestamp())
        r = self._request('/ph/upload', {
            'media_id': media_id,
            'type': media_type,
            'timestamp': now,
            'username': self.username,
            'zipped': '0'
            }, {'now': now, 'gauth': self._get_gauth()}, files={'data': data})

        return media_id if len(r.content) == 0 else None

    def send(self, media_id, recipients, time=5):
        """Send a snap. Requires a media_id returned by the upload method
        Returns true if the snap was sent successfully.
        """
        now = str(timestamp())
        recipients = '["' + '","'.join(recipients) + '"]'
        r = self._request('/loq/send', {
            'media_id': media_id,
            'zipped': '0',
            'recipients': recipients,
            'username': self.username,
            'time': time,
            'timestamp': now,
            'features_map': '{}'
            }, {'now': now, 'gauth': self._get_gauth()})
        return len(r.content) == 0

    def send_to_story(self, media_id, time=5, media_type=0, is_zip=0):
        """Send a snap to your story. Requires a media_id returned by the upload method
           Returns true if the snap was sent successfully.
        """
        now = str(timestamp())
        r = self._request('/bq/post_story', {
            'username': self.username,
            'media_id': media_id,
            'client_id': media_id,
            'time': time,
            'type': media_type,
            'zipped': is_zip
            }, {'now': now, 'gauth': self._get_gauth()})
        return r.json()

    def get_conversation_info(self, tos):
        messages = {}
        if not isinstance(tos, list):
            tos = [tos]
        
        for to in tos:
            auth_info = self._get_conversation_auth(to)
            if 'messaging_auth' in auth_info:
                payload = auth_info['messaging_auth']['payload']
                mac = auth_info['messaging_auth']['mac']
                conv_id = str(uuid1())
                messages = {
                        'presences': {self.username: True, to: False},
                        'receiving_video': False,
                        'supports_here': True,
                        'header': {
                                'auth': {
                                        'mac': mac,
                                        'payload': payload
                                },
                                'to': [to],
                                'conv_id': self.username + "~" + to,
                                'from': self.username,
                                'conn_sequence_number': 0
                        },
                        'retried': False,
                        'id': conv_id,
                        'type': 'presence'
                        }
            now = str(timestamp())
            r = self._request('/loq/conversation_post_messages',{
                'auth_token': self._get_gauth(),
                'messages': messages,
                'timestamp': now,
                'username': self.username
                },{'now': now, 'gauth': self._get_gauth()})
            return r

    def clear_feed(self):
        """Clear the user's feed
        Returns true if feed was successfully cleared.
        """

        r = self._request('clear', {
            'username': self.username
        })

        return len(r.content) == 0

    def get_snaptag(self):
        """Get a QR code-like image used to add friends on Snapchat.
        Returns False if unable to get a QR code.
        """
        updates = self.get_updates()

        if not updates:
            return False

        else:
            qr_path = updates['updates_response']['qr_path']
            now = str(timestamp())

            r = self._request('/bq/snaptag_download', {
                'image': qr_path,
                'username': self.username,
                'timestamp': now
            }, {
                'now': now,
                'gauth': self._get_gauth()
            })

            return r.content

    def get_my_story(self):
        now = str(timestamp())
        r = self._request('/bq/stories', {
                'timestamp': now,
                'screen_height_in': 4.527565,
                'screen_height_px': 1920,
                'screen_width_in': 2.5590599,
                'screen_width_px': 1080,
                'username': self.username,
                'features_map': {}
            })
        
        result = r.json()['my_stories']
        return result
