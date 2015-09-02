#!/usr/bin/env python2

"""Basic Snapchat client

Usage:
  get_stories.py [-q -z] -u <username> [-p <password>] --gmail=<gmail> --gpasswd=<gpasswd> <path>

Options:
  -h --help                 Show usage
  -q --quiet                Suppress output
  -u --username=<username>  Username
  -p --password=<password>  Password (optional, will prompt if omitted)
     --gmail=<gmail>        Gmail address
     --gpasswd=<gpasswd>    Gmail password
  -z --unzip                Unzip files
"""
from __future__ import print_function

import os.path
import sys
from getpass import getpass
import base64

from docopt import docopt

from snapy import get_file_extension, Snapchat
from snapy.utils import unzip_snap_mp4
from zipfile import is_zipfile

def main():
    arguments = docopt(__doc__)
    quiet = arguments['--quiet']
    unzip = arguments['--unzip']

    username = arguments['--username']
    if arguments['--password'] is None:
        password = getpass('Password:')
    else:
        password = arguments['--password']

    gmail = arguments['--gmail']
    if arguments['--gpasswd'] is None:
        gpasswd = getpass('Gmail password:')
    else:
        gpasswd = arguments['--gpasswd']

    path = arguments['<path>']

    if not os.path.isdir(path):
        print('No such directory: {0}'.format(arguments['<path>']))
        sys.exit(1)

    s = Snapchat()
    if not s.login(username, password, gmail, gpasswd)['updates_response'].get('logged'):
        print('Invalid username or password')
        sys.exit(1)

    for snap in s.get_friend_stories():
        filename = '{0}.{1}'.format(snap['id'],
                                    get_file_extension(snap['media_type']))
        abspath = os.path.abspath(os.path.join(path, filename))

        if os.path.isfile(abspath):
            continue

        data = s.get_story_blob(snap['media_id'],
                                snap['media_key'],
                                snap['media_iv'])
        if data is None:
            continue

        with open(abspath, 'wb') as f:
            f.write(data)
            if not quiet:
                print('Saved: {0}'.format(abspath))

        if is_zipfile(abspath) and unzip:
            unzip_snap_mp4(abspath, quiet)


if __name__ == '__main__':
    main()
