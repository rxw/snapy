Snapy
===============

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A fork of pysnap by [martinp](https://github.com/martinp/pysnap) updated to
use the new Snapchat API. 

Installation
------------

Snapy is a standard Python package (setuptools) which can be installed by
running:

    python setup.py install

If you prefer not to install it globally, you can install it inside a
[virtualenv](http://www.virtualenv.org/).


Getting a Casper API Key
------------------------

This is required for the API to work.

Go to https://clients.casper.io/login.php and create an account.

Once you have created an account, go to "Projects" and create a new project.

![projects](http://s2.postimg.org/r7olutpah/projects.png)

Now you will have your project with your API Key and API Secret.

![api](http://s2.postimg.org/vi39qeudl/api.png)

You will need to set this data in the constructor, as shown in the [examples] (/examples).
Example API usage
-----------------

```python

from pprint import pprint
from snapy import Snapchat

s = Snapchat()
s.login('username', 'password', 'gmail', 'gpasswd')
snaps = s.get_snaps()

pprint(snaps)
```

Basic clients
-------------

There are two basic clients included in the package, `get_stories.py` for
downloading stories and `get_snaps.py` for downloading snaps.

    $ get_snaps.py -h
    Basic Snapchat client

    Usage:
      get_snaps.py [-q] -u <username> [-p <password>]  --gmail=<gmail>
                    --gpasswd=<gpasswd> <path>

    Options:
      -h --help                 Show usage
      -q --quiet                Suppress output
      -u --username=<username>  Username
      -p --password=<password>  Password (optional, will prompt if omitted)
         --gmail=<gmail>        Gmail
         --gpasswd=<gpasswd>    Gmail password

Announcements
-------------

- As of 2015-08-31, your Snapchat credentials are sent to 
https://api.casper.io as a work around for an API change. 
