Pysnap Improved
===============

A Python library for the Snapchat API.

A fork of pysnap by [martinp](https://github.com/martinp/pysnap) updated to
use the new Snapchat API. 

Installation
------------

Pysnap is a standard Python package (setuptools) which can be installed by
running:

    python setup.py install

If you prefer not to install it globally, you can install it inside a
[virtualenv](http://www.virtualenv.org/).

Example API usage
-----------------

```python

from pprint import pprint
from pysnap import Snapchat

s = Snapchat()
s.login('username', 'password')
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
      get_snaps.py [-q] -u <username> [-p <password>] <path>

    Options:
      -h --help                 Show usage
      -q --quiet                Suppress output
      -u --username=<username>  Username
      -p --password=<password>  Password (optional, will prompt if omitted)
