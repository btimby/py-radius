.. image:: https://travis-ci.org/btimby/py-radius.svg?branch=master
   :alt: Travis CI Status
   :target: https://travis-ci.org/btimby/py-radius

.. image:: https://coveralls.io/repos/github/btimby/py-radius/badge.svg?branch=master
    :target: https://coveralls.io/github/btimby/py-radius?branch=master
    :alt: Code Coverage

.. image:: https://badge.fury.io/py/py-radius.svg
    :target: https://badge.fury.io/py/py-radius

py-radius
=========

RADIUS authentication module for Python 2.7.13+

\(c) 1999 Stuart Bishop <stuart@stuartbishop.net>

This module provides basic RADIUS client capabilities, allowing your Python
code to authenticate against any RFC2138 compliant RADIUS server.

Installation
------------

::

    $ pip install py-radius

Usage
-----

The radius.py module can be run from the command line, providing a minimal
RADIUS client to test out RADIUS servers:

::

    $ python -m radius
    Host [default: 'radius']: radius
    Port [default: 1812]: 1812
    Enter RADIUS Secret: s3cr3t
    Enter your username: foobar
    Enter your password: qux
    ...
    Authentication Successful

Example
-------

Here is an example of using the library.

.. code:: python

    import radius

    radius.authenticate(secret, username, password, host='radius', port=1812)

    # - OR -

    r = radius.Radius(secret, host='radius', port=1812)
    print('success' if r.authenticate(username, password) else 'failure')

If your RADIUS server requires challenge/response, the usage is a bit more
complex.

.. code:: python

    import radius

    r = radius.Radius(secret, host='radius')

    try:
        print('success' if r.authenticate(username, password) else 'failure')
        sys.exit(0)
    except radius.ChallengeResponse as e:
        pass

    # The ChallengeResponse exception has `messages` and `state` attributes
    # `messages` can be displayed to the user to prompt them for their
    # challenge response. `state` must be echoed back as a RADIUS attribute.

    # Send state as an attribute _IF_ provided.
    attrs = {'State': e.state} if e.state else {}

    # Finally authenticate again using the challenge response from the user
    # in place of the password.
    print('success' if r.authenticate(username, response, attributes=attrs)
                    else 'failure')

This module has extensive logging, enable it using the Python logging framework.
