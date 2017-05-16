.. image:: https://travis-ci.org/btimby/py-radius.svg?branch=master
   :alt: Travis CI Status
   :target: https://travis-ci.org/btimby/py-radius

.. image:: https://coveralls.io/repos/github/btimby/py-radius/badge.svg?branch=master
    :target: https://coveralls.io/github/btimby/py-radius?branch=master
    :alt: Code Coverage

.. image:: https://badge.fury.io/py/py-radius.svg
    :target: https://badge.fury.io/py/py-radius

RADIUS authentication module for Python 2.7.13

(c) 1999 Stuart Bishop <zen@shangri-la.dropbear.id.au>

This module provides basic RADIUS client capabilities, allowing
your Python code to authenticate against any RFC2138 compliant RADIUS
server.

Installation
------------

.. code:: python

    pip install py-radius

Usage
-----

The radius.py module can be run from the command line, providing a minimal
RADIUS client to test out RADIUS servers:

    $ python -m radius

Example
-------

Here is an example of using the library.

.. code:: python

    import radius

    radius.authenticate(username, password, secret, host='radius', port=1812)

    # - OR -

    r = radius.Radius(secret, host='radius', port=1812)
    r.authenticate(username, password)

If your RADIUS server requires challenge/response, the usage is a bit more
complex.

.. code:: python

    import radius

    r = radius.Radius(secret, host='radius')

    try:
        r.authenticate(username, password)
    except radius.ChallengeResponse as e:
        # The ChallengeResponse exception has `messages` and `state` attributes
        # `messages` can be displayed to the user to prompt them for their
        # challenge response. `state` must be echoed back as a RADIUS attribute.

        # By default send no attributes.
        attrs = radius.Attributes()
        if e.state:
            # If server provided state, echo it.
            attrs['State'] = e.state

        # Finally authenticate again using the challenge response from the user
        # in place of the password.
        r.authenticate(username, response, attributes=attrs)

This module has extensive logging, enable it using the Python logging framework.