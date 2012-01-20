RADIUS authentication module for Python 1.5.2+

(c) 1999 Stuart Bishop <zen@shangri-la.dropbear.id.au>

This module provides basic RADIUS client capabilities, allowing
your Python code to authenticate against any RFC2138 compliant RADIUS
server.


Installation
-----

The following command will install radius.py into your Python
modules library:

    python setup.py install

This command will generally need to be run with an administrative
level account (root under Unix, Administrator under NT etc.).

RPM Package
-----

You can build an RPM package for py-radius using the following procedure.

    $ mkdir -p $HOME/rpmbuild/SOURCES
    $ python setup.py sdist
    $ cp dist/*.tar.gz $HOME/rpmbuild/SOURCES
    $ rpmbuild -ba py-radius.spec

Usage
-----

The radius.py module can be run from the command line, providing a minimal
RADIUS client to test out RADIUS servers:

    $ python radius.py


The module defines the following items:

    authenticate(username, password, secret, host='radius', port=1645)

A simple, thread safe function to authenticate off a RADIUS
server with the minimum possible fuss. Returns 1 on success,
0 on failure. May throw a NoResponse or SocketError exception.

    RADIUS(secret, host='radius', port=1645)

Return a new instance of the RADIUS class. RADIUS objects
provide a more efficient interface if your code makes many
calls to the same RADIUS server. RADIUS objects should not
be shared between threads, unless only one thread accesses
the authenticate method at a time.

    NoResponse

Exception thrown if no response or no valid responses are
received.

    SocketError

Subclass of NoResponse. Exception thrown if an exception is
thrown from Python's socket module.

RADIUS instances have the following methods and attributes available:

    authenticate(username, password)

Authenticate a username/password combination. Returns 1 on
success or 0 on failure. May throw a NoResponse or SocketError
exception.

    closesocket()

Close the outgoing UDP socket. Called automatically in the
RADIUS instance's destructor. 

    retries

The number of times the authenticate method tries to 
authenticate before returning a NoResponse exception. Defaults
to 3.

    timeout

The number of seconds the authenticate method waits for
a response from the RADIUS server before giving up and
retrying. Defaults to 5.


Example
-----

    #!/bin/env python
    from getpass import getpass
    from radius import RADIUS

    host = raw_input("Host? (default = 'radius')")
    port = raw_input('Port? (default = 1645) ')

    if not host: host = 'radius'

    if port: port = int(port)
    else: port = 1645

    secret = ''
    uname,passwd = None,None
    while not secret: secret = getpass('RADIUS Secret? ')
    while not uname:  uname  = raw_input("Username? ")
    while not passwd: passwd = getpass("Password? ")

    r = RADIUS(secret,host,port)
    r.timeout = 10


    if r.authenticate(uname,passwd):
        print "Authentication Succeeded"
    else:
        print "Authentication Failed"

