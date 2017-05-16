#!/usr/bin/env python
'''
Extremly basic RADIUS authentication. Bare minimum required to authenticate
a user, yet remain RFC2138 compliant (I hope). 

Homepage at http://github.com/btimby/py-radius/
'''
# Copyright (c) 1999, Stuart Bishop <zen@shangri-la.dropbear.id.au> 
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# 
#     Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
# 
#     Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the
#     distribution.
# 
#     The name of Stuart Bishop may not be used to endorse or promote 
#     products derived from this software without specific prior written 
#     permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import socket
import logging
import struct

from select import select
from random import randint
from contextlib import closing, contextmanager

try:
    from collections import UserDict
except ImportError:
    from UserDict import UserDict

try:
    from hashlib import md5
except ImportError:
    from md5 import new as md5


__version__ = '1.0.4'

LOGGER = logging.getLogger(__name__)

# Networking constants.
# -------------------------------
PACKET_MAX = 4096
DEFAULT_PORT = 1812
DEFAULT_RETRIES = 3
DEFAULT_TIMEOUT = 5
# -------------------------------

# Protocol specific constants.
# -------------------------------
CODE_ACCESS_REQUEST = 1
CODE_ACCESS_ACCEPT = 2
CODE_ACCESS_REJECT = 3
CODE_ACCOUNTING_REQUEST = 4
CODE_ACCOUNTING_RESPONSE = 5
CODE_ACCESS_CHALLENGE = 11
CODE_STATUS_SERVER = 12
CODE_STATUS_CLIENT = 13
# CODE_RESERVED = 255

CODES = {
    CODE_ACCESS_REQUEST: 'Access-Request',
    CODE_ACCESS_ACCEPT: 'Access-Accept',
    CODE_ACCESS_REJECT: 'Access-Reject',
    CODE_ACCOUNTING_REQUEST: 'Accounting-Request',
    CODE_ACCOUNTING_RESPONSE: 'Accounting-Response',
    CODE_ACCESS_CHALLENGE: 'Access-Challenge',
    CODE_STATUS_SERVER: 'Status-Server',
    CODE_STATUS_CLIENT: 'Status-Client',
}

CODE_NAMES = {v: k for k, v in CODES.items()}

ATTR_USER_NAME = 1
ATTR_USER_PASSWORD = 2
ATTR_CHAP_PASSWORD = 4
ATTR_NAS_IP_ADDRESS = 4
ATTR_NAS_PORT = 5
ATTR_SERVICE_TYPE = 6
ATTR_FRAMED_PROTOCOL = 7
ATTR_FRAMED_IP_ADDRESS = 8
ATTR_FRAMED_IP_NETMASK = 9
ATTR_FRAMED_ROUTING = 10
ATTR_FILTER_ID = 11
ATTR_FRAMED_MTU = 12
ATTR_FRAMED_COMPRESSION = 13
ATTR_LOGIN_IP_HOST = 14
ATTR_LOGIN_SERVICE = 15
ATTR_LOGIN_TCP_PORT = 16
# ATTR_UNASSIGNED = 17
ATTR_REPLY_MESSAGE = 18
ATTR_CALLBACK_NUMBER = 19
ATTR_CALLBACK_ID = 20
# ATTR_UNASSIGNED = 21
ATTR_FRAMED_ROUTE = 22
ATTR_FRAMED_IPX_NETWORK = 23
ATTR_STATE = 24
ATTR_CLASS = 25
ATTR_VENDOR_SPECIFIC = 26
ATTR_SESSION_TIMEOUT = 27
ATTR_IDLE_TIMEOUT = 28
ATTR_TERMINATION_ACTION = 29
ATTR_CALLED_STATION_ID = 30
ATTR_CALLING_STATION_ID = 31
ATTR_NAS_IDENTIFIER = 32
ATTR_PROXY_STATE = 33
ATTR_LOGIN_LAT_SERVICE = 34
ATTR_LOGIN_LAT_NODE = 35
ATTR_LOGIN_LAT_GROUP = 36
ATTR_FRAMED_APPLETALK_LINK = 37
ATTR_FRAMED_APPLETALK_NETWORK = 38
ATTR_FRAMED_APPLETALK_ZONE = 39
# ATTR_RESERVED = 40-59
ATTR_CHAP_CHALLENGE = 60
ATTR_NAS_PORT_TYPE = 61
ATTR_PORT_LIMIT = 62
ATTR_LOGIN_LAT_PORT = 63

ATTRS = {
    ATTR_USER_NAME: 'User-Name',
    ATTR_USER_PASSWORD: 'User-Password',
    ATTR_CHAP_PASSWORD: 'CHAP-Password',
    ATTR_NAS_IP_ADDRESS: 'NAS-IP-Address',
    ATTR_NAS_PORT: 'NAS-Port',
    ATTR_SERVICE_TYPE: 'Service-Type',
    ATTR_FRAMED_PROTOCOL: 'Framed-Protocol',
    ATTR_FRAMED_IP_ADDRESS: 'Framed-IP-Address',
    ATTR_FRAMED_IP_NETMASK: 'Framed-IP-NetMask',
    ATTR_FRAMED_ROUTING: 'Framed-Routing',
    ATTR_FILTER_ID: 'Filter-Id',
    ATTR_FRAMED_MTU: 'Framed-MTU',
    ATTR_FRAMED_COMPRESSION: 'Framed-Compression',
    ATTR_LOGIN_IP_HOST: 'Login-IP-Host',
    ATTR_LOGIN_SERVICE: 'Login-Service',
    ATTR_LOGIN_TCP_PORT: 'Login-TCP-Port',
    ATTR_REPLY_MESSAGE: 'Reply-Message',
    ATTR_CALLBACK_NUMBER: 'Callback-Number',
    ATTR_CALLBACK_ID: 'Callback-Id',
    ATTR_FRAMED_ROUTE: 'Framed-Route',
    ATTR_FRAMED_IPX_NETWORK: 'Framed-IPX-Network',
    ATTR_STATE: 'State',
    ATTR_CLASS: 'Class',
    ATTR_VENDOR_SPECIFIC: 'Vendor-Specific',
    ATTR_SESSION_TIMEOUT: 'Session-Timeout',
    ATTR_IDLE_TIMEOUT: 'Idle-Timeout',
    ATTR_TERMINATION_ACTION: 'Termination-Action',
    ATTR_CALLED_STATION_ID: 'Called-Station-Id',
    ATTR_CALLING_STATION_ID: 'Calling-Station-Id',
    ATTR_NAS_IDENTIFIER: 'NAS-Identifier',
    ATTR_PROXY_STATE: 'Proxy-State',
    ATTR_LOGIN_LAT_SERVICE: 'Login-LAT-Service',
    ATTR_LOGIN_LAT_NODE: 'Login-LAT-Node',
    ATTR_LOGIN_LAT_GROUP: 'Login-LAT-Group',
    ATTR_FRAMED_APPLETALK_LINK: 'Framed-AppleTalk-Link',
    ATTR_FRAMED_APPLETALK_NETWORK: 'Framed-AppleTalk-Network',
    ATTR_FRAMED_APPLETALK_ZONE: 'Framed-AppleTalk-Zone',
    ATTR_CHAP_CHALLENGE: 'CHAP-Challenge',
    ATTR_NAS_PORT_TYPE: 'NAS-Port-Type',
    ATTR_PORT_LIMIT: 'Port-Limit',
    ATTR_LOGIN_LAT_PORT: 'Login-LAT-Port',
}

ATTR_NAMES = {v: k for k, v in ATTRS.items()}
# -------------------------------


class Error(Exception):
    pass


class NoResponse(Error):
    pass


class ChallengeResponse(Error):
    """
    Raised when radius replies with a challenge.

    Provides the message(s) if any, as well as the state (if provided).

    There can be 0+ messages. State is either defined or not.
    """
    def __init__(self, msg=None, state=None):
        if msg is None:
            self.messages = None
        elif isinstance(msg, list):
            self.messages = msg
        else:
            self.messages = [msg]
        self.state = state


class SocketError(NoResponse):
    pass


def join(items):
    return ''.join(items)


def authenticate(username, password, secret, **kwargs):
    """
    Authenticate the user against a radius server.

    Return True if the user successfully logged in and False if not.
    
    If the server replies with a challenge, a `ChallengeResponse` exception is
    raised with the challenge.

    Can raise either NoResponse or SocketError
    """
    return Radius(secret, **kwargs).authenticate(username, password)


def radcrypt(secret, authenticator, text):
    """Encrypt a password with the secret."""
    # First, pad the password to multiple of 16 octets.
    text += chr(0) * (16 - (len(text) % 16))

    if len(text) > 128:
        raise ValueError('Password exceeds maximun of 128 bytes')

    result, last = '', authenticator
    while text:
        # md5sum the shared secret with the authenticator,
        # after the first iteration, the authenticator is the previous
        # result of our encryption.
        hash = md5(secret + last).digest()
        for i in range(16):
            result += chr(ord(hash[i]) ^ ord(text[i]))
        # The next iteration will act upon the next 16 octets of the password
        # and the result of our xor operation above. We will set last to
        # the last 16 octets of our result (the xor we just completed). And
        # remove the first 16 octets from the password.
        last, text = result[-16:], text[16:]

    return result


class Attributes(UserDict):
    """
    Dictionary-style interface.

    Can retrieve or set values by name or by code. Internally stores items by
    their assigned code. A given attribute can be present more than once.
    """
    def __init__(self, initialdata={}):
        UserDict.__init__(self, {})
        # Set keys via update() to invoke validation.
        self.update(initialdata)

    def _getkeys(self, value):
        """Return tuple of code, name for given code or name."""
        if isinstance(value, int):
            return value, ATTRS[value]
        else:
            return ATTR_NAMES[value], value

    def __getitem__(self, key):
        for k in self._getkeys(key):
            try:
                values = UserDict.__getitem__(self, k)
                if len(values) == 1:
                    return values[0]
                return values
            except KeyError:
                continue
        raise KeyError(key)

    def __setitem__(self, key, value):
        try:
            code, name = self._getkeys(key)
        except KeyError:
            raise ValueError('Invalid radius attribute: %s' % key)
        values = self.get(code, [])
        values.append(value)
        UserDict.__setitem__(self, code, values)

    def update(self, data):
        """
        Sets keys via __setitem__() to invoke validation.
        """
        for k, v in data.items():
            self[k] = v

    def nameditems(self):
        for k, v in self.items():
            yield self._getkeys(k)[1], v

    def pack(self):
        data = []
        for key, values in self.items():
            for value in values:
                data.append(struct.pack('BB%ds' % len(value), key,
                                        len(value) + 2, value))
        return join(data)

    @staticmethod
    def unpack(data):
        pos, attrs = 0, {}
        while pos < len(data):
            code, l = struct.unpack('BB', data[pos:pos + 2])
            attrs[code] = data[pos + 2:pos + l]
            pos += l
        return Attributes(attrs)


class Message(object):
    """
    Represents a radius protocol packet.

    This class can be used for requests and replies. The RFC dictates the
    format.

     0                   1                   2                   3   
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Code      |  Identifier   |            Length             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                     Response Authenticator                    |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Attributes ...
    +-+-+-+-+-+-+-+-+-+-+-+-+-
    
    Code - one octet, see CODES enum.
    Identifier - one octet, unique value that represents request/response pair.
                 Provided by client and echoed by server.
    Length - two octets, the length of the packet up to the max of 4096.
    """

    def __init__(self, code, secret, id=None, authenticator=None,
                 attributes=None):
        self.code = code
        self.secret = secret
        self.id = id if id else randint(0, 255)
        self.authenticator = authenticator if authenticator else os.urandom(16)
        if isinstance(attributes, dict):
            attributes = Attributes(attributes)
        self.attributes = attributes if attributes else Attributes()

    def pack(self):
        """Pack the packet into binary form for transport."""
        # First pack the attributes, since we need to know their length.
        attrs = self.attributes.pack()
        data = []
        # Now pack the code, id, total length, authenticator
        data.append(struct.pack('!BBH16s'), self.code, self.id,
                                len(attrs) + 20, self.authenticator)
        # Attributes take up the remainder of the message.
        data.append(attrs)
        return join(data)

    @classmethod
    def unpack(self, data):
        """Unpack the data into it's fields."""
        code, id, l, authenticator = struct.unpack('!BBH16s', data[:20])
        attrs = Attributes.unpack(data[20:])
        return Message(code, id, authenticator, attrs)

    def verify(self, data):
        """
        Verify and unpack a response.

        Ensures that a message is a valid response to this message. Then unpack
        it.
        """
        assert self.id == ord(data[2]), 'Identifier mismatch'
        signature = md5(
            data[:4] + self.authenticator + data[20:] + self.secret).digest()
        assert signature == data[4:20], 'Invalid authenticator'
        return Message.unpack(data)


def access_request(secret, username, password, **kwargs):
    attributes = kwargs.pop('attributes', Attributes())
    attributes.update({
        'User-Name': username,
        'User-Password': radcrypt(secret, username, password)
    })
    return Message(CODE_ACCESS_REQUEST, secret, attributes=attributes,
                   **kwargs)


class Radius(object):
    """
    Radius client implementation.
    """

    def __init__(self, secret, host='radius', port=DEFAULT_PORT,
                 retries=DEFAULT_RETRIES, timeout=DEFAULT_TIMEOUT):
        self._secret = secret
        self.retries = retries
        self.timeout = timeout
        self._host = host
        self._port = port

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @property
    def secret(self):
        return self._secret

    @contextmanager
    def connect(self):
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as c:
            c.connect((self.host, self.port))
            LOGGER.debug('Connected to %s:%s', self.host, self.port)
            yield c

    def authenticate(self, username, password):
        """
        Attempt to authenticate with the given username and password.

           Returns False on failure
           Returns True on success
           Raises a NoResponse (or its subclass SocketError) exception if no
               responses or no valid responses are received
        """
        with self.connect() as c:
            try:
                msg = access_request(self.secret, username, password)
                data = msg.pack()

                for i in range(self.retries):
                    self._socket.send(data)

                    r, w, x = select([self._socket,], [], [], self.timeout)
                    if self._socket in r:
                        recv = self._socket.recv(4096)
                    else:
                        # No data available on our socket. Try again.
                        LOGGER.warning('Timeout expired on try %s', i)
                        continue

                    LOGGER.debug('Received (as hex): %s', hex(recv))

                    try:
                        reply = msg.verify(recv)
                    except AssertionError as e:
                        LOGGER.warning('Invalid response discarded %s',
                                       e.message)
                        # Silently discard invalid replies (as RFC states).
                        continue

                    LOGGER.debug('Received valid response')

                    if reply.code == CODE_ACCESS_ACCEPT:
                        LOGGER.info('Access accepted')
                        return True

                    elif reply.code == CODE_ACCESS_CHALLENGE:
                        LOGGER.info('Access challenged')
                        # TODO: parse attributes to extract the
                        # Reply-Message(s), which could be an actual challenge
                        # messages (to display to the user). Also, pass along
                        # state which should be echoed back to the server.
                        raise ChallengeResponse(
                            reply.attributes.get('Reply-Message', None),
                            state=reply.attributes.get('State', None))

                    LOGGER.info('Access rejected')
                    return False

            except socket.error as e: # SocketError
                LOGGER.debug('Socket error', exc_info=True)
                raise SocketError(e)

            LOGGER.error('Request timed out after %s tries', i)
            raise NoResponse()


# Don't break code written for radius.py distributed with the ZRadius
# Zope product
RADIUS = Radius


if __name__ == '__main__':

    from getpass import getpass

    host = raw_input("Host [default: 'radius']:")
    port = raw_input('Port [default: %s]:' % DEFAULT_PORT)

    host = host if host else 'radius'
    port = int(port) if port else DEFAULT_PORT

    secret, uname, passwd = None, None, None

    while not secret:
        secret = getpass('RADIUS Secret? ')

    while not uname:
        uname = raw_input("Username? ")

    while not passwd:
        passwd = getpass("Password? ")

    if Radius(secret, host, port).authenticate(uname, passwd):
        print("Authentication Succeeded")
    else:
        print("Authentication Failed")
