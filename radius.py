#!/usr/bin/env python
'''
Basic RADIUS authentication. Minimum necessary to be able to authenticate a
user with or without challenge/response, yet remain RFC2865 compliant (I hope).

Homepage at http://github.com/btimby/py-radius/
'''

# Copyright (c) 1999, Stuart Bishop <stuart@stuartbishop.net>
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
import sys
import socket
import logging
import struct

from random import randint
import contextlib

try:
    from collections import UserDict
except ImportError:
    from UserDict import UserDict

try:
    from hashlib import md5
except ImportError:
    from md5 import new as md5


__version__ = '2.0.2'

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())

# Networking constants.
# -------------------------------
PACKET_MAX = 4096
DEFAULT_PORT = 1812
DEFAULT_RETRIES = 3
DEFAULT_TIMEOUT = 5
# -------------------------------

# Protocol specific constants.
# -------------------------------
# Codes indicating packet type.
CODE_ACCESS_REQUEST = 1
CODE_ACCESS_ACCEPT = 2
CODE_ACCESS_REJECT = 3
CODE_ACCOUNTING_REQUEST = 4
CODE_ACCOUNTING_RESPONSE = 5
CODE_ACCESS_CHALLENGE = 11
CODE_STATUS_SERVER = 12
CODE_STATUS_CLIENT = 13
# CODE_RESERVED = 255

# Map from name to id.
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

CODE_NAMES = {v.lower(): k for k, v in CODES.items()}

# Attributes that can be part of the RADIUS payload.
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
# For RSA Authentication Manager
ATTR_PROMPT = 76

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
    ATTR_PROMPT: 'Prompt',
}

# Map from name to id.
ATTR_NAMES = {v.lower(): k for k, v in ATTRS.items()}
# -------------------------------


class Error(Exception):
    """
    Base Error class.
    """

    pass


class NoResponse(Error):
    """
    Indicates no valid response received.
    """

    pass


class ChallengeResponse(Error):
    """
    Raised when radius replies with a challenge.

    Provides the message(s) if any, as well as the state (if provided).

    There can be 0+ messages. State and prompt are either defined or None.
    """
    def __init__(self, msg=None, state=None, prompt=None):
        if msg is None:
            self.messages = []
        elif isinstance(msg, list):
            self.messages = msg
        else:
            self.messages = [msg]
        self.state = state
        self.prompt = prompt


class SocketError(NoResponse):
    """
    Indicates general network error.
    """

    pass


PY3 = sys.version_info > (3, 0, 0)
if PY3:
    # These functions are used to act upon strings in Python2, but bytes in
    # Python3. Their functions are not necessary in PY3, so we NOOP them.
    def ord(s):
        return s

    def chr(s):
        return bytes([s])


def bytes_safe(s, e='utf-8'):
    try:
        return s.encode(e)
    except (AttributeError, UnicodeDecodeError):
        return s


def join(items):
    """
    Shortcut to join collection of strings.
    """
    return b''.join(items)


def authenticate(secret, username, password, host=None, port=None, **kwargs):
    """
    Authenticate the user against a radius server.

    Return True if the user successfully logged in and False if not.

    If the server replies with a challenge, a `ChallengeResponse` exception is
    raised with the challenge.

    Can raise either NoResponse or SocketError
    """
    # Pass host/port to the Radius instance. But ONLY if they are defined,
    # otherwise we allow Radius to use the defaults for the kwargs.
    rkwargs = {}
    if host:
        rkwargs['host'] = host
    if port:
        rkwargs['port'] = port
    # Additional kwargs (like attributes) are sent to Radius.authenticate().
    return Radius(secret, **rkwargs).authenticate(username, password, **kwargs)


def radcrypt(secret, authenticator, password):
    """Encrypt a password with the secret and authenticator."""
    # First, pad the password to multiple of 16 octets.
    password += b'\0' * (16 - (len(password) % 16))

    if len(password) > 128:
        raise ValueError('Password exceeds maximun of 128 bytes')

    result, last = b'', authenticator
    while password:
        # md5sum the shared secret with the authenticator,
        # after the first iteration, the authenticator is the previous
        # result of our encryption.
        hash = md5(secret + last).digest()
        for i in range(16):
            result += chr(ord(hash[i]) ^ ord(password[i]))
        # The next iteration will act upon the next 16 octets of the password
        # and the result of our xor operation above. We will set last to
        # the last 16 octets of our result (the xor we just completed). And
        # remove the first 16 octets from the password.
        last, password = result[-16:], password[16:]

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

    def __getkeys(self, value):
        """Return tuple of code, name for given code or name."""
        if isinstance(value, int):
            return value, ATTRS.get(value, None)

        else:
            id = ATTR_NAMES[value.lower()]
            return id, ATTRS[id]

    def __contains__(self, key):
        """
        Override in operator.
        """
        code = self.__getkeys(key)[0]
        return UserDict.__contains__(self, code)

    def __getitem__(self, key):
        """
        Retrieve an item from attributes (by name or id).
        """
        for k in self.__getkeys(key):
            try:
                return UserDict.__getitem__(self, k)
            except KeyError:
                continue
        raise KeyError(key)

    def __setitem__(self, key, value):
        """
        Add an item to attributes (by name or id)
        """
        try:
            code, name = self.__getkeys(key)

        except KeyError:
            raise ValueError('Unknown radius attribute: %s' % key)

        if name is None:
            LOGGER.warning('Unknown radius attribute code %s' % code)

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
        """
        Yields name value pairs as names (instead of ids).
        """
        for k, v in self.items():
            yield self.__getkeys(k)[1], v

    def pack(self):
        """
        Packs Attributes instance into data buffer.
        """
        data = []
        for key, values in self.items():
            for value in values:
                data.append(struct.pack('BB%ds' % len(value), key,
                                        len(value) + 2, bytes_safe(value)))
        return join(data)

    @staticmethod
    def unpack(data):
        """
        Unpacks data into Attributes instance.
        """
        pos, attrs = 0, {}
        while pos < len(data):
            code, length = struct.unpack('BB', data[pos:pos + 2])
            attrs[code] = data[pos + 2:pos + length]
            pos += length
        return Attributes(attrs)


class VerificationError(AssertionError):
    pass


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

    def __init__(self, secret, code, id=None, authenticator=None,
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
        data.append(struct.pack('!BBH16s', self.code, self.id,
                    len(attrs) + 20, self.authenticator))
        # Attributes take up the remainder of the message.
        data.append(attrs)
        return join(data)

    @staticmethod
    def unpack(secret, data):
        """Unpack the data into it's fields."""
        code, id, length, authenticator = struct.unpack('!BBH16s', data[:20])
        if length != len(data):
            LOGGER.warning('Too much data!')
        attrs = Attributes.unpack(data[20:length])
        return Message(secret, code, id, authenticator, attrs)

    def verify(self, data):
        """
        Verify and unpack a response.

        Ensures that a message is a valid response to this message, then
        unpacks it.
        """
        id = ord(data[1])
        if self.id != id:
            raise VerificationError('ID mismatch (%s != %s)' % (self.id, id))
        signature = md5(
            data[:4] + self.authenticator + data[20:] + self.secret).digest()
        if signature != data[4:20]:
            raise VerificationError('Invalid authenticator')
        return Message.unpack(self.secret, data)


class Radius(object):
    """
    Radius client implementation.
    """

    def __init__(self, secret, host='radius', port=DEFAULT_PORT,
                 retries=DEFAULT_RETRIES, timeout=DEFAULT_TIMEOUT):
        self._secret = bytes_safe(secret)
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

    def send_message(self, message):
        send = message.pack()

        addrs = socket.getaddrinfo(
            self.host,
            self.port,
            0,
            socket.SOCK_DGRAM,
        )

        @contextlib.contextmanager
        def connect(res):
            af, socktype, proto, canonname, sa = res
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                sock.settimeout(self.timeout)
                sock.connect(sa)
                yield sock
            finally:
                if sock is not None:
                    sock.close()

        def attempt(res):
            with connect(res) as c:
                c.send(send)
                recv = c.recv(PACKET_MAX)

                LOGGER.debug(
                    'Received (as hex): %s',
                    ':'.join(format(ord(c), '02x') for c in recv))

                return message.verify(recv)

        err = None
        LOGGER.debug(
            'Sending (as hex): %s',
            ':'.join(format(ord(c), '02x') for c in send))

        for i in range(self.retries):
            for res in addrs:
                try:
                    return attempt(res)
                except socket.timeout:
                    LOGGER.warning('Timeout expired on try %s', i)
                except VerificationError as e:
                    LOGGER.warning('Invalid response discarded %s', e)
                    # Silently discard invalid replies (as RFC states).
                except socket.error as e:
                    LOGGER.debug('Socket error', exc_info=True)
                    err = e

        if err is not None:
            raise SocketError(err)

        LOGGER.error('Request timed out after %s tries', i)
        raise NoResponse()

    def access_request_message(self, username, password, **kwargs):
        username = bytes_safe(username)
        password = bytes_safe(password)

        message = Message(self.secret, CODE_ACCESS_REQUEST, **kwargs)
        message.attributes['User-Name'] = username
        message.attributes['User-Password'] = \
            radcrypt(self.secret, message.authenticator, password)

        return message

    def authenticate(self, username, password, **kwargs):
        """
        Attempt to authenticate with the given username and password.

           Returns False on failure
           Returns True on success
           Raises a NoResponse (or its subclass SocketError) exception if no
               responses or no valid responses are received
        """
        reply = self.send_message(
            self.access_request_message(username, password, **kwargs))

        if reply.code == CODE_ACCESS_ACCEPT:
            LOGGER.info('Access accepted')
            return True

        elif reply.code == CODE_ACCESS_CHALLENGE:
            LOGGER.info('Access challenged')
            rkwargs = {}
            try:
                rkwargs['msg'] = reply.attributes['Reply-Message']
            except KeyError:
                pass
            try:
                rkwargs['state'] = reply.attributes['State'][0]
            except (KeyError, IndexError):
                pass
            try:
                prompt = reply.attributes['Prompt'][0]
            except KeyError:
                pass
            else:
                rkwargs['prompt'] = struct.unpack('!i', prompt)[0]

            raise ChallengeResponse(**rkwargs)

        LOGGER.info('Access rejected')
        return False


# Don't break code written for radius.py distributed with the ZRadius
# Zope product
RADIUS = Radius


def main():
    import sys
    import traceback

    host = raw_input("Host [default: 'radius']: ")
    port = raw_input('Port [default: %s]: ' % DEFAULT_PORT)

    host = host if host else 'radius'
    port = int(port) if port else DEFAULT_PORT

    secret = username = password = None

    while not secret:
        secret = raw_input('Enter RADIUS Secret: ')

    while not username:
        username = raw_input('Enter your username: ')

    while not password:
        password = raw_input('Enter your password: ')

    def _status(outcome):
        if outcome:
            print('Authentication Succeeded')
            sys.exit(0)
        else:
            sys.exit('Authentication Failed')
    err = None

    try:
        _status(authenticate(secret, username, password, host=host, port=port))
    except ChallengeResponse as e:
        err = e
    except Exception:
        traceback.print_exc()
        sys.exit('Authentication Error')

    print('RADIUS server replied with a challenge.')

    for m in getattr(err, 'messages', []):
        print(' - %s' % m)

    response = None
    while not response:
        response = raw_input('Enter your challenge response: ')

    state = getattr(err, 'state', None)
    a = Attributes({'State': state} if state else {})

    try:
        _status(authenticate(secret, username, response, host=host, port=port,
                attributes=a))
    except Exception:
        traceback.print_exc()
        sys.exit('Authentication Error')


if __name__ == '__main__':
    LOGGER.addHandler(logging.StreamHandler())
    LOGGER.setLevel(logging.DEBUG)

    main()
