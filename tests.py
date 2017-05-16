import unittest
import radius


TEST_SECRET = 's3cr3t'
TEST_HOST = 'localhost'
TEST_PORT = 1812


class AttributesTestCase(unittest.TestCase):
    def test_set_get_item(self):
        a = radius.Attributes()

        # Cannot use invalid radius codes or names.
        with self.assertRaises(ValueError):
            a[128] = 'bar'
        with self.assertRaises(ValueError):
            a['foo'] = 'bar'

        a['User-Name'] = 'foobar'
        self.assertEqual('foobar', a[radius.ATTR_USER_NAME])

    def test_init_update(self):
        with self.assertRaises(ValueError):
            a = radius.Attributes({'foo': 'bar'})

        a = radius.Attributes({'User-Name': 'foobar'})
        self.assertEqual('foobar', a['User-Name'])

        with self.assertRaises(ValueError):
            a.update({'foo': 'bar'})

        a.update({'User-Password': 'raboof'})
        self.assertEqual('foobar', a['User-Name'])
        self.assertEqual('raboof', a['User-Password'])

    def test_un_pack(self):
        a = radius.Attributes()
        a['User-Name'] = 'foobar'
        a['User-Password'] = 'raboof'
        data = a.pack()
        self.assertEqual(16, len(data))
        b = radius.Attributes.unpack(data)
        self.assertEqual(2, len(b))
        self.assertEqual('foobar', b['User-Name'])
        self.assertEqual('raboof', b['User-Password'])


class MessageTestCase(unittest.TestCase):
    def test_message(self):
        m = radius.Message(radius.CODE_ACCESS_REQUEST, TEST_SECRET,
                           attributes={})
        self.assertLess(0, m.id)
        self.assertGreater(256, m.id)
        self.assertEqual(16, len(m.authenticator))
        self.assertIsInstance(m.attributes, radius.Attributes)


class RadcryptTestCase(unittest.TestCase):
    """
      On transmission, the password is hidden.  The password is first
      padded at the end with nulls to a multiple of 16 octets.  A one-
      way MD5 hash is calculated over a stream of octets consisting of
      the shared secret followed by the Request Authenticator.  This
      value is XORed with the first 16 octet segment of the password and
      placed in the first 16 octets of the String field of the User-
      Password Attribute.

      If the password is longer than 16 characters, a second one-way MD5
      hash is calculated over a stream of octets consisting of the
      shared secret followed by the result of the first xor.  That hash
      is XORed with the second 16 octet segment of the password and
      placed in the second 16 octets of the String field of the User-
      Password Attribute.

      If necessary, this operation is repeated, with each xor result
      being used along with the shared secret to generate the next hash
      to xor the next segment of the password, to no more than 128
      characters.

      The method is taken from the book "Network Security" by Kaufman,
      Perlman and Speciner [9] pages 109-110.  A more precise
      explanation of the method follows:

      Call the shared secret S and the pseudo-random 128-bit Request
      Authenticator RA.  Break the password into 16-octet chunks p1, p2,
      etc.  with the last one padded at the end with nulls to a 16-octet
      boundary.  Call the ciphertext blocks c(1), c(2), etc.  We'll need
      intermediate values b1, b2, etc.

         b1 = MD5(S + RA)       c(1) = p1 xor b1
         b2 = MD5(S + c(1))     c(2) = p2 xor b2
                .                       .
                .                       .
                .                       .
         bi = MD5(S + c(i-1))   c(i) = pi xor bi

      The String will contain c(1)+c(2)+...+c(i) where + denotes
      concatenation.
    """
    def setUp(self):
        self.authenticator = '\xa0\xdb7\xe2\x1f1\x18-op\xff>&A\xb0g'

    def test_radcrypt_small(self):
        'Test a password shorter than 16 octets.'
        SMALL_PASS = 'I3Zl@"42Xs%^[nk'
        SMALL_CRYPT = '\xdc\xf7V\x82\xeb\xa8Zm\x1b\x92\xb3\xa3\x06\x02\xbc\x16'
        c = radius.radcrypt(TEST_SECRET, self.authenticator, SMALL_PASS)
        self.assertEqual(c, SMALL_CRYPT)

    def test_radcrypt_large(self):
        'Test a password longer than 16 octets.'
        LARGE_PASS = '`0T8/Ub\tojdP;\rc:L}#_hOF'
        LARGE_CRYPT = '\xf5\xf4X\xd6\x84\xdf\x0cV,\x8b\xf2\xadfa\xb4,S\xef\x0f\x908\xfcH\x9a\xe9r\xcc\xd0\x07\x84\xdc\x98'
        c = radius.radcrypt(TEST_SECRET, self.authenticator, LARGE_PASS)
        self.assertEqual(c, LARGE_CRYPT)


if __name__ == '__main__':
    unittest.main()
