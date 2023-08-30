import unittest

from devca import *
from tempfile import TemporaryDirectory
import os


class DevCaTest(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.ctx = DevCa(self.directory.name)

    def test_create_keystore(self):
        self.ctx.create_keystore("ca")
        self.assertEqual(self.ctx.list_keystores(), ["ca"])

    def test_create_keystore_with_validity(self):
        self.ctx.create_keystore("ca", validity=timedelta(seconds=1))
        self.assertEqual(self.ctx.list_keystores(), ["ca"])

    def test_create_keystore_with_validity_days(self):
        self.ctx.create_keystore("ca", validity=timedelta(days=5, seconds=8555))
        self.assertEqual(self.ctx.list_keystores(), ["ca"])

    def test_sign_keystore(self):
        self.ctx.create_keystore("ca")
        self.ctx.create_keystore("server")
        self.ctx.sign_keystore("server", "ca")

    def test_create_truststore(self):
        self.ctx.create_keystore("ca")
        self.ctx.create_keystore("ca2")
        self.ctx.create_truststore("client.truststore", ["ca", "ca2"])
        self.assertCountEqual(self.ctx.list_keystores(), ["ca", "ca2", "client.truststore"])

    def test_remove_keystore(self):
        self.ctx.create_keystore("ca")
        self.ctx.create_keystore("ca2")
        self.ctx.remove_keystore("ca2")
        self.assertEqual(self.ctx.list_keystores(), ["ca"])

    def tearDown(self) -> None:
        del self.directory


if __name__ == '__main__':
    unittest.main()
