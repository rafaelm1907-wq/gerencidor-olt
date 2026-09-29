import unittest

from huawei_telnet import HuaweiTelnet


class FakeSocket:
    def __init__(self):
        self.responses = [b"OLT(config)#\r\n", b"OLT#\r\n", b"Are you sure to log out? (y/n)[n]:", b""]
        self.sent = []
        self.closed = False

    def settimeout(self, _): pass
    def sendall(self, value): self.sent.append(value.decode("utf-8"))
    def recv(self, _): return self.responses.pop(0)
    def close(self): self.closed = True


class GracefulLogoutTests(unittest.TestCase):
    def test_confirms_huawei_logout_before_closing_socket(self):
        client = HuaweiTelnet("10.0.0.1", "reader", "secret")
        client.socket = FakeSocket()
        sock = client.socket
        client.close()
        self.assertEqual(sock.sent, ["quit\r\n", "quit\r\n", "quit\r\n", "y\r\n"])
        self.assertTrue(sock.closed)
        self.assertIsNone(client.socket)


if __name__ == "__main__":
    unittest.main()
