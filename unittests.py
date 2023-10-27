import unittest

from checksum import checksum


class TestCase(unittest.TestCase):

    def test_checksum_0(self):
        address = open('tcp_data/tcp_addrs_0.txt', 'r')
        data = open('tcp_data/tcp_data_0.dat', 'r')

        self.assertTrue(checksum(address, data))


if __name__ == '__main__':
    unittest.main()