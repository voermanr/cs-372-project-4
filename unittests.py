import os
import unittest

import checksum


class TestChecksum(unittest.TestCase):

    # All this to avoid a magic number.
    EXPECTED_OUTCOMES = {
        0: True,
        1: True,
        2: True,
        3: True,
        4: True,
        5: False,
        6: False,
        7: False,
        8: False,
        9: False,
    }

    def _test_file_pair(self, i):
        # This is the big pass or fail test, but not the string printing logic

        a = f'tcp_data/tcp_addrs_{i}.txt'
        d = f'tcp_data/tcp_data_{i}.dat'

        with open(a, 'r') as address, open(d, 'rb') as data:

            self.assertEqual(
                checksum.checksum(address=address, data=data),
                self.EXPECTED_OUTCOMES[i],

                f"Failed for file pair {i}. Expected {self.EXPECTED_OUTCOMES[i]}"
            )

    def test_file_pair_0(self):
        self._test_file_pair(0)

    def test_file_pair_1(self):
        self._test_file_pair(1)

    def test_file_pair_2(self):
        self._test_file_pair(2)

    def test_file_pair_3(self):
        self._test_file_pair(3)

    def test_file_pair_4(self):
        self._test_file_pair(4)

    def test_file_pair_5(self):
        self._test_file_pair(5)

    def test_file_pair_6(self):
        self._test_file_pair(6)

    def test_file_pair_7(self):
        self._test_file_pair(7)

    def test_file_pair_8(self):
        self._test_file_pair(8)

    def test_file_pair_9(self):
        self._test_file_pair(9)


class TestAddressSplit(unittest.TestCase):

    # The path to the file we're going to set up and tear down
    TEST_FILE_PATH = 'tcp_data/tcp_addrs_test.txt'

    def setUp(self):
        # Set up the test file with sample content
        with open(self.TEST_FILE_PATH, 'w') as f:
            f.write('192.0.2.1 198.51.100.1')

    def tearDown(self):
        # Clean up: remove the test file to ensure no side effects
        if os.path.exists(self.TEST_FILE_PATH):
            os.remove(self.TEST_FILE_PATH)

    # Now you can write your test methods to use the created file
    def test_addr_split(self):
        with open(self.TEST_FILE_PATH, 'r') as f:
            content = f.read()

            src_addr, dest_addr = checksum._addr_split(content)

            self.assertEqual(src_addr, '192.0.2.1')
            self.assertEqual(dest_addr, '198.51.100.1')


class TestAddrByteConversion(unittest.TestCase):

    def test_addr_to_bytestring(self):
        address = '1.2.3.4'

        self.assertEqual(
            checksum._addr_to_bytestring(address=address),
            b'\x01\x02\x03\x04',
        )

    def test_ip_addr_split(self):
        address = '1.2.3.4'
        expected_return = [1, 2, 3, 4]

        self.assertEqual(checksum._ip_split(address), expected_return)


if __name__ == '__main__':
    unittest.main()
