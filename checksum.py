def checksum(address, data):
    # Load in content from the address file
    address = address.readline().strip()

    # split address into two
    source_ip_addr, dest_ip_addr = _addr_split(address)

    # convert addresses to byte strings
    source_ip_addr = source_ip_addr.encode()
    dest_ip_addr = dest_ip_addr.encode()

    # load in content from the data file
    data = data.read()

    # Build IP psuedo header
    ip_psuedo_header = {
        'source_addr': source_ip_addr,
        'dest_addr': dest_ip_addr
    }

    return False


def _addr_split(address_pair: str):
    return address_pair.split(sep=' ', maxsplit=1)


def _addr_to_bytestring(address: str) -> bytes:
    bytestring = b''

    # split address into array
    arr = _ip_split(address)

    return bytestring


def _ip_split(ip_address: str) -> [int]:
    return [int(part) for part in ip_address.split('.')]


checksum(open('tcp_data/tcp_addrs_0.txt', 'r'), open('tcp_data/tcp_data_0.dat', 'rb'))
