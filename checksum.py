def checksum(address, data):
    # Load in content from the address file
    address = address.readline().strip()

    # split address into two
    source_ip_addr, dest_ip_addr = _addr_split(address)

    # load in content from the data file
    data = data.read()

    # Build IP pseudo header
    ip_pseudo_header = _build_ip_pseudo_header(
        source_ip_address=source_ip_addr,
        dest_ip_address=dest_ip_addr
    )

    return False


def _addr_split(address_pair: str):
    return address_pair.strip().split(sep=' ', maxsplit=1)


def _addr_to_bytestring(address: str) -> bytes:
    bytestring = b''

    # split address into array
    arr = _ip_split(address)

    for i in range(len(arr)):
        bytestring += int.to_bytes(arr[i],1, 'big')

    # This should always hold true based on how ip addresses are constructed
    assert len(bytestring) == 4

    return bytestring


def _ip_split(ip_address: str) -> [int]:
    return [int(part) for part in ip_address.split('.')]


def _build_ip_pseudo_header(source_ip_address: str, dest_ip_address: str) -> bytes:

    ip_pseudo_header = _addr_to_bytestring(source_ip_address)
    ip_pseudo_header += _addr_to_bytestring(dest_ip_address)

    return ip_pseudo_header


def _get_tcp_data_length(content: bytes):
    return len(content)


def _extract_checksum(tcp_header: bytes) -> int:
    return int.from_bytes(tcp_header[16:18], byteorder='big')