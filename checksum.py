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
        dest_ip_address=dest_ip_addr,
        tcp_data_length=_get_tcp_data_length(data)
    )

    provided_checksum = _extract_checksum(data)

    calculated_checksum = 0

    return provided_checksum == calculated_checksum


def _addr_split(address_pair: str):
    return address_pair.strip().split(sep=' ', maxsplit=1)


def _addr_to_bytestring(address: str) -> bytes:
    byte_parts = [int.to_bytes(int(part), 1, 'big') for part in address.split('.')]

    return b''.join(byte_parts)


def _ip_split(ip_address: str) -> [int]:
    return [int(part) for part in ip_address.split('.')]


def _build_ip_pseudo_header(source_ip_address: str, dest_ip_address: str, tcp_data_length: int) -> bytes:

    ip_pseudo_header = b''.join(
        [
        _addr_to_bytestring(source_ip_address),
        _addr_to_bytestring(dest_ip_address),
        b'\x00\x06',
        tcp_data_length.to_bytes(1,'big')
        ]
    )

    return ip_pseudo_header


def _get_tcp_data_length(content: bytes):
    return len(content)


def _extract_checksum(tcp_header: bytes) -> int:
    return int.from_bytes(tcp_header[16:18], byteorder='big')


def _reset_checksum(tcp_header: bytes) -> bytes:
    zeroed_header = tcp_header[:16] + b'\x00\x00' + tcp_header[18:]

    return zeroed_header
