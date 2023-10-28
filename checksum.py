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

    calculated_checksum = _calculate_checksum(header=ip_pseudo_header, tcp_data=data)

    match = provided_checksum == calculated_checksum
    print(str(match).upper())
    return match


def _addr_split(address_pair: str):
    return address_pair.strip().split(sep=' ', maxsplit=1)


def _addr_to_bytestring(address: str) -> bytes:
    byte_parts = [int.to_bytes(int(part), 1, 'big') for part in address.split('.')]

    return b''.join(byte_parts)


# def _ip_split(ip_address: str) -> [int]:
#     return [int(part) for part in ip_address.split('.')]


def _build_ip_pseudo_header(source_ip_address: str, dest_ip_address: str, tcp_data_length: int) -> bytes:
    ip_pseudo_header = b''.join(
        [
            _addr_to_bytestring(source_ip_address),
            _addr_to_bytestring(dest_ip_address),
            b'\x00\x06',
            tcp_data_length.to_bytes(2, 'big')
        ]
    )

    return ip_pseudo_header


def _get_tcp_data_length(content: bytes):
    return len(content)


def _extract_checksum(tcp_header: bytes) -> int:
    return int.from_bytes(tcp_header[16:18], byteorder='big')


def _reset_checksum(tcp_data: bytes) -> bytes:
    zeroed_header = tcp_data[:16] + b'\x00\x00' + tcp_data[18:]

    return zeroed_header


def _equalize_length(tcp_data: bytes) -> bytes:
    if len(tcp_data) % 2 == 1:
        tcp_data += b'\x00'

    return tcp_data


def _calculate_checksum(header, tcp_data):
    tcp_data = _reset_checksum(tcp_data)
    tcp_data = _equalize_length(tcp_data)

    data = header + tcp_data

    total = 0
    offset = 0

    while offset < len(data):
        word = int.from_bytes(data[offset:offset + 2], 'big')
        total += word

        total = (total & 0xffff) + (total >> 16)
        offset += 2

    return (~total) & 0xffff


if __name__ == '__main__':
    for i in range(10):
        addr_path = f'tcp_data/tcp_addrs_{i}.txt'
        data_path = f'tcp_data/tcp_data_{i}.dat'

        with open(addr_path, 'r') as address, open(data_path, 'rb') as data:
            checksum(address=address, data=data)