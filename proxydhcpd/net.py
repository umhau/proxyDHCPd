import socket
import fcntl
import struct
import array
import platform

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def all_interfaces():

    arch = platform.architecture()[0]

    if arch == '32bit':
        magic1 = 32
        magic2 = 32
    elif arch == '64bit':
        magic1 = 16
        magic2 = 40
    else:
        raise OSError("Unknown architecture: %s" % arch)

    max_possible = 128
    bytes = max_possible * 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array.array('B', '\0' * bytes)
    outbytes = struct.unpack('iL', fcntl.ioctl(
        s.fileno(),
        0x8912,  # SIOCGIFCONF
        struct.pack('iL', bytes, names.buffer_info()[0])
    ))[0]
    namestr = names.tostring()
    return [namestr[i:i+magic1].split('\0', 1)[0] for i in range(0, outbytes, magic2)]

def get_dev_name(ipaddr):
    for netdev in all_interfaces():
        if get_ip_address(netdev) == ipaddr:
            return netdev
    raise OSError("Misconfigured IP address %s: IP Address not found." % ipaddr)