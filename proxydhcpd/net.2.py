import socket
import fcntl
import struct
import array

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def all_interfaces():
    max_possible = 128
    bytes = max_possible * 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array.array('B', '\0' * bytes)
    # print names
    outbytes = struct.unpack('iL', fcntl.ioctl(
        s.fileno(),
        0x8912,  # SIOCGIFCONF
        struct.pack('iL', bytes, names.buffer_info()[0])
    ))[0]
    print outbytes
    print names
    namestr = names.tostring()
    print namestr 
    print [namestr[i:i+32].split('\0', 1)[0] for i in range(0, outbytes, 32)]
    return [namestr[i:i+32].split('\0', 1)[0] for i in range(0, outbytes, 32)]

def get_dev_name(ipaddr):
    for netdev in all_interfaces():
        if get_ip_address(netdev) == ipaddr:
            return netdev

print all_interfaces()