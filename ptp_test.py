"""
This is a script for testing whether a switch fills the correction field in relevant PTPv2 messages.
The following combinations of message types and two-step clock should get the correction field filled:
|       TYPE       | 2-STEP |
| SYNC             | 0      |
| DELAY_RESP       | -      |
| FOLLOW_UP        | -      |
| PDELAY_RESP      | 0      |
| PDELAY_FOLLOW_UP | -      |
I.e. SYNC and PDELAY_RESP with TWO_STEP=1 can have zero correction.
You may need to run this program as root.
"""

from scapy.sendrecv import sendp, sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP

from enum import Enum
import fcntl
import select
import socket
import struct
import sys
import time


class PtpType(Enum):
    SYNC = 0
    DELAY_REQ = 1
    PDELAY_REQ = 2
    PDELAY_RESP = 3
    FOLLOW_UP = 8
    DELAY_RESP = 9
    PDELAY_FOLLOW_UP = 10
    ANNOUNCE = 11
    SIGNALLING = 12
    MANAGEMENT = 13
    ALL = 16


TYPES_TO_CHECK = (
    PtpType.SYNC,
    PtpType.PDELAY_REQ,
    PtpType.PDELAY_RESP,
    PtpType.FOLLOW_UP,
    PtpType.DELAY_REQ,
    PtpType.DELAY_RESP,
    PtpType.PDELAY_FOLLOW_UP,
)


STR_TO_TYPE = {}


for type in PtpType:
    STR_TO_TYPE[type.name] = type


def get_control_field(ptp_type):
    if ptp_type == PtpType.SYNC:
        return 0
    elif ptp_type == PtpType.DELAY_REQ:
        return 1
    elif ptp_type == PtpType.FOLLOW_UP:
        return 2
    elif ptp_type == PtpType.DELAY_RESP:
        return 3
    elif ptp_type == PtpType.MANAGEMENT:
        return 4
    else:
        return 5


# https://stackoverflow.com/a/4789267/1076564
def get_hw_addr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    s.close()
    return ':'.join('%02x' % b for b in info[18:24])

# https://stackoverflow.com/a/24196955/1076564
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', bytes(ifname[:15], 'utf-8'))
    )[20:24])
    s.close()
    return addr

def build_packet(ptp_type, two_step):

    # change this value if you use a different transportSpecific setting and want the other end to process the sent messages
    transport_specific = 0

    sequence_id = 100
    flags = 0

    payload = b''

    if ptp_type in (PtpType.DELAY_REQ, PtpType.DELAY_RESP, PtpType.PDELAY_REQ, PtpType.PDELAY_RESP, PtpType.PDELAY_FOLLOW_UP):
        payload += b'\x00\x00\x62\x27\x95\x61'  # receive stamp secs
        payload += b'\x30\x0f\xba\xac'  # receive stamp nsecs
        if ptp_type != PtpType.DELAY_REQ:
            payload += b'\x48\xb0\x2d\xff\xfe\x3c\x80\x5b'  # requesting source port identity
            payload += b'\x00\x01'  # requesting source port id
    elif ptp_type == PtpType.SYNC:
        payload += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # origin stamp
    elif ptp_type == PtpType.FOLLOW_UP:
        payload += b'\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00'  # origin stamp
        payload += b'\x00\x03\x00\x1c\x00\x80\xc2\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # TLV additional data

    if ptp_type in (PtpType.SYNC, PtpType.PDELAY_RESP):
        if two_step:
            flags += (1 << 9)

    payload_header = bytes([(transport_specific << 4) + ptp_type.value])  # transportSpecific and packet type
    payload_header += b'\x12'  # PTP version (2.1)
    payload_header += (34 + len(payload)).to_bytes(2, "big")  # packet length
    payload_header += b'\x00\x00'  # domain
    payload_header += flags.to_bytes(2, "big")  # flags
    payload_header += b'\x00\x00\x00\x00\x00\x00\x00\x00'  # correction
    payload_header += b'\x00\x00\x00\x00'
    payload_header += b'\x1c\x69\x7a\xff\xfe\xa4\x34\x7e'  # clock identity
    payload_header += b'\x00\x01'  # sourcePortID
    payload_header += sequence_id.to_bytes(2, "big")  # sequenceId
    payload_header += bytes([get_control_field(ptp_type)])  # deprecated (V1) packet type
    payload_header += b'\x00'  # log message period

    return payload_header + payload


usage = "Usage: python3 ptp_test.py send INTERFACE_NAME PACKET_TYPE [TWO_STEP]\n" \
        "   or: python3 ptp_test.py receive INTERFACE_NAME\n" \
        "   or: python3 ptp_test.py send4 INTERFACE_NAME PACKET_TYPE [TWO_STEP]\n" \
        "   or: python3 ptp_test.py receive4 INTERFACE_NAME\n" \
        "PACKET_TYPE = [ SYNC | FOLLOW_UP | DELAY_RESP | PDELAY_RESP | PDELAY_FOLLOW_UP | ALL ]\n" \
        "  ALL will send a set of all known packets\n" \
        "TWO_STEP = [ 0 | 1 ] (only affects SYNC and PDELAY_RESP messages)"

if len(sys.argv) < 3:
    print(usage, file=sys.stderr)
    sys.exit(1)

send = sys.argv[1].lower().startswith("send")
udp = sys.argv[1][-1] == "4"

ifname = sys.argv[2]
ptp_type = PtpType.DELAY_RESP
two_step = False  # can be turned on for SYNC packets

bcast_mac = "01:80:c2:00:00:0e"
mcast_grp = "224.0.1.129"
mac_addr = get_hw_addr(ifname)
ip_addr = get_ip_address(ifname)

def get_mcast_port(type):
    if type in (PtpType.SYNC, PtpType.DELAY_REQ, PtpType.PDELAY_REQ, PtpType.PDELAY_RESP):
        return 319
    return 320

if send:
    if len(sys.argv) < 4 or (sys.argv[3] != "ALL" and STR_TO_TYPE[sys.argv[3]] not in TYPES_TO_CHECK):
        print(usage, file=sys.stderr)
        sys.exit(1)

    ptp_type = STR_TO_TYPE[sys.argv[3]]

    if ptp_type in (PtpType.SYNC, PtpType.PDELAY_RESP) and len(sys.argv) > 4:
        two_step = bool(int(sys.argv[4]))

if send:
    if udp:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 3)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip_addr))
    packets = []
    for type in TYPES_TO_CHECK:
        if type == ptp_type or ptp_type == PtpType.ALL:
            if udp:
                packets.append((build_packet(type, two_step), (mcast_grp, get_mcast_port(type))))
                if ptp_type == PtpType.ALL and type in (PtpType.SYNC, PtpType.PDELAY_RESP):
                    packets.append((build_packet(type, True), (mcast_grp, get_mcast_port(type))))
            else:
                x = Ether(src=mac_addr, dst=bcast_mac, type=0x88f7) / build_packet(type, two_step)
                packets.append(x)
                if ptp_type == PtpType.ALL and type in (PtpType.SYNC, PtpType.PDELAY_RESP):
                    x = Ether(src=mac_addr, dst=bcast_mac, type=0x88f7) / build_packet(type, True)
                    packets.append(x)
    if udp:
        for packet in packets:
            print(packet)
            sock.sendto(*packet)
            time.sleep(0.1)
    else:
        sendp(packets, ifname)
else:
    def print_packet(pkt):
        data = bytes(pkt.payload)
        print_payload(data)
    def print_packet4(pkt):
        data = bytes(pkt.getlayer(UDP).payload)
        print_payload(data)
    def print_payload(data):
        correction_int = int.from_bytes(data[8:16], "big", signed=True)
        correction = correction_int / (1 << 16)
        type = PtpType(data[0] & 0x0F)
        flags = int.from_bytes(data[6:8], "big", signed=False)
        two_step = flags & (1 << 9)
        ok = "OK"
        if correction_int == 0 and not (type in (PtpType.SYNC, PtpType.PDELAY_RESP) and two_step):
            ok = "WRONG"
        print("Type %18s, correction %10.4f ns, %s, %s" % (type.name, correction, "Two step" if two_step else "One step", ok))

    if udp:
        pkts = sniff(count=0, filter="udp and (port 319 or port 320)", iface=ifname, prn=print_packet4)
    else:
        pkts = sniff(count=0, filter="ether proto 0x88f7", iface=ifname, prn=print_packet)