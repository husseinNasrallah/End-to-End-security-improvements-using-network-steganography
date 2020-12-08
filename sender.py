import socket
import struct
import binascii
from time import sleep
import sys

"""function to transform the string to string of binary"""


def string_tobinary(str):
    res = ""
    # convert every char in the string
    for i in str:
        # change every char into an 8 bit binary number and add them together
        x = format(ord(i), 'b')
        # since some of the strings arent 8 bits change them to 8 bits by adding 0 on the left side until they are of
        # length 8
        while len(x) < 8:
            x = "0" + x
        # add all the binaries in 1 string
        res = res + x
    return res


"""function to transform a binary to int"""


def binary_toint(binary):
    # change a binary into a an int
    number = int(binary, 2)
    return number


"""function to transform string into an array of 16bits integers to send them in packets"""


def fragmentingthebits(string):
    bits = string_tobinary(string)
    convertedbits = []
    str = ""
    counter = 0
    nummberofints = 0
    # since we can only send a 16 bit per packet we want a 16 bit integers so we pack each 16 bits together and
    # transform them into integers
    while nummberofints < len(bits) // 16:
        str = str + bits[counter]
        counter = counter + 1
        # stack every 16 bits and transform them into strings and add them to the array
        if len(str) == 16:
            convertedbits.append(binary_toint(str))
            str = ""
            nummberofints = nummberofints + 1
    # if the string of bits isnt a multiple of 16 add the last 8 bits as an integer of its own and add it to the array
    if len(bits) % 16 != 0:
        str = bits[counter:]
        convertedbits.append(binary_toint(str))
    return convertedbits


class PktGen():
    def __init__(self):
        # 16 Hexadecimal payload, you can customize more fields
        self.payload_hex = ""

    def send_packet(self, src_ip, dst_ip, dst_port, code, tos=0, flag=2):
        # Use raw sockets for packet sending
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 255)
        s.setsockopt(0, socket.IP_HDRINCL, 1)
        # Bind a specific IP network card, if you comment out this sentence, use the default network card
        s.bind((src_ip, 55566))

        # now start constructing the packet
        source_ip = src_ip
        dest_ip = dst_ip

        # ip header fields
        ihl = 5  # shaorted IP pkt
        version = 4  # ipv4
        tos = tos  # no special priority
        tot_len = 0  # total length /kernel will fill this
        id = code
        flag = flag
        frag_off = 0
        ttl = 255
        protocol = 153  # protocol number /seanet is 99
        check = 0
        saddr = socket.inet_aton(source_ip)  # Spoof the source ip address if you want to
        daddr = socket.inet_aton(dest_ip)
        ihl_version = (version << 4) + ihl
        flag_offset = (flag << 13) + frag_off

        # the ! in the pack format string means network order
        # first parameter is formate
        # B is 8, H is 16
        ip_header = struct.pack('!BBHHHBBH4s4s', ihl_version, tos, tot_len, id,
                                flag_offset, ttl, protocol, check, saddr, daddr)

        # print the sent header
        print("("+str(ihl_version)+", "+str(tos)+", "+str(tot_len)+", "+str(id)+", "+str(frag_off)+", "+str(ttl)+", "+str(protocol)+", "+str(check)+", "+str(src_ip)+", "+str(dst_ip)+")")

        # Base 2
        payload_bin = binascii.a2b_hex(self.payload_hex)

        # concatenate the payload with the header if wanted
        packet = ip_header + payload_bin

        # Send the data packet to the host whose ip is dst_ip and port number is dst_port
        s.sendto(packet, (dst_ip, dst_port))


"""function to take a string then encode it into the headers of multiple packet and send these packets"""


def sendthestringencoded(string):
    data = fragmentingthebits(string)
    # send a packet to initialize the connection
    pkt.send_packet(src_ip, dst_ip, dst_port, 1, 0, 6)
    print("The initialization packet has been sent")
    # send packets to containing the data in the identification header
    for i in range(len(data)):
        pkt.send_packet(src_ip, dst_ip, dst_port, data[i])
        print("The packet of number " + str(i + 1) + "has been sent")
        sleep(0.5)
    # send a packet to terminate the connection
    pkt.send_packet(src_ip, dst_ip, dst_port, 1, 6, 6)
    print("The connection has been terminated")


# the src_ip and dst_ip should be the host ip
if __name__ == '__main__':
    pkt = PktGen()
    src_ip = "192.168.1.7"
    dst_ip = "192.168.1.7"
    dst_port = 0
    string = "This project deserve 100/100"
    sendthestringencoded(string)

