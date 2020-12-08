import struct
import os
import socket
import sys
# host to listen

"""function to transform a binary to int"""


def binary_toint(binary):
    # change a binary into a an int
    number = int(binary, 2)
    return number


""" this function takes an array of integers and transform it to string of bits"""


def intarray_tobinary(array):
    # start with an empty string
    bits = ""
    # take each int from the array
    for i in range(len(array)):
        # transform the int into a binary
        string = str(bin(array[i]))[2:]
        # since we have each int is 16 bits we keep adding 0 at the beginning until its back to a 16 bit number
        while len(string) < 16:
            string = "0" + string
        # add up all the bits of the integers into 1 string of binary numbers
        bits = bits + string
    return bits


""" this function takes a string of bits and transform it into a string of chars """


def binary_tostring(bin):
    bin_data = bin
    # initializing a empty string for
    # storing the string data
    str_data = ''

    # slicing the input and converting it into 8 bits of ints
    # in decimal and then converting it in string
    for i in range(0, len(bin_data), 8):
        # and storing it in temp_data
        temp_data = bin_data[i:i + 8]

        # passing temp_data in binary_toint() function
        # to get decimal value of corresponding temp_data
        decimal_data = binary_toint(temp_data)

        # Deccoding the decimal value returned by
        # BinarytoDecimal() function, using chr()
        # function which return the string corresponding
        # character for given ASCII value, and store it
        # in str_data
        str_data = str_data + chr(decimal_data)
        # return the string
    return str_data


""""function takes the array of ints and print string"""


def printthemessage(array):
    # call the function on the array to change it to binary call the other function to change binary to string
    print("The secret message is:"+binary_tostring(intarray_tobinary(array)))
    return binary_tostring(intarray_tobinary(array))


def sniffing(host, win, socket_prot):
    dic = {}
    while True:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_prot)
        sniffer.bind((host, 0))
        # include the IP headers in the captured packets
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if win == 1:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        # read in a single packet
        raw_buffer = sniffer.recvfrom(65530)
        # save the parts of the packet containing the IP header in the IP_header variable
        ip_header = raw_buffer[0][0:20]
        # decode the header and assign each variable to its corresponding part
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        # Create our IP structure
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0xF) * 4
        TOS = iph[1]
        Total_Lengh = iph[2]
        Identification = iph[3]
        flag_offset = iph[4]
        flag = flag_offset >> 13
        offset = flag_offset & 0x1FFF
        ttl = iph[5]
        protocol = iph[6]
        checksum = iph[7]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        # check if the address is already in the dictionary
        if (s_addr, d_addr) in dic.keys():
            # if the packet contains TOS=6 and flag=6 and identification=0 close the connection and print the message
            # and delete the value from the dic
            if TOS == 6 and flag == 6 and Identification == 1:
                printthemessage(dic[(s_addr, d_addr)])
                del dic[(s_addr, d_addr)]
            # if the dic already contain the IP address and no termination for the connection is requested add the
            # data into the array of dic and print the packet that was accepted
            else:
                dic[(s_addr, d_addr)].append(Identification)
                print('IP -> Version:' + str(version) + ', Header Length:' + str(ihl) + \
                      ', TTL:' + str(ttl) + ', TOS ' + str(TOS) + ', Total length ' + str(
                    Total_Lengh) + ', Identification ' + str(Identification) + ', IP flag ' + str(
                    flag) + ', offset ' + str(
                    offset) + ', Protocol:' + str(
                    protocol) + ', checksum: ' + str(checksum) + ', Source:' \
                      + str(s_addr) + ', Destination:' + str(d_addr))
        # if the IP address of the sender isn't in the dictionary and flag=6 and Identification=0 and TOS=0 this means
        # that the sender wants to start a new message so add it to the dictionary
        elif s_addr not in dic.keys() and flag == 6 and Identification == 1 and TOS == 0:
            dic[(s_addr, d_addr)] = []
        # else this packet doesnt contain secret messages
        else:
            pass


def main(host):
    if os.name == 'nt':
        sniffing(host, 1, socket.IPPROTO_IP)
    else:
        sniffing(host, 0, socket.IPPROTO_ICMP)


if __name__ == '__main__':
    HOST = '192.168.1.7'
    main(HOST)
