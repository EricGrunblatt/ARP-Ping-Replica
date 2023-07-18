import sys, dpkt, ipaddress

# Prints all contents from arpArr
def print_contents(arpArr):
    opcodeString = ''

    # Loop through exchanges (even number == reply, otherwise response)
    for i in range(0, len(arpArr)): 
        if i == 0:
            print("------ ARP EXCHANGE START ------\n")
            print("ARP REQUEST:")
            opcodeString = 'Request'
        else: 
            print("ARP RESPONSE:") 
            opcodeString = 'Response'   

        # Print contents of reply or response
        print("Hardware type: ", arpArr[i][0])
        print("Protocol type: ", arpArr[i][1])
        print("Hardware size: ", arpArr[i][2])
        print("Protocol size: ", arpArr[i][3])
        print("Opcode: %s (%s)" % (opcodeString, arpArr[i][4]))
        print("Sender MAC address: ", arpArr[i][5])
        print("Sender IP address: ", arpArr[i][6])
        print("Target MAC address: ", arpArr[i][7])
        print("Target IP address: %s\n" % arpArr[i][8])

        if not(i == 0 or i % 2 == 0): 
            print("------ ARP EXCHANGE END ------\n")
            return

# Creates an array of pcap file elements to be printed 
def analyze_pcap(pcapFileRead):

    # Make array for arp packets to be sent to print_contents function
    arpArr = []

    # Loop through each packet found in the file
    for ts, pkt in pcapFileRead:

        etherType = int.from_bytes(pkt[12:14], byteorder='big')


        # Make sure EtherType is 0x0806 (used to identify ARP frames) in hexadecimal
        if etherType == 0x0806:

            # Extract all data from packets
            # hType, pType, hLen, pLen, oper, sMac, sIP, dMac, dIP = struct.unpack('!HHBBH6sL6sL', pkt[14:42])
            hType = int.from_bytes(pkt[14:16], byteorder='big')
            pType = int.from_bytes(pkt[16:18], byteorder='big')
            hLen = int.from_bytes(pkt[18:19], byteorder='big')
            pLen = int.from_bytes(pkt[19:20], byteorder='big')
            oper = int.from_bytes(pkt[20:22], byteorder='big')
            sMac = pkt[22:28]
            sIP = int.from_bytes(pkt[28:32], byteorder='big')
            dMac = pkt[32:38]
            dIP = int.from_bytes(pkt[38:42], byteorder='big')
            
            # Clean up mac addresses and ip addresses
            pType = hex(pType)
            sMac = sMac.hex()
            dMac = dMac.hex()
            sMac = ':'.join(map('{}{}'.format, *(sMac[::2], sMac[1::2])))
            dMac = ':'.join(map('{}{}'.format, *(dMac[::2], dMac[1::2])))
            sIP = ipaddress.ip_address(sIP)
            dIP = ipaddress.ip_address(dIP)
            arpArr.append([hType, pType, hLen, pLen, oper, sMac, sIP, dMac, dIP])

    printArr = []
    for i in range(0, len(arpArr)):
        for j in range(1, len(arpArr)):
            if i != j and arpArr[i][4] == 1 and arpArr[j][4] == 2:
                if arpArr[i][6] == arpArr[j][8] and arpArr[i][5] == arpArr[j][7]:
                    printArr.append(arpArr[i])
                    printArr.append(arpArr[j])
                    break

    if len(printArr) == 0:
        print("There is no ARP exchange available")
        exit(-1)
    print_contents(printArr)

# Takes in pcap file argument and tries to open it. If successful, analyze it, otherwise exit
if __name__ == '__main__':

    # Make sure there were at least two arguments
    if len(sys.argv) < 2:
        print("Please make sure to follow the format: python analysis_pcap_arp.py [pcap file]")
        exit(-1)
    
    # Try opening pcap file, exit if invalid
    try:
        fileReader = dpkt.pcap.Reader(open(sys.argv[1], 'rb'))
    except:
        print("PCAP file is invalid")
        exit(-1)
    
    # Analyze the pcap file
    analyze_pcap(fileReader)