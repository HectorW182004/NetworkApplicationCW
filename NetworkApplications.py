#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback
import threading
# NOTE: Do NOT import other libraries!

UDP_CODE = socket.IPPROTO_UDP
ICMP_ECHO_REQUEST = 8
MAX_DATA_RECV = 65535
MAX_TTL = 30

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.231.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=2, count=10)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=2, protocol='udp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_m = subparsers.add_parser('mtroute', aliases=['mt'],
                                         help='run traceroute')
        parser_m.set_defaults(timeout=2, protocol='udp')
        parser_m.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_m.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_m.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_m.set_defaults(func=MultiThreadedTraceRoute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        if len(sys.argv) < 2:
            parser.print_help()
            sys.exit(1)

        args = parser.parse_args()

        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: bytes) -> int: 
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    # Print Ping output
    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, seq: int, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationHostname, destinationAddress, seq, ttl, time))
        else:
            print("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationAddress, seq, ttl, time))

    def printAdditionalDetails(self, host, numPacketsTransmitted, rtts):
        if len(rtts) > 0:
            print(f'--- {host} ping statistics ---')
            lossPercent = int((100.0 - 100.0*(len(rtts)/numPacketsTransmitted)))
            print(f'{numPacketsTransmitted} packets transmitted, {len(rtts)} received, {lossPercent}% packet loss')
            avgRTT = sum(rtts) / len(rtts)
            deviations = [abs(rtt - avgRTT) for rtt in rtts]
            mdev = sum(deviations) / len(deviations)
            minRTT = min(rtts)
            maxRTT = max(rtts)
            print("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms" % (1000*minRTT, 1000*avgRTT, 1000*maxRTT, 1000*mdev))

    # Print one line of traceroute output
    def printMultipleResults(self, ttl: int, pkt_keys: list, hop_addrs: dict, rtts: dict, destinationHostname = ''):
        if pkt_keys is None:
            print(str(ttl) + '   * * *')
            return
        # Sort packet keys (sequence numbers or UDP ports)
        pkt_keys = sorted(pkt_keys)
        output = str(ttl) + '   '
        last_hop_addr = None
        last_hop_name = None

        for pkt_key in pkt_keys:
            # If packet key is missing in hop addresses, this means no response received: print '*'
            if pkt_key not in hop_addrs.keys():
                output += '* '
                continue
            hop_addr = hop_addrs[pkt_key]

            # Get the RTT for the probe
            rtt = rtts[pkt_key]
            if last_hop_addr is None or hop_addr != last_hop_addr:
                hostName = None
                try:
                    # Get the hostname for the hop
                    hostName = socket.gethostbyaddr(hop_addr)[0]
                    if last_hop_addr is None:
                        output += hostName + ' '
                    else: 
                        output += ' ' + hostName + ' '
                except socket.herror:
                    output += hop_addr + ' '
                last_hop_addr = hop_addr
                last_hop_name = hostName
                output += '(' + hop_addr + ') '

            output += str(round(1000*rtt, 3))
            output += ' ms  '
                
        print(output)           

class ICMPPing(NetworkApplication):
    
    def __init__(self, args):
        host = None
        # 1. Look up hostname, resolving it to an IP address
        try:
            host = socket.gethostbyname(args.hostname)
        except socket.gaierror:
            print('Invalid hostname: ', args.hostname) 
            return

        print('Ping to: %s (%s)...' % (args.hostname, host))

        # 1. Create an ICMP socket 
        try:
            self.icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as err:
            traceback.print_exception(err)
            exit(1)

        # 2. Set a timeout on the socket
        self.icmpSocket.settimeout(args.timeout)

        # 3. Send ping probes and collect responses 
        numPings = args.count
        seq_num = 0
        numPingsSent = numPings
        rtts = [] 
        while(numPings > 0):

            # 4. Do one ping approximately every second
            rtt, ttl, packetSize, seq = self.doOnePing(host, args.timeout, seq_num)

            # 5. Print out the RTT (and other relevant details) using the printOneResult method
            if rtt is not None:
                self.printOneResult(host, packetSize, rtt*1000, seq, ttl) 
                rtts.append(rtt)

            # 6. Sleep for a second
            time.sleep(1) 

            # 7. Update sequence number and number of pings
            seq_num += 1
            numPings -= 1

        # 8. Print loss and RTT statistics (average, max, min, etc.)
        self.printAdditionalDetails(args.hostname, numPingsSent, rtts)
        
        # 9. Close ICMP socket
        self.icmpSocket.close()

    # Receive Echo ping reply
    def receiveOnePing(self, destinationAddress, packetID, sequenceNumSent, timeout):
        
        # 1. Wait for the socket to receive a reply
        echoReplyPacket = None
        isTimedout = False
        try:
            echoReplyPacket, addr = self.icmpSocket.recvfrom(MAX_DATA_RECV)
        except socket.timeout as e:
            isTimedout = True

        # 2. Once received, record time of receipt, otherwise, handle a timeout
        timeRecvd = time.time()
        if isTimedout: # timeout
            return None, None, None, None

        # 3. Extract the IP header: 

        # The first 20 bytes is the IP header:  
        # (see: https://en.wikipedia.org/wiki/IPv4#/media/File:IPv4_Packet-en.svg):
        # 0          4             8          16          24           32 bits
        # |  Version | IP Hdr  Len |     TOS   |      Total Length     |
        # |         Identification             |Flag |  Fragment offset|
        # |        TTL             |  Protocol |     Header Checksum   |
        # |           Source IP  Address(32 bits, i.e., 4 bytes)       |
        # |           Destination IP Address (32 bits, i.e., 4 bytes)  |
        # |     Option (up to 40 bytes) this is an optional field      |

        ip_header = echoReplyPacket[:20]
        version_ihl, tos, total_length, identification, flags_offset, ttl, proto, checksum, src_ip, dest_ip = struct.unpack('!BBHHHBBH4s4s', ip_header)

        # Read the IP Header Length (using bit masking) 
        ip_header_len_field = (version_ihl & 0x0F)

        # This field contains the length of the IP header in terms of 
        # the number of 4-byte words. So value 5 indicates 5*4 = 20 bytes. 
        ip_header_len = ip_header_len_field * 4

        payloadSize = total_length - ip_header_len

        # Now parse the ICMP header:
        # 0         8           16         24          32 bits
        #     Type  |    Code   |       Checksum       |
        #     Packet Identifier |       Sequence num   |
        #        <Optional timestamp (8 bytes) for     |
        #        a stateless ping>                     |        
        icmpHeader = echoReplyPacket[ip_header_len:ip_header_len + 8]
        icmpType, code, checksum, p_id, sequenceNumReceived = struct.unpack('!BBHHH', icmpHeader)

        # 5. Check that the ID and sequence numbers match between the request and reply
        if packetID != p_id or sequenceNumReceived != sequenceNumSent:
            return None, None, None, None

        # 6. Return the time of Receipt
        return timeRecvd, ttl, payloadSize, sequenceNumReceived

    # NOTE: This method can be re-used by ICMP traceroute
    # Send Echo Ping Request
    def sendOnePing(self, destinationAddress, packetID, sequenceNumber, ttl=None, dataLength=0):
        # 1. Build ICMP header
        header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, 0, packetID, sequenceNumber)
        
        # 2. Checksum ICMP packet using given function
        # include some bytes 'AAA...' in the data (payload) of ping
        data = str.encode(dataLength * 'A')
        my_checksum = self.checksum(header+data)

        # 3. Insert checksum into packet
        # NOTE: it is optional to include an additional 8-byte timestamp (time when probe is sent)
        # in which case, a stateless ping can be implemented: the response will contain
        # the sending time so no need to keep that state, 
        # but we don't do that here (instead, we record sending time state in step 5)
        packet = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), packetID, sequenceNumber)

        if ttl is not None:
            self.icmpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        # 4. Send packet using socket
        self.icmpSocket.sendto(packet+data, (destinationAddress, 1))

        # 5. Record time of sending (state)
        timeSent = time.time()
        return timeSent

    def doOnePing(self, destinationAddress, timeout, seq_num):

        # 3. Call sendOnePing function
        packetID = random.randint(1, 65535)
        timeSent = self.sendOnePing(destinationAddress, packetID, seq_num, dataLength=48)

        # 4. Call receiveOnePing function
        timeReceipt, ttl, packetSize, seq = self.receiveOnePing(destinationAddress, packetID, seq_num, timeout)

        # 5. Compute RTT
        rtt = None
        if timeReceipt is None:
            print("Error receiveOnePing() has timed out")
        else:
            rtt = timeReceipt - timeSent

        # 6. Return total network delay, ttl, size and sequence number
        return rtt, ttl, packetSize, seq

# A partially implemented traceroute 
class Traceroute(ICMPPing):

    def __init__(self, args):
        args.protocol = args.protocol.lower()

        # 1. Look up hostname, resolving it to an IP address
        self.dstAddress = None
        try:
            self.dstAddress = socket.gethostbyname(args.hostname)
            #socket.getaddrinfo(args.hostname, None, socket.AF_INET6)
        except socket.gaierror:
            print('Invalid hostname: ', args.hostname) 
            return
        print('%s traceroute to: %s (%s) ...' % (args.protocol, args.hostname, self.dstAddress))

        # 2. Initialise instance variables
        self.isDestinationReached = False

        # 3. Create a raw socket bound to ICMP protocol
        self.icmpSocket = None
        try:
            self.icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as err:
            traceback.print_exception(err)
            exit(1)

        # 4. Set a timeout on the socket
        self.icmpSocket.settimeout(args.timeout)

        # 5. Run traceroute
        self.runTraceroute()

        # 6. Close ICMP socket
        self.icmpSocket.close()

    def runTraceroute(self):

        hopAddr = None
        pkt_keys = []
        hop_addrs = dict()
        rtts = dict()
        ttl = 1

        while(ttl <= MAX_TTL and self.isDestinationReached == False):
            if args.protocol == "icmp":
                self.sendIcmpProbesAndCollectResponses(ttl)

            elif args.protocol == "udp":
                self.sendUdpProbesAndCollectResponses(ttl)
            else:
                print(f"Error: invalid protocol {args.protocol}. Use udp or icmp")
                sys.exit(1)
            ttl += 1

    # TODO: send 3 ICMP traceroute probes per TTL and collect responses
    def sendIcmpProbesAndCollectResponses(self, ttl):
        hopAddr = None
        icmpType = None
        pkt_keys = []
        hop_addrs = dict()
        rtts = dict()

        for seq in range(3):
            packetID = random.randint(1, 65535)
            timeSent = self.sendOnePing(self.dstAddress, packetID,seq,ttl=ttl, dataLength=48)

            pkt_keys.append(seq)

            trReplyPacket, hopAddr, timeRecvd = self.receiveOneTraceRouteResponse()

            if trReplyPacket is None:
                continue

            seqReceived, icmpType= self.parseICMPTracerouteResponse(trReplyPacket)

            if self.dstAddress == hopAddr and icmpType == 0:
                self.isDestinationReached = True
            
            if seq == seqReceived:
                rtts[seq] = timeRecvd - timeSent
                hop_addrs[seq] = hopAddr
        
        self.printMultipleResults(ttl, pkt_keys, hop_addrs, rtts, args.hostname)
        

    # Send 3 UDP traceroute probes per TTL and collect responses
    def sendUdpProbesAndCollectResponses(self, ttl):
        
        hopAddr = None
        icmpType = None
        pkt_keys = []
        hop_addrs = dict()
        rtts = dict()

        numBytes = 52
        dstPort = 33439
        
        for _ in range(3): 
            # 1. Send one UDP traceroute probe
            dstPort += 1
            timeSent = self.sendOneUdpProbe(self.dstAddress, dstPort , ttl, numBytes)

            # 2. Record a unique key (UDP destination port) associated with the probe
            pkt_keys.append(dstPort)

            # 3. Receive the response (if one arrives within the timeout)
            trReplyPacket, hopAddr, timeRecvd = self.receiveOneTraceRouteResponse()
            if trReplyPacket is None:
                # Nothing is received within the timeout period
                continue
            
            # 4. Extract destination port from the reply
            dstPortReceived, icmpType = self.parseUDPTracerouteResponse(trReplyPacket)
        
            # 5. Check if we reached the destination 
            if self.dstAddress == hopAddr and icmpType == 3:
                self.isDestinationReached = True

            # 6. If the response matches the request, record the rtt and the hop address
            if dstPort == dstPortReceived:
                rtts[dstPort] = timeRecvd - timeSent
                hop_addrs[dstPort] = hopAddr

        # 7. Print one line of the results for the 3 probes
        self.printMultipleResults(ttl, pkt_keys, hop_addrs, rtts, args.hostname)

    # Parse the response to UDP probe 
    def parseUDPTracerouteResponse(self, trReplyPacket):

        # 1. Parse the IP header
        dst_port = None
        # Extract the first 20 bytes 
        ip_header = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[:20])

        # 2. Read the IP Header Length (using bit masking) 
        ip_header_len_field = (ip_header[0] & 0x0F)

        # 3. Compute the IP header length
        # This field contains the length of the IP header in terms of 
        # the number of 4-byte words. So value 5 indicates 5*4 = 20 bytes. 
        ip_header_len = ip_header_len_field * 4
        
        # 4. Parse the outermost ICMP header which is 8 bytes long:
        # 0         8           16         24          32 bits
        #     Type  |    Code   |       Checksum       |
        #     Packet Identifier |       Sequence num   |
        # This header contains type, Code and Checksum + 4 bytes of padding (0's)
        # We only care about type field
        icmpType, _, _, _, _  = struct.unpack("!BBHHH", trReplyPacket[ip_header_len:ip_header_len + 8])
        
        # 5. Parse the ICMP message if it has the expected type
        if icmpType == 3 or icmpType == 11:
            ip_header_inner = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[ip_header_len + 8:ip_header_len+28])

            # This is the original IP header sent in the probe packet
            # It should be 20 bytes, but let's not assume anything and extract the length
            # of the header
            ip_header_len_field = (ip_header_inner[0] & 0x0F)
            ip_header_inner_len = ip_header_len_field * 4
            
            # Extract the destination port and match using source port (UDP)
            _, dst_port, _, _ = struct.unpack('!HHHH', trReplyPacket[ip_header_len + 8 + ip_header_inner_len : ip_header_len + 8 + ip_header_inner_len + 8])

        return dst_port, icmpType
    
    # TODO: parse the response to the ICMP probe
    def parseICMPTracerouteResponse(self, trReplyPacket):

        ip_header = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[:20])
        ip_header_len_field = (ip_header[0] & 0x0F)
        ip_header_len = ip_header_len_field * 4

        icmpType,code,_,p_id,sequence = struct.unpack("!BBHHH", trReplyPacket[ip_header_len:ip_header_len + 8])

        if icmpType == 11: 
            icmp_header_inner = trReplyPacket[ip_header_len + 28 : ip_header_len + 36]
            _,_,_,orignal_p_id,original_sequence = struct.unpack("!BBHHH", icmp_header_inner)
            return original_sequence, icmpType
        elif icmpType == 0:
            return sequence, icmpType
        elif icmpType == 8:
            return sequence, icmpType
        
        return None, None

    def receiveOneTraceRouteResponse(self):

        timeReceipt = None
        hopAddr = None
        pkt = None

        # 1. Receive one packet or timeout
        try:
            pkt, addr = self.icmpSocket.recvfrom(MAX_DATA_RECV)
            timeReceipt = time.time()
            hopAddr = addr[0]
        
        # 2. Handler for timeout on receive
        except socket.timeout as e:
            timeReceipt = None

        # 3. Return the packet, hop address and the time of receipt
        return pkt, hopAddr, timeReceipt

    def sendOneUdpProbe(self, destAddress, port, ttl, dataLength):

        # 1. Create a UDP socket
        udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, UDP_CODE)

        # 2. Use a socket option to set the TTL in the IP header
        udpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        # 3. Send the UDP traceroute probe
        udpSocket.sendto(str.encode(dataLength * '0'), (destAddress, port))

        # 4. Record the time of sending
        timeSent = time.time()

        # 5. Close the UDP socket
        udpSocket.close()

        return timeSent

# TODO: A multi-threaded traceroute implementation
class MultiThreadedTraceRoute(Traceroute):

    def __init__(self, args):
        # 1. Initialise instance variables (add others if needed)
        args.protocol = args.protocol.lower()
        self.timeout = args.timeout
        self.send_complete = threading.Event()
        # NOTE you must use a lock when accessing data shared between the two threads
        self.lock = threading.Lock()

        self.destAddres = socket.gethostbyname(args.hostname)

        try:
            self.icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.icmpSocket.settimeout(args.timeout)
        except socket.error as err:
            traceback.print_exception(err)
            exit(1)

        #results structure to store the results
        self.results  = dict()

        self.udp_Port = 33439

        self.seq_counter = 0  

        # 2. Create a thread to send probes
        self.send_thread = threading.Thread(target=self.send_probes)
        # 3. Create a thread to receive responses 
        self.recv_thread = threading.Thread(target=self.receive_responses)

        # 4. Start the threads
        self.send_thread.start()
        self.recv_thread.start()

        # 5. Wait until both threads are finished executing
        self.send_thread.join()
        self.recv_thread.join()

        # 6. TODO Print results

        #*The results will be printed in order of increasing TTL values.

        with self.lock:
            sorted_ttls = sorted(self.results.keys())
            for ttl in sorted_ttls:
                pkt_keys = []
                hop_addrs = {}
                rrts = {}

                probes = self.results[ttl]

                for probe_key, probe_data in probes.items():
                    pkt_keys.append(probe_key)
                    if probe_data.get('hop_addr') is not None:
                        hop_addrs[probe_key] = probe_data['hop_addr']
                        rrts[probe_key] = probe_data['rtt']


                self.printMultipleResults(ttl, pkt_keys, hop_addrs, rrts, args.hostname)

                for probe_data in probes.values():
                    if probe_data.get('hop_addr') == self.destAddres and (
                        (args.protocol == "icmp" and probe_data.get("icmp_type") == 0) or
                        (args.protocol == "udp" and probe_data.get("icmp_type") == 3)
                    ):
                        return
            
        
            
    # Thread to send probes (to be implemented, a skeleton is provided)
    def send_probes(self):

        ttl = 1
        while ttl <= MAX_TTL:

            with self.lock:
                if ttl not in self.results:
                    self.results[ttl] = dict()

            #* Send three probes per TTL
            for _ in range(3):  
                if args.protocol == "icmp":
                    packetID = random.randint(1, 65535) #*Unique packet id  
                    seq = self.seq_counter
                    self.seq_counter += 1

                    timeSent = self.sendOnePing(self.destAddres, packetID, seq, ttl=ttl, dataLength=48)

                    with self.lock:
                        self.results[ttl][seq] = {
                            'time_sent': timeSent,
                            'hop_addr': None,
                            'rrt': None,
                            'icmp_type': None,
                            'packet_id': packetID   
                        }
                    
                elif args.protocol == "udp":
                    self.udp_Port += 1
                    port = self.udp_Port
                    timeSent = self.sendOneUdpProbe(self.destAddres, port, ttl, dataLength=52)

                    with self.lock:
                        self.results[ttl][port] = {
                            'time_sent': timeSent,
                            'hop_addr':None,
                            'rrt': None,
                            'icmp_type': None,
                            'dst_port':port
                        }       

                #* Sleep for a short period between sending probes
                time.sleep(0.05)  #* Small delay between probes

            ttl += 1

        #* A final sleep before notifying the receive thread to exit
        time.sleep(args.timeout)
        #* Notify the other thread that sending is complete
        self.send_complete.set()
        
        return       

    #* Thread to receive responses (to be implemented, a skeleton is provided)
    def receive_responses(self):

        #* Keep receiving responses until notified by the other thread
        while not self.send_complete.is_set():

            try:
                trReplyPacket, hopAddr = self.icmpSocket.recvfrom(MAX_DATA_RECV)
                timeReceipt = time.time()
                hopAddrIP = hopAddr[0]

                if args.protocol == "icmp":
                    seq, icmpType = self.parseICMPTracerouteResponse(trReplyPacket)

                    if seq is not None:
                        with self.lock:
                            for ttl in self.results:
                                if seq in self.results[ttl]:
                                    timeSent = self.results[ttl][seq]['time_sent']
                                    rtt = (timeReceipt - timeSent) * 10
                                    self.results[ttl][seq]['hop_addr'] = hopAddrIP
                                    self.results[ttl][seq]['rtt'] = rtt
                                    self.results[ttl][seq]['icmp_type'] = icmpType
                                    break        

                elif args.protocol == "udp":
                    dstPort, icmpType = self.parseUDPTracerouteResponse(trReplyPacket)

                    if dstPort is not None:
                        with self.lock: 
                            for ttl in self.results:
                                if dstPort in self.results[ttl]:
                                    timeSent = self.results[ttl][dstPort]['time_sent']
                                    rtt = (timeReceipt - timeSent) * 10
                                    self.results[ttl][dstPort]['hop_addr'] = hopAddrIP
                                    self.results[ttl][dstPort]['rtt'] = rtt
                                    self.results[ttl][dstPort]['icmp_type'] = icmpType
                                    break
            except socket.timeout:
                continue
            except Exception as e:
                continue
        return       



# A basic multi-threaded web server implementation

# You can test the web server as follows: 
# First, run the server in the terminal: python3 NetworkApplications.py web 
# Then, copy the following and paste to a browser's address bar: 127.0.0.1:8080/index.html
# NOTE: the index.html file needs to be downloaded from the Moodle (Dummy HTML file)
# and copied to the folder where you run this code
class WebServer(NetworkApplication):

    def __init__(self, args):
        print('Web Server starting on port: %i...' % args.port)
        
        # 1. Create a TCP socket 
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 2. Bind the TCP socket to server address and server port
        serverSocket.bind(("", args.port))
        
        # 3. Continuously listen for connections to server socket
        serverSocket.listen(100)
        print("Server listening on port", args.port)
        
        while True:
            # 4. Accept incoming connections
            connectionSocket, addr = serverSocket.accept()
            print(f"Connection established with {addr}")
            
            # 5. Create a new thread to handle each client request
            threading.Thread(target=self.handleRequest, args=(connectionSocket,)).start()

        # Close server socket (this would only happen if the loop was broken, which it isn't in this example)
        serverSocket.close()

    def handleRequest(self, connectionSocket):
        try:
            # 1. Receive request message from the client
            message = connectionSocket.recv(MAX_DATA_RECV).decode()

            # 2. Extract the path of the requested object from the message (second part of the HTTP header)
            filename = message.split()[1]

            # 3. Read the corresponding file from disk
            with open(filename[1:], 'r') as f:  # Skip the leading '/'
                content = f.read()

            # 4. Create the HTTP response
            response = 'HTTP/1.1 200 OK\r\n\r\n'
            response += content

            # 5. Send the content of the file to the socket
            connectionSocket.send(response.encode())

        except IOError:
            # Handle file not found error
            error_response = "HTTP/1.1 404 Not Found\r\n\r\n"
            error_response += "<html><head></head><body><h1>404 Not Found</h1></body></html>\r\n"
            connectionSocket.send(error_response.encode())

        except Exception as e:
            print(f"Error handling request: {e}")

        finally:
            # Close the connection socket
            connectionSocket.close()

# TODO: A proxy implementation 
class Proxy(NetworkApplication):

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))

        self.cache = {}
        self.cache_path = './proxy_cache'
        self.cache_lock = threading.Lock()

        try: 
            os.makedirs(self.cache_path, exist_ok=True)
        except OSError as e: 
            print(f"Error creating cache path: {e}")

        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.bind(("", args.port))

        serverSocket.listen(100)
        print("Proxy listening on port", args.port)

        while True: 
            connectionSocket, addr = serverSocket.accept()
            print(f"Connection established with {addr}")

            request_handler = threading.Thread(target=self.handleRequest, args=(connectionSocket,))

            request_handler.start()
        serverSocket.close()
        
    #!The cache key in this context is the host + path for GET requests    
    def getCacheKey(self, request_string): 
        try: 
            request_line = request_string.decode()

            request_parts = request_line.split()

            if len(request_parts) >= 2:
                HTTP_method = request_parts[0]
                path = request_parts[1]

                if HTTP_method == 'GET':
                    host_start = request_string.find(b"Host: ") + len(b"Host: ")
                    host_end = request_string.find(b"\r\n", host_start)
                    host = request_string[host_start:host_end].decode()
                    return f"{host}{path}"
        except Exception as e: 
            print(f"Error generating cache key: {e}")
            return None
    
    def getCachedResponse(self, cache_key): 
        if cache_key not in self.cache: 
            return None
        
        try: 
            cache_entry = self.cache[cache_key]
            filepath = cache_entry['filepath']

            with open(filepath, 'rb') as f: 
                cached_response = f.read()
            
            print(f"Cache hit for: {cache_key}")
            return cached_response
        except Exception as e:
            print(f"Error retrieving cache response: {e}")
            return None
    
    def storeCachedResponse(self, cache_key, response): 
        with self.cache_lock: 
            try:
                cache_filename = str(hash(cache_key)) + '.cache' #*Generating a unique filename for the cache file
                filepath = os.path.join(self.cache_path, cache_filename)

                with open(filepath,'wb') as f: 
                    f.write(response)
                
                self.cache[cache_key] = {
                    'filepath': filepath,
                    'timestamp': time.time()
                }

                print(f"Cache Miss: cached new response for: {cache_key}")
            except Exception as e:
                print(f"Error caching response: {e}")
    




    def handleRequest(self,connectionSocket):

        print("Received request: \n")

        request_message = b""

        connectionSocket.settimeout(5.0)

        while b"\r\n\r\n" not in request_message:
            try: 
                data = connectionSocket.recv(MAX_DATA_RECV)
                if not data:
                    break
                request_message += data
                print(f"{data.decode()}")

            except socket.timeout:
                break
            except Exception as e: 
                print(f"Error receiving request: {e}")
        if not request_message: 
            connectionSocket.close()
            return

        cache_key = self.getCacheKey(request_message)

        if cache_key:
            cached_response = self.getCachedResponse(cache_key)
            if cached_response:
                connectionSocket.sendall(cached_response)
                connectionSocket.close()
                return


        host,port = self.extract_host_port(request_message)
        destinationSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try: 

            destinationSocket.connect((host,port))
            destinationSocket.sendall(request_message)

            destinationSocket.settimeout(2.0)

            print("Received response: \n")
            response_message = b""

            while True:
                try:
                    data = destinationSocket.recv(MAX_DATA_RECV)
                    if not data:
                        break

                    print(f"{data.decode(errors='ignore')}")

                    if len(data) > 0:
                        response_message +=data
                        connectionSocket.sendall(data)
                except socket.timeout:
                    print("Response complete (timeout)")
                    break
                except Exception as e: 
                    print(f"Error receiving response: {e}")
            if cache_key and self.isResponseCacheable(response_message):
                self.storeCachedResponse(cache_key,response_message)
        except Exception as e:
            print(f"Error connecting to destination: {e}")
            error_response = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
            connectionSocket.sendall(error_response)
        finally:
            destinationSocket.close()
            connectionSocket.close()
    
    def isResponseCacheable(self, response_message):
        response_string = response_message.decode()
        try: 
            if '200 OK' in response_string:
                if 'Cache-Control: no-cache' not in response_string:
                    return True
        except Exception as e: 
            print(f"Error checking if response is cacheable: {e}")
        return False   

    
    def extract_host_port(self, request_message):
        host_start = request_message.find(b"Host: ") + len(b"Host: ")
        host_end = request_message.find(b"\r\n", host_start)

        host_string = request_message[host_start:host_end].decode()

        webserver_pos = host_string.find("/")

        if webserver_pos == -1: 
            webserver_pos = len(host_string)
        
        port_pos = host_string.find(":")

        if port_pos == -1:
            host = host_string
            port = 80
        else:

            port = int((host_string[(port_pos + 1):])[:webserver_pos - port_pos - 1])
            host = host_string[:port_pos]

        return host, port       
            

# NOTE: Do NOT delete the code below
if __name__ == "__main__":
        
    args = setupArgumentParser()
    args.func(args)
