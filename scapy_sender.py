# from __future__ import absolute_import, print_function
# import itertools
# from threading import Thread, Event
# import os
# import re
# import subprocess
# import time

# from scapy.compat import plain_str
# from scapy.data import ETH_P_ALL
# from scapy.config import conf
# from scapy.error import warning
# from scapy.interfaces import (
#     network_name,
#     resolve_iface,
#     NetworkInterface,
# )
# from scapy.packet import Packet
# from scapy.utils import get_temp_file, tcpdump, wrpcap, \
#     ContextManagerSubprocess, PcapReader, EDecimal
# from scapy.plist import (
#     PacketList,
#     QueryAnswer,
#     SndRcvList,
# )
# from scapy.error import log_runtime, log_interactive, Scapy_Exception
# from scapy.base_classes import Gen, SetGen
# from scapy.libs import six
# from scapy.sessions import DefaultSession
# from scapy.supersocket import SuperSocket, IterSocket

# # Typing imports
# from scapy.compat import (
#     Any,
#     Callable,
#     Dict,
#     Iterator,
#     List,
#     Optional,
#     Tuple,
#     Type,
#     Union,
#     cast
# )
# from scapy.interfaces import _GlobInterfaceType
# from scapy.plist import _PacketIterable

# from scapy.all import *

# if conf.route is None:
#     # unused import, only to initialize conf.route and conf.iface*
#     import scapy.route  # noqa: F401

# #################
# #  Debug class  #
# #################


# class debug:
#     recv = PacketList([], "Received")
#     sent = PacketList([], "Sent")
#     match = SndRcvList([], "Matched")
#     crashed_on = None  # type: Optional[Tuple[Type[Packet], bytes]]


# ####################
# #  Send / Receive  #
# ####################

# _DOC_SNDRCV_PARAMS = """
#     :param pks: SuperSocket instance to send/receive packets
#     :param pkt: the packet to send
#     :param timeout: how much time to wait after the last packet has been sent
#     :param inter: delay between two packets during sending
#     :param verbose: set verbosity level
#     :param chainCC: if True, KeyboardInterrupts will be forwarded
#     :param retry: if positive, how many times to resend unanswered packets
#         if negative, how many times to retry when no more packets
#         are answered
#     :param multi: whether to accept multiple answers for the same stimulus
#     :param rcv_pks: if set, will be used instead of pks to receive packets.
#         packets will still be sent through pks
#     :param prebuild: pre-build the packets before starting to send them.
#         Automatically enabled when a generator is passed as the packet
#     :param _flood:
#     :param threaded: if True, packets will be sent in an individual thread
#     :param session: a flow decoder used to handle stream of packets
#     :param chainEX: if True, exceptions during send will be forwarded
#     """


# _GlobSessionType = Union[Type[DefaultSession], DefaultSession]


# class SndRcvHandler(object):
#     """
#     Util to send/receive packets, used by sr*().
#     Do not use directly.

#     This matches the requests and answers.

#     Notes::
#       - threaded mode: enabling threaded mode will likely
#         break packet timestamps, but might result in a speedup
#         when sending a big amount of packets. Disabled by default
#       - DEVS: store the outgoing timestamp right BEFORE sending the packet
#         to avoid races that could result in negative latency. We aren't Stadia
#     """
#     def __init__(self,
#                  pks,  # type: SuperSocket
#                  pkt,  # type: _PacketIterable
#                  timeout=None,  # type: Optional[int]
#                  inter=0,  # type: int
#                  verbose=None,  # type: Optional[int]
#                  chainCC=False,  # type: bool
#                  retry=0,  # type: int
#                  multi=False,  # type: bool
#                  rcv_pks=None,  # type: Optional[SuperSocket]
#                  prebuild=False,  # type: bool
#                  _flood=None,  # type: Optional[_FloodGenerator]
#                  threaded=False,  # type: bool
#                  session=None,  # type: Optional[_GlobSessionType]
#                  chainEX=False  # type: bool
#                  ):
#         # type: (...) -> None
#         # Instantiate all arguments
#         if verbose is None:
#             verbose = conf.verb
#         if conf.debug_match:
#             debug.recv = PacketList([], "Received")
#             debug.sent = PacketList([], "Sent")
#             debug.match = SndRcvList([], "Matched")
#         self.nbrecv = 0
#         self.ans = []  # type: List[QueryAnswer]
#         self.pks = pks
#         self.rcv_pks = rcv_pks or pks
#         self.inter = inter
#         self.verbose = verbose
#         self.chainCC = chainCC
#         self.multi = multi
#         self.timeout = timeout
#         self.session = session
#         self.chainEX = chainEX
#         self._send_done = False
#         self.notans = 0
#         self.noans = 0
#         self._flood = _flood
#         # Instantiate packet holders
#         if prebuild and not self._flood:
#             self.tobesent = list(pkt)  # type: _PacketIterable
#         else:
#             self.tobesent = pkt

#         if retry < 0:
#             autostop = retry = -retry
#         else:
#             autostop = 0

#         if timeout is not None and timeout < 0:
#             self.timeout = None

#         while retry >= 0:
#             self.hsent = {}  # type: Dict[bytes, List[Packet]]

#             if threaded or self._flood:
#                 # Send packets in thread.
#                 # https://github.com/secdev/scapy/issues/1791
#                 snd_thread = Thread(
#                     target=self._sndrcv_snd
#                 )
#                 snd_thread.daemon = True

#                 # Start routine with callback
#                 self._sndrcv_rcv(snd_thread.start)

#                 # Ended. Let's close gracefully
#                 if self._flood:
#                     # Flood: stop send thread
#                     self._flood.stop()
#                 snd_thread.join()
#             else:
#                 self._sndrcv_rcv(self._sndrcv_snd)

#             if multi:
#                 remain = [
#                     p for p in itertools.chain(*six.itervalues(self.hsent))
#                     if not hasattr(p, '_answered')
#                 ]
#             else:
#                 remain = list(itertools.chain(*six.itervalues(self.hsent)))

#             if autostop and len(remain) > 0 and \
#                len(remain) != len(self.tobesent):
#                 retry = autostop

#             self.tobesent = remain
#             if len(self.tobesent) == 0:
#                 break
#             retry -= 1

#         if conf.debug_match:
#             debug.sent = PacketList(remain[:], "Sent")
#             debug.match = SndRcvList(self.ans[:])

#         # Clean the ans list to delete the field _answered
#         if multi:
#             for snd, _ in self.ans:
#                 if hasattr(snd, '_answered'):
#                     del snd._answered

#         if verbose:
#             print(
#                 "\nReceived %i packets, got %i answers, "
#                 "remaining %i packets" % (
#                     self.nbrecv + len(self.ans), len(self.ans),
#                     max(0, self.notans - self.noans)
#                 )
#             )

#         self.ans_result = SndRcvList(self.ans)
#         self.unans_result = PacketList(remain, "Unanswered")

#     def results(self):
#         # type: () -> Tuple[SndRcvList, PacketList]
#         return self.ans_result, self.unans_result

#     def _sndrcv_snd(self):
#         # type: () -> None
#         """Function used in the sending thread of sndrcv()"""
#         i = 0
#         p = None
#         try:
#             if self.verbose:
#                 print("Begin emission:")
#             for p in self.tobesent:
#                 # Populate the dictionary of _sndrcv_rcv
#                 # _sndrcv_rcv won't miss the answer of a packet that
#                 # has not been sent
#                 self.hsent.setdefault(p.hashret(), []).append(p)
#                 # Send packet
#                 self.pks.send(p)
#                 time.sleep(self.inter)
#                 i += 1
#             if self.verbose:
#                 print("Finished sending %i packets." % i)
#         except SystemExit:
#             pass
#         except Exception:
#             if self.chainEX:
#                 raise
#             else:
#                 log_runtime.exception("--- Error sending packets")
#         finally:
#             try:
#                 cast(Packet, self.tobesent).sent_time = \
#                     cast(Packet, p).sent_time
#             except AttributeError:
#                 pass
#             if self._flood:
#                 self.notans = self._flood.iterlen
#             elif not self._send_done:
#                 self.notans = i
#             self._send_done = True

#     def _process_packet(self, r):
#         # type: (Packet) -> None
#         """Internal function used to process each packet."""
#         if r is None:
#             return
#         ok = False
#         h = r.hashret()
#         if h in self.hsent:
#             hlst = self.hsent[h]
#             for i, sentpkt in enumerate(hlst):
#                 if r.answers(sentpkt):
#                     self.ans.append(QueryAnswer(sentpkt, r))
#                     if self.verbose > 1:
#                         os.write(1, b"*")
#                     ok = True
#                     if not self.multi:
#                         del hlst[i]
#                         self.noans += 1
#                     else:
#                         if not hasattr(sentpkt, '_answered'):
#                             self.noans += 1
#                         sentpkt._answered = 1
#                     break
#         if self._send_done and self.noans >= self.notans and not self.multi:
#             if self.sniffer:
#                 self.sniffer.stop(join=False)
#         if not ok:
#             if self.verbose > 1:
#                 os.write(1, b".")
#             self.nbrecv += 1
#             if conf.debug_match:
#                 debug.recv.append(r)

#     def _sndrcv_rcv(self, callback):
#         # type: (Callable[[], None]) -> None
#         """Function used to receive packets and check their hashret"""
#         self.sniffer = None  # type: Optional[AsyncSniffer]
#         try:
#             self.sniffer = AsyncSniffer()
#             self.sniffer._run(
#                 prn=self._process_packet,
#                 timeout=self.timeout,
#                 store=False,
#                 opened_socket=self.rcv_pks,
#                 session=self.session,
#                 started_callback=callback
#             )
#         except KeyboardInterrupt:
#             if self.chainCC:
#                 raise


# def sndrcv(*args, **kwargs):
#     # type: (*Any, **Any) -> Tuple[SndRcvList, PacketList]
#     """Scapy raw function to send a packet and receive its answer.
#     WARNING: This is an internal function. Using sr/srp/sr1/srp is
#     more appropriate in many cases.
#     """
#     sndrcver = SndRcvHandler(*args, **kwargs)
#     return sndrcver.results()


# def __gen_send(s,  # type: SuperSocket
#                x,  # type: _PacketIterable
#                inter=0,  # type: int
#                loop=0,  # type: int
#                count=None,  # type: Optional[int]
#                verbose=None,  # type: Optional[int]
#                realtime=False,  # type: bool
#                return_packets=False,  # type: bool
#                *args,  # type: Any
#                **kargs  # type: Any
#                ):
#     # type: (...) -> Optional[PacketList]
#     """
#     An internal function used by send/sendp to actually send the packets,
#     implement the send logic...

#     It will take care of iterating through the different packets
#     """
#     if isinstance(x, str):
#         x = conf.raw_layer(load=x)
#     if not isinstance(x, Gen):
#         x = SetGen(x)
#     if verbose is None:
#         verbose = conf.verb
#     n = 0
#     if count is not None:
#         loop = -count
#     elif not loop:
#         loop = -1
#     sent_packets = PacketList() if return_packets else None
#     p = None
#     try:
#         while loop:
#             dt0 = None
#             for p in x:
#                 if realtime:
#                     ct = time.time()
#                     if dt0:
#                         st = dt0 + float(p.time) - ct
#                         if st > 0:
#                             time.sleep(st)
#                     else:
#                         dt0 = ct - float(p.time)
#                 s.send(p)
#                 if sent_packets is not None:
#                     sent_packets.append(p)
#                 n += 1
#                 if verbose:
#                     os.write(1, b".")
#                 time.sleep(inter)
#             if loop < 0:
#                 loop += 1
#     except KeyboardInterrupt:
#         pass
#     finally:
#         try:
#             cast(Packet, x).sent_time = cast(Packet, p).sent_time
#         except AttributeError:
#             pass
#     if verbose:
#         print("\nSent %i packets." % n)
#     return sent_packets




#Define your custom TCP options with an editable overflow field
class TCPTimestampOption(Packet):
    name = "Timestamp"
    fields_desc = [FieldLenField("length", None, length_of="overflow", adjust=lambda pkt, x:x//4), 
                   ShortField("tsval", 0), 
                   ShortField("tsecr", 0), 
                   BitField("overflow", 0, 4)]

# Function to craft TCP options with timestamp and overflow fields
def craft_timestamp_options(data_groups):
    options = []
    for group in data_groups:
        options.append(TCPTimestampOption(tsval=0, tsecr=0, overflow=group))
    return options

# Function to break input data into groups of 4 bits
def split_into_groups(data, group_size):
    return [data[i:i+group_size] for i in range(0, len(data), group_size)]

def string_to_binary(string):
    binary_str = ''.join(format(ord(char), '08b') for char in string)
    return binary_str

def split_binary(binary_str):
    # Check if the binary string is less than or equal to 16 bits
    if len(binary_str) <= 16:
        return [binary_str], 0
    else:
        # Calculate the number of 16-bit groups
        num_groups = len(binary_str) // 16
        if len(binary_str) % 16 != 0:
            num_groups += 1
        
        # Split the binary string into groups of 16 bits each
        binary_groups = [binary_str[i:i+16] for i in range(0, len(binary_str), 16)]
        return binary_groups, num_groups

# Input data (16 bits)
input_data = input("Enter string to encode: ")
print(f"String entered: {input_data}");

input_data_binary = string_to_binary(input_data)
print(f'Binary representation of input string: {input_data_binary}')

#Check if binary > 16 bits
input_data_binary_groups, num_groups = split_binary(input_data_binary)

print("\n-------groups-------")
for i in (input_data_binary_groups):
    print(i)
print("--------------------\n")
#print(num_groups)

# Split input data into groups of 4 bits each
data_groups = []
for i in range (num_groups):
        data_groups.append(split_into_groups(input_data_binary_groups[i], 4))

for i in range (num_groups):
    if (len(data_groups[i]) < 4):
        for x in range (4-len(data_groups[i])):
            data_groups[i].append('0000')

print("--------------data groups---------------")
for i in range (num_groups):
    print(data_groups[i])
print("----------------------------------------")
# Craft TCP options with timestamp and overflow fields
options = []
for i in range (num_groups):
    timestamp_options = [(int(tsval, 2), 0) for tsval in data_groups[i]]
    options.append(timestamp_options)
    # options.append(craft_timestamp_options(data_groups[i]))
    #options.append([(TCPTimestampOption(tsval=0, tsecr=0, overflow=data_groups[i][0][j])) for j in range(len(data_groups[i][0]))])
for i in range(num_groups):
    print(options[i])

print("------------------tcp packets-----------------")
ip_packet = []
for i in range (num_groups):
    # Craft the IPv4 packet
    # ip_packet.append(IP(dst="192.168.12.2")/TCP(dataofs=5, options=[('Timestamp', ts) for ts in timestamp_options]))
    # ip_packet.append(IP(dst="192.168.12.2")/TCP(dataofs=5, options=[('Timestamp', (11,0))]))
    curr_option = options[i]
    packet = IP(dst="192.168.1.1") / TCP(sport=1234, dport=80, dataofs=15, options=[('Timestamp', ts) for ts in curr_option])
    print(packet.show())
    #send(packet)
    #options[i]

# for i in range (num_groups):
#     print(ip_packet[i])
#     # Display the packet
#     print(ip_packet[i].show())

# # Send the packet
# for i in range (num_groups): 
#     send(ip_packet[i])

