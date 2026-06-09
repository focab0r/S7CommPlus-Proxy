
from scapy.all import IP, TCP, Raw, PcapWriter
from .checks import *
from .decode import *

from collections import deque


seq1 = 1000
seq2 = 1000

# Save the packets in a PCAP file.
# Client will be 192.168.1.1, server is 192.168.1.2
def save_tls_packet(pck, code):
	global seq1
	global seq2
	if code == 1:
		pkt = (
			IP(src="192.168.1.1", dst="192.168.1.2") /
			TCP(sport=12345, dport=102, seq=seq1, flags="PA") /
			Raw(load=pck)
		)
		seq1 += len(pck)
	elif code == 2:
		pkt = (
			IP(src="192.168.1.2", dst="192.168.1.1") /
			TCP(sport=102, dport=12345, seq=seq2, flags="PA") /
			Raw(load=pck)
		)
		seq2 += len(pck)
	writer = PcapWriter("decrypted.pcap", append=True, sync=True)
	writer.write(pkt)

pcapfile_mutex = 0
init_pcapfile_mutex = 0

# Save the packets in S7CommPlus wireshark dissector mode (by splitting them)
def save_tls_packet_to_file(decrypted_data, code):
	global pcapfile_mutex
	global init_pcapfile_mutex
	if init_pcapfile_mutex == 0:
		pcapfile_mutex = threading.Lock()
		init_pcapfile_mutex = 1
	pcapfile_mutex.acquire()
	offset = 0
	max_COTP_len = 0x404-7
	while offset < len(decrypted_data): 
		chain = decrypted_data[offset:offset+max_COTP_len]
		if offset+max_COTP_len < len(decrypted_data):
			chain = wrap_COTP_packet(chain, 1)      # There will be more packets
		else:
			chain = wrap_COTP_packet(chain, 0)      # The last packet
		save_tls_packet(chain, code)                # Add packet to the queue
		offset+=max_COTP_len
	pcapfile_mutex.release()


# Type = 0 --> No fragment
# Type = 1 --> Fragment
def wrap_COTP_packet(tls_data, type):
	data_len = len(tls_data) + 7  # 4 TPKT + 3 COTP
	tpkt_data = bytes.fromhex(format(0x03000000 + data_len, '08x'))		# 4 bytes
	if type == 0:
		cotp_data = bytes.fromhex(format(0x02f080, '06x'))				# Final package (0x80)
	elif type == 1:
		cotp_data = bytes.fromhex(format(0x02f000, '06x'))				# Not final package (0x00)
	tcp_payload = tpkt_data + cotp_data + tls_data
	return tcp_payload

def unwrap_COTP_packet(pck):
	return pck[7:]


def parse_tpkt_packets(data: bytes) -> list[bytes]:
	packets = deque()
	offset = 0
	while offset < len(data):
		if offset + 4 > len(data):
			raise ValueError(f"Incomplete header at offset {offset}")
		if data[offset:offset+2] != b'\x03\x00':
			raise ValueError(f"Invalid TPKT magic at offset {offset}: {data[offset:offset+2].hex()}")
		total_length = int.from_bytes(data[offset+2:offset+4], byteorder='big')
		if total_length < 7:
			raise ValueError(f"Packet length {total_length} too small (min 7 to strip header)")
		if offset + total_length > len(data):
			raise ValueError(f"Packet at offset {offset} claims length {total_length} but only {len(data) - offset} bytes remain")
		packet = data[offset : offset+total_length]
		packets.append(packet)
		offset += total_length
	return packets
