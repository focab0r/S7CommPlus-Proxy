### TLS management ###

import ssl
from ssl import SSLWantReadError, SSLWantWriteError, SSLError

import connection
from proxy_utils.checks import *
from proxy_utils.decode import *
from proxy_utils.utils import *
from scapy.layers.tls.all import TLS
from scapy.all import IP, TCP, Raw, PcapWriter

import time
from colorama import Fore, Style



### [Start] Secure read/write to queue ###


def save_data(data, code):
	if code == 1:
		connection.server_mutex.acquire()
		connection.server_data_buffer.append(data)
		connection.server_mutex.release()
	elif code == 2:
		connection.client_mutex.acquire()
		connection.client_data_buffer.append(data)
		connection.client_mutex.release()

def read_data(code):
	if code == 1:
		connection.client_mutex.acquire()
		data_to_send = connection.client_data_buffer.popleft()
		connection.client_mutex.release()
	elif code == 2:
		connection.server_mutex.acquire()
		data_to_send = connection.server_data_buffer.popleft()
		connection.server_mutex.release()
	return data_to_send


### [End] Secure read/write to queue ###

### [Start] BIOS programming ###

def encrypt_data_in_bio(decrypted_data, code):
	if code == 1:
		bio_out = connection.server_bio_out
		ssl_obj = connection.server_ssl_obj
		mutex = connection.server_bio_mutex
	elif code == 2:
		bio_out = connection.client_bio_out
		ssl_obj = connection.client_ssl_obj
		mutex = connection.client_bio_mutex

	mutex.acquire()
	ssl_obj.write(decrypted_data)
	encrypted_data = bio_out.read()
	if len(encrypted_data) > 0x404:
		print(Fore.YELLOW + f'[{"Server" if code == 1 else "Client"}] [WARNING] TLS data to send is bigger that COTP max len' + Style.RESET_ALL)
	mutex.release()
	return encrypted_data

def decrypt_data_in_bio(pck, code):
	if code == 1:
		bio_in = connection.server_bio_in
		ssl_obj = connection.server_ssl_obj
		mutex = connection.server_bio_mutex
	elif code == 2:
		bio_in = connection.client_bio_in
		ssl_obj = connection.client_ssl_obj
		mutex = connection.client_bio_mutex

	mutex.acquire()
	pck_u = unwrap_COTP_packet(pck)
	bio_in.write(pck_u)
	while 1:
		try:
			decrypted_data = ssl_obj.read()
			while len(decrypted_data) % 1024 == 0:
				print(Fore.YELLOW + f'[{"Server" if code == 1 else "Client"}] [WARNING] Decrypted data is multiple of 1024 bytes. Reading one more time' + Style.RESET_ALL)
				decrypted_data += ssl_obj.read()
			break
		except SSLWantReadError:
			receive_data_to_bio(code)
	mutex.release()
	return decrypted_data

def send_data_from_bio(code):
	if code == 1:
		bio_out = connection.server_bio_out
		socket = connection.server_socket
	elif code == 2:
		bio_out = connection.client_bio_out
		socket = connection.client_socket

	tls_data = bio_out.read()
	if tls_data:
		print(f'[{"Server" if code == 1 else "Client"}] ----> Sending {len(tls_data)} bytes of TLS data to client... {tls_data}')
		pck = wrap_COTP_packet(tls_data, 0)
		socket.send(pck)

def receive_data_to_bio(code):
	if code == 1:
		bio_in = connection.server_bio_in
		socket = connection.server_socket
		main_pck_list = connection.server_queue
	elif code == 2:
		bio_in = connection.client_bio_in
		socket = connection.client_socket
		main_pck_list = connection.client_queue

	try:
		if len(main_pck_list) == 0:
			raw_data = bytes(socket.recv())									# If there is no data recv will fail
			pck_list = parse_tpkt_packets(raw_data)
			main_pck_list.extend(pck_list)
		pck = main_pck_list.popleft()
		if not is_empty_COPT(pck):											# Check if we've read TLS
			tls_data = unwrap_COTP_packet(pck)
			print(f'[{"Server" if code == 1 else "Client"}] <---- Received {len(tls_data)} bytes of TLS data from client. {pck}')
			bio_in.write(tls_data)
		else:
			print(Fore.RED + f'[{"Server" if code == 1 else "Client"}] Declined packet {bytes(pck)}' + Style.RESET_ALL)
	except BlockingIOError:
		return   


def read_and_write(code):
	send_data_from_bio(code)
	receive_data_to_bio(code)


### [End] BIOS programming ###

### [Start] Handshake ###


def create_tls_server(pck_tls):
	ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
	ctx.load_cert_chain(connection.CERTFILE, connection.KEYFILE)
	connection.server_bio_in = ssl.MemoryBIO()
	connection.server_bio_out = ssl.MemoryBIO()
	connection.server_ssl_obj = ctx.wrap_bio(connection.server_bio_in, connection.server_bio_out, server_side=True)
	print(Fore.GREEN + "[Server] Starting TLS handshake..." + Style.RESET_ALL)
	connection.server_bio_in.write(pck_tls)
	while True:
		try:
			connection.server_ssl_obj.do_handshake()
			print(Fore.GREEN + "[Server] TLS Handshake successful!" + Style.RESET_ALL)
			send_data_from_bio(1)
			break
		except (SSLWantReadError, SSLWantWriteError):
			read_and_write(1)



def create_tls_client():
	ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
	ctx.minimum_version = ssl.TLSVersion.TLSv1_3
	ctx.maximum_version = ssl.TLSVersion.TLSv1_3
	ctx.set_ecdh_curve("X25519")
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE
	connection.client_bio_in = ssl.MemoryBIO()
	connection.client_bio_out = ssl.MemoryBIO()
	connection.client_ssl_obj = ctx.wrap_bio(connection.client_bio_in, connection.client_bio_out, server_side=False)
	print(Fore.GREEN + "[Client] Starting TLS handshake..." + Style.RESET_ALL)
	while True:
		try:
			connection.client_ssl_obj.do_handshake()
			print(Fore.GREEN + "[Client] TLS Handshake successful!" + Style.RESET_ALL)
			send_data_from_bio(2)
			break
		except (SSLWantReadError, SSLWantWriteError):
			read_and_write(2)


### [End] Handshake ###


def manage_tls_packet(pck, code):
	if code == 1:
		while connection.client_create_tls != 2:			# Wait until the client has finished the handshake
			time.sleep(100/1000000.0)                           
		decrypted_data = decrypt_data_in_bio(pck, 1)		# Decrypt TLS using a save way to use the SSL_OBJ and the BIO
		print(f'[Server] Decrypted Data!!: {decrypted_data}')
		save_tls_packet_to_file(decrypted_data, 1)			# Save packet in a PCAP
		tls_data = encrypt_data_in_bio(decrypted_data, 2)	# Encrypt TLS using a save way to use the SSL_OBJ and the BIO
		offset = 0
		max_COTP_len = 0x404-7
		while offset < len(tls_data): 
			chain = tls_data[offset:offset+max_COTP_len]
			if offset+max_COTP_len < len(tls_data):
				chain = wrap_COTP_packet(chain, 1)			# There will be more packets
			else:
				chain = wrap_COTP_packet(chain, 0)			# The last packet
			print(f'[Server-queue]: [->Save Data<-] [TLS]: {chain}')
			save_data(chain, 1)								# Add packet to the queue
			offset+=max_COTP_len
	elif code == 2:
		decrypted_data = decrypt_data_in_bio(pck, 2)		# Decrypt TLS using a save way to use the SSL_OBJ and the BIO
		print(f'[Client] Decrypted Data!!: {decrypted_data}')
		save_tls_packet_to_file(decrypted_data, 2)			# Save packet in a PCAP
		tls_data = encrypt_data_in_bio(decrypted_data, 1)	# Encrypt TLS using a save way to use the SSL_OBJ and the BIO
		offset = 0
		max_COTP_len = 0x404-7
		while offset < len(tls_data):
			if offset != 0:
				print(Fore.YELLOW + f'[Client] [WARNING] TLS data to send is bigger that COTP max len' + Style.RESET_ALL)
			chain = tls_data[offset:offset+max_COTP_len]
			if offset+max_COTP_len < len(tls_data):
				chain = wrap_COTP_packet(chain, 1)			# There will be more packets
			else:
				chain = wrap_COTP_packet(chain, 0)			# The last packet
			print(f'[Client-queue]: [->Save Data<-] [TLS]: {chain}')
			save_data(chain, 2)								# Add packet to the queue
			offset+=max_COTP_len


def manage_tls_handshake(pck, code):
	if code == 2:
		print(Fore.RED + f'[CRITICAL]: Received a TLS handshake from the client' + Style.RESET_ALL)
	else:
		pck_u = unwrap_COTP_packet(pck)
		create_tls_server(pck_u)
		connection.client_create_tls = 1