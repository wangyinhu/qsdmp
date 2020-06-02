#!/usr/bin/env python3

from time import sleep
import sys, signal
from secure import *

sys.path.append('./cmake-build-debug')
import QsdmpPyClient


def signal_handler(signal, frame):
	# print('\nplease type exit or quit\n' + inputstart)
	print("\r")
	sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

if len(sys.argv) == 2 and sys.argv[1] == 'l':
	host = 'localhost'

conn = QsdmpPyClient.client(host=host, port=2005, did=DEVDID6, cid=0x21, devk=devdk, cok=headerk, timeout=5, sockettype="TCP")

conn.send(b"hello! I'm device!\n", 0)

while (1):
	rtn = conn.getpacks()
	for pack in rtn:
		print (pack)
		# print (pack['data'].decode('utf-8'))
		conn.send(b"hello! I'm device!\n", sessionID=pack['sessionID'])


