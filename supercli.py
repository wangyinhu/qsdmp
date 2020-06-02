#!/usr/bin/env python3

import sys
from secure import *

sys.path.append('./cmake-build-debug')
import QsdmpPyClient

if len(sys.argv) == 2 and sys.argv[1] == 'l':
	host = 'localhost'

conn = QsdmpPyClient.super(host=host, port=2005, devk=superdk, cok=headerk, timeout=5)


'''
conn.sendto(did=SUPERYDID, cid=0x20, data=b"hello! How do you do!\n")

sleep(0.1) # Time in seconds.
'''

while (1):
	rtn = conn.getpacks()
	print (rtn)
	for pack in rtn:
		if(pack['cid'] == 33):
			conn.swdevsvr(pack["did"], "www.hehe.com")

del conn
