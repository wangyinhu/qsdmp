#!/usr/bin/env python3

from time import sleep
import sys
from secure import *

sys.path.append('./cmake-build-debug')
import QsdmpPyClient

if len(sys.argv) == 2 and sys.argv[1] == 'l':
	host = 'localhost'

conn = QsdmpPyClient.client(host=host, port=2005, did=DEVDID2, cid=0x21, devk=devdk, cok=headerk, timeout=5)

conn.send(b"hello! How do you do!\n", 4321)

while (1):
	rtn = conn.getpacks()
	print (rtn)
	conn.send(b"hello! How do you do!\n", sessionID=1234)

del conn
