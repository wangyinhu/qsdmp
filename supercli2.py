#!/usr/bin/env python3

import sys
from secure import *

sys.path.append('./cmake-build-debug')
import QsdmpPyClient

if len(sys.argv) == 2 and sys.argv[1] == 'l':
	host = 'localhost'

conn = QsdmpPyClient.super(host=host, port=2005, devk=superdk, cok=headerk, timeout=5)

result = conn.disableloadlog()
print('getload1s = ', result)

del conn
