#!/usr/bin/env python3
import re, readline, sys, time, signal
from secure import *
from clicmds import COMMANDS, functions

sys.path.append('./cmake-build-debug')
import QsdmpPyClient


inputstart = '\x1b[32;1m>>>\x1b[0m '
RE_SPACE = re.compile('.*\s+$', re.M)

if len(sys.argv) == 2 and sys.argv[1] == 'l':
	host = 'localhost'

def signal_handler(signal, frame):
	# print('\nplease type exit or quit\n' + inputstart)
	print("\r")
	sys.exit(0)


def complete(text, state):
	"Generic readline completion entry point."
	# print ('hehe')
	buffer = readline.get_line_buffer()
	line = readline.get_line_buffer().split()
	# show all commands
	if not line:
		return [c + ' ' for c in COMMANDS][state]
	# account for last argument ending in a space
	if RE_SPACE.match(buffer):
		line.append('')
	# resolve command to the implementation function
	cmd = line[0].strip()
	if cmd in COMMANDS:
		impl = getattr('complete_%s' % cmd)
		args = line[1:]
		if args:
			return (impl(args) + [None])[state]
		return [cmd + ' '][state]
	results = [c + ' ' for c in COMMANDS if c.startswith(cmd)] + [None]
	return results[state]


signal.signal(signal.SIGINT, signal_handler)

print("Qsdmp server testing...")

testconn = QsdmpPyClient.super(host=host, port=port, devk=superdk, cok=headerk, timeout=5)

del testconn

print("Qsdmp server test \x1b[32;1mOK!\x1b[0m")

readline.set_completer_delims(' \t\n;')
readline.parse_and_bind("tab: complete")
readline.set_completer(complete)
while (1):
	indata = input(inputstart)
	inlist = indata.split()
	if (len(inlist) < 1):
		continue

	if (inlist[0] == "quit" or inlist[0] == "exit"):
		break
	elif (inlist[0] in functions.keys()):
		if inlist[0] not in ("help", ):
			conn = QsdmpPyClient.super(host=host, port=port, devk=superdk, cok=headerk, timeout=5)
		else:
			conn = None
		functions[inlist[0]](conn, inlist[1:])
	else:
		print("\x1b[33;1merror! unknow command.\x1b[0m type \x1b[32;1mhelp\x1b[0m for help.")










