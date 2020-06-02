def getnodecount(conn, args):
	result = conn.getnodecount()
	print('node count = ' + str(result))


def getpackercount(conn, args):
	result = conn.getpackercount()
	print('packer count = ' + str(result))


def setCliLogLevel(conn, args):
	if len(args) == 1:
		try:
			loglevel = int(args[0])
			if (loglevel > 7 or loglevel < 0):
				print('argument out of range')
			else:
				result = conn.setCliLogLevel(loglevel)
				print('log level set to ' + str(loglevel) + ' successfully!')
		except:
			print('argument not digitail')
	else:
		print('argument number error!')


def setSvrLogLevel(conn, args):
	if len(args) == 1:
		try:
			loglevel = int(args[0])
			if (loglevel > 7 or loglevel < 0):
				print('argument out of range')
			else:
				result = conn.setSvrLogLevel(loglevel)
				print('log level set to ' + str(loglevel) + ' successfully!')
		except:
			print('argument not digitail')
	else:
		print('argument number error!')


def getload1s(conn, args):
	result = conn.getload1s()
	print('pack load in last second = ' + str(result))


def getpacks(conn, args):
	conn.evtReg()
	result = conn.getpacks()
	print('getpacks = ' + str(result))


def queryip(conn, args):
	if len(args) > 0:
		result = conn.queryip(args, 1)
		print(result)
	else:
		print('did not given\n')


# print('pack load in last second = ' + str(result))


def querystatus(conn, args):
	if len(args) > 0:
		result = conn.querystatus(args)
		print(result)
	else:
		print('did not given\n')


def enableloadlog(conn, args):
	result = conn.enableloadlog()
	if (result is None):
		print('load log enabled successfully')


def loadcidroms(conn, args):
	if len(args) == 1:
		result = conn.loadcidroms(int(args[0]))
		print(result)
	else:
		print('cid required')


def loadcidmakers(conn, args):
	if len(args) == 0:
		result = conn.loadcidmakers()
		print(result)
	else:
		print('need no parameters')


def sendto(conn, args):
	if len(args) == 4:
		data = eval(args[2])
		# print ("type(args[3])=" + str(type(args[3])) + "value=" + args[3])
		# print ("type(data)=" + str(type(data)) + "value=" + str(data))
		result = conn.sendto(args[0], int(args[1]), data, int(args[3]))
		print(result)
	# packs = conn.getpacks()
	# print (packs)
	# if len(packs):
	# 	print(packs[0]['data'].hex())
	else:
		print('need 4 parameters: cmd: did cid data sessionID')


def transceive(conn, args):
	if len(args) == 4:
		data = eval(args[2])
		# print ("type(args[2])=" + str(type(args[2])) + "value=" + args[2])
		# print ("type(data)=" + str(type(data)) + "value=" + str(data))
		result = conn.transceive(args[0], int(args[1]), data, int(args[3]))
		print(result)
		if result:
			print(result['data'].hex())
	else:
		print('need 4 parameters: cmd: did cid data sessionID')


def disableloadlog(conn, args):
	result = conn.disableloadlog()
	if (result is None):
		print('load log disabled successfully')


def help(conn, args):
	if len(args) == 0:
		print("Commands you can run:\n\x1b[36;1m" + '\n'.join('\t' + cmd for cmd in COMMANDS) + '\x1b[0m')
	else:
		print('arguments are not supported')


def __get_functions():
	dick = dict(globals())
	pop_keys = []
	for key in dick.keys():
		if key.startswith("__"):
			pop_keys.append(key)
	for key in pop_keys:
		dick.pop(key, None)

	return dick


COMMANDS = ["quit", "exit", "help"] + list(__get_functions().keys())


functions = __get_functions()

