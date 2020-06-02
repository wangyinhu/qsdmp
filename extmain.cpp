#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "qezcli.h"
#include "Ylog.h"
#include "Ylib.h"


Ylog yglog("qsdmppyext");

static PyObject *QsdmpPyClientError;

struct QsdmpPyClient{
	PyObject_HEAD
	qezcli *cli = nullptr;
};


static PyObject *QsdmpPyClient_new(PyTypeObject * type, PyObject * args, PyObject * kwds) {
	auto self = (QsdmpPyClient *) type->tp_alloc(type, 0);
	if (self == NULL) {
		return NULL;
	}

	static const char *kwlist[] = {"host", "port", "did", "cid", "devk", "cok", "timeout", "sockettype", NULL};
	char *host = 0;
	int port;
	char *didc = 0;
	int cid;
	uint8_t *devk = 0;
    Py_ssize_t devklen;
	uint8_t *cok = 0;
    Py_ssize_t coklen;
	int timeout;
	static const char TCP[] = "TCP";
	const char *socketType = TCP;
	if (PyArg_ParseTupleAndKeywords(args, kwds, "sisis#s#i|s;", (char **) kwlist, &host, &port, &didc, &cid, &devk,
									&devklen, &cok, &coklen, &timeout, &socketType)) {
		if ((devklen >= 16) && (coklen >= 16)) {
			DID_Type did;
			hex2raw((uint8_t *) &did, didc, 16);
			self->cli = new qezcli(host, port, did, cid, devk, cok, timeout);
			if (self->cli->Auth(socketType) == 0) {
				return (PyObject *) self;
			} else {
				delete self->cli;
				PyErr_SetString(QsdmpPyClientError, "connect or Auth fail\n");
			}
		}
	} else {
		PyErr_SetString(QsdmpPyClientError,
						"parameter error, keys: host(str), port(int), did(str), cid(int), devk(bstr), cok(bstr), timeout(int), sockettype(str)\n");
	}
	Py_TYPE(self)->tp_free((PyObject *) self);
	return NULL;
}

static void QsdmpCli_dealloc(QsdmpPyClient *self) {
	delete self->cli;
	Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *QsdmpSup_new(PyTypeObject * type, PyObject * args, PyObject * kwds) {
	auto self = (QsdmpPyClient *) type->tp_alloc(type, 0);
	if (self == NULL) {
		return NULL;
	}

	static const char *kwlist[] = {"host", "port", "devk", "cok", "timeout", "sockettype", NULL};
	char *host = 0;
	int port;
	uint8_t *devk = 0;
    Py_ssize_t devklen;
	uint8_t *cok = 0;
    Py_ssize_t coklen;
	int timeout;
	static const char TCP[] = "TCP";
	const char *socketType = TCP;

	if (PyArg_ParseTupleAndKeywords(args, kwds, "sis#s#i|s;", (char **) kwlist, &host, &port, &devk, &devklen, &cok,
									&coklen, &timeout, &socketType)) {
		if ((devklen >= 16) && (coklen >= 16)) {
			self->cli = new qezcli(host, port, 3, 0x20, devk, cok, timeout);
			if (self->cli->Auth(socketType) == 0) {
				return (PyObject *) self;
			} else {
				delete self->cli;
				PyErr_SetString(QsdmpPyClientError, "connect or Auth fail\n");
			}
		}
	} else {
		PyErr_SetString(QsdmpPyClientError, "parameter error, keys: host(str), port(int), devk(bstr), cok(bstr), timeout(int), sockettype(str)\n");
	}
	Py_TYPE(self)->tp_free((PyObject *) self);
	return NULL;
}

static void QsdmpSup_dealloc(QsdmpPyClient *self) {
	delete self->cli;
	Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *sendto_func(QsdmpPyClient *self, PyObject *args, PyObject *kwds) {
	static const char *kwlist[] = {"did", "cid", "data", "sessionID", NULL};
	char *didc = 0;
	int cid;
	uint8_t *data = 0;
    Py_ssize_t datalen;
	int sessionID;
	if (PyArg_ParseTupleAndKeywords(args, kwds, "sis#i;", (char **) kwlist, &didc, &cid, &data, &datalen, &sessionID)) {
		DID_Type did;
		hex2raw((uint8_t *) &did, didc, 16);
		if (YPA_NULL == self->cli->sendto(did, cid, data, datalen, sessionID)) {
			return PyLong_FromLong(0);
		} else {
			PyErr_SetString(QsdmpPyClientError, "fail to send data\n");
			return NULL;
		}

	} else {
		return NULL;
	}
}

static PyObject *transceive_func(QsdmpPyClient *self, PyObject *args, PyObject *kwds) {
	static const char *kwlist[] = {"did", "cid", "data", "sessionID", NULL};
	char *didc = 0;
	int cid;
	uint8_t *data = 0;
    Py_ssize_t datalen;
	int sessionID;
	if (PyArg_ParseTupleAndKeywords(args, kwds, "sis#i;", (char **) kwlist, &didc, &cid, &data, &datalen, &sessionID)) {
		DID_Type did;
		hex2raw((uint8_t *) &did, didc, 16);
		if (YPA_NULL == self->cli->sendto(did, cid, data, datalen, sessionID)) {
			std::list<Ypack<0xFF0> *> packlist;

			if (YPA_NULL == self->cli->getpacks(packlist, YPA_NMPACKGOT)) {
				PyObject* packdict = nullptr;
				for (auto &i : packlist) {
					char didhex[20];
                    Py_ssize_t dl;
					raw2hex(didhex, (uint8_t *) &i->did, 8);
					packdict = Py_BuildValue("{s:s,s:i,s:y#,s:i}", "did", didhex, "cid", i->cid, "data", (char *) i->data,
												  &dl, "sessionID", i->sessionID);
                    i->CBC_lowLen = dl;
					delete i;
				}
				if(packdict) {
//					Py_DECREF(packdict);
					return packdict;
				} else {
					Py_RETURN_NONE;
				}
			} else {
				PyErr_SetString(QsdmpPyClientError, "get pack error, remote close or decryption fail.\n");
				return NULL;
			}
		} else {
			PyErr_SetString(QsdmpPyClientError, "fail to send data\n");
			return NULL;
		}

	} else {
		return NULL;
	}
}

static PyObject *sws_func(QsdmpPyClient *self, PyObject *args, PyObject *kwds) {
	static const char *kwlist[] = {"did", "server", NULL};
	char *didc = 0;
	char *serverc = 0;

	if (PyArg_ParseTupleAndKeywords(args, kwds, "ss;", (char **) kwlist, &didc, &serverc)) {
		DID_Type did;
		hex2raw((uint8_t *) &did, didc, 16);
		auto rtn = self->cli->switchdevsvr(did, serverc);
		if (0 == rtn) {
			return PyLong_FromLong(0);
		} else if (1 == rtn) {
			return PyLong_FromLong(1);
		} else {
			PyErr_SetString(QsdmpPyClientError, "fail to \n");
			return NULL;
		}

	} else {
		return NULL;
	}
}

static PyObject *udk_func(QsdmpPyClient *self, PyObject *args, PyObject *kwds) {
	static const char *kwlist[] = {"did", "aesk", NULL};
	char *didc = 0;
	uint8_t *aesk = 0;
    Py_ssize_t aesklen = 0;

	if (PyArg_ParseTupleAndKeywords(args, kwds, "ss#;", (char **) kwlist, &didc, &aesk, &aesklen)) {
		if (aesklen != DEVAESKSIZE) {
			PyErr_SetString(QsdmpPyClientError, "aesk length is not valide\n");
			return NULL;
		}
		DID_Type did;
		hex2raw((uint8_t *) &did, didc, 16);
		auto rtn = self->cli->updatedevK(did, aesk);
		if (0 == rtn) {
			return PyLong_FromLong(0);
		} else if (1 == rtn) {
			return PyLong_FromLong(1);
		} else {
			PyErr_SetString(QsdmpPyClientError, "fail to \n");
			return NULL;
		}

	} else {
		return NULL;
	}
}

static PyObject *setCliloglevel_func(QsdmpPyClient *self, PyObject *args, PyObject *kwds) {
	static const char *kwlist[] = {"level", NULL};

	int loglevel = 0;

	if (PyArg_ParseTupleAndKeywords(args, kwds, "i;", (char **) kwlist, &loglevel)) {
		if (loglevel < 0) {
			PyErr_SetString(QsdmpPyClientError, "level parameter is not valide\n");
			return NULL;
		}
		LOGLVLSET((yloglevel)loglevel);
		return PyLong_FromLong(0);
	} else {
		return NULL;
	}
}

static PyObject *setSvrloglevel_func(QsdmpPyClient *self, PyObject *args, PyObject *kwds) {
	static const char *kwlist[] = {"level", NULL};

	int loglevel = 0;

	if (PyArg_ParseTupleAndKeywords(args, kwds, "i;", (char **) kwlist, &loglevel)) {
		if (loglevel < 0) {
			PyErr_SetString(QsdmpPyClientError, "level parameter is not valide\n");
			return NULL;
		}
		auto rtn = self->cli->setLogLevel((yloglevel)loglevel);
		if (0 == rtn) {
			return PyLong_FromLong(0);
		} else if (1 == rtn) {
			return PyLong_FromLong(1);
		} else {
			PyErr_SetString(QsdmpPyClientError, "fail to \n");
			return NULL;
		}

	} else {
		return NULL;
	}
}

static PyObject *did_addr_build_dict(uint64_t dids[], char ipaddresses[][16], int length) {
	PyObject * d = PyDict_New();
	char hexdid[20];
	for (int i = 0; i < length; i++) {
		raw2hex(hexdid, (uint8_t *) &dids[i], 8);
		if(strlen(ipaddresses[i])){
			PyDict_SetItem(d, PyUnicode_FromString(hexdid), PyUnicode_FromString(ipaddresses[i]));
		} else{
			PyDict_SetItem(d, PyUnicode_FromString(hexdid), Py_None);
		}
	}
	return d;
}


static PyObject *did_status_build_dict(uint64_t dids[], uint8_t * statusArray, int length) {
	PyObject * d = PyDict_New();
	char hexdid[20];
	for (int i = 0; i < length; i++) {
		raw2hex(hexdid, (uint8_t *) &dids[i], 8);
		PyDict_SetItem(d, PyUnicode_FromString(hexdid), PyBool_FromLong(statusArray[i]));
	}
	return d;
}


static PyObject *queryip_func(QsdmpPyClient *self, PyObject *args, PyObject *kwds) {
	static const char *kwlist[] = {"dids", "sessionID", NULL};

	PyObject * didObj = nullptr;
	uint32_t sessionID;

	if (not PyArg_ParseTupleAndKeywords(args, kwds, "Oi;", (char **) kwlist, &didObj, &sessionID)) {
		return nullptr;
	}
	if (PyUnicode_Check(didObj)) {
		auto hex_did = (char *) PyUnicode_DATA(didObj);
		uint64_t did;
		char IPaddress[16] = "";
		if (strlen(hex_did) == 16) {
			hex2raw((uint8_t *) &did, hex_did, 16);
		} else {
			printf("warning! given='%s' must have length=16\n", hex_did);
			did = 0;
			return did_addr_build_dict(&did, &IPaddress, 1);
		}
		if (0 == self->cli->queryIP(&did, &IPaddress, 1, sessionID)) {
			return did_addr_build_dict(&did, &IPaddress, 1);
		} else {
			PyErr_SetString(QsdmpPyClientError, "failed\n");
			return nullptr;
		}
	} else if (PySequence_Check(didObj)) {
		auto arglen = PySequence_Size(didObj);
		uint64_t dids[arglen];
		char IPaddress_array[arglen][16];
		for (Py_ssize_t i = 0; i < arglen; i++) {
			auto op = PySequence_GetItem(didObj, i);
			if (PyUnicode_Check(op)) {
				auto hex_did = (char *) PyUnicode_DATA(op);

				if (strlen(hex_did) == 16) {
					hex2raw((uint8_t *) (dids + i), hex_did, 16);
				} else {
					printf("warning! given element(index=%ld)='%s' must have length=16\n", i, hex_did);
					dids[i] = 0;
				}
			} else if (PyLong_Check(op)) {
				dids[i] = PyLong_AsUnsignedLong(op);
			} else {
				printf("warning! given element(index=%ld) type error! must be a number or a 16 byte string\n", i);
				dids[i] = 0;
			}
		}
		if (arglen == 0) {
			return did_addr_build_dict(nullptr, nullptr, 0);
		} else if (0 == self->cli->queryIP(dids, IPaddress_array, arglen, sessionID)) {
			return did_addr_build_dict(dids, IPaddress_array, arglen);
		} else {
			PyErr_SetString(QsdmpPyClientError, "failed\n");
			return nullptr;
		}

	} else if (PyLong_Check(didObj)) {
		char IPaddress[16];
		uint64_t did = PyLong_AsUnsignedLong(didObj);
		if (0 == self->cli->queryIP(&did, &IPaddress, 1, sessionID)) {
			return did_addr_build_dict(&did, &IPaddress, 1);
		} else {
			PyErr_SetString(QsdmpPyClientError, "failed\n");
			return nullptr;
		}

	} else if (Py_None == didObj) {
		uint64_t did = 0;
		char ipaddress[16] = "";
		return did_addr_build_dict(&did, &ipaddress, 1);

	} else {
//			if (PyBytes_Check(didObj)) {
//			printf("arg is py bytes\n");
//			Py_RETURN_NONE;
//
//		} else
		printf("warning! did/dids parameter type should be either number or hex string length=16\n");
		return did_addr_build_dict(nullptr, nullptr, 0);
	}
}

static PyObject *querystatus_func(QsdmpPyClient *self, PyObject *args, PyObject *kwds) {
	static const char *kwlist[] = {"dids", "sessionID", NULL};

	PyObject * didObj = nullptr;
	uint32_t sessionID;

	if (not PyArg_ParseTupleAndKeywords(args, kwds, "Oi;", (char **) kwlist, &didObj, &sessionID)) {
		return nullptr;
	}
	if (PyUnicode_Check(didObj)) {
		auto hex_did = (char *) PyUnicode_DATA(didObj);
		uint64_t did;
		uint8_t status = 0;
		if (strlen(hex_did) == 16) {
			hex2raw((uint8_t *) &did, hex_did, 16);
		} else {
			printf("warning! given='%s' must have length=16\n", hex_did);
			did = 0;
			return did_status_build_dict(&did, &status, 1);
		}
		if (0 == self->cli->queryStatus(&did, &status, 1, sessionID)) {
			return did_status_build_dict(&did, &status, 1);
		} else {
			PyErr_SetString(QsdmpPyClientError, "failed\n");
			return nullptr;
		}
	} else if (PySequence_Check(didObj)) {
		auto arglen = PySequence_Size(didObj);
		uint64_t dids[arglen];
		uint8_t statusArray[arglen];
		for (Py_ssize_t i = 0; i < arglen; i++) {
			auto op = PySequence_GetItem(didObj, i);
			if (PyUnicode_Check(op)) {
				auto hex_did = (char *) PyUnicode_DATA(op);

				if (strlen(hex_did) == 16) {
					hex2raw((uint8_t *) (dids + i), hex_did, 16);
				} else {
					printf("warning! given element(index=%ld)='%s' must have length=16\n", i, hex_did);
					dids[i] = 0;
				}
			} else if (PyLong_Check(op)) {
				dids[i] = PyLong_AsUnsignedLong(op);
			} else {
				printf("warning! given element(index=%ld) type error! must be a number or a 16 byte string\n", i);
				dids[i] = 0;
			}
		}
		if (arglen == 0) {
			return did_status_build_dict(nullptr, nullptr, 0);
		} else if (0 == self->cli->queryStatus(dids, statusArray, arglen, sessionID)) {
			return did_status_build_dict(dids, statusArray, arglen);
		} else {
			PyErr_SetString(QsdmpPyClientError, "failed\n");
			return nullptr;
		}

	} else if (PyLong_Check(didObj)) {
		uint8_t status = 0;
		uint64_t did = PyLong_AsUnsignedLong(didObj);
		if (0 == self->cli->queryStatus(&did, &status, 1, sessionID)) {
			return did_status_build_dict(&did, &status, 1);
		} else {
			PyErr_SetString(QsdmpPyClientError, "failed\n");
			return nullptr;
		}

	} else if (Py_None == didObj) {
		uint64_t did = 0;
		uint8_t status = 0;
		return did_status_build_dict(&did, &status, 1);

	} else {
//			if (PyBytes_Check(didObj)) {
//			printf("arg is py bytes\n");
//			Py_RETURN_NONE;
//
//		} else
		printf("warning! did/dids parameter type should be either number or hex string length=16\n");
		return did_status_build_dict(nullptr, nullptr, 0);
	}
}

static PyObject *getnodecount_func(QsdmpPyClient *self) {
	auto rtn = self->cli->getnodecount();
	if (0 <= rtn) {
		return PyLong_FromLong(rtn);
	} else {
		PyErr_SetString(QsdmpPyClientError, "fail to \n");
		return NULL;
	}
}

static PyObject *getpackercount_func(QsdmpPyClient *self) {
	auto rtn = self->cli->getpackercount();
	if (0 <= rtn) {
		return PyLong_FromLong(rtn);
	} else {
		PyErr_SetString(QsdmpPyClientError, "fail to \n");
		return NULL;
	}
}

static PyObject *loadcidroms_func(QsdmpPyClient *self, PyObject *args, PyObject *kwds) {
	static const char *kwlist[] = {"cid", NULL};

	int cid = 0;

	if (PyArg_ParseTupleAndKeywords(args, kwds, "I;", (char **) kwlist, &cid)) {
		auto rtn = self->cli->loadcidroms((uint8_t)cid);
		if (rtn < 0) {
			Py_RETURN_FALSE;
		} else {
			return PyLong_FromLong(rtn);
		}

	} else {
		return NULL;
	}
}

static PyObject *loadcidmakers_func(QsdmpPyClient *self) {
	auto rtn = self->cli->loadcidmakers();
	if (rtn < 0) {
		Py_RETURN_FALSE;
	} else {
		Py_RETURN_TRUE;
	}
}

static PyObject *getaomsgload1s_func(QsdmpPyClient *self) {
	auto rtn = self->cli->getaomsgload1s();
	if (0 <= rtn) {
		return PyLong_FromLong(rtn);
	} else {
		PyErr_SetString(QsdmpPyClientError, "fail to \n");
		return NULL;
	}
}

static PyObject *send_func(QsdmpPyClient *self, PyObject *args, PyObject *kwds) {
	static const char *kwlist[] = {"data", "sessionID", NULL};
	uint8_t *data = 0;
    Py_ssize_t datalen;
	int sessionID;
	if (PyArg_ParseTupleAndKeywords(args, kwds, "s#i;", (char **) kwlist, &data, &datalen, &sessionID)) {
		if (YPA_NULL == self->cli->send(data, datalen, sessionID)) {
			return PyLong_FromLong(0);
		} else {
			PyErr_SetString(QsdmpPyClientError, "fail to send data\n");
			return NULL;
		}

	} else {
		return NULL;
	}
}

static PyObject *evtReg_func(QsdmpPyClient *self, PyObject *args) {
	if (0 == self->cli->evtReg()) {
		Py_RETURN_NONE;
	} else {
		PyErr_SetString(QsdmpPyClientError, "fail regist for event message\n");
		return NULL;
	}
}

static PyObject *msgloadlogenable_func(QsdmpPyClient *self, PyObject *args) {
	if (0 == self->cli->msgloadlogenable()) {
		Py_RETURN_NONE;
	} else {
		PyErr_SetString(QsdmpPyClientError, "fail\n");
		return NULL;
	}
}

static PyObject *msgloadlogdisable_func(QsdmpPyClient *self, PyObject *args) {
	if (0 == self->cli->msgloadlogdisable()) {
		Py_RETURN_NONE;
	} else {
		PyErr_SetString(QsdmpPyClientError, "fail\n");
		return NULL;
	}
}

static PyObject *getnmpack_func(QsdmpPyClient *self) {
	std::list<Ypack<0xFF0> *> packlist;

	if (YPA_NULL == self->cli->getpacks(packlist, YPA_NMPACKGOT)) {
		auto returnlist = PyList_New(0);
		for (auto &i : packlist) {
			char didhex[20];
            Py_ssize_t dl;
			raw2hex(didhex, (uint8_t *) &i->did, 8);
			auto packdict = Py_BuildValue("{s:s,s:i,s:y#,s:i}", "did", didhex, "cid", i->cid, "data", (char *) i->data,
										  &dl, "sessionID", i->sessionID);
            i->CBC_lowLen = dl;
			PyList_Append(returnlist, packdict);
			Py_DECREF(packdict);
			delete i;
		}
		return returnlist;
	} else {
		PyErr_SetString(QsdmpPyClientError, "get pack error, remote close or decryption fail.\n");
		return NULL;
	}
}

static PyObject *getmypack_func(QsdmpPyClient *self) {
	std::list<Ypack<0xFF0> *> packlist;

	if (YPA_NULL == self->cli->getpacks(packlist, YPA_MYPACKGOT)) {
		auto returnlist = PyList_New(0);
		for (auto &i : packlist) {
			char didhex[20];
            Py_ssize_t dl;
			raw2hex(didhex, (uint8_t *) &i->did, 8);
			auto packdict = Py_BuildValue("{s:s,s:i,s:y#,s:i}", "did", didhex, "cid", i->cid, "data", (char *) i->data,
										  &dl, "sessionID", i->sessionID);
            i->CBC_lowLen = dl;
			PyList_Append(returnlist, packdict);
			Py_DECREF(packdict);
			delete i;
		}
		return returnlist;
	} else {
		PyErr_SetString(QsdmpPyClientError, "get pack error, remote close or decryption fail.\n");
		return NULL;
	}
}

static PyMethodDef QsdmpCli_PyMethods[] = {
		{"send",     (PyCFunction) send_func,      METH_VARARGS |
												   METH_KEYWORDS, "send data to init did, cid"},
		{"getpacks", (PyCFunction) getmypack_func, METH_NOARGS, "get pack from server push"},
		{"setCliLogLevel",    (PyCFunction) setCliloglevel_func,       METH_VARARGS |
																	   METH_KEYWORDS, "set client log level"},
		{nullptr,    nullptr, 0,                                nullptr}  /* Sentinel */
};

static PyTypeObject QsdmpCli_PyClass = {
		PyVarObject_HEAD_INIT(nullptr, 0)
		"Qsdmp.client",             /* tp_name */
		sizeof(QsdmpPyClient),             /* tp_basicsize */
		0,                         /* tp_itemsize */
		(destructor) QsdmpCli_dealloc, /* tp_dealloc */
		0,                              /* tp_print */
		nullptr,                         /* tp_getattr */
		nullptr,                         /* tp_setattr */
		nullptr,                         /* tp_reserved */
		nullptr,                         /* tp_repr */
		nullptr,                         /* tp_as_number */
		nullptr,                         /* tp_as_sequence */
		nullptr,                         /* tp_as_mapping */
		nullptr,                         /* tp_hash  */
		nullptr,                         /* tp_call */
		nullptr,                         /* tp_str */
		nullptr,                         /* tp_getattro */
		nullptr,                         /* tp_setattro */
		nullptr,                         /* tp_as_buffer */
		Py_TPFLAGS_DEFAULT |
		Py_TPFLAGS_BASETYPE,   			 /* tp_flags */
		"Qsdmp protocol device client",  /* tp_doc */
		nullptr,                         /* tp_traverse */
		nullptr,                         /* tp_clear */
		nullptr,                         /* tp_richcompare */
		0,                         		 /* tp_weaklistoffset */
		nullptr,                         /* tp_iter */
		nullptr,                         /* tp_iternext */
		QsdmpCli_PyMethods,              /* tp_methods */
		nullptr,                         /* tp_members */
		nullptr,                         /* tp_getset */
		nullptr,                         /* tp_base */
		nullptr,                         /* tp_dict */
		nullptr,                         /* tp_descr_get */
		nullptr,                         /* tp_descr_set */
		0,                         /* tp_dictoffset */
		nullptr,                           /* tp_init */
		nullptr,                         /* tp_alloc */
		QsdmpPyClient_new,                 /* tp_new */
		nullptr,                            //freefunc tp_free; /* Low-level free-memory routine */
		nullptr,                            //inquiry tp_is_gc; /* For PyObject_IS_GC */
		nullptr,                            //PyObject *tp_bases;
		nullptr,                            //PyObject *tp_mro; /* method resolution order */
		nullptr,                            //PyObject *tp_cache;
		nullptr,                            //PyObject *tp_subclasses;
		nullptr,                            //PyObject *tp_weaklist;
		nullptr,                            //destructor tp_del;
		0,                            //unsigned int tp_version_tag;
		nullptr,                            //destructor tp_finalize;
};

static PyMethodDef QsdmpSup_PyMethods[] = {
		{"sendto",         (PyCFunction) sendto_func,            METH_VARARGS |
																 METH_KEYWORDS, "send data to specified did, cid"},
		{"transceive",     (PyCFunction) transceive_func,        METH_VARARGS |
																 METH_KEYWORDS, "send and receive data"},
		{"swdevsvr",       (PyCFunction) sws_func,               METH_VARARGS |
																 METH_KEYWORDS, "switch device server address"},
		{"updatedevk",     (PyCFunction) udk_func,               METH_VARARGS |
																 METH_KEYWORDS, "update device aes key"},
		{"setSvrLogLevel",    (PyCFunction) setSvrloglevel_func,       METH_VARARGS |
																 METH_KEYWORDS, "set server log level"},
		{"setCliLogLevel",    (PyCFunction) setCliloglevel_func,       METH_VARARGS |
																 METH_KEYWORDS, "set client log level"},
		{"queryip",        (PyCFunction) queryip_func,           METH_VARARGS |
																 METH_KEYWORDS, "query ip address of given did/dids"},
		{"querystatus",    (PyCFunction) querystatus_func,       METH_VARARGS |
																 METH_KEYWORDS, "query link status of given did/dids"},
		{"loadcidroms",    (PyCFunction) loadcidroms_func,       METH_VARARGS |
																 METH_KEYWORDS, "load device ota rom "},
		{"loadcidmakers",  (PyCFunction) loadcidmakers_func,     METH_NOARGS, "load device flpu maker"},
		{"getpacks",       (PyCFunction) getnmpack_func,         METH_NOARGS, "get pack from server push"},
		{"getnodecount",   (PyCFunction) getnodecount_func,      METH_NOARGS, "get node count of the connected server"},
		{"getpackercount", (PyCFunction) getpackercount_func,    METH_NOARGS, "get packer count of the connected server"},
		{"getload1s",      (PyCFunction) getaomsgload1s_func,    METH_NOARGS, "get massage load of the server connected in last 1s"},
		{"evtReg",         (PyCFunction) evtReg_func,            METH_NOARGS, "regist event push"},
		{"enableloadlog",  (PyCFunction) msgloadlogenable_func,  METH_NOARGS, "enable massage load log"},
		{"disableloadlog", (PyCFunction) msgloadlogdisable_func, METH_NOARGS, "disable massage load log"},
		{nullptr,          nullptr, 0,                                        nullptr}  /* Sentinel */
};

static PyTypeObject QsdmpSup_PyClass = {
		PyVarObject_HEAD_INIT(nullptr, 0)
		"Qsdmp.super",             /* tp_name */
		sizeof(QsdmpPyClient),             /* tp_basicsize */
		0,                         /* tp_itemsize */
		(destructor) QsdmpSup_dealloc, /* tp_dealloc */
		0,                               /* tp_print */
		nullptr,                         /* tp_getattr */
		nullptr,                         /* tp_setattr */
		nullptr,                         /* tp_reserved */
		nullptr,                         /* tp_repr */
		nullptr,                         /* tp_as_number */
		nullptr,                         /* tp_as_sequence */
		nullptr,                         /* tp_as_mapping */
		nullptr,                         /* tp_hash  */
		nullptr,                         /* tp_call */
		nullptr,                         /* tp_str */
		nullptr,                         /* tp_getattro */
		nullptr,                         /* tp_setattro */
		nullptr,                         /* tp_as_buffer */
		Py_TPFLAGS_DEFAULT |
		Py_TPFLAGS_BASETYPE,   /* tp_flags */
		"Qsdmp protocol super client",           /* tp_doc */
		nullptr,                         /* tp_traverse */
		nullptr,                         /* tp_clear */
		nullptr,                         /* tp_richcompare */
		0,                         /* tp_weaklistoffset */
		nullptr,                         /* tp_iter */
		nullptr,                         /* tp_iternext */
		QsdmpSup_PyMethods,             /* tp_methods */
		nullptr,                       /* tp_members */
		nullptr,                         /* tp_getset */
		nullptr,                         /* tp_base */
		nullptr,                         /* tp_dict */
		nullptr,                         /* tp_descr_get */
		nullptr,                         /* tp_descr_set */
		0,                         /* tp_dictoffset */
		nullptr,                           /* tp_init */
		nullptr,                         /* tp_alloc */
		QsdmpSup_new,                 /* tp_new */
		nullptr,                            //freefunc tp_free; /* Low-level free-memory routine */
		nullptr,                            //inquiry tp_is_gc; /* For PyObject_IS_GC */
		nullptr,                            //PyObject *tp_bases;
		nullptr,                            //PyObject *tp_mro; /* method resolution order */
		nullptr,                            //PyObject *tp_cache;
		nullptr,                            //PyObject *tp_subclasses;
		nullptr,                            //PyObject *tp_weaklist;
		nullptr,                            //destructor tp_del;
		0,                            //unsigned int tp_version_tag;
		nullptr,                            //destructor tp_finalize;
};

static PyModuleDef QsdmpModule = {
		PyModuleDef_HEAD_INIT,
		"Qsdmp",
		"Qsdmp protocol client.",
		-1,
		nullptr, nullptr, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit_QsdmpPyClient(void) {
	PyObject * MainModule = PyModule_Create(&QsdmpModule);
	if (MainModule == NULL)
		return NULL;

	if (PyType_Ready(&QsdmpCli_PyClass) < 0) return NULL;

	Py_INCREF(&QsdmpCli_PyClass);

	if (PyType_Ready(&QsdmpSup_PyClass) < 0) return NULL;

	Py_INCREF(&QsdmpSup_PyClass);

	QsdmpPyClientError = PyErr_NewException("Qsdmp.error", NULL, NULL);
	Py_INCREF(QsdmpPyClientError);

	PyModule_AddObject(MainModule, "client", (PyObject *) &QsdmpCli_PyClass);
	PyModule_AddObject(MainModule, "super", (PyObject *) &QsdmpSup_PyClass);
	PyModule_AddObject(MainModule, "error", QsdmpPyClientError);
	return MainModule;
}