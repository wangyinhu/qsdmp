#ifndef SUPERCMDS_H
#define SUPERCMDS_H

#include <stdint.h>

using SUPERCMD_TYPE = uint16_t;

enum : SUPERCMD_TYPE {
	SUPERIFCMD_NULL = 0,                //NULL
	SUPERIFCMD_SWSVR,                    //Switch dev server request
	SUPERIFCMD_UPDTK,                    //Update devk
	SUPERIFCMD_EVTREG,                    //Event register
	SUPERIFCMD_MSGREG,                    //Message register
	SUPERIFCMD_GETPS,                    //Get packtable size
	SUPERIFCMD_SETPL,                    //Set packtable size limit
	SUPERIFCMD_GETNS,                    //Get nodeTable size
	SUPERIFCMD_SETNL,                    //Set nodeTable size limit
	SUPERIFCMD_SETLOGLVL,                //Set log level
	SUPERIFCMD_GETLOGLVL,                //Get log level
	SUPERIFCMD_GETAOMSGLOAD1S,            //Get all over message load
	SUPERIFCMD_SETMLOADLOGEN,            //Set all over message load log enable
	SUPERIFCMD_SETMLOADLOGDS,            //Set all over message load log disable
	SUPERIFCMD_QUERYIP,                //query devices ip addresses
	SUPERIFCMD_QUERYSTATE,                //query devices states
	SUPERIFCMD_GET1SMAXEVT,                        //
	SUPERIFCMD_LOADCIDROMS,                        //
	SUPERIFCMD_LOADCIDMAKERS,                        //
	SUPERIFCMD_,                        //
	SUPERIFCMD_TOP,                    //
	SUPERIFCMD_ERRMASK = 0X8000,            //
};


#endif //SUPERCMDS_H