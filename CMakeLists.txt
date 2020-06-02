cmake_minimum_required(VERSION 3.10)
project(qsdmp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE RELEASE)


# --------------qsdmpd-----------------
add_executable(qsdmpd
		Absflpu.cpp
		FLPUdefault.cpp
		dglobal.cpp
		dmain.cpp
		Dnode.cpp
		Dpacker.cpp
		QsdmpSvr.cpp
		Ypoller.cpp
		rediscli.cpp
		Yage.cpp
		Ylib.cpp
		Ylog.cpp
		Ypacker.cpp
		sbvector.cpp
		supercmds.h
		encryption.cpp
		encryption.h
#		configuru.hpp
		UDPPeer.cpp
		UDPPeer.h)

set_target_properties(qsdmpd
		PROPERTIES COMPILE_FLAGS "-mrdrnd -Wall -Wextra -g")

target_link_libraries(qsdmpd
		PUBLIC crypto
		PUBLIC dl
		PUBLIC hiredis
		)

add_dependencies(qsdmpd
		FLPUdefault)


## --------------qsdmp_fcgi-----------------
#add_executable(qsdmp_fcgi
#		fcgiglobal.cpp
#		fcgimain.cpp
#		QsdmpCli.cpp
#		qezcli.cpp
#		rediscli.cpp
#		Yage.cpp
#		Ylib.cpp
#		Ylog.cpp
#		Ypacker.cpp
#		supercmds.h encryption.cpp encryption.h)
#
#set_target_properties(qsdmp_fcgi
#		PROPERTIES COMPILE_FLAGS "-mrdrnd -Wextra -Wall -g")
#
#target_link_libraries(qsdmp_fcgi
#		PUBLIC crypto
#		PUBLIC curl
#		PUBLIC hiredis
#		PUBLIC fcgi
#		)
#
#
# --------------FLPUdefault-----------------
add_library(FLPUdefault MODULE
		Absflpu.cpp
		Ylib.cpp
		Ylog.cpp
		FLPUdefault.cpp)

set_target_properties(FLPUdefault
		PROPERTIES COMPILE_FLAGS "-Wall -Wextra -fPIC -g"
		PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/FLPU_plugins
		PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/FLPU_plugins
		PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/FLPU_plugins
		PROPERTIES PREFIX ""
		)

target_compile_definitions(FLPUdefault
		PRIVATE FLPU_BUILD_FLAG
		)


# --------------FLPUcharger-----------------
add_library(FLPUcharger MODULE
		Absflpu.cpp
		Ylib.cpp
		Ylog.cpp
		FLPUcharger.cpp
		IAPserver.cpp)

set_target_properties(FLPUcharger
		PROPERTIES COMPILE_FLAGS "-Wall -Wextra -fPIC -g"
		PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/FLPU_plugins
		PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/FLPU_plugins
		PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/FLPU_plugins
		PROPERTIES PREFIX ""
		)

#target_compile_definitions(FLPUcharger
#		PRIVATE FLPU_BUILD_FLAG
#		)

#target_link_libraries(FLPUcharger
#		PUBLIC z
#		)

# --------------QsdmpPyClient python-----------------
add_library(QsdmpPyClient MODULE
		extmain.cpp
		QsdmpCli.cpp
		qezcli.cpp
		Yage.cpp
		Ylib.cpp
		Ylog.cpp
		Ypacker.cpp
		sbvector.cpp
		supercmds.h encryption.cpp encryption.h)

set_target_properties(QsdmpPyClient
		PROPERTIES COMPILE_FLAGS "-mrdrnd -Wall -Wextra -fPIC -g")

target_link_libraries(QsdmpPyClient
		${PYTHON_LIBRARIES}
		PUBLIC crypto
		)

find_package (Python3 COMPONENTS Development)

target_include_directories(QsdmpPyClient PUBLIC
		${Python3_INCLUDE_DIRS})

set_target_properties(QsdmpPyClient
		PROPERTIES PREFIX ""
		)

set(TEST1DIR ${CMAKE_BINARY_DIR}/../../if4admin/api/QsdmpPyClient.so)
set(TEST2DIR ${CMAKE_BINARY_DIR}/../../qsdmproxy/QsdmpPyClient.so)
add_custom_command(TARGET QsdmpPyClient
		POST_BUILD
		COMMAND cp QsdmpPyClient.so ${TEST1DIR}
		COMMAND cp QsdmpPyClient.so ${TEST2DIR}
		)

