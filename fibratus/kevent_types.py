# Copyright 2015 by Nedim Sabic (RabbitStack)
# http://rabbitstack.github.io
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from fibratus.errors import UnknownKeventTypeError
from fibratus.kevent import KEvents

"""
Kernel event types as determined by the GUID/opcode tuple
which is forwarded from the kernel event stream collector.
"""

# start process event
CREATE_PROCESS = ('3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c', 1)
# end process event
TERMINATE_PROCESS = ('3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c', 2)
# enum processes event
ENUM_PROCESS = ('3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c', 3)
# start thread event
CREATE_THREAD = ('3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c', 1)
# end thread event
TERMINATE_THREAD = ('3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c', 2)
# enum threads event
ENUM_THREAD = ('3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c', 3)

# create file event
CREATE_FILE = ('90cbdc39-4a3e-11d1-84f4-0000f80464e3', 64)
# delete file event
DELETE_FILE = ('90cbdc39-4a3e-11d1-84f4-0000f80464e3', 70)
# close file event generated when the file object is freed
CLOSE_FILE = ('90cbdc39-4a3e-11d1-84f4-0000f80464e3', 66)
# read file event
READ_FILE = ('90cbdc39-4a3e-11d1-84f4-0000f80464e3', 67)
# write file event
WRITE_FILE = ('90cbdc39-4a3e-11d1-84f4-0000f80464e3', 68)
# rename file event
RENAME_FILE = ('90cbdc39-4a3e-11d1-84f4-0000f80464e3', 71)
# enumerate directory event
ENUM_DIRECTORY = ('90cbdc39-4a3e-11d1-84f4-0000f80464e3', 72)

# disk read event
DISK_IO_READ = ('3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c', 10)
# disk write event
DISK_IO_WRITE = ('3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c', 11)

# create registry key event
REG_CREATE_KEY = ('ae53722e-c863-11d2-8659-00c04fa321a1', 10)
# create registry key event
REG_DELETE_KEY = ('ae53722e-c863-11d2-8659-00c04fa321a1', 12)
# delete registry value event
REG_DELETE_VALUE = ('ae53722e-c863-11d2-8659-00c04fa321a1', 15)
# registry open key
REG_OPEN_KEY = ('ae53722e-c863-11d2-8659-00c04fa321a1', 11)
# registry set value key event
REG_SET_VALUE = ('ae53722e-c863-11d2-8659-00c04fa321a1', 14)
# registry query value key event
REG_QUERY_VALUE = ('ae53722e-c863-11d2-8659-00c04fa321a1', 16)
# registry query value key event
REG_QUERY_KEY = ('ae53722e-c863-11d2-8659-00c04fa321a1', 13)
# create the key control block
REG_CREATE_KCB = ('ae53722e-c863-11d2-8659-00c04fa321a1', 22)
# delete the key control block
REG_DELETE_KCB = ('ae53722e-c863-11d2-8659-00c04fa321a1', 23)

# image load event generated when a DLL or executable file is loaded
LOAD_IMAGE = ('2cb15d1d-5fc1-11d2-abe1-00a0c911f518', 10)
# generated when a DLL or executable file is unloaded
UNLOAD_IMAGE = ('2cb15d1d-5fc1-11d2-abe1-00a0c911f518', 2)
# enumerates all loaded images
ENUM_IMAGE = ('2cb15d1d-5fc1-11d2-abe1-00a0c911f518', 3)

# virtual memory allocation event
VIRTUAL_ALLOC = ('3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c', 98)
# virtual memory free event
VIRTUAL_FREE = ('3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c', 99)

# system call enter event
SYSCALL_ENTER = ('ce1dbfb4-137e-4da6-87b0-3f59aa102cbc', 51)
# system call exit event
SYSCALL_EXIT = ('ce1dbfb4-137e-4da6-87b0-3f59aa102cbc', 52)

# context switch event
CONTEXT_SWITCH = ()

# starts an incoming connection attempt on socket
ACCEPT_SOCKET_TCPV4 = ('9a280ac0-c8e0-11d1-84e2-00c04fb998a2', 15)
ACCEPT_SOCKET_TCPV6 = ('9a280ac0-c8e0-11d1-84e2-00c04fb998a2', 31)

# sends data on a connected socket
SEND_SOCKET_TCPV4 = ('9a280ac0-c8e0-11d1-84e2-00c04fb998a2', 10)
SEND_SOCKET_UDPV4 = ('bf3a50c5-a9c9-4988-a005-2df0b7c80f80', 10)
# establishes a connection to a specified socket
CONNECT_SOCKET_TCPV4 = ('9a280ac0-c8e0-11d1-84e2-00c04fb998a2', 12)
# disconnect event
DISCONNECT_SOCKET_TCPV4 = ('9a280ac0-c8e0-11d1-84e2-00c04fb998a2', 13)
# reconnect attempt event
RECONNECT_SOCKET_TCPV4 = ('9a280ac0-c8e0-11d1-84e2-00c04fb998a2', 16)
# receives data from a connected socket
RECV_SOCKET_TCPV4 = ('9a280ac0-c8e0-11d1-84e2-00c04fb998a2', 11)
RECV_SOCKET_UDPV4 = ('bf3a50c5-a9c9-4988-a005-2df0b7c80f80', 11)


def kname_to_tuple(name):

    if name == KEvents.CREATE_PROCESS:
        return CREATE_PROCESS
    elif name == KEvents.TERMINATE_PROCESS:
        return TERMINATE_PROCESS
    elif name == KEvents.CREATE_THREAD:
        return CREATE_THREAD
    elif name == KEvents.TERMINATE_THREAD:
        return TERMINATE_THREAD

    elif name == KEvents.REG_CREATE_KEY:
        return REG_CREATE_KEY
    elif name == KEvents.REG_QUERY_KEY:
        return REG_QUERY_KEY
    elif name == KEvents.REG_OPEN_KEY:
        return REG_OPEN_KEY
    elif name == KEvents.REG_QUERY_VALUE:
        return REG_QUERY_VALUE
    elif name == KEvents.REG_SET_VALUE:
        return REG_SET_VALUE
    elif name == KEvents.REG_DELETE_KEY:
        return REG_DELETE_KEY
    elif name == KEvents.REG_DELETE_VALUE:
        return REG_DELETE_VALUE

    elif name == KEvents.CREATE_FILE:
        return CREATE_FILE
    elif name == KEvents.READ_FILE:
        return READ_FILE
    elif name == KEvents.WRITE_FILE:
        return WRITE_FILE
    elif name == KEvents.CLOSE_FILE:
        return CLOSE_FILE
    elif name == KEvents.DELETE_FILE:
        return DELETE_FILE
    elif name == KEvents.RENAME_FILE:
        return RENAME_FILE

    elif name == KEvents.LOAD_IMAGE:
        return LOAD_IMAGE
    elif name == KEvents.UNLOAD_IMAGE:
        return UNLOAD_IMAGE

    elif name == KEvents.SEND:
        return [SEND_SOCKET_UDPV4, SEND_SOCKET_TCPV4]
    elif name == KEvents.RECEIVE:
        return [RECV_SOCKET_UDPV4, RECV_SOCKET_TCPV4]
    elif name == KEvents.ACCEPT:
        return [ACCEPT_SOCKET_TCPV4, ACCEPT_SOCKET_TCPV6]
    elif name == KEvents.CONNECT:
        return CONNECT_SOCKET_TCPV4
    elif name == KEvents.RECONNECT:
        return RECONNECT_SOCKET_TCPV4
    elif name == KEvents.DISCONNECT:
        return DISCONNECT_SOCKET_TCPV4
    else:
        raise UnknownKeventTypeError(name)


def ktuple_to_name(ktuple):

    if ktuple == CREATE_PROCESS:
        return KEvents.CREATE_PROCESS
    elif ktuple == CREATE_THREAD:
        return KEvents.CREATE_THREAD
    elif ktuple == TERMINATE_PROCESS:
        return KEvents.TERMINATE_PROCESS
    elif ktuple == TERMINATE_THREAD:
        return KEvents.TERMINATE_THREAD

    elif ktuple == REG_CREATE_KEY:
        return KEvents.REG_CREATE_KEY
    elif ktuple == REG_DELETE_KEY:
        return KEvents.REG_DELETE_KEY
    elif ktuple == REG_DELETE_VALUE:
        return KEvents.REG_DELETE_VALUE
    elif ktuple == REG_OPEN_KEY:
        return KEvents.REG_OPEN_KEY
    elif ktuple == REG_SET_VALUE:
        return KEvents.REG_SET_VALUE
    elif ktuple == REG_QUERY_VALUE:
        return KEvents.REG_QUERY_VALUE
    elif ktuple == REG_QUERY_KEY:
        return KEvents.REG_QUERY_KEY

    elif ktuple == CREATE_FILE:
        return KEvents.CREATE_FILE
    elif ktuple == DELETE_FILE:
        return KEvents.DELETE_FILE
    elif ktuple == CLOSE_FILE:
        return KEvents.CLOSE_FILE
    elif ktuple == WRITE_FILE:
        return KEvents.WRITE_FILE
    elif ktuple == READ_FILE:
        return KEvents.READ_FILE

    elif ktuple == LOAD_IMAGE:
        return KEvents.LOAD_IMAGE
    elif ktuple == UNLOAD_IMAGE:
        return KEvents.UNLOAD_IMAGE

    elif ktuple == SEND_SOCKET_UDPV4 or\
            ktuple == SEND_SOCKET_TCPV4:
        return KEvents.SEND
    elif ktuple == RECV_SOCKET_UDPV4 or\
            ktuple == RECV_SOCKET_TCPV4:
        return KEvents.RECEIVE
    elif ktuple == ACCEPT_SOCKET_TCPV4:
        return KEvents.ACCEPT
    elif ktuple == CONNECT_SOCKET_TCPV4:
        return KEvents.CONNECT
    elif ktuple == DISCONNECT_SOCKET_TCPV4:
        return KEvents.DISCONNECT
    elif ktuple == RECONNECT_SOCKET_TCPV4:
        return KEvents.RECONNECT