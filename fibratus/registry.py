# Copyright 2015/2016 by Nedim Sabic (RabbitStack)
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
import os
from ctypes import cast, byref

from fibratus.common import NA
from fibratus.handle import HandleType
from fibratus.kevent_types import *
from fibratus.apidefs.registry import *
from fibratus.apidefs.sys import malloc, free


class HiveParser(object):

    def __init__(self, kevent, thread_registry):
        self._kcblocks = {}
        self._kevent = kevent
        self.thread_registry = thread_registry
        self.hive_regexs = [
            r'(?i)(REGISTRY\\MACHINE\\SOFTWARE)(.*)',
            r'(?i)(REGISTRY\\MACHINE\\HARDWARE)(.*)',
            r'(?i)(REGISTRY\\MACHINE\\SECURITY)(.*)',
            r'(?i)(REGISTRY\\MACHINE\\SYSTEM)(.*)',
            r'(?i)(REGISTRY\\MACHINE\\SAM)(.*)',
            r'(?i)(REGISTRY\\USER\\.DEFAULT)(.*)',
            r'(?i)(REGISTRY\\USER\\S-.+?)\\(.*)',
            r'(?i)(REGISTRY\\USER)(.*)']
        self._reg_value_types = [v.value for v in ValueType]

    @property
    def kcblocks(self):
        return self._kcblocks

    def remove_kcb(self, key_handle):
        if key_handle in self._kcblocks:
            self._kcblocks.pop(key_handle)

    def add_kcb(self, kkcb):
        """Adds a key control block (KCB).

        Parameters
        ----------

        kkcb: dict
            metadata for the KCB

        """
        handle = kkcb.key_handle
        # index the KCB by key handle
        # we also save the process and
        # thread id which created the KCB
        kcb = Kcb(handle, kkcb.key_name,
                  kkcb.index,
                  kkcb.status,
                  kkcb.thread_id,
                  kkcb.process_id)
        self._kcblocks[handle] = kcb

    def parse_hive(self, ketype, regkevt):
        """Parses a hive from the registry kernel event.

        Hive is a logical group of keys, subkeys and values
        which are commonly called as nodes.

        Parameters
        ----------

        ketype: tuple
            kernel event type
        regkevt: dict
            kernel registry event payload as forwarded from the
            event stream collector
        """
        hive = NA
        key = regkevt.key_name
        status = regkevt.status
        tid = regkevt.thread_id
        pid = regkevt.process_id
        index = regkevt.index

        self._kevent.tid = tid
        self._kevent.pid = pid

        # if the node handle (KCB handle) is equal to 0
        # we have the full node name. Otherwise
        # we have to query the key control blocks
        # to found the full node name
        handle = regkevt.key_handle
        if handle == 0:
            # find the hive by applying
            # the regular expression
            hive, key = self._dissect_hive(key)
        else:
            if handle in self._kcblocks:
                # KCB found. Concatenate the
                # full node path
                kcb = self._kcblocks[handle]
                full_path = '%s\%s' % (kcb.key, key)
                hive, key = self._dissect_hive(full_path)
            else:
                # we missed the KCB creation
                # lookup the handles
                # to find the key name
                thread = self.thread_registry.get_thread(pid)
                if thread:
                    key_handles = [kh for kh in thread.handles if kh.handle_type is not None and
                                   kh.handle_type == HandleType.KEY]
                    for khandle in key_handles:
                        if ketype in [REG_CREATE_KEY,
                                      REG_DELETE_KEY,
                                      REG_OPEN_KEY,
                                      REG_QUERY_KEY]:
                            # try to find the match of the key name
                            # from registry key handle name.
                            # Replace the backslash to prevent
                            # bogus escape exceptions
                            khandle_name = khandle.name
                            f = re.findall(r"%s" % key.replace('\\', '_'),
                                           khandle_name.replace('\\', '_'))
                            if len(f) > 0:
                                hive, key = self._dissect_hive(khandle_name)
                                kcb = Kcb(handle,
                                          khandle_name,
                                          index,
                                          status,
                                          tid,
                                          pid)
                                self._kcblocks[handle] = kcb
                                break

        if hive == NA:
            # set the unknown hive and
            # the partial node name
            key = '..\%s' % key

        if ketype in [REG_CREATE_KEY,
                      REG_DELETE_KEY,
                      REG_OPEN_KEY,
                      REG_QUERY_KEY]:
            self._kevent.params = dict(hive=hive,
                                       key=key,
                                       status=status,
                                       tid=tid,
                                       pid=pid)
        elif ketype in [REG_SET_VALUE,
                        REG_DELETE_VALUE,
                        REG_QUERY_VALUE]:
            if ketype == REG_SET_VALUE or ketype == REG_QUERY_VALUE:
                # we have the hive and the subkey
                # including the registry value name
                # which means we are able to query the content
                # of the registry value
                if hive != NA and not key.startswith('..'):
                    # resolve the root key name
                    # from the registry hive
                    hkey = self._hive_to_hkey(hive)
                    subkey, value_name = os.path.split(key)
                    # get the value data and value type
                    # from the registry
                    value, value_type = self._query_value(hkey,
                                                          subkey,
                                                          value_name)
                    self._kevent.params = dict(hive=hive, key=key,
                                               value_type=value_type,
                                               value=value,
                                               status=status,
                                               tid=tid,
                                               pid=pid)
                else:
                    self._kevent.params = dict(hive=hive, key=key,
                                               value_type=NA,
                                               value=NA,
                                               status=status,
                                               tid=tid,
                                               pid=pid)

            else:
                self._kevent.params = dict(hive=hive, key=key,
                                           status=status,
                                           tid=tid,
                                           pid=pid)

    def _query_value(self, hkey, subkey, value_name):
        """Get value content and value type from registry.

        Parameters
        ----------

        hkey: HKEY
            handle to registry root key
        subkey: str
            path representing the subkey
        value:
            the name of the value
        """
        if not hkey:
            return NA, NA
        value_type = c_ulong()
        buff = malloc(MAX_BUFFER_SIZE)
        buff_size = c_ulong(MAX_BUFFER_SIZE)

        status = reg_get_value(hkey, c_wchar_p(subkey),
                               c_wchar_p(value_name),
                               RRF_RT_ANY,
                               byref(value_type),
                               buff, byref(buff_size))
        if status == ERROR_SUCCESS:
            value = cast(buff, c_wchar_p).value
            value_type = value_type.value
            if value_type in self._reg_value_types:
                if value_type == ValueType.REG_BINARY.value:
                    value = '<binary>'
                [value_type] = [v.name for v in ValueType if v.value == value_type]
            else:
                value_type = ValueType.REG_NONE.name
            free(buff)
            return value, value_type
        else:
            free(buff)
            return NA, NA

    def _dissect_hive(self, key_name):
        """Extracts the hive name and the subkey from the key path.

        Parameters
        ----------

        key_name: str
            key path from whom the hive
            can be resolved
        """
        for rx in self.hive_regexs:
            # for each regex match it
            # against key path
            m = re.search(rx, key_name)
            if m and len(m.groups()) > 0:
                hive = m.group(1).upper()
                # hive found, now try
                # to get the node path
                if len(m.groups()) > 1:
                    node = m.group(2)
                    if node:
                        # because the hive contains the
                        # child node of the registry subkey
                        # we have to include it
                        _, hive_child = os.path.split(hive)
                        if not node.startswith('\\'):
                            node = '\\%s' % node
                        node = '%s%s' % (hive_child, node)
                        return hive.replace('\\', '_'), node
                return hive.replace('\\', '_'), key_name
        return key_name, key_name

    def _hive_to_hkey(self, hive):
        if re.match(r'(?i).*MACHINE.*', hive):
            return HKEY_LOCAL_MACHINE
        elif re.match(r'(?i).*USER_S-.*|\.DEFAULT', hive):
            return HKEY_USERS
        else:
            return None


class Kcb(object):
    """The container for the Key Control Block data.
    """
    def __init__(self, handle, key, index,
                 status, tid, pid):
        self._handle = handle
        self._key = key
        self._index = index
        self._status = status
        self._thread_id = tid
        self._process_id = pid

    @property
    def key(self):
        return self._key



