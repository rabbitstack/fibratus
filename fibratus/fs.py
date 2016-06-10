# Copyright 2015 by Nedim Sabic (RabbitStack)
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
from enum import Enum

from fibratus.common import NA
from fibratus.handle import HandleType
from fibratus.kevent_types import *
from fibratus.apidefs.fs import *


class FileOps(Enum):

    # if the file already exists,
    # replace it with the given file
    # otherwise create the given file
    SUPERSEDE = 0
    # if the file already exists,
    # open it instead of creating a new file
    OPEN = 1
    # if the file already exists,
    # fail the request otherwise create the file
    CREATE = 2
    # if the file already exists,
    # open it, otherwise create the given file
    OPEN_IF = 3
    # if the file already exists,
    # open it and overwrite it,
    # otherwise fail the request
    OVERWRITE = 4
    # if the file already exists,
    # open it and overwrite it,
    # otherwise create the given file
    OVERWRITE_IF = 5


class FileType(Enum):

    FILE = 0
    DIRECTORY = 1
    REPARSE_POINT = 2
    UNKNOWN = 3


class FsIO(object):

    def __init__(self, kevent, handles):
        self._kevent = kevent
        self.file_pool = {}
        self.file_handles = {handle.obj: (handle.name, handle.handle_type, handle.handle)
                             for handle in handles
                             if handle.handle_type in [HandleType.FILE, HandleType.DIRECTORY]}

    def parse_fsio(self, ketype, kfsio):
        """Parses the file system related kevents.

        Parameters
        ----------

        ketype: tuple
            kevent type
        kfsio: dict
            kevent payload as forwarded from
        """

        # thread which is perfoming the op
        tid = kfsio.ttid
        obj = kfsio.file_object
        self._kevent.tid = tid
        # creates or opens a file or the I/O device.
        # The device can be a file, file stream, directory,
        # physical disk, volume, console buffer, tape drive,
        # communications resource, mailslot, or pipe.
        if ketype == CREATE_FILE:
            file = kfsio.open_path
            # the high 8 bits correspond to the value of the
            # `CreateDisposition` parameter and the low 24 bits
            # are the value of the `CreateOptions` parameter
            # of the `NtCreateFile` system call
            co = kfsio.create_options

            # extract the most significat 8 bits
            flags = (co >> 24) & ((1 << 8) - 1)

            op = FileOps.OPEN
            if flags == FILE_SUPERSEDE:
                op = FileOps.SUPERSEDE
            elif flags == FILE_OPEN:
                op = FileOps.OPEN
            elif flags == FILE_CREATE:
                op = FileOps.CREATE
            elif flags == FILE_OPEN_IF:
                op = FileOps.OPEN_IF
            elif flags == FILE_OVERWRITE:
                op = FileOps.OVERWRITE
            elif flags == FILE_OVERWRITE_IF:
                op = FileOps.OVERWRITE_IF

            # determine file descriptor type
            file_type = FileType.FILE
            if (co & FILE_DIRECTORY_FILE) == FILE_DIRECTORY_FILE:
                file_type = FileType.DIRECTORY
            elif (co & FILE_OPEN_REPARSE_POINT) == FILE_OPEN_REPARSE_POINT:
                file_type = FileType.REPARSE_POINT

            # type of share access that
            # the caller would like to use
            # in the file.
            # For example, FILE_SHARE_READ would allow other
            # threads to open the file for read access
            share_access = kfsio.share_access
            if share_access == FILE_SHARE_READ:
                share_mask = 'r--'
            elif share_access == FILE_SHARE_WRITE:
                share_mask = '-w-'
            elif share_access == FILE_SHARE_DELETE:
                share_mask = '--d'
            elif share_access == (FILE_SHARE_READ | FILE_SHARE_WRITE):
                share_mask = 'rw-'
            elif share_access == (FILE_SHARE_READ | FILE_SHARE_DELETE):
                share_mask = 'r-d'
            elif share_access == (FILE_SHARE_WRITE | FILE_SHARE_DELETE):
                share_mask = '-wd'
            elif share_access == (FILE_SHARE_READ | FILE_SHARE_WRITE |
                                  FILE_SHARE_DELETE):
                share_mask = 'rwd'
            else:
                share_mask = '---'

            self._kevent.params = dict(file=file,
                                       file_type=file_type.name,
                                       tid=tid,
                                       operation=op.name,
                                       share_mask=share_mask)

            # index by file object pointer
            # so we can query the pool
            # to resolve the file name
            self.file_pool[obj] = file

        elif ketype == DELETE_FILE or ketype == CLOSE_FILE:
            file = self._query_file_name(obj, True)
            params = dict(file=file,
                          tid=tid)
            self._kevent.params = params

        elif ketype == WRITE_FILE or ketype == READ_FILE:
            # the number of kb read/written
            io_size = kfsio.io_size / 1024
            file = self._query_file_name(obj)
            params = dict(file=file,
                          tid=tid,
                          io_size=io_size)
            self._kevent.params = params

        elif ketype == RENAME_FILE:
            file = self._query_file_name(obj)
            params = dict(file=file,
                          tid=tid)
            self._kevent.params = params
            if NA not in file:
                self.file_pool[obj] = file

    def _query_file_name(self, fobj, remove=False):
        if fobj in self.file_pool:
            return self.file_pool.pop(fobj) if remove \
                else self.file_pool[fobj]
        else:
            # couldn't find the file in the file pool,
            # query the file handles
            if fobj in self.file_handles:
                file, _, _ = self.file_handles.pop(fobj)
                if file and not remove:
                    self.file_pool[fobj] = file
                return file if file else NA
            else:
                return NA



