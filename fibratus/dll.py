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

import os


class DllRepository(object):

    def __init__(self, kevent):
        self.dlls = {}
        self._kevent = kevent

    def register_dll(self, kdll):
        """Registers a loaded image.

        Registers an image when
        the latter is loaded into the address space
        of the process.

        Parameters
        ----------

        kdll: dict
            Image load event payload as forwarded
            from the kernel event stream collector
        """
        pid = kdll.process_id
        path = kdll.file_name
        image = os.path.basename(path)
        size = kdll.image_size
        checksum = kdll.image_checksum
        base = kdll.image_base

        self._kevent.pid = pid

        dll = Dll(pid, path,
                  image,
                  size,
                  checksum,
                  base)

        if pid in self.dlls:
            # append a new image to
            # the associated process
            self.dlls[pid].append(dll)
        else:
            self.dlls[pid] = [dll]

        self._kevent.params = dict(image=image,
                                   pid=pid,
                                   path=path,
                                   size=dll.size,
                                   checksum=checksum,
                                   base=hex(base))

    def unregister_dll(self, kdll):
        """Unregisters a loaded image.

        Removes the loaded image from
        the repository for a given process.

        Parameters
        ----------

        kdll: dict
            Image unload event payload as forwarded
            from the kernel event stream collector
        """
        pid = kdll.process_id
        path = kdll.file_name
        image = os.path.basename(path)
        size = kdll.image_size / 1024
        checksum = kdll.image_checksum
        base = kdll.image_base

        self._kevent.pid = pid

        if pid in self.dlls:
            dlls = self.dlls[pid]
            for dll in dlls:
                if dll.image == image:
                    dlls.remove(dll)
        self._kevent.params = dict(image=image,
                                   pid=pid,
                                   path=path,
                                   size=size,
                                   checksum=checksum,
                                   base=hex(base))

    def dlls_for_process(self, pid):
        return self.dlls[pid] if pid in self.dlls else []


class Dll(object):

    def __init__(self, pid, path, image, size, checksum, base):
        self._pid = pid
        self._path = path
        self._size = size
        self._checksum = checksum
        self._base = base
        self._image = image

    @property
    def pid(self):
        return self._pid

    @property
    def path(self):
        return self._path

    @property
    def image(self):
        return self._image

    @property
    def size(self):
        return self._size

    @property
    def base(self):
        return hex(self._base)

    @property
    def checksum(self):
        return self._checksum
