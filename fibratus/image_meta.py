# Copyright 2016 by Nedim Sabic (RabbitStack)
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
import pefile
from fibratus.common import DotD as ddict, underscore_dict_keys


def __decode__(value):
    return value.decode('utf-8')


def __from_idx__(string_table, idx):
    """Lookups the entry in the string table.

    Parameters
    ----------
    string_table: dict
        the string table
    idx: int
        index for the entry
    """
    _, v = string_table[idx]
    return __decode__(v)


class ImageMetaRegistry(object):

    def __init__(self, enabled=True, imports=False, file_info=False):
        """Creates an instace of the image meta registry.

        Arguments
        ---------

        enabled: bool
            determines if image meta information should be added to the registry
        imports: bool
            it instructs the PE module to parse the directory entry import structure
        file_info: bool
            determines if file information meta data should be extracted from the PE
        """
        self.image_metas = {}
        self.imports = imports
        self.file_info = file_info
        self.enabled = enabled
        self.full_loaded = False

    def add_image_meta(self, path):
        """Registers image meta information.

        This method parses the PE (Portable Executable) binary format
        of the the image passed in the `path` parameter.

        It then extracts some basic headers present in the PE, as well
        as sections which form the binary image.

        Parameters
        ----------

        path: str
            the absolute path of the image file
        """
        if not self.enabled:
            return None
        try:
            if (path.endswith('exe') or
                path.endswith('dll') or
                path.endswith('sys')) and \
                 path not in self.image_metas:
                    pe = pefile.PE(path, fast_load=True)
                    file_header = ddict(underscore_dict_keys(pe.FILE_HEADER.dump_dict()))
                    # create image meta instance
                    image_meta = ImageMeta(file_header.machine.value,
                                           file_header.time_date_stamp.value,
                                           file_header.number_of_sections.value)
                    image_meta.sections = [dict(name=__decode__(ddict(se.dump_dict()).Name.Value),
                                                entropy=se.get_entropy(),
                                                md5=se.get_hash_md5(),
                                                sha1=se.get_hash_sha1(),
                                                sha256=se.get_hash_sha256(),
                                                sha512=se.get_hash_sha512())
                                           for se in pe.sections]
                    # parse directory entry imports
                    if self.imports:
                        pe.full_load()
                        self.full_loaded = True
                        for module in self.__directory_entry_import__(pe):
                            dll = __decode__(module.dll)
                            imports = [__decode__(i.name)
                                       for i in module.imports
                                       if not i.import_by_ordinal]
                            image_meta.imports[dll] = imports
                    # parse the string table to extract
                    # the copyright, company, description
                    # and other attributes
                    if self.file_info:
                        if not self.full_loaded:
                            pe.full_load()
                        if self.__pe_has_version_info__(pe):
                            file_info = pe.FileInfo
                            if file_info and len(file_info) > 0:
                                file_info = file_info[0]
                                if self.__fi_has_string_table__(file_info):
                                    string_table = sorted(list(file_info.StringTable[0].entries.items()))
                                    # get file info entries from table index
                                    image_meta.org = __from_idx__(string_table, 0)
                                    image_meta.description = __from_idx__(string_table, 1)
                                    image_meta.version = __from_idx__(string_table, 2)
                                    image_meta.internal_name = __from_idx__(string_table, 3)
                                    image_meta.copyright = __from_idx__(string_table, 4)

                    self.image_metas[path] = image_meta

                    return image_meta
        except Exception:
            # ignore the exception for now
            # but consider logging it to file
            # in case it can provide hints for
            # troubleshooting purposes
            pass

    def get_image_meta(self, path):
        return self.image_metas[path] if path in self.image_metas else None

    def remove_image_meta(self, path):
        return self.image_metas.pop(path, None)

    def __pe_has_version_info__(self, pe):
        return hasattr(pe, 'VS_VERSIONINFO')

    def __fi_has_string_table__(self, file_info):
        return len(file_info.StringTable) > 0 and hasattr(file_info, 'StringTable')

    def __directory_entry_import__(self, pe):
        return getattr(pe, 'DIRECTORY_ENTRY_IMPORT') if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else []


class ImageMeta(object):
    """Container for a plethora of metadata extracted from the PE headers.

    Attributes
    ----------
    arch: str
        identifies the target architecture for which this image is compiled
    timestamp: str
        the date and time the image was created by the linker
    num_sections: int
        indicates the size of the section table
    sections: list
        information for every section found in the image
    """
    def __init__(self, arch, timestamp, num_sections):
        self._arch = 'x86-64' if arch == 34404 else 'x86'
        self._timestamp = timestamp
        self._num_sections = num_sections
        self._sections = []
        self._org = None
        self._description = None
        self._version = None
        self._internal_name = None
        self._copyright = None

        self._imports = {}

    @property
    def arch(self):
        return self._arch

    @property
    def timestamp(self):
        return self._timestamp

    @property
    def num_sections(self):
        return self._num_sections

    @property
    def org(self):
        return self._org

    @org.setter
    def org(self, org):
        self._org = org

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, description):
        self._description = description

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, version):
        self._version = version

    @property
    def internal_name(self):
        return self._internal_name

    @internal_name.setter
    def internal_name(self, internal_name):
        self._internal_name = internal_name

    @property
    def copyright(self):
        return self._copyright

    @copyright.setter
    def copyright(self, copyright):
        self._copyright = copyright

    @property
    def sections(self):
        return self._sections

    @sections.setter
    def sections(self, sections):
        self._sections = sections

    @property
    def imports(self):
        return self._imports
