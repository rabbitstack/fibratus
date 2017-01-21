# Copyright 2015 by Nedim Sabic (RabbitStack)
# All Rights Reserved.
# http://rabbitstack.github.io

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

import sys
import re
from prettytable import PrettyTable

__underscore_regex__ = re.compile('((?<=[a-z0-9])[A-Z]|(?!^)[A-Z](?=[a-z]))')


NA = '<NA>'


def panic(msg):
    """Write the message on the console and terminates the process.

    Parameters
    ----------
    msg: str
        the message to be written on the standard output stream
    """
    print(msg)
    sys.exit()


def underscore_dict_keys(in_dict):
    if type(in_dict) is dict:
        out_dict = {}
        for key, item in in_dict.items():
            out_dict[__underscore_regex__.sub(r'_\1', key).lower()] = underscore_dict_keys(item)
        return out_dict
    elif type(in_dict) is list:
        return [__underscore_regex__.sub(r'_\1', obj).lower() for obj in in_dict]
    else:
        return in_dict


class Tabular(PrettyTable):

    def __init__(self, columns, align_col=None, align_type='l', sort_by=None):
        PrettyTable.__init__(self, columns)
        if align_col:
            self.align[align_col] = align_type
        if sort_by:
            self.sortby = sort_by

    def draw(self):
        print(self.get_string())


class DotD(dict):
    """This code is borrowed from easydict
    Credits to:

    https://github.com/makinacorpus/easydict/blob/master/easydict/__init__.py
    """
    def __init__(self, d=None, **kwargs):
        if d is None:
            d = {}
        if kwargs:
            d.update(**kwargs)
        for k, v in d.items():
            setattr(self, k, v)
        # class attributes
        for k in self.__class__.__dict__.keys():
            if not (k.startswith('__') and k.endswith('__')):
                setattr(self, k, getattr(self, k))

    def __setattr__(self, name, value):
        if isinstance(value, (list, tuple)):
            value = [self.__class__(x)
                     if isinstance(x, dict) else x for x in value]
        else:
            value = self.__class__(value) if isinstance(value, dict) else value
        super(DotD, self).__setattr__(name, value)
        super(DotD, self).__setitem__(name, value)

    __setitem__ = __setattr__

