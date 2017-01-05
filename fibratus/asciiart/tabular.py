# Copyright 2016 by Nedim Sabic (RabbitStack)
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

from prettytable import PrettyTable


class Tabular(PrettyTable):

    def __init__(self, columns, align_col=None, align_type='l', sort_by=None):
        PrettyTable.__init__(self, columns)
        if align_col:
            self.align[align_col] = align_type
        if sort_by:
            self.sortby = sort_by

    def draw(self):
        print(self.get_string())

