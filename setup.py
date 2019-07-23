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
import re
import os
import shutil
from os.path import expanduser
from setuptools import setup, find_packages
from setuptools.extension import Extension
from Cython.Distutils import build_ext
try:
    from pip._internal.req import parse_requirements
except ImportError:
    from pip.req import parse_requirements

from fibratus.version import VERSION


def copy_artifacts():
    home_dir = expanduser('~')
    here = os.path.abspath(os.path.dirname(__file__))
    fibratus_dir = os.path.join(home_dir, '.fibratus')
    if not os.path.exists(fibratus_dir):
        os.mkdir(fibratus_dir)
        shutil.copy(os.path.join(here, 'fibratus.yml'), fibratus_dir)
        shutil.copy(os.path.join(here, 'schema.yml'), fibratus_dir)
        shutil.copytree(os.path.join(here, 'filaments'), os.path.join(fibratus_dir, 'filaments'))

kstreamc_ext = Extension('kstreamc',
                         ['kstream/kstreamc.pyx'],
                         libraries=["tdh", "advapi32", "ole32", "ws2_32"],
                         language='c++')

install_reqs = parse_requirements('requirements.txt', session=False)
reqs = [str(ir.req) for ir in install_reqs if not re.match('pytest|codecov', str(ir.req))]

copy_artifacts()

setup(
    name="fibratus",
    version=VERSION,
    author="Nedim Sabic (RabbitStack)",
    author_email="bhnedo@hotmail.com",
    description="Tool for exploration and tracing of the Windows kernel",
    long_description="Fibratus is a tool which is able to capture the most of the Windows kernel activity - "
                     "process/thread creation and termination, file system I/O, registry, network activity, "
                     "DLL loading/unloading and much more. Fibratus has a very simple CLI which encapsulates "
                     "the machinery to start the kernel event stream collector, set kernel event filters or "
                     "run the lightweight Python modules called filaments. You can use filaments to extend "
                     "Fibratus with your own arsenal of tools.",
    license="Apache",
    keywords="windows kernel, tracing, system exploration, syscalls",
    platforms=["Windows"],
    url="https://github.com/rabbitstack/fibratus",
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Topic :: System',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4'
    ],
    ext_modules=[kstreamc_ext],
    cmdclass={"build_ext": build_ext},
    packages=find_packages(),
    install_requires=reqs,
    entry_points={
        'console_scripts': [
            'fibratus=fibratus.cli:main',
        ],
    }
)
