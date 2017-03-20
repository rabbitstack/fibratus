Fibratus [![PyPI version](https://badge.fury.io/py/fibratus.svg)](https://badge.fury.io/py/fibratus)
========
[![Build status](https://ci.appveyor.com/api/projects/status/dlvxhc0j026ikcyv?svg=true)](https://ci.appveyor.com/project/rabbitstack/fibratus)
[![Coverage Status](https://codecov.io/gh/rabbitstack/fibratus/branch/master/graph/badge.svg)](https://codecov.io/gh/rabbitstack/fibratus)
[![Code Health](https://landscape.io/github/rabbitstack/fibratus/master/landscape.svg?style=flat)](https://landscape.io/github/rabbitstack/fibratus/master)

**Fibratus** is a tool which is able to capture the most of the Windows kernel activity - process/thread creation and termination, 
context switches, file system I/O, registry, network activity, DLL loading/unloading and much more. The kernel events can be easily streamed to a number of output sinks like **AMQP** message brokers, **Elasticsearch** clusters or standard output stream.
You can use **filaments** (lightweight Python modules) to extend Fibratus with your own arsenal of tools and so leverage the power of the Python's ecosystem.

## Installation

1. Install the dependencies
  * [Download](https://www.python.org/ftp/python/3.4.0/python-3.4.0.amd64.msi) and install Python 3.4.
  * Install Visual Studio 2015 (you'll only need the Visual C compiler to build the kstreamc extension). Make sure to export the `VS100COMNTOOLS` environment variable so it points to `%VS140COMNTOOLS%`. 
  * Get **cython**: `pip install Cython >=0.23.4`
2. Install **fibratus** via the pip package manager:

```bash
pip install fibratus
```
3. Run it:

```bash
fibratus --help
fibratus run --filters CreateProcess
```
## Documentation

See the [wiki](https://github.com/rabbitstack/fibratus/wiki/Running).

## Support

[![Beerpay](https://beerpay.io/rabbitstack/fibratus/badge.svg?style=beer-square)](https://beerpay.io/rabbitstack/fibratus) 
[![Beerpay](https://beerpay.io/rabbitstack/fibratus/make-wish.svg?style=flat-square)](https://beerpay.io/rabbitstack/fibratus?focus=wish)
[![OpenCollective](https://opencollective.com/fibratus/backers/badge.svg)](https://opencollective.com/fibratus) 
[![OpenCollective](https://opencollective.com/fibratus/sponsors/badge.svg)](https://opencollective.com/fibratus)

