Fibratus [![PyPI version](https://badge.fury.io/py/fibratus.svg)](https://badge.fury.io/py/fibratus)
========
[![Build status](https://ci.appveyor.com/api/projects/status/dlvxhc0j026ikcyv?svg=true)](https://ci.appveyor.com/project/rabbitstack/fibratus)
[![Coverage Status](https://codecov.io/gh/rabbitstack/fibratus/branch/master/graph/badge.svg)](https://codecov.io/gh/rabbitstack/fibratus)
[![Code Health](https://landscape.io/github/rabbitstack/fibratus/master/landscape.svg?style=flat)](https://landscape.io/github/rabbitstack/fibratus/master)

**Fibratus** is a tool which is able to capture the most of the Windows kernel activity - process/thread creation and termination, 
file system I/O, registry, network activity, DLL loading/unloading and much more.
Fibratus has a very simple CLI which encapsulates the machinery to start the kernel event stream collector, 
set kernel event filters or run the lightweight Python modules called **filaments**. You can use filaments to extend Fibratus with your own arsenal of tools.

## Requirements

- Python 3.4
- Visual C++ 2012 or above 
- Cython >=0.23.4

## Installation

Install via the pip package manager:

`pip install fibratus`

## Documentation

See the [wiki](https://github.com/rabbitstack/fibratus/wiki/Running).

## Support

[![Beerpay](https://beerpay.io/rabbitstack/fibratus/badge.svg?style=beer-square)](https://beerpay.io/rabbitstack/fibratus) 
[![Beerpay](https://beerpay.io/rabbitstack/fibratus/make-wish.svg?style=flat-square)](https://beerpay.io/rabbitstack/fibratus?focus=wish)
[![OpenCollective](https://opencollective.com/fibratus/backers/badge.svg)](https://opencollective.com/fibratus) 
[![OpenCollective](https://opencollective.com/fibratus/sponsors/badge.svg)](https://opencollective.com/fibratus)

