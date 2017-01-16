Fibratus
========
[![Build status](https://ci.appveyor.com/api/projects/status/dlvxhc0j026ikcyv?svg=true)](https://ci.appveyor.com/project/rabbitstack/fibratus)
[![Coverage Status](https://codecov.io/gh/rabbitstack/fibratus/branch/master/graph/badge.svg)](https://codecov.io/gh/rabbitstack/fibratus)
[![Code Health](https://landscape.io/github/rabbitstack/fibratus/master/landscape.svg?style=flat)](https://landscape.io/github/rabbitstack/fibratus/master)

**Fibratus** is a tool which is able to capture the most of the Windows kernel activity - process/thread creation and termination, 
file system I/O, registry, network activity, DLL loading/unloading and much more. 
Fibratus has a very simple CLI which encapsulates the machinery to start the kernel event stream collector, 
set kernel event filters or run the lightweight Python modules called **filaments**. You can use filaments to extend Fibratus with your own arsenal of tools.

![fibratus]( https://github.com/rabbitstack/fibratus/blob/master/static/fibratus.png "fibratus" )

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

If you want to support Fibratus, please consider a donation.

[![Beerpay](https://beerpay.io/rabbitstack/fibratus/badge.svg?style=beer-square)](https://beerpay.io/rabbitstack/fibratus)  [![Beerpay](https://beerpay.io/rabbitstack/fibratus/make-wish.svg?style=flat-square)](https://beerpay.io/rabbitstack/fibratus?focus=wish)

<a href="https://opencollective.com/fibratus/backer/0/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/0/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/1/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/1/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/2/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/2/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/3/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/3/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/4/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/4/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/5/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/5/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/6/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/6/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/7/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/7/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/8/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/8/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/9/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/9/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/10/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/10/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/11/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/11/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/12/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/12/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/13/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/13/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/14/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/14/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/15/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/15/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/16/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/16/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/17/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/17/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/18/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/18/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/19/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/19/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/20/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/20/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/21/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/21/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/22/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/22/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/23/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/23/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/24/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/24/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/25/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/25/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/26/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/26/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/27/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/27/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/28/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/28/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/backer/29/website" target="_blank"><img src="https://opencollective.com/fibratus/backer/29/avatar.svg"></a>

<a href="https://opencollective.com/fibratus/sponsor/0/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/0/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/1/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/1/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/2/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/2/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/3/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/3/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/4/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/4/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/5/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/5/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/6/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/6/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/7/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/7/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/8/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/8/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/9/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/9/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/10/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/10/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/11/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/11/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/12/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/12/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/13/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/13/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/14/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/14/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/15/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/15/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/16/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/16/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/17/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/17/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/18/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/18/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/19/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/19/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/20/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/20/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/21/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/21/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/22/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/22/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/23/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/23/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/24/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/24/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/25/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/25/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/26/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/26/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/27/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/27/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/28/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/28/avatar.svg"></a>
<a href="https://opencollective.com/fibratus/sponsor/29/website" target="_blank"><img src="https://opencollective.com/fibratus/sponsor/29/avatar.svg"></a>
