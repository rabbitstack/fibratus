Fibratus
========

![fibratus logo]( https://github.com/rabbitstack/fibratus/blob/master/fibratus.png "fibratus logo" )

[![Build status](https://ci.appveyor.com/api/projects/status/dlvxhc0j026ikcyv?svg=true)](https://ci.appveyor.com/project/rabbitstack/fibratus)
[![Coverage Status](https://codecov.io/gh/rabbitstack/fibratus/branch/master/graph/badge.svg)](https://codecov.io/gh/rabbitstack/fibratus)
[![Code Health](https://landscape.io/github/rabbitstack/fibratus/master/landscape.svg?style=flat)](https://landscape.io/github/rabbitstack/fibratus/master)

**Fibratus** is a tool which is able to capture the most of the Windows kernel activity - process/thread creation and termination, 
file system I/O, registry, network activity, DLL loading/unloading and much more. 
Fibratus has a very simple CLI which encapsulates the machinery to start the kernel event stream collector, 
set kernel event filters or run the lightweight Python modules called **filaments**. You can use filaments to extend Fibratus with your own arsenal of tools.

![fibratus]( https://github.com/rabbitstack/fibratus/blob/master/static/fibratus.png "fibratus" )
![filaments]( https://github.com/rabbitstack/fibratus/blob/master/static/filaments.png "filaments" )

## Requirements

- Python 3.4
- Visual C++ 2012 or above 
- Cython >=0.23.4

## Installation

Install via the pip package manager:

`pip install fibratus`

## Documentation

See the [wiki](https://github.com/rabbitstack/fibratus/wiki/Running).

## Running

Execute `fibratus run` from the command prompt. If you are interested in a particular kernel event, use `--filters` option:
`fibratus run --filters CreateProcess`.

## Contributing

Please use Github's pull-request model to submit your contributions. Before you send the pull-request you should keep in mind:

* the code has to be in harmony with the **Zen Of Python** principles
* you need to test the code (fibratus uses the `pytest` unit testing framework)
* make sure your code satisfy the **PEP** coding style

## License

Copyright 2015/2016 by Nedim Sabic (RabbitStack) 
All Rights Reserved. 

http://rabbitstack.github.io

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

## Support on Beerpay
Hey dude! Help me out for a couple of :beers:!

[![Beerpay](https://beerpay.io/rabbitstack/fibratus/badge.svg?style=beer-square)](https://beerpay.io/rabbitstack/fibratus)  [![Beerpay](https://beerpay.io/rabbitstack/fibratus/make-wish.svg?style=flat-square)](https://beerpay.io/rabbitstack/fibratus?focus=wish)
