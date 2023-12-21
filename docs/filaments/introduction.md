# Python Meets Kernel Events

**Python** is the lingua franca of pen testers and other **SecOps**-driven individuals. Many security tools are written in Python language.
Wouldn't it be awesome to exploit the arsenal of those tools in Fibratus or build your own tools atop them?

Fibratus incorporates a framework for painlessly extending the functionality and incorporating new features via Python scripts. These scripts are called **filaments**. You can also think of them as extension points with virtually endless possibilities. Whatever you are allowed to craft in Python, you can also implement in filaments.

Filaments are executed on top of kernel event flux and thus they have access to all event's parameters, process state and so on.
From technical perspective, a filament is a full-fledged instance of the Python interpreter. Fibratus interacts with the **CPython** API to bootstrap the interpreter, initialize the module from filament definition, declare functions and other related tasks.
