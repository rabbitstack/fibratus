# Installation

### Minimum requirements {docsify-ignore}

- 64-bits Windows operating system starting from Windows 7
- 40 MB of free disk space
- 1 (V)CPU
- 50 MB of RAM

### Deployment  {docsify-ignore}

The easiest way to get started with Fibratus is by downloading the Windows installer. Head over to the [releases](https://github.com/rabbitstack/fibratus/releases) and pick your download. Latest releases are recommended as they ship with new features, bug fixes and tend to improve the performance.
Windows installers are automatically built by the CI platform each time new Fibratus release is published.

After the install completes, you can verify if Fibratus was correctly installed. Spin up a command line prompt. Alternatively, you can use [Windows Terminal](https://github.com/microsoft/terminal) or [Cmder](https://cmder.net/) consoles which is the recommended choice for better user experience. Run the following command:

```
$ fibratus -h

Usage:
  fibratus [command]

Available Commands:
  capture         Capture kernel event stream to the kcap file
  config          Show runtime config
  docs            Open Fibratus docs in the web browser
  help            Help about any command
  install-service Install fibratus within the Windows service control manager
  list            Show info about filaments, filter fields or kernel event types
  remove-service  Remove fibratus from the Windows service control manager
  replay          Replay kernel event flow from the kcap file
  restart-service Restart fibratus service
  run             Bootstrap fibratus or a filament
  start-service   Start fibratus service
  stats           Show runtime stats
  stop-service    Stop fibratus service
  version         Show version info
```

If you're able to see the output like in the snippet above, congratulations! You have successfully installed Fibratus. Jump to [running](/setup/running).

### Uninstall {docsify-ignore}

To remove Fibratus from your system, either head to the Control Panel > Programs and Features or run the uninstaller manually from the `%PROGRAMFILES%\Fibratus` directory. The uninstaller will make sure to get rid of all installation data.

## Building from source {docsify-ignore}

To build Fibratus directly from source code you have satisfy the following requirements:

- Go compiler 1.15
- C compiler (optional)
- Python headers (optional)
- [libyara](https://github.com/VirusTotal/yara/tree/master/libyara) (optional)

### Installing dependencies {docsify-ignore}

!> You can skip this step if you're not interested in building features that interop with the C code.

1. Download the `msys2` installer and follow the instructions [here](https://www.msys2.org/).
  - open the `msys2` shell (by default located in `C:\msys2\msys2.exe`). You can also access it from the `MSYS2 64-bit` Start Menu item.
  - install the `MinGW` compiler toolchain and the `base-devel` package
    - `pacman -S base-devel mingw-w64-x86_64-gcc`
2. [Download](https://www.python.org/ftp/python/3.7.9/python-3.7.9-amd64.exe) and install the `Python 3.7`. Assuming the Python distribution was installed in `C:\Python37`, set the `PKG_CONFIG_PATH` environment variable to the location of the `pkg-config` directory within the `fibratus` directory.
  - `set PKG_CONFIG_PATH=<pkg-config absolute path>`
3. Build `libyara`
  - clone the `yara` repository into the path visible to the `msys2` environment
    - `git clone https://github.com/VirusTotal/yara.git`
    - go to the `yara` repository you previously cloned. Run the following commands:
      - `autoreconf -fiv`
      - `./configure --host=x86_64-w64-mingw32`
      - `make install`

### Building the executable {docsify-ignore}

The **optional dependencies are only needed** if you'll be building features that interop with the C code. The Go compiler is instructed to build all features by default, but you can circumvent compiling certain features through build flags by setting the following values:

- `filament`: compiles Fibratus with filaments support
- `kcap`: compiles Fibratus with support for capturing/replaying kcap files
- `yara`: builds Fibratus with support for [Yara](https://virustotal.github.io/yara/) pattern matching

To build the Fibratus binary with the filaments support, you would run the following commands within the `fibratus` directory:

```
$ set TAGS=filament
$ make
```

To avoid triggering the [cgo](https://golang.org/cmd/cgo/) and thus producing pure Go code, run the following commands:

```
$ set TAGS=""
$ make
```

In either case, the resulting binary is placed in the `cmd\fibratus` directory.
