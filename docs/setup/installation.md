# Installation

### System requirements {docsify-ignore}

- 64-bits Windows operating system starting from Windows 7
- 40 MB of free disk space
- 1 (V)CPU
- 50 MB of available memory

### Permission requirements {docsify-ignore}

Fibratus requires **administrator** or **SYSTEM** privileges to capture system events from the ETW subsystem. During execution, Fibratus performs the following operations on your system:

- takes a snapshot of allocated system handles. You can control this option through [configuration](/kevents/handle?id=handle-state) flags. Disabled by default.
- periodically writes the current event sequence into volatile registry value
- writes logs to disk. The default logs directory location is `%PROGRAMFILES%\Fibratus\Logs`
- grants the `SeDebugPrivilege` to its process token. However, you can disable granting this privilege by setting the `debug-privilege` option to `false`
- transports event messages over the wire if the eligible output sink is active.
- inspects process image [PE](/pe/introduction.md) metadata. Again, you can disable this feature through [config](/pe/introduction) file
- executes [YARA](/yara/introduction.md) rules on freshly created process images or other image files when the [YARA scanner](/yara/introduction) is enabled
- spins up an embedded Python interpreter to run [filaments](/filaments/introduction)
- accesses raw disk devices to read file data


### Deployment  {docsify-ignore}

The easiest way to get started with Fibratus is by downloading the Windows installer. Head over to the [releases](https://github.com/rabbitstack/fibratus/releases) and pick your download. Latest releases are recommended as they ship with new features, bug fixes and tend to improve the performance.
Windows installers are automatically built by the CI platform each time new Fibratus release is published.

<p align="center">
  <a href="https://github.com/rabbitstack/fibratus/releases"><img src="setup/images/fibratus-installer-msi.png"/></a>
</p>

There are two flavors of Windows MSI installers:

- __full installers__ ship with all features ([captures](captures/introduction), [filaments](filaments/introduction), [yara](yara/introduction)) and bundle the embedded Python distribution
- __slim installers__ support less features but are more portable and have lower disk space requirements

The installer will automatically register and start Fibratus as **Windows Service**. To verify if the service is running correctly, spin up a command line prompt and execute the following command:

```
$ fibratus service status
Fibratus service is running
```

If you're able to see the output like in the snippet above, congratulations! You have successfully installed Fibratus. Jump to [quick start](/setup/quick-start).

### Uninstall {docsify-ignore}

To remove Fibratus from your system, head to the Control Panel > Programs and Features and start the uninstall process. The uninstaller will make sure to stop/remove the Windows Service and get rid of all installation data.

## Building from source {docsify-ignore}

To build Fibratus directly from source code you have to satisfy the following requirements:

- Go compiler 1.21+
- C compiler (optional)
- Python headers (optional)
- [libyara](https://github.com/VirusTotal/yara/tree/master/libyara) (optional)

### Installing dependencies {docsify-ignore}

!> You can skip this step if you're not interested in building features that interop with the C code.

1. Download the `msys2` installer and follow the instructions [here](https://www.msys2.org/).
  - open the `msys2` shell (by default located in `C:\msys2\msys2.exe`). You can also access it from the `MSYS2 64-bit` Start Menu item.
  - install the `MinGW` compiler toolchain along with other dependencies:
    - `pacman -S base-devel mingw-w64-x86_64-openssl mingw-w64-x86_64-gcc mingw-w64-x86_64-pkg-config automake libtool autoconf`
2. [Download](https://www.python.org/ftp/python/3.7.9/python-3.7.9-amd64.exe) and install the `Python 3.7`. Assuming the Python distribution was installed in `C:\Python37`, set the `PKG_CONFIG_PATH` environment variable to the location of the `pkg-config` directory within the `fibratus` directory.
  - `set PKG_CONFIG_PATH=<pkg-config absolute path>`
3. Build `libyara`
  - clone the `yara` repository into the path visible to the `msys2` environment. This is ideally done from the `MSYS2 64-bit` shell.
    - `pacman -S git`
    - `git clone https://github.com/VirusTotal/yara.git`
    - go to the `yara` repository you previously cloned. Run the following commands:
      - `autoreconf -fiv`
      - `./configure --host=x86_64-w64-mingw32`
      - `make install`

### Building the executable {docsify-ignore}

The **optional dependencies are only needed** if you'll be building features that interop with the C code. The Go compiler is instructed to ignore all features that trigger the [cgo](https://golang.org/cmd/cgo/), but you can control which features are built into Fibratus through the following build flags:

- `filament`: compiles Fibratus with filaments support
- `kcap`: compiles Fibratus with support for capturing/replaying kcap files
- `yara`: builds Fibratus with support for [Yara](https://virustotal.github.io/yara/) pattern matching

To build the Fibratus binary without filament, kcap nor yara features, run the following command from the `cmd` shell and within the`fibratus` directory:

```
$ make
```

To produce the Fibratus binary with the filaments support, you would run the following commands:

```
$ set TAGS=filament
$ make
```

In either case, the resulting binary is placed in the `cmd\fibratus` directory.
