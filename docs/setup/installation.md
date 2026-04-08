# Installation

### System requirements

- **Windows 10** and higher or **Windows Server 2016** and higher
- 50 MB of free disk space
- 1 (V)CPU
- 100 MB of available physical memory

### Permission requirements

Fibratus requires **administrator** or **SYSTEM** privileges to capture system events from the ETW subsystem. During execution, Fibratus performs the following operations on your system:

- takes a snapshot of allocated system handles. You can control this option through [configuration](/events/handle?id=handle-state) flags. Disabled by default.
- periodically writes the current event sequence into volatile registry value
- writes logs to disk. The default logs directory location is `%PROGRAMFILES%\Fibratus\Logs`
- grants the `SeDebugPrivilege` to its process token. However, you can disable granting this privilege by setting the `debug-privilege` option to `false`
- transports event messages over the wire if the eligible output sink is active
- executes [YARA](/yara/introduction.md) rules on freshly created process images or other image files when the [YARA scanner](/yara/introduction) is enabled
- spins up an embedded Python interpreter to run [filaments](/filaments/introduction)


### Installation

<Stepper>

<Step title="Download">

Head over to the [downloads](https://fibratus.io/downloads) page and pick your release artifact. Latest releases are recommended as they ship with new features, bug fixes and tend to improve the performance.

!> There are two flavors of Windows MSI packages: **full** and **slim** installers. Full installers ship with all features including [captures](../captures/introduction), [filaments](../filaments/introduction), [yara](../yara/introduction) and bundle the embedded **Python** distribution. Slim installers lack the aforementioned features but have lower disk space footprint.

+> You can verify the integrity of the downloaded MSI by computing the SHA256 hash and comparing it with the hash from the release download page `Get-FileHash -Path fibratus-[version]-amd64.msi -Algorithm SHA256`

</Step>

<Step title="Install">

Double-click the MSI package and follow the UI wizard or alternatively install via `msiexec` in silent mode:

<Terminal>
$ msiexec /i fibratus-[version]-amd64.msi /qn
</Terminal>

</Step>

<Step title="Verify">

The installer will automatically register and start Fibratus as **Windows Service**. To verify if the service is running correctly, spin up a command line prompt and execute the following command:

<Terminal>
$ fibratus service status

Fibratus service is running

</Terminal>

</Step>

<Step title="Ready to Go">

If you're able to see the output like in the terminal above, congratulations! You have successfully installed Fibratus. Jump to [quick start](/setup/quick-start).

</Step>

</Stepper>

### Uninstall

To remove Fibratus from your system, head to the **Control Panel > Programs and Features** and start the uninstall process. The uninstaller will make sure to stop/remove the Windows Service and get rid of all installation data.

## Building from source

To build Fibratus directly from source code you have to satisfy the following requirements:

- [Go 1.26+](https://go.dev/doc/install)
- C compiler (optional)
- Python headers (optional)
- [libyara](https://github.com/VirusTotal/yara/tree/master/libyara) (optional)

### Installing dependencies

!> You can skip this step if you're not interested in features that require [`cgo`](https://go.dev/wiki/cgo)

<Stepper>

<Step title="Install msys2">

[Download](https://www.msys2.org/) the `msys2` installer and follow the instructions [here](https://www.msys2.org/).

</Step>
<Step title="Launch msys2 shell">

Launch the `msys2` shell which by default located in `C:\msys2\msys2.exe`. You can also access it from the `MSYS2 64-bit` Start Menu item.

</Step>
<Step title="Install build dependencies">

Install the `MinGW` compiler toolchain along with other dependencies.

<Terminal>
$ pacman -S base-devel mingw-w64-x86_64-openssl mingw-w64-x86_64-gcc mingw-w64-x86_64-pkg-config automake libtool autoconf

</Terminal>

</Step>
<Step title="Download Python">

[Download](https://www.python.org/ftp/python/3.7.9/python-3.7.9-amd64.exe) and install `Python 3.7`. Assuming the Python distribution was installed in `C:\Python37`, set the `PKG_CONFIG_PATH` environment variable to the location of the `pkg-config` directory within the `fibratus` directory.

<Terminal>
$ set PKG_CONFIG_PATH=[pkg-config absolute path]

</Terminal>

</Step>
<Step title="Compile libyara">

Clone the `yara` repository into the path visible to the `msys2` environment. This is ideally done from the `MSYS2 64-bit` shell. Next, build the `libyara` library.

<Terminal>

$ pacman -S git
$ git clone https://github.com/VirusTotal/yara.git
$ cd yara
$ autoreconf -fiv
$ ./configure --host=x86_64-w64-mingw32
$ make install

</Terminal>

</Step>

</Stepper>

### Building the executable

The **optional dependencies are needed only** if you'll be building features that interop with the C code. By default, the Go compiler is instructed to ignore all features that trigger [cgo](https://golang.org/cmd/cgo/), but you can control which features are built into Fibratus through the following build flags:

- `filament` compiles Fibratus with [filaments](/filaments/introduction) support
- `cap` compiles Fibratus with support for capturing/replaying capture files
- `yara` builds Fibratus with [Yara](https://virustotal.github.io/yara/) memory scanning capabilities

To build the Fibratus binary without `filament`, `cap` and `yara` features, run the following command from `Powershell` terminal and within the `fibratus` directory:

<Terminal>
$ ./make

</Terminal>

To produce the Fibratus binary with filaments support, you would run the following commands:

<Terminal>
$ $env:TAGS="filament"
$ ./make
</Terminal>

The resulting `fibratus.exe` binary is placed in the `cmd\fibratus` directory.
