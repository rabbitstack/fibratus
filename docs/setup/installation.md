# Installation

### Minimum system requirements

- AMD64 processor architecture
- **Windows 10** and higher or **Windows Server 2016** and higher
- 60 MB of free disk space
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

+> To confirm the integrity of the downloaded MSI, calculate its SHA256 hash and compare it with the hash listed on the release download page. Use this command to compute the SHA256 hash `Get-FileHash -Path fibratus-[version]-amd64.msi -Algorithm SHA256`

!> There are two flavors of Windows MSI packages: **full** and **slim** installers. Full installers ship with all features including [captures](../captures/introduction), [filaments](../filaments/introduction), [yara](../yara/introduction) and bundle the embedded **Python** distribution. Slim installers lack the aforementioned features but have lower disk space footprint.

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

To remove Fibratus from your system, head to the **Control Panel > Programs and Features** and start the uninstall process. The uninstaller will make sure to stop/remove the Windows Service and get rid of all installation data. Alternatively, uninstall from the command line with `msiexec`

<Terminal>
$ msiexec.exe /x fibratus-[version]-amd64.msi

</Terminal>

## Building from source

To build Fibratus directly from source code you have to satisfy the following requirements:

- [Go 1.26+](https://go.dev/doc/install)
- [git](https://git-scm.com/install/windows)
- C compiler (optional)
- Python headers (optional)
- [libyara](https://github.com/VirusTotal/yara/tree/master/libyara) (optional)

### Installing dependencies

!> You can skip this step if you're not interested in capture, YARA, and filaments features, as they require interoperability with [`cgo`](https://go.dev/wiki/cgo)

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

### Building

Optional dependencies are only required if you plan to build features that interoperate with C code. By default, the Go compiler ignores any features that rely on [cgo](https://golang.org/cmd/cgo/), but you can control which features are included in Fibratus using the following build flags:

- `filament` compiles Fibratus with [filaments](/filaments/introduction) support
- `cap` compiles Fibratus with support for capturing/replaying capture files
- `yara` builds Fibratus with [YARA](https://virustotal.github.io/yara/) memory scanning capabilities

!> The build flags are injected via the `TAGS` environment variable. It needs to be set prior to running the build script, for example, running the folllwing snippet from Powershell terminal: `$env:TAGS="filament,cap,yara"`

To build the binary run the following commands from `Powershell` terminal.

<Stepper>

<Step title="Clone repository">

Clone the Fibratus repository to the location of your choice.

<Terminal>
$ git clone https://github.com/rabbitstack/fibratus.git

</Terminal>

</Step>

<Step title="Build binary">

Launch the `make` script to initiate the build process.

<Terminal>

$ cd fibratus
$ ./make

</Terminal>

After compilation completes, the `fibratus.exe` binary can be found in the `cmd\fibratus` directory.

</Step>

</Stepper>
