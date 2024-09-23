# Contributing

We greatly appreciate you have considered contributing to Fibratus! Please, read carefully through the guidelines before you start the contribution process.

## Introduction

1. **You're familiar with [Github](https://github.com), git, and the pull request workflow**
2. **Make sure you've read Fibratus [docs](https://www.fibratus.io)**
3. If you got an idea about some feature that's not currently in the backlog, please create the [feature request](https://github.com/rabbitstack/fibratus/issues/new) first. The feature request should precisely describe the scope, requirements, and the motivation for the intended changeset

## Your First Contribution

1. [Fork](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/fork-a-repo) the Fibratus repository in your own Github account
2. Clone the repository into the location of your choice
3. [Create](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-and-deleting-branches-within-your-repository) a new Git branch. Give branch a meaningful name.
4. Work on your changes
5. [Submit](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request-from-a-fork) the branch as a pull request to the upstream Fibratus repository. When submitting the pull request, the title must adhere to the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification. For example, `feat: Add thread start address parameter`. The pull request body is automatically filled with the list of checks describing the type of change that the pull request introduces and specific project areas related to the PR. Please mark the right option with `[x]` and remove any options that don't apply to your changeset. Be generous when communicating the purpose of the pull request, and clearly indicate any notes for the reviewer
6. It is highly recommended to prefix all commit messages pertaining to the pull request with the aforementioned [Conventional Commit](https://www.conventionalcommits.org/en/v1.0.0/) specs. For example:
   1. `feat(event): Add thread start address parameter`
   2. `refactor(filter): Rename start address filter field name`
7. Keep the commit history clean and concise. Let's say you pushed two commits and immediately noticed the first commit contains a typo. If possible, avoid pushing a third commit to fix the typo. Rather adopt the following workflow:
   1. Reset the branch with `git reset --soft HEAD~2`. This makes the `HEAD` point to the commit before our changes were introduced. 
   2. Fix the typo, then stage and commit the first change, and subsequently the second change.
   3. Push force to your branch. `git push -f origin <your-branch-name>`
8. Your pull request will undergo a review process. Core maintainers or contributors should leave comments/suggestions on your pull request and potentially require changes

### Conflicting changes

If your pull request brings conflicting changes, you should follow these steps to resolve the conflicts.

1. Pull the latest changes from the `master` branch
   1. `git checkout master`
   2. `git pull`
2. Checkout back to your branch and rebase on top of the `master` branch
   1. `git checkout <your-branch-name>`
   2. `git rebase master`
3. Work through your conflicts and resolve them. Once you're happy with the result run
   1. `git rebase --continue`
4. Push force to your branch. Be sure to understand the implications and risks of [force-pushing](https://stackoverflow.com/questions/33247309/why-is-it-dangerous-to-do-a-force-push-against-a-remote-repository) 
   1. `git push -f origin <your-branch-name>`

## Development

### Directory Structure

- [`.github`](/.github) Github artifacts
    1. [`/workflows`](/.github/workflows) Github Actions workflows
- [`/build`](/build) Resources for producing software packages
    1. [`msi`](/build/msi) [WiX Toolset](https://wixtoolset.org/) manifest for creating the MSI package
- [`/cmd`](/cmd)
    1. [`/fibratus`](/cmd/fibratus/) - Contains Fibratus entrypoint source file, CLI command implementations and the resource compiler manifest.
    2. [`/systray`](/cmd/systray/) - Systray server implementation. Uses named pipe IPC to pull [systray alertsender](https://www.fibratus.io/#/alerts/senders/systray) messages from the main process.
- [`/configs`](/config) - Configuration files in `yml` and `json` format, included in every release.
- [`/docs`](/docs) - Markdown files for generating the [documentation](https://www.fibratus.io/) site.
- [`/filaments`](/filaments) - The collection of [filaments](https://www.fibratus.io/#/filaments/introduction) that are included in every release.
- [`/internal`](/pkg) - Fibratus internal source.
- [`/pkg`](/pkg) - Fibratus main source.
- [`/pkg-config`](/pkg-config) - [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/) descriptors for externalizing the `cgo` flags.
- [`/rules`](/rules) - Detection rules.

### Setting Up The Dev Environment 

- [Download](https://golang.org/dl/) and install the Go toolchain. We love to live on the bleeding edge and regularly bump the Go toolchain in the [CI pipeline](https://github.com/rabbitstack/fibratus/blob/e9e956fd91bb2626ed7cf2fdb5f4d0091312fec3/.github/workflows/master.yml#L13).
- IDE of your choice. [GoLand](https://www.jetbrains.com/go/) is dope. [Go extension](https://code.visualstudio.com/docs/languages/go) for Visual Code does a decent job. Most IDEs can automatically [format and rearrange](https://www.jetbrains.com/help/go/reformat-and-rearrange-code.html) the code abiding by the Go code style standards. This is important to guarantee that your code is in harmony with the Go code style.

#### The Easy Way

No further dependencies are required if you have already installed the Go compiler. Fibratus includes a [`make.bat`](/make.bat) in the root directory of the repo. The `bat` script mimics the [Makefile](https://www.gnu.org/software/make/manual/html_node/Introduction.html) execution workflow. Refer to the [`make.bat`](/make.bat) file for a full list of tasks.

To build the Fibratus binary, run `./make` from the Powershell terminal. The resulting binary is placed inside the `cmd\fibratus` directory. Additionally, `fibratus-systray.exe` binary is generated in the `cmd\systray` directory. It acts as a named pipe server and sends notifications to the systray area from the corresponding alert sender.

#### The Hard Way

To build Fibratus directly from source code you have to satisfy the following dependencies:

- C compiler
- Python headers
- [libyara](https://github.com/VirusTotal/yara/tree/master/libyara)

**Installing dependencies**

1. [Download](https://www.msys2.org/#installation) the `msys2` installer and follow the instructions [here](https://www.msys2.org/).
  - open the `msys2` shell (by default located in `C:\msys2\msys2.exe`). You can also access it from the `MSYS2 64-bit` Start Menu item.
  - install the `MinGW` compiler toolchain along with other dependencies:
    - `pacman -S base-devel mingw-w64-x86_64-openssl mingw-w64-x86_64-gcc mingw-w64-x86_64-pkg-config automake libtool autoconf`
2. [Download](https://www.python.org/ftp/python/3.7.9/python-3.7.9-amd64.exe) and install the `Python 3.7`. Assuming the Python distribution was installed in `C:\Python37`, set the `PKG_CONFIG_PATH` environment variable to the location of the `pkg-config` directory within the `fibratus` directory.
  - `$env:PKG_CONFIG_PATH="<pkg-config absolute path>"`
3. Build `libyara`
  - clone the `yara` repository into the path visible to the `msys2` environment. This is ideally done from the `MSYS2 64-bit` shell.
    - `pacman -S git`
    - `git clone https://github.com/VirusTotal/yara.git`
    - go to the `yara` repository you previously cloned. Run the following commands:
      - `autoreconf -fiv`
      - `./configure --host=x86_64-w64-mingw32`
      - `make install`

**Build flags**

By default, when building Fibratus, the Go compiler is instructed to ignore all features that trigger the [cgo](https://golang.org/cmd/cgo/), but you can control which features are enabled through the following build flags:

- `filament`: compiles Fibratus with filaments support
- `kcap`: compiles Fibratus with support for capturing/replaying kcap files
- `yara`: builds Fibratus with support for [Yara](https://virustotal.github.io/yara/) pattern matching

To produce the Fibratus binary with the filaments support, you would run the following commands from the Powershell terminal:

```
$ $env:TAGS="filament"
$ ./make
```

To create the full-fledged Fibratus binary, activate all build flags:

```
$ $env:TAGS="filament,kcap,yara"
$ ./make
```

### Running For The First Time

By default, Fibratus operates in rule engine mode. It loads the rule set from the `%PROGRAM FILES%\Fibratus\Rules` directory and sends security alerts to the [systray](/alerts/senders/systray) notification area. Optionally, it takes response actions when the rule is fired, such as killing the process.
Alternatively, Fibratus can forward events to [output](/outputs/introduction) sinks, if it started in event forwarding mode.

To start Fibratus in event forwarding mode run the next command from the root directory of this repo:

```
$ .\cmd\fibratus\fibratus.exe run --forward
```

If you want to run Fibratus in rule engine mode, follow the next steps:

- run the systray server or disable the systray alert sender in the configuration file. You can start the systray server by running the `.\cmd\fibratus\fibratus-systray.exe` binary.
- modify the configuration file to set the location to the rule files. Go to the `filters` section, and specify the absolute path to the `Rules` and `Macros` directories of this repository.
  ```
  filters:
    rules:
      # The list of file system paths were rule files are located. Supports glob expressions in path names.
      from-paths:
       - C:\Fibratus\Rules\*.yml
      #from-urls:
    macros:
      # The list of file system paths were macro library files are located. Supports glob expressions in path names.
      from-paths:
       - C:\Fibratus\Rules\Macros\*.yml
  ```
  Change the paths according to the location of your repository.

- start Fibratus passing the path to the configuration file 
  ```
  $ .\cmd\fibratus\fibratus.exe --config-file=configs/fibratus.yml
  ```

### Packaging

[Wix Toolset](https://wixtoolset.org/) is a set of tools that allow creating MSI packages. To bundle all Fibratus components inside the MSI package, it is required that you first install Wix Toolset.

Use the `dotnet` command to install Wix Toolset. If you don't have **.NET runtime** installed, it is possible to fetch it via [choco](https://community.chocolatey.org/) package manager.

```
$ choco install dotnet
$ dotnet tool install --global wix --version 5.0.0
```

Now use the `pkg` target from the `./make.bat` script to build the MSI package.

```
$ $env:VERSION="0.0.0"
$ ./make.bat pkg
```

The resulting MSI is placed in the `build\msi` directory.


