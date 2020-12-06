# Contributing

We greatly appreciate you have considered contributing to Fibratus! Please, read carefully through the contribution guidelines before you start the contribution process.

## Introduction

1. **You're familiar with [Github](https://github.com) and the pull request workflow.**
2. **Make sure you've read Fibratus' [docs](https://www.fibratus.io).**
3. If you got an idea about some feature that's not currently in the backlog, please create the [feature request](https://github.com/rabbitstack/fibratus/issues/new) first.

## Development

1. Clone the Fibratus repository into the location of your choice.
2. [Download](https://golang.org/dl/) and install the Go compiler.
3. If you are intending to contribute to features that interop with the `C` code, such as [filaments](https://www.fibratus.io/#/filaments/introduction) or [YARA](https://www.fibratus.io/#/yara/introduction), [set up](https://www.fibratus.io/#/setup/installation?id=installing-dependencies) the required dependencies.

#### Directory Structure

- [`/build/package`](/build/package) - [NSIS](https://nsis.sourceforge.io/Main_Page) script for producing the Windows installer.
- [`/cmd/fibratus`](/cmd/fibratus) - Contains the entrypoint, CLI command implementations and the resource compiler manifest.
- [`/config`](/config) - Configuration files in `yml` and `json` format, included in releases.
- [`/docs`](/docs) - Markdown files for generating the [documentation](https://www.fibratus.io/) site.
- [`/filaments`](/filaments) - The collection of [filaments](https://www.fibratus.io/#/filaments/introduction) that are included in releases.
- [`/pkg`](/pkg) - Fibratus main source.
- [`/pkg-config`](/pkg-config) - [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/) descriptors for externalizing the `cgo` flags.

#### Make

Fibratus includes a [`make.bat`](/make.bat) in the root of the repo. The `bat` script mimics the [Makefile](https://www.gnu.org/software/make/manual/html_node/Introduction.html) execution workflow.
Running `make` will produce the Fibratus binary with all build flags enabled. Refer to the `make.bat` file for a list of available tasks.

#### Code Style

Fibratus uses `gofmt` to format the code. Run the `make fmt` from the root directory to emit indentation blocks that are in harmony with the Go code style.

Besides this, the `golint` ensures you adhere to best practices regarding identifier naming, code docs, and so on. You can invoke the linter with `make lint`.
