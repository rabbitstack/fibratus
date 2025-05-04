<p align="center" >
  <a href="https://www.fibratus.io" >
    <img src="logo.png" alt="Fibratus">
  </a>
</p>

<h2 align="center">Fibratus</h2>

<p align="center">
  Adversary tradecraft detection, protection, and hunting
  <br>
  <a href="https://www.fibratus.io/#/setup/installation"><strong>Get Started »</strong></a>
  <br>
  <br>
  <strong>
    <a href="https://www.fibratus.io">Docs</a>
    &nbsp;&nbsp;&bull;&nbsp;&nbsp;
    <a href="https://github.com/rabbitstack/fibratus/tree/master/rules">Rules</a>
    &nbsp;&nbsp;&bull;&nbsp;&nbsp;
    <a href="https://github.com/rabbitstack/fibratus/tree/master/filaments">Filaments</a>
    &nbsp;&nbsp;&bull;&nbsp;&nbsp;
    <a href="https://github.com/rabbitstack/fibratus/releases">Download</a>
    &nbsp;&nbsp;&bull;&nbsp;&nbsp;
    <a href="https://github.com/rabbitstack/fibratus/discussions">Discussions</a>
  </strong>
</p>

Fibratus detects, protects, and eradicates advanced adversary tradecraft by scrutinizing
and asserting a wide spectrum of system events against a behavior-driven [rule engine](https://www.fibratus.io/#/filters/rules) and [YARA](https://www.fibratus.io/#/yara/introduction) memory scanner.

Events can also be shipped to a wide array of [output sinks](https://www.fibratus.io/#/outputs/introduction) or dumped to [capture](https://www.fibratus.io/#/captures/introduction) files for local inspection and forensics analysis. You can use [filaments](https://www.fibratus.io/#/filaments/introduction) to extend Fibratus with your own arsenal of tools and so leverage the power of the Python ecosystem. 

In a nutshell, the Fibratus mantra is defined by the pillars of **realtime behavior detection**, **memory scanning**, and **forensics** capabilities.


### Installation

- Download the latest [MSI package](https://github.com/rabbitstack/fibratus/releases) and follow the [UI](https://www.fibratus.io/#/setup/installation) wizard or
alternatively install via `msiexec` in silent mode

```
$ msiexec /i fibratus-2.4.0-amd64.msi /qn
```

### Quick start

---

- spin up a command line prompt
- list credentials from the vault by using the `VaultCmd` tool

```
$ VaultCmd.exe /listcreds:"Windows Credentials" /all
```

`Credential discovery via VaultCmd tool` rule should trigger and emit the alert to the [Eventlog](https://www.fibratus.io/#/alerts/senders/eventlog). Check the short demo [here](https://www.fibratus.io/alerts/senders/images/eventlog.gif).

### Documentation

To fully exploit and learn about Fibratus capabilities, read the [docs](https://www.fibratus.io).

### Rules

Detection rules live in the [`rules`](/rules) directory of this repository. The CLI provides a set of
commands to explore the rule catalog, validate the rules, or [create a new rule](https://github.com/rabbitstack/fibratus/tree/master/rules#structure) from the template.

To describe all rules in the catalog, use the `fibratus rules list` command. It is possible to pass the
`-s` flag to show rules summary by MITRE tactics and techniques.

### Contributing

We love contributions. To start contributing to Fibratus, please read our [contribution guidelines](https://github.com/rabbitstack/fibratus/blob/master/CONTRIBUTING.md).

### Code Signing Policy

Free code signing provided by [SignPath.io], certificate by
[SignPath Foundation]. All releases are automatically signed.

[SignPath.io]: https://signpath.io
[SignPath Foundation]: https://signpath.org

---

<p align="center">
  Developed with ❤️ by <strong>Nedim Šabić Šabić</strong>
</p>
