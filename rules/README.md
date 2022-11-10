# Detection Rules

This directory contains a catalog of detection rules modelled around the prominent [MITRE ATT&CK](https://attack.mitre.org/) framework. The goal is to provide a direct mapping of tactics, techniques, and subtechniques for each rule. The following sections introduce the general structure, design guidelines, and best practices to keep in mind when creating new rules.

## Structure

Detection rules are organized as `yaml` files whose names adhere to the `tactic-name_technique-name.yml` nomenclature. Every `yaml` file may contain a number of different rules grouped under a specific [rule policy](https://www.fibratus.io/#/filters/rules). Each rule in the group represents a particular adversary subtechnique. If the technique doesn't break down into individual subtechniques, it is expressed as a sole rule in the group. Let's suppose we want to detect unusual accesses to Windows Credentials history which is backed by [Windows Credentials Manager](https://attack.mitre.org/techniques/T1555/004/) MITRE subtechnique. Since it pertains to `Credentials from Password Stores` technique living under the `Credential Access` tactic, we would have created the `credential_access_credentials_from_password_stores.yml` file.

Next, we describe the `Credentials access from Windows Credential Manager` group using the [rule specification](https://www.fibratus.io/#/filters/rules?id=defining-rules) idiom, and define the rule that fires when an unusual process accesses a file in `?:\\Users\\*\\AppData\\*\\Microsoft\\Protect` location. Similarly, we can define additional rules to supervise Windows Credential Manager or Windows Vault file accesses. All of the above rules can be expressed with the `include` rule policy and the `CreateFile` selector.

## Guidelines

### Always include MITRE labels


## Macros
