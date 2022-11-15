# Detection Rules

<p align="center" >
  <a href="https://www.fibratus.io" >
    <img width="600px" height="800px" src="rule-alert.png" alt="Email rule alert">
  </a>
</p>

This directory contains a catalog of detection rules modeled around the prominent [MITRE ATT&CK](https://attack.mitre.org/) framework. The goal is to provide a direct mapping of tactics, techniques, and sub-techniques for each rule. The following sections introduce the general structure, design guidelines, and best practices to keep in mind when creating new rules.

## Structure

Detection rules are organized as `yaml` files whose names adhere to the `tactic-name_technique-name.yml` nomenclature. Every `yaml` file may contain several rules grouped under a specific [rule policy](https://www.fibratus.io/#/filters/rules). Each rule in the group represents the detection of a particular adversary sub-technique which may employ different data sources. If the technique doesn't break down into individual sub-techniques, it is expressed as a sole rule in the group. Let's suppose we want to detect unusual accesses to Windows Credentials history which is backed by the [Windows Credentials Manager](https://attack.mitre.org/techniques/T1555/004/) MITRE sub-technique. Since the sub-technique pertains to `Credentials from Password Stores` technique living under the `Credential Access` tactic, we would have created the `credential_access_credentials_from_password_stores.yml` file to store the rule definitions.

Next, we declare the `Credentials access from Windows Credential Manager` group using the [rule specification](https://www.fibratus.io/#/filters/rules?id=defining-rules) idiom, and define the rule that fires when an unusual process accesses a file matching the `?:\\Users\\*\\AppData\\*\\Microsoft\\Protect` wildcard expression. Similarly, we can append additional rules if the technique/sub-technique employs multiple data sources to describe the detection logic or uses a single telemetry source to express variations of the detection reasoning. For instance, file accesses to Windows Vault resources use the file telemetry, meanwhile, credentials enumeration via `VaultCmd.exe` relies on process execution. Check [here](credential_access_credentials_from_password_stores.yml) the result of all rules meant to hunt suspicious activities regarding accessing credentials from password stores.

## Guidelines

### Stick to naming nomenclature

It is highly recommended to name the rule files after the pattern explained in the above section. This facilitates the organization and searching through the detection rules catalog and fosters standardization.

### Include descriptions and labels

Rule groups should have a meaningful description. Individual rules inside the group should ideally have a description too.
For example, the `Spearphishing attachment execution of files written by Microsoft Office processes` group has the following description that has been borrowed verbatim from the MITRE knowledge base. 

> Adversaries may send spearphishing emails with a malicious attachment in an
attempt to gain access to victim systems. Spearphishing attachment is a specific
variant of spearphishing. Spearphishing attachment is different from other forms
of spearphishing in that it employs the use of malware attached to an email.

Additionally, there should exist labels attached to every rule group describing the MITRE tactic, technique, and sub-technique. This information is used when rendering email rule alert templates.

### Rules should have narrowed event scope

Rule groups may have multiple rules each targeting different event types. If the rule definition lacks the event type or category condition, the rule engine needs to devote extra resources to evaluate the incoming event against every single rule. To alleviate the pressure on the rule engine, all rules should
have the event type condition. In fact, if a rule is declared without the scoped conditions, you'll get a warning message in `Fibratus` logs informing you about unwanted side effects. In the case of `include` or `exclude` rule policies, **this may lead to the rule being utterly discarded by the engine!**

### Sequence policies with early binding index condition

When writing detections that employ various event types or event multiple data sources, relationships between events are connected via [binding patterns](https://www.fibratus.io/#/filters/rules?id=stateful-event-tracking). The rule engine can lazily evaluate binary expressions comprising a rule. If the binding patterns are the first condition in downstream sequence rule groups, the rule engine will not keep on evaluating every single binary expression in the rule and thus will benefit the overall runtime performance.

### Prefer macros over raw conditions

Fibratus comes with a macro library to promote the reusability and modularization of rule conditions and lists. Before trying to spell out a raw rule condition, explore the library to check if there's already a macro you can pull into the rule. For example, detecting file accesses could be accomplished by declaring the `kevt.name = 'CreateFile' and file.operation = 'open'`. However, the macro library comes with the `open_file` macro that you can directly call in any rule. If you can't encounter a particular macro in the library, please consider creating it. Future detection engineers and rule writers could profit from those macros.

### Formatting styles

Pay attention to rule condition/action formatting style. If the rule consists of multiple conditions, it is desirable to split each spanning condition on a new line and properly indent the `and`, `or`, or `not` operators. By default, we use 4 space tabs for indenting operators and rule actions. This will greatly improve readability and preventing formatting inconsistencies.
