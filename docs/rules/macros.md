# Macros

##### Macros foment rule patterns reusability and a human-friendly domain-specific language (DSL). A vast majority of detection rules may require conditions to express process execution or file writes. For such cases, an expression such as `evt.name = 'CreateProcess'` can be crafted. 

However, this may lead to bloated and boilerplate rules. From the maintenance standpoint, introducing a small change in the rule condition would force us to update all the rules, while macros are a much more convenient mechanism for declaring reusable rule patterns. Fibratus ships with a [macros library](https://github.com/rabbitstack/fibratus/blob/master/rules/macros/macros.yml) containing a dozen of different macros ready to use. Macros library is loaded from the file system and can be split across multiple `yaml` files. The default location is designated by the `%PROGRAM FILES%\Fibratus\Rules\Macros` directory.

```yaml
filters:
  macros:
    from-paths:
      - C:\Program Files\Fibratus\Rules\Macros\*.yml
```

## Macro types

### Expressions

**Expression** macros encapsulate rule conditions. A macro declaration requires a unique macro name, the expression, and an optional description.

```yaml
- macro: spawn_process
  expr: evt.name = 'CreateProcess'
  description: Identifies the execution of a new process
```

Where macro expressions really shine is when combined with other macros to forge recursive macros. For example, the `spawn_msoffice_process` is composed of `spawn_process` expression macro and the `msoffice_binaries` list macro.

```yaml
- macro: spawn_msoffice_process
  expr: spawn_process and ps.sibling.exe iin msoffice_binaries
  description: Identifies the execution of the MS Office process
```
### Lists

- **list** macros declare a sequence of items such as file system paths, process names, or registry keys. List macros help to make the rules succinct and clean. An example of a macro list containing Microsoft Office process image names. Various operators, such as `in`, `matches`, or `startswith` can accept list macros as RHS (Right Hand Side) expressions.

```yaml
- macro: msoffice_binaries
  list: [EXCEL.EXE, WINWORD.EXE, MSACCESS.EXE, POWERPNT.EXE]
```