# Macros

##### Macros enable reusable rule patterns and provide a more expressive, human-friendly domain-specific language (DSL). Many detection rules rely on common conditions, such as process execution or file creation. For example, a rule might include an expression like `evt.name = 'CreateProcess'`

Repeatedly embedding such conditions can lead to verbose, boilerplate-heavy rules. From a maintenance perspective, even a small change would require updating every affected rule. Macros solve this problem by offering a convenient way to define and reuse common patterns. Fibratus includes a built-in [macros library](https://github.com/rabbitstack/fibratus/blob/master/rules/macros/macros.yml) with a variety of ready-to-use definitions. The macros library is loaded from the file system and can be organized across multiple `yaml` files. By default, macros are located in the `%PROGRAM FILES%\Fibratus\Rules\Macros` directory.

```yaml
filters:
  macros:
    from-paths:
      - C:\Program Files\Fibratus\Rules\Macros\*.yml
```

## Macro types

### Expressions

Expression macros encapsulate rule conditions. A macro declaration requires a unique macro name, the expression, and an optional description.

```python
- macro: spawn_process
  expr: evt.name = 'CreateProcess'
  description: Identifies the execution of a new process
```

Macros can be composed with other macros to build more complex, recursive patterns. For example, the `spawn_msoffice_process` macro combines the `spawn_process` expression macro and the `msoffice_binaries` list macro.

```python
- macro: spawn_msoffice_process
  expr: spawn_process and ps.sibling.exe iin msoffice_binaries
  description: Identifies the execution of the MS Office process
```
### Lists

List macros define a sequence of values such as file system paths, process names, or registry keys. They help keep rules concise, readable, and easier to maintain. For example, a list macro can contain Microsoft Office process executable names. Operators such as `in`, `matches`, or `startswith` can accept list macros as right-hand side (RHS) expressions in rule conditions.

```python
- macro: msoffice_binaries
  list: [EXCEL.EXE, WINWORD.EXE, MSACCESS.EXE, POWERPNT.EXE]
```