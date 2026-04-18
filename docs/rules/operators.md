# Operators

##### Operators define **how expressions are evaluated** in the Fibratus rule language. They are used to compare values, combine conditions, and perform advanced string matching.

Operator names are **case-insensitive**, so `AND`, `and`, and `And` are equivalent.

---

## Operator categories

Fibratus supports several classes of operators:

* **Comparison (binary)** — compare values
* **Logical** — combine expressions
* **String / pattern** — match and search text
* **Set / collection** — operate on lists

---

## Comparison (binary) operators

These operators compare two values:

| Operator | Description                         |
| -------- | ----------------------------------- |
| `=`      | Equal                               |
| `!=`     | Not equal                           |
| `<`      | Less than                           |
| `>`      | Greater than                        |
| `<=`     | Less than or equal                  |
| `>=`     | Greater than or equal               |
| `~=`     | Case-insensitive equality (strings) |

### Examples

```text
ps.pid = 4
thread.cpu.usage > 10
file.name ~= 'CMD.EXE'
```

> 💡 `~=` is useful when you want equality semantics without manually normalizing case.

---

## Logical operators

Logical operators combine multiple expressions into a single condition.

### `and` (intersection)

Evaluates to `true` only if **both expressions are true**.

```text
ps.name = 'System' and ps.pid = 4
```

---

### `or` (union)

Evaluates to `true` if **at least one expression is true**.

```text
ps.name = 'svchost.exe' or ps.name contains 'svc'
```

---

### `not` (negation)

Negates the result of an expression.

```text
not ps.is_system
```

Or:

```text
ps.name = 'svchost.exe' and not ps.args in ('/c', '/k')
```

---

### Operator precedence

Logical operators follow this order:

1. `not`
2. `and`
3. `or`

Example:

```text
A or B and C
```

Is interpreted as:

```text
A or (B and C)
```

> ⚠️ Always use parentheses to make intent explicit.

---

## String operators

String operators apply to **string fields or string collections**.

---

### `in`, `iin`

Checks if a value exists in a collection.

* `in` → case-sensitive
* `iin` → case-insensitive

```text
ps.name in ('cmd.exe', 'powershell.exe')
ps.modules iin ('kernel32.dll')
```

---

### `contains`, `icontains`

Checks whether a string (or any element in a list) contains a substring.

```text
ps.name contains 'cmd'
ps.cmdline icontains 'windows tasks'
```

---

### `startswith`, `istartswith`

Checks if a string begins with a prefix.

```text
ps.name startswith 'svchost'
```

---

### `endswith`, `iendswith`

Checks if a string ends with a suffix.

```text
file.name iendswith '.exe'
```

---

### `intersects`, `iintersects`

Checks whether **all elements in RHS** exist in the LHS collection.

```text
ps.args intersects ('DcomLaunch', 'LSM')
```

> 💡 Useful for matching command-line argument combinations.

---

### `matches`, `imatches`

Wildcard-based matching (similar to globbing):

* `*` → matches any sequence of characters
* `?` → matches a single character

```text
file.name matches ('C:\\*\\lsass?.dmp', 'C:\\ProgramData\\*.dll')
registry.key.name matches 'HKEY_USERS\\*\\Environment\\windir'
```

---

## Fuzzy matching operators

Fuzzy operators enable **approximate string matching**, which is useful for detecting obfuscation or minor variations.

| Operator     | Description                            |
| ------------ | -------------------------------------- |
| `fuzzy`      | Approximate match                      |
| `ifuzzy`     | Case-insensitive fuzzy match           |
| `fuzzynorm`  | Fuzzy match with Unicode normalization |
| `ifuzzynorm` | Case-insensitive + normalized          |

---

### Examples

```text
file.name fuzzy 'C:\\Windows\\Sys\\ser3ll'
```

Matches something like:

```
C:\Windows\System32\user32.dll
```

---

```text
file.name fuzzynorm 'C:\\Windows\\Sys\\sér3ll'
```

Handles Unicode-normalized variations.

---

## Working with collections

Some operators operate on **lists (slices)**:

* `in`, `iin`
* `contains`, `icontains`
* `intersects`, `iintersects`

Example:

```text
ps.modules in ('kernel32.dll')
```

---

## Combining operators

Operators can be combined to build expressive filters:

```text
ps.name in ('powershell.exe', 'cmd.exe')
  and
ps.cmdline contains '-enc'
  and
not file.path contains 'Windows\\System32'
```

---

## Practical patterns

### Case-insensitive equality

```text
file.name ~= 'cmd.exe'
```

---

### Detect suspicious command-line usage

```text
ps.name = 'powershell.exe'
  and
ps.cmdline icontains '-encodedcommand'
```

---

### Match multiple wildcard patterns

```text
file.path matches ('C:\\Temp\\*.exe', 'C:\\Users\\Public\\*.dll')
```

---

### Detect argument combinations

```text
ps.args intersects ('-nop', '-w hidden')
```

---

## Best practices

* Prefer **case-insensitive operators** when dealing with user-controlled input
* Use `matches` for flexible patterns instead of complex string chains
* Use `intersects` for multi-argument matching
* Avoid overusing fuzzy matching — it is powerful but can be expensive
* Always use **parentheses** for complex logical expressions

---

## Summary

Operators are the backbone of the filtering language. They allow you to:

* Compare values precisely
* Combine conditions logically
* Perform advanced string and pattern matching
* Work with collections and approximate matches

Mastering operators is key to building **accurate, expressive, and performant detection logic** in Fibratus.

---

If you want, I can also add a **cheat sheet table (one-pager)** or a **“which operator should I use?” decision guide**, which tends to help users a lot in practice.


The filter engine supports logical, arithmetic, and string operators. Operator names are case-insensitive.

## Binary operators

The filtering query language supports the following comparison binary operators:

- `=` (equal)
- `!=` (not equal)
- `<` (less than)
- `>` (greater than)
- `>=` (greater or equal)
- `<=` (less or equal)
- `~=` (case-insensitive string comparison)

## Logical operators

Logical operators are applied on two or more binary expressions, except for `not` that acts as a unary operator.

### or

`or` (union) evalutes to true if either one of the LHS (Left Hand Side) or RHS (Right Hand Side) expressions are true. 

- **Example**

   Filter events where the originating process name is equal to `svchost.exe` or the process name contains the `svc` string

   ```
   fibratus run ps.name = 'svchost.exe' or ps.name contains ('svc')
   ```

### and

`and` (intersection) evalutes to true if both of the LHS (Left Hand Side) and RHS (Right Hand Side) expressions are true.

- **Example**

   Filter events only when the originating process name is equal to `System` and the process identifier is equal to `4`

   ```
   fibratus run ps.name = 'System' and ps.pid = 4
   ```

### not

`not` (negation) negates the result of the adjacent expression.

- **Example**

   Filter events only when the originating process name is equal to `svchost.exe` and none of the process' command line arguments is equal to `/-C` or `/cdir`

   ```
   fibratus run ps.name = 'svchost.exe' and ps.args not in ('/-C', '/cdir') 
   ```

## String operators

String operators are applied to string field types or string literals.

### in, iin

`in` operator validates the presence of a value in the string sequence. It can be applied to string literal sequences or dynamic string slices given by filter fields. `iin` is the case-insensitive variant of the `in` operator.

- **Examples**

   Tests if the process name producing the event is either `cmd.exe` or `powershell.exe`

   ```
   $ fibratus run ps.name in ('cmd.exe', 'powershell.exe')
   ```

   Checks if any of the process modules contains the `kernel32` dynamic linked object

   ```
   $ fibratus run ps.modules in ('kernel32.dll')
   ```

### contains, icontains

`contains` operator checks whether a string field contains a sequence of characters. This operator works on both simple string values and lists of strings. `icontains` is the case-insensitive variant of the `contains` operator.

- **Examples**

   Checks if the process' name contains the `cmd` or `power` substrings

   ```
   $ fibratus run ps.name contains ('cmd', 'power')
   ```

   Checks if the process' command line contains the `Windows Tasks` substring

   ```
   $ fibratus run ps.comm contains 'Windows Tasks'
   ```


### startswith, istartswith

`startswith` checks whether a string field starts with a specified prefix. This operator works on both simple string values and lists of strings. `istartswith` is the case-insensitive variant of the `startswith` operator.

- **Example**

   Filter events where the originating process name is equal to `svchost.exe`

   ```
   fibratus run ps.name startswith 'svchost'
   ```


### endswith, iendswith

`endswith` checks whether a string field ends with a specified suffix. This operator works on both simple string values and lists of strings. `iendswith` is the case-insensitive variant of the `endswith` operator.

- **Example**

   Filter events where the originating process name is equal to `svchost.exe`

   ```
   fibratus run ps.name endswith '.exe'
    ```

### intersects, iintersects

`intersects` operator and its case-insensitive `iintersects` variant operate on string slices. If all elements in the RHS slice are present in the slice given by LHS, the operator evaluates to `true`. Otherwise, it evaluates to `false`.

- **Example**

   Filter events where the originating process command line arguments contain both `DcomLaunch` and `LSM` arguments

   ```
   fibratus run ps.args intersects ('DcomLaunch', 'LSM')
   ```

### matches, imatches

`matches` is the swiss army knife string matching operator. It allows string matching by using the wildcard characters similar to [globbing](https://en.wikipedia.org/wiki/Glob_(programming)). The `*` wildcard matches a sequence of characters, while the `?` wildcard matches a single character. `imatches` is the case-insensitive variant of the `matches` operator.

- **Examples**

   To match events with file paths equal to `C:\\Windows\\System32\\lsass2.dmp` or `C:\\ProgramData\\Directory\\tmp\\anubis.dll`

   ```
   fibratus run file.name matches ('C:\\*\\lsass?.dmp', 'C:\\ProgramData\\*.dll')
   ```

   For filtering registry events with key names such as `HKEY_USERS\\S-1-5-21-2271034452-2606270099-984871569-1001\\Environment\\windir`

   ```
   fibratus run registry.key.name matches 'HKEY_USERS\\*\\Environment\\windir'
   ```

### fuzzy, ifuzzy, fuzzynorm, ifuzzynorm

`fuzzy` operators allow for flexibly matching a string with partial input based on [fuzzy matching](https://en.wikipedia.org/wiki/Fuzzy_matching_(computer-assisted_translation)) techniques. `fuzzynorm` applies Unicode normalization before running the matching phase. `ifuzzy` and `ifuzzynorm` are the case-insensitive variants of the respective fuzzy operators.

- **Examples**

   To match events with file paths that contain `C:\\Windows\\System32\\user32.dll`, you could create an expression with the  partial path input

   ```
   fibratus run file.name fuzzy 'C:\\Windows\\Sys\\ser3ll'
   ```

   `fuzzynorm` operates on normalized Unicode codepoints

   ```
   fibratus run file.name fuzzynorm 'C:\\Windows\\Sys\\sér3ll'
   ```