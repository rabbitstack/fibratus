# Operators

##### Operators define how expressions are evaluated in the Fibratus rule language. They are used to compare values, combine conditions, and perform advanced string matching.

Operator names are case-insensitive, so `AND`, `and`, and `And` are equivalent. Fibratus supports several classes of operators including binary, logical, and string.

## Binary operators

Binary operators compare two values and evaluate the relationship between them, producing a boolean result that can be used in rule conditions. In Fibratus, binary operators are used to express comparisons such as equality, inequality or ordering, forming the building blocks of more complex detection logic.


| OPERATOR  | DESCRIPTION |
| :---        |    :----   |
| `=`      | Equal                               |
| `!=`     | Not equal                           |
| `<`      | Less than                           |
| `>`      | Greater than                        |
| `<=`     | Less than or equal                  |
| `>=`     | Greater than or equal               |
| `~=`     | Case-insensitive equality (strings) |

!> `~=` is useful when you want equality semantics without manually normalizing case.


## Logical operators

Logical operators combine multiple expressions into a single condition, allowing rules to express more complex logic in a clear and structured way. In Fibratus, binary logical operators are used to evaluate relationships between two boolean expressions and determine the overall outcome of a condition. These operators enable combining checks such as comparisons, membership tests, or pattern matches into a unified rule, making detection logic more expressive and precise.

### Intersection

The intersection operator is denoted by the `and` keyword and evaluates to `true` only if both expressions are true.

```python
ps.name = 'System' and ps.pid = 4
```

### Union

The union operator is denoted by the `or` keyword and evaluates to `true` if at least one expression is true.

```python
ps.name = 'svchost.exe' or ps.name contains 'svc'
```

### Negation

The negation operator is denoted by the `not` keyword and it negates the result of an expression.

```python
ps.name = 'svchost.exe' and ps.args not in ('/c', '/k')
```

## String operators

String operators apply to string [fields](fields.md) or collections of strings, enabling evaluation and comparison of textual values within rules. In Fibratus, these operators are used to perform operations such as pattern matching, prefix or suffix checks, containment tests, and exact or case-insensitive comparisons. They help build precise detection logic by allowing rules to express conditions based on the structure and content of string data.


| OPERATOR  | DESCRIPTION | EXAMPLE |
| :---        |    :----   |  :---- |
| `in`      | Checks if a value exists in a collection. | `ps.name in ('cmd.exe', 'powershell.exe')` |
| `iin`      | Checks if a value exists in a collection but ignores case sensitivity.  | `ps.modules iin ('kernel32.dll')` |
| `contains` | Checks whether a string or any element in a list contains a substring. | `ps.name contains 'cmd'` |
| `icontains` | Checks whether a string or any element in a list contains a substring but ignores case sensitivity. | `ps.cmdline icontains 'windows tasks'` |
| `startswith` | Checks if a string begins with a prefix. | `ps.name startswith 'svchost'` |
| `istartswith` | Checks if a string begins with a prefix but ignores case sensitivity. | `ps.name istartswith 'cmd'` |
| `endswith` | Checks if a string ends with a suffix. | `file.path endswith 'Windows'` |
| `iendswith` | Checks if a string ends with a suffix but ignores case sensitivity. | `file.path iendswith '.exe'` |
| `intersects` | Checks whether all elements in RHS exist in the LHS collection. | `ps.args intersects ('DcomLaunch', 'LSM')` |
| `iintersects` | Checks whether all elements in RHS exist in the LHS collection but ignores case sensitivity. | `ps.args iintersects ('dcomLaunch', 'LSM')` |
| `matches` | Wildcard-based matching similar to globbing. `*` matches any sequence of characters, while `?` matches a single character. | `registry.path matches 'HKEY_USERS\\*\\Environment\\?'` |
| `imatches` | Wildcard-based matching but ignores case sensitivity. `*` matches any sequence of characters, while `?` matches a single character. | `file.path imatches ('?:\\*\\lsass?.dmp', '?:\\ProgramData\\*.dll')` |


## Fuzzy operators

Fuzzy operators enable approximate string matching, which is useful for detecting obfuscation or minor variations in textual data. They help identify values that are not identical but remain similar enough to indicate a potential match, even when attackers introduce small modifications such as typos, character substitutions, or encoding tricks. This makes fuzzy matching particularly valuable for uncovering evasive behaviors and reducing false negatives in detection rules.


| OPERATOR  | DESCRIPTION | EXAMPLE |
| :---        |    :----   |  :---- |
| `fuzzy`      | Approximate match.                      | `file.path fuzzy 'C:\\Windows\\Sys\\ser3ll'` matches `C:\Windows\System32\user32.dll` |
| `ifuzzy`     | Case-insensitive fuzzy match.           | `file.path ifuzzy 'C:\\Windows\\Sys\\ser3ll'` matches `C:\WINDOWS\System32\user32.dll`|
| `fuzzynorm`  | Fuzzy match with Unicode normalization. | `file.path fuzzynorm 'C:\\Windows\\Sys\\sér3ll'` matches `C:\Windows\System32\usér32.dll` |
| `ifuzzynorm` | Case-insensitive and Unciode normalized.          | `file.path ifuzzynorm 'C:\\Windows\\Sys\\sér3ll'` matches `C:\Windows\System32\usér32.dll`|
