# Functions

##### Functions significantly extend the expressive power of the rule language by enabling **data transformation, enrichment, and dynamic evaluation** at runtime. A function can return a primitive values such as string/boolean or a collection of primitive values.

Functions can be used anywhere a value is expected inside comparisons, logical expressions, or even as inputs to other functions.
For example, this expression removes the `C:` prefix from `file.path` and converts the resulting string to lowercase.

```python
lower(ltrim(file.path, 'C:'))
```

Functions can be nested arbitrarily, allowing to build complex transformations step by step. In this example, the execution proceeds from the innermost function outward. `replace` normalizes path separators. Next,`trim` removes leading/trailing whitespace, and finally, `lower` ensures case-insensitive comparasion. This makes it easy to normalize data before applying detection logic.

```python
lower(trim(replace(file.path, '\\', '/')))
```

Some functions return collections (lists) instead of single values. These are especially useful when combined with operators like `in`, `iin`, `contains`, or `intersects`. In this example, `get_reg_value` may return multiple strings, for example from a `MULTI_SZ` registry value. The `iin` operator checks whether any element matches the provided list.

```python
get_reg_value(registry.path) iin ('mimikatz.dll', 'rpcrt4.dll')
```

?> Each function expects arguments of specific types. Passing an incompatible type results in rule compilation error.


## Network functions

### `cidr_contains`

Determines if the specified IP is contained within the block referenced by the given CIDR masks.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---        |    :----   |  :---- | :----  |
| `ip` | ip | IP address in v4/v6 notation. | yes |
| `cidrs` | array | List of IP masks in CIDR notation. | yes |

##### Return

> `return` Boolean Indicates whether the IP pertains to the CIDR block

##### Usage

```
cidr_contains(net.sip, '192.168.1.1/24', '172.17.1.1/8') = true
```

## Hash functions

### `md5`

Computes the MD5 hash of the given value.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---        |    :----   |  :---- | :----  |
| `data` | string or byte | The input string or byte array used to compute the MD5 hash. | yes |

##### Return

> `return` String MD5 hash in string format

##### Usage

```
md5(registry.path) = 'eab870b2a516206575d2ffa2b98d8af5'
```

## String functions

### `concat`

Concatenates string/integer input arguments.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `tokens` | strings or integers | Strings or integers to be concatenated. | yes |

##### Return

> `return` String Concatenated string of all input tokens

##### Usage

```
concat(ps.domain, '-', ps.username) = 'NT_AUTHORITY-SYSTEM'
```
---

### `ltrim`

Trims the prefix from the string.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `string` | string | Input string. | yes |
| `prefix` | string | Prefix to be removed. | yes |

##### Return

> `return` String Resulting string with the prefix removed

##### Usage

```
ltrim(registry.path, 'HKEY_LOCAL_MACHINE\\') = 'SYSTEM\\Setup\\Pid'
```
---

### `rtrim`

Trims the suffix from the string.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `string` | string | Input string. | yes |
| `suffix` | string | Suffix to be removed. | yes |

##### Return

> `return` String Resulting string with the suffix removed

##### Usage

```
rtrim(registry.path, '\\Pid') = 'HKEY_LOCAL_MACHINE\\SYSTEM\\Setup'
```
---

### `lower`

Converts the string with all Unicode letters mapped to their lower case.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `string` | string | Input string. | yes |

##### Return

> `return` String Resulting string converted to lower case

##### Usage

```
lower(registry.path) = 'hkey_local_machine\\system\\setup'
```

---

### `upper`

Converts the string with all Unicode letters mapped to their upper case.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `string` | string | Input string. | yes |

##### Return

> `return` String Resulting string converted to upper case

##### Usage

```
upper(registry.path) = 'HKEY_LOCAL_MACHINE\\SYSTEM\\SETUP'
```

---

### `replace`

Replaces all occurrences in the string as given by arbitrary old/new replacement pairs. You can specify multiple `old`/`new` pairs to be replaced.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `string` | string | Input string. | yes |
| `old` | string | Substring in the original string that is replaced with the `new` string. | yes |
| `new` | string | Replacement string. | yes |

##### Return

> `return` String Resulting string with all occurrences replaced by old/new pairs

##### Usage

```
replace(registry.path, 'HKEY_LOCAL_MACHINE', 'HKLM') = 'HKLM\\SYSTEM\\Setup'
```

---

### `count`

Counts the number of items in the slice or substrings in the string by matching a wildcard pattern.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `string` or `slice` | string or array | Input string or string array. | yes |
| `pattern` | string | Wildcard pattern used to match the string. `*` matches any sequence of characters, while `?` matches a single character.  | yes |
| `case_insensitive` | boolean | Indicates if case insensitive matching is performed when counting substrings. | no |

##### Return

> `return` Integer The count of matched substring occurrences

##### Usage

```
count(ps.modules, '?:\\*ntdll.dll') >= 2
```

---

### `split`

Produces a slice of substrings separated by the given delimiter.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `string` | string | Input string. | yes |
| `separator` | string | The separator used for splitting the string. | yes |

##### Return

> `return` Array Collection of substrings contained in the string

##### Usage

```
split(file.path, '\\') in ('kernel32.dll', 'System32', 'Windows')
```
---

### `length`

Returns the number of characters for string arguments and the size of the slice for slice arguments.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `string` or `slice` | string or array | Input string or array. | yes |

##### Return

> `return` Integer The number of characters in the string or array length

##### Usage

```
length(ps.cmdline) > 200
```

---

### `indexof`

Returns the index of the instance of substring in a given string depending on the provided search order.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `string` | string | Input string. | yes |
| `substring` | string | Substring for which the search is performed. | yes |
| `order` | string | Specifies the string index search order. It can be `first`, `any`, `last`, `lastany` | no |

##### Return

> `return` Integer The index of the substring or -1 if the substring is not found

##### Usage

```
indexof(ps.domain, 'NT') = 0
```
---

### `substr`

Creates a substring of a given string.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `string` | string | Input string. | yes |
| `start` | integer | Substring start index. | yes |
| `end` | integer | Substring end index.| no |

##### Return

> `return` String Substring contained within start and end indices

##### Usage

```
substr(file.path, indexof(file.path, '\\'), indexof(file.path, '\\Hard')) = '\\Device'
```

---

### `entropy`

Calculates the string entropy.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `string` | string | Input string. | yes |
| `algo` | integer | The algorithm used to calculate the string entropy. `shannon` is the default entropy type. | no |

##### Return

> `return` Integer String entropy value

##### Usage

```
entropy(file.path) > 255
```

---

### `regex`

Applies single/multiple regular expressions on the provided string.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `string` | string | Input string. | yes |
| `patterns` | string | [Go](https://pkg.go.dev/regexp/syntax) compatible regular expression patterns. | yes |

##### Return

> `return` Boolean True if at least one regular expression matches or false otherwise

##### Usage

```
regex(ps.name, 'power.*(shell|hell).dll', '.*hell.exe') = true
```

## File functions

### `base`

Returns the last element of the path.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `path` | string or array | The string or an array of strings representing file system path(s). | yes |
| `ext` | boolean | Determines whether the extension is retained in the file path. Default `true`| no |

##### Return

> `return` String|Array String or a slice of strings with file name(s)

##### Usage

```
base(file.path) = 'cmd.exe'
```
---

### `dir`

Returns all but the last element of the path, typically the path's directory.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `path` | string or array | The string or an array of strings representing file system path(s). | yes |

##### Return

> `return` String|Array String or a slice of strings with directory name(s)

##### Usage

```
dir(file.path) = 'C:\\Windows'
```
---

### `ext`

Returns the file name extension used by the path.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `path` | string or array | The string representing file system path. | yes |
| `dot` | boolean | Indicates if the dot symbol is retained as part of extension. Default `true` | no |

##### Return

> `return` String File name extension used by the path

##### Usage

```
ext(file.name) = '.exe'
```
---

### `glob`

Returns the names of all files in the file system matching the pattern.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `pattern` | string | Shell file name pattern as described [here](https://pkg.go.dev/path/filepath#Match). | yes |

##### Return

> `return` Array Names of all files matching the pattern or an empty list if there is no matching file

##### Usage

```
glob('C:\\Windows\\*.exe') in ('C:\\Windows\\notepad.exe')
```

---

### `is_abs`

Reports whether the path is absolute.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `path` | string | The string representing file system path. | yes |

##### Return

> `return` Boolean True if the path references an absolute path or false otherwise

##### Usage

```
is_abs(file.path) = false
```
---

### `symlink`

Returns the path name after the evaluation of any symbolic links.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `path` | string | The string representing file system path. | yes |

##### Return

> `return` String The path name after the evaluation of any symbolic links, or the original path if any errors occur

##### Usage

```
symlink('C:\\Windows\\symlink.txt') = 'C:\\Windows\\target.txt'
```
---

### `volume`

Returns leading volume name.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `path` | string | The string representing file system path. | yes |

##### Return

> `return` String Leading volume name

##### Usage

```
volume(file.path) = 'C:'
```

---

### `is_minidump`

Checks the signature of the provided file and returns `true` if the signature matches the `minidump` header.

Returns leading volume name.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `path` | string | The string representing file system path. | yes |

##### Return

> `return` Boolean True if the file contains the minidump header or false otherwise

##### Usage

```
is_minidump(file.path) = true
```

---

## Registry functions

### `get_reg_value`

Reads the content of the registry value.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `key` | string | Fully-qualified registry key path including the value name. The root key can be expressed in abbreviated notation, for example, `HKLM` instead of `HKEY_LOCAL_MACHINE` | yes |

##### Return

> `return` Variant Depending on the registry value type, it can return a string, array of strings, blob, or an integer value.

##### Usage

```
 get_reg_value('HKCU\Volatile Environment\Envs') in ('SYSTEM', 'ROOT')
```

## YARA functions

### `yara`

Provides signature-based detection in rules. [YARA](https://virustotal.github.io/yara/) is a tool aimed at (but not limited to) helping malware
researchers to identify and classify malware samples. With YARA you can create descriptions of malware families based on textual or binary patterns. Depending on the parameter type supplied to this function, the scan can be performed on the process, file path or a memory block.

##### Arguments

| ARGUMENT  | TYPE | DESCRIPTION | REQUIRED? |
| :---     |    :----   |  :---- | :----  |
| `target` | int, string or byte array | If the parameter is an integer value, it's assumed to be a `pid` for which the memory area is scanned. If it is a string, the scan is performed on the process executable or arbitrary file system file. Otherwise, it is a stream of bytes that represents a memory block to be scanned. | yes |
| `rules` | string | YARA rule definitions. | yes |

##### Return

> `return` Boolean If any rule the function returns true or false othwerise

##### Usage

```
yara(file.path, 'rule Notepad : notepad
{
	strings:
		$c0 = "Notepad" fullword ascii
	condition:
		$c0
}') = true
```
