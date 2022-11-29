# Functions

Functions expand the scope of the filtering language by bringing a plethora of capabilities. The function can return a primitive value, including integers, strings, and booleans. Function calls can be nested where the result of one function is used as an input in another function. For example, `lower(ltrim(file.name, 'C:'))`, removes the `C` drive letter from the file path and converts it to a lower case string.

Additionally, some functions may return a collection of values. Function names are case insensitive.

### Network functions

#### cidr_contains

`cidr_contains` determines if the specified IP is contained within the block referenced by the given CIDR mask. The first argument represents the IP address and the subsequent   arguments are IP masks in CIDR notation.

- **Specification**
    ```
    cidr_contains(ip: <string>, cidrs: <string>...) :: <boolean>
    ```
    - `ip`: The IP address in v4/v6 notation
    - `cidrs`: The list of CIDR masks
    - `return` a boolean value indicating whether the IP pertains to the CIDR block

- **Examples**

    Assuming the `net.sip` field contains the `192.168.1.20` IP address, the following filter
    would match on this event.

    ```
    fibratus run kevt.category = 'net' and cidr_contains(net.sip, '192.168.1.1/24', '172.17.1.1/8')
    ```

### Hash functions

#### md5

`md5` computes the MD5 hash of the given value.

- **Specification**
    ```
    md5(data: <string|[]byte>) :: <string>
    ```
    - `data`: The string or the byte array for which to calculate the hash
    - `return` a string representing the md5 hash

- **Examples**

    Assuming the `registry.key.name` field contains `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid`, the following would filter events for the matching md5 hash.

    ```
    fibratus run kevt.category = 'net' and md5(registry.key.name) = 'eab870b2a516206575d2ffa2b98d8af5'
    ```

### String functions

#### concat

`concat` concatenates string/integer input arguments.

- **Specification**
    ```
    concat(args: <string|int>...) :: <string>
    ```
    - `args`: Strings or integers to be concatenated. This function requires at least 2 input arguments
    - `return` a concatenated string of all input arguments

- **Examples**

    Assuming the `ps.domain` field contains `NT_AUTHORITY` and `ps.username` field contains `admin`, the following would filter events for the matching concatenated string.

    ```
    fibratus run concat(ps.domain, '-', ps.username) = 'NT_AUTHORITY-admin'
    ```

#### ltrim

`ltrim` trims the specified prefix from a string.

- **Specification**
    ```
    ltrim(string: <string>, prefix: <string>) :: <string>
    ```
    - `string`: Input string
    - `prefix`: Prefix that is removed from the original input string
    - `return` a string with the specified prefix removed

- **Examples**

    Assuming the `registry.key.name` field contains `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid`, the following filter expression would match on all events where the resulting string is equal to `SYSTEM\Setup\Pid`

    ```
    fibratus run ltrim(registry.key.name, 'HKEY_LOCAL_MACHINE\\') = 'SYSTEM\\Setup\\Pid'
    ```

#### rtrim

`rtrim` trims the specified suffix from a string.

- **Specification**
    ```
    rtrim(string: <string>, suffix: <string>) :: <string>
    ```
    - `string`: Input string
    - `prefix`: Suffix that is removed from the original string
    - `return` a string with the specified suffix removed

- **Examples**

    Assuming the `registry.key.name` field contains `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid`, the following filter expression would match on all events where the resulting string is equal to `HKEY_LOCAL_MACHINE\SYSTEM\Setup`

    ```
    fibratus run rtrim(registry.key.name, '\\Pid') = 'HKEY_LOCAL_MACHINE\\SYSTEM\\Setup'
    ```

#### lower

`lower` converts the string with all Unicode letters mapped to their lower case.

- **Specification**
    ```
    lower(string: <string>) :: <string>
    ```
    - `string`: Input string
    - `return` a string converted to lower case

- **Examples**

    Assuming the `registry.key.name` field contains `HKEY_LOCAL_MACHINE\SYSTEM\Setup`, the following filter expression would match on all events where the resulting string is equal to `hkey_local_machine\system\setup`

    ```
    fibratus run lower(registry.key.name) = 'hkey_local_machine\\system\\setup'
    ```

#### upper

`upper` converts the string with all Unicode letters mapped to their upper case.

- **Specification**
    ```
    upper(string: <string>) :: <string>
    ```
    - `string`: Input string
    - `return` a string converted to upper case

- **Examples**

    Assuming the `registry.key.name` field contains `HKEY_LOCAL_MACHINE\SYSTEM\Setup`, the following filter expression would match on all events where the resulting string is equal to `HKEY_LOCAL_MACHINE\SYSTEM\SETUP`

    ```
    fibratus run upper(registry.key.name) = 'HKEY_LOCAL_MACHINE\\SYSTEM\\SETUP'
    ```

#### replace

`replace` replaces all occurrences in the string as given by arbitrary old/new replacement pairs.

- **Specification**
    ```
    replace(string: <string>, old: <string>, new: <string>, ..., old-n: <string>, new-n: <string>) :: <string>
    ```
    - `string`: Input string
    - `old`: substring in the original string that is replaced with the `new` string
    - `new`: the replacement string
    - `return` a string with all occurrences replaced by old/new pairs

- **Examples**

    Assuming the `registry.key.name` field contains `HKEY_LOCAL_MACHINE\SYSTEM\Setup`, the following filter expression would match on all events where the resulting string is equal to `HKLM\SYS\Setup`

    ```
    fibratus run replace(registry.key.name, 'HKEY_LOCAL_MACHINE', 'HKLM', 'SYSTEM', 'SYS') = 'HKLM\\SYS\\Setup'
    ```

#### split

`split` produces a slice of substrings separated by the given delimiter.

- **Specification**
    ```
    split(string: <string>, sep: <string>) :: <[]string>
    ```
    - `string`: Input string
    - `prefix`: The separator that is used to split the string
    - `return` a slice of substrings

- **Examples**

    Assuming the `file.name` field contains `C:\Windows\System32\kernel32.dll`, the following filter expression would match on all events where the `kernel32.dll` or `System32` strings are present in the resulting slice.

    ```
    fibratus run split(file.name, '\\') in ('kernel32.dll', 'System32')
    ```

#### length

`length` returns the number of characters for string arguments and the size of the slice for slice arguments.

- **Specification**
    ```
    length(string: <string|slice>) :: <int>
    ```
    - `string`: Input string or slice
    - `return` the number of characters or array length

- **Examples**

    Assuming the `ps.domain` field contains `"こんにちは"`, the following would filter events with 5 symbols in the process domain.

    ```
    fibratus run length(ps.domain) = 5
    ```

#### indexof

`indexof` returns the index of the instance of substring in a given string depending on the provided search order.

- **Specification**
    ```
    indexof(string: <string>, substring: <string>, order: <string>) :: <int>
    ```
    - `string`: Input string
    - `prefix`: Substring for which the search is performed
    - `order`: Specifies the string index search order. It can be `first`, `any`, `last`, `lastany`. This is an optional argument.
    - `return` the index of the substring

- **Examples**

    Assuming the `ps.domain` field contains `NT_AUTHORITY`, the following would filter events for the matching substring index.

    ```
    fibratus run indexof(ps.domain, 'NT') = 0
    ```

#### substr

`substr` creates a substring of a given string.

- **Specification**
    ```
    substr(string: <string>, start: <int>, end: <int>) :: <string>
    ```
    - `string`: Input string
    - `start`: Substring start index
    - `end`: Substring end index
    - `return` a substring contained within start and end indices

- **Examples**

    Assuming the `file.name` field contains `\Device\HarddiskVolume2\Windows\system32\user32.dll`, the following filter expression would match on all events where the substring is equal to `\Device`

    ```
    fibratus run substr(file.name, indexof(file.name, '\\'), indexof(file.name, '\\Hard')) = '\\Device'
    ```

#### entropy

`entropy` measures the string entropy.

- **Specification**
    ```
    entropy(string: <string>, algo: <string>) :: <int>
    ```
    - `string`: Input string
    - `algo`: The algorithm used to calculate the string entropy. `shannon` is the default entropy type. This argument is optional
    - `return` the string entropy

- **Examples**

    Assuming the `file.name` field contains `\Device\HarddiskVolume2\Windows\system32\user32.dll`, the following filter expression would match on all events where file name entropy is greater than 255.

    ```
    fibratus run entropy(file.name) > 255
    ```

#### regex

`regex` applies single/multiple regular expressions on the provided string argument.

- **Specification**
    ```
    regex(string: <string>, patterns: <string>...) :: <bool>
    ```
    - `string`: Input string
    - `patterns`: Regular expression patterns
    - `return` `true` if at least one regular expression matches or `false` otherwise

- **Examples**

    Assuming the `ps.name` field contains `powershell.exe`, the following would filter events matching the regular expressions.

    ```
    fibratus run regex(ps.name, 'power.*(shell|hell).dll', '.*hell.exe')
    ```

### Miscellaneous functions

#### is_minidump

`is_minidump` checks the signature of the provided file and returns `true` if the signature matches the `minidump` file.

- **Specification**
    ```
    is_mindump(path: <string>) :: <bool>
    ```
    - `string`: File path for which the minidump signature is checked
    - `return` `true` if the file contains the `minidump` signature or `false` otherwise

- **Examples**

    Assuming the `file.name` field contains `C:\\Temp\\lsass.dmp` which is a valid `minidump` file. The function call would return a `true` value.

    ```
    fibratus run is_minidump(file.name)
    ```
