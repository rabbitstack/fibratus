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

    Assuming `net.sip` contains the `192.168.1.20` IP address

    ```
    cidr_contains(net.sip, '192.168.1.1/24', '172.17.1.1/8') = true
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

    Assuming `registry.key.name` contains the `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid` key.

    ```
    md5(registry.key.name) = 'eab870b2a516206575d2ffa2b98d8af5'
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

    Assuming `ps.domain` field contains `NT_AUTHORITY` and `ps.username` field contains `admin`.

    ```
    concat(ps.domain, '-', ps.username) = 'NT_AUTHORITY-admin'
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

    Assuming `registry.key.name` contains the `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid` key.

    ```
    ltrim(registry.key.name, 'HKEY_LOCAL_MACHINE\\') = 'SYSTEM\\Setup\\Pid'
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

    Assuming `registry.key.name` contains the `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid` key.

    ```
    rtrim(registry.key.name, '\\Pid') = 'HKEY_LOCAL_MACHINE\\SYSTEM\\Setup'
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

    Assuming `registry.key.name` contains the `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid` key.

    ```
    lower(registry.key.name) = 'hkey_local_machine\\system\\setup'
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

    Assuming `registry.key.name` contains the `HKEY_LOCAL_MACHINE\SYSTEM\Setup` key. 

    ```
    upper(registry.key.name) = 'HKEY_LOCAL_MACHINE\\SYSTEM\\SETUP'
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

    Assuming `registry.key.name` contains the `HKEY_LOCAL_MACHINE\SYSTEM\Setup` key.

    ```
    replace(registry.key.name, 'HKEY_LOCAL_MACHINE', 'HKLM', 'SYSTEM', 'SYS') = 'HKLM\\SYS\\Setup'
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

    Assuming `file.name` contains the `C:\Windows\System32\kernel32.dll` path.

    ```
    split(file.name, '\\') in ('kernel32.dll', 'System32', 'Windows')
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

    Assuming `ps.domain` field contains `"こんにちは"`.

    ```
    length(ps.domain) = 5
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

    Assuming `ps.domain` contains `NT_AUTHORITY`.

    ```
    indexof(ps.domain, 'NT') = 0
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

    Assuming `file.name` contains the `\Device\HarddiskVolume2\Windows\system32\user32.dll` path.

    ```
    substr(file.name, indexof(file.name, '\\'), indexof(file.name, '\\Hard')) = '\\Device'
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

    Assuming `file.name` contains the `\Device\HarddiskVolume2\Windows\system32\user32.dll` path.

    ```
    entropy(file.name) > 255
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

    Assuming `ps.name` contains `powershell.exe`.

    ```
    regex(ps.name, 'power.*(shell|hell).dll', '.*hell.exe') = true
    ```

### File functions

#### base

`base` returns the last element of the path.

- **Specification**
    ```
    base(path: <string|[]string>, ext: bool) :: <string|[]string>
    ```
    - `path`: The string or an array of strings representing file system path(s)
    - `ext`: Determines whether the extension is retained in the file path. This parameter is optional and `true` by default
    - `return` a string or a slice of strings with file names

- **Examples**

    Assuming `file.name` contains the `C:\\Windows\\cmd.exe` path.

    ```
    base(file.name) = 'cmd.exe'
    base(file.name, false) = 'cmd'
    ```

#### dir

`dir` returns all but the last element of the path, typically the path's directory.

- **Specification**
    ```
    dir(path: <string|[]string>) :: <string|[]string>
    ```
    - `path`: The string or an array of strings representing file system path(s)
    - `return` a string or a slice of strings with directory names

- **Examples**

    Assuming `file.name` contains the `C:\\Windows\\cmd.exe` path.

    ```
    dir(file.name) = 'C:\\Windows'
    ```

#### ext

`ext` returns the file name extension used by the path.

- **Specification**
    ```
    ext(path: <string>, dot: bool) :: <string>
    ```
    - `path`: The string representing file system path
    - `dot`: Indicates if the dot symbol is retained as part of extension. This parameter is optional and `true` by default
    - `return` file name extension used by the path

- **Examples**

    Assuming `file.name` contains the `C:\\Windows\\cmd.exe` path.

    ```
    ext(file.name) = '.exe'
    ext(file.name, false) = 'exe'
    ```

#### glob

`glob` returns the names of all files matching the pattern.

- **Specification**
    ```
    glob(pattern: <string>) :: <[]string>
    ```
    - `pattern`: Shell file name pattern as described [here](https://pkg.go.dev/path/filepath#Match)
    - `return` returns the names of all files matching the pattern or an empty list if there is no matching file

- **Examples**

    ```
    glob('C:\\Windows\\*.exe') in ('C:\\Windows\\notepad.exe')
    ```

#### is_abs

`is_abs` reports whether the path is absolute.

- **Specification**
    ```
    is_abs(path: <string>) :: bool
    ```
    - `path`: The string representing file system path
    - `return` `true` if `path` references an absolute path or `false` otherwise

- **Examples**

    Assuming `file.name` contains the `Windows\\cmd.exe` path.

    ```
    is_abs(file.name) = false
    ```

#### symlink

`symlink` returns the path name after the evaluation of any symbolic links.

- **Specification**
    ```
    symlink(path: <string>) :: string
    ```
    - `path`: The string representing file system path
    - `return` the path name after the evaluation of any symbolic links, or the original path if any errors occur

- **Examples**

    Assuming `file.name` contains the `C:\\Windows\\symlink.txt` path which is a symlink to `C:\Windows\target.txt`.

    ```
    symlink('C:\\Windows\\symlink.txt') = 'C:\\Windows\\target.txt'
    ```

#### volume

`volume` returns leading volume name.

- **Specification**
    ```
    volume(path: <string>) :: string
    ```
    - `path`: The string representing file system path
    - `return` leading volume name

- **Examples**

    Assuming `file.name` contains the `C:\\Windows\\symlink.txt` path.

    ```
    volume(file.name) = 'C:'
    ```

#### is_minidump

`is_minidump` checks the signature of the provided file and returns `true` if the signature matches the `minidump` file.

- **Specification**
    ```
    is_mindump(path: <string>) :: <bool>
    ```
    - `string`: The file path for which the minidump signature is checked
    - `return` `true` if the file contains the `minidump` signature or `false` otherwise

- **Examples**

    Assuming `file.name` contains the `C:\\Temp\\lsass.dmp` path with a valid `minidump` file. 

    ```
    is_minidump(file.name) = true
    ```

### Registry functions

`get_reg_value` retrieves the content of the registry value.

- **Specification**
    ```
    get_reg_value(key: <string>) :: <string|[]string|int>
    ```
    - `key`: Is the fully-qualified registry key path including the value name. The root key can be expressed in abbreviated notation, e.g. instead of `HKEY_LOCAL_MACHINE` you can write `HKLM`.
    - `return` depending on the registry value type, it can return a string, array of strings or an integer value.

- **Examples**

    Assuming the `HKEY_CURRENT_USER\Volatile Environment\Envs` registry value contains a multi-size string with `dev\0staging` values.

    ```
    get_reg_value('HKCU\Volatile Environment\Envs') in ('dev', 'staging')
    ```


### YARA functions

`yara` provides signature-based detection in filters and rules. YARA is a tool aimed at (but not limited to) helping malware
researchers to identify and classify malware samples. With YARA you can create descriptions of malware families based on textual
or binary patterns. Depending on the parameter type supplied to this function, the scan can be performed on the process, filename or a memory block.

- **Specification**
    ```
    yara(target: <int|string|[]byte>, rules: <string>) :: bool
    ```
    - `target`: If this parameter is an integer value, it's assumed to be a pid for which the memory area is scanned. If it is a string, the scan is performed on the process image executable or arbitrary file system file. Otherwise, it is a stream of bytes that represents a memory block to be scanned.
    - `rules`: a string containing YARA rules
    - `return` if any rule defined in the `rules` parameter matches, the function returns `true`. Otherwise, it returns `false`.

- **Examples**

    Assuming `file.name` contains `C:\\Windows\\notepad.exe`. 

    ```
    yara(file.name, 'rule Notepad : notepad
{
	strings:
		$c0 = "Notepad" fullword ascii
	condition:
		$c0
}') = true
    ```
