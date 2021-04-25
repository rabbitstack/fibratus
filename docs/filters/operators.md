# Operators

The filter engine supports logical, arithmetic, and string operators. Operator names are case-insensitive.

## Binary operators

The filtering query language supports the following  comparison binary operators:

- `=` (equal)
- `!=` (not equal)
- `<` (less than)
- `>` (greater than)
- `>=` (greater or equal)
- `<=` (less or equal)

## Logical operators

Logical operators are applied on two or more binary expressions, except for `not` that acts as a unary operator.

#### or

`or` (union) evalutes to true if either one of the LHS (Left Hand Side) or RHS (Right Hand Side) expressions are true. 

- **Example**

   Filter events where the originating process name is equal to `svchost.exe` or the process name contains the `svc` string

   ```
   fibratus run ps.name = 'svchost.exe' or ps.name contains ('svc')
   ```

#### and

`and` (intersection) evalutes to true if both of the LHS (Left Hand Side) and RHS (Right Hand Side) expressions are true.

- **Example**

   Filter events only when the originating process name is equal to `System` and the process identifier is equal to `4`

   ```
   fibratus run ps.name = 'System' and ps.pid = 4
   ```

#### not

`not` (negation) negates the result of the adjacent expression.

- **Example**

   Filter events only when the originating process name is equal to `svchost.exe` and none of the process' command line arguments is equal to `/-C` or `/cdir`

   ```
   fibratus run ps.name = 'svchost.exe' and ps.args not in ('/-C', '/cdir') 
   ```

## String operators

String operators are applied to string field types or string literals.

#### in

`in` operator validates the presence of a value in the string sequence. It can be applied to string literal sequences or dynamic string slices given by filter fields. 

- **Examples**

   Tests if the process name producing the event is either `cmd.exe` or `powershell.exe`

   ```
   $ fibratus run ps.name in ('cmd.exe', 'powershell.exe')
   ```

   Checks if any of the process modules contains the `kernel32` dynamic linked object

   ```
   $ fibratus run ps.modules in ('kernel32.dll')
   ```

#### contains

`contains` operator checks whether a string field contains a sequence of characters. This operator works on both simple string values and lists of strings. 

- **Examples**

   Checks if the process' name contains the `cmd` or `power` substrings

   ```
   $ fibratus run ps.name contains ('cmd', 'power')
   ```

   Checks if the process' command line contains the `Windows Tasks` substring

   ```
   $ fibratus run ps.comm contains 'Windows Tasks'
   ```

#### icontains

`icontains` is the case-insensitive variant of the `contains` operator.

#### startswith

`startswith` checks whether a string field starts with a specified prefix. This operator works on both simple string values and lists of strings.

- **Example**

   Filter events where the originating process name is equal to `svchost.exe`

   ```
   fibratus run ps.name startswith 'svchost'
   ```

#### endswith

`endswith` checks whether a string field ends with a specified suffix. This operator works on both simple string values and lists of strings.

- **Example**

   Filter events where the originating process name is equal to `svchost.exe`

   ```
   fibratus run ps.name endswith '.exe'

#### matches

`matches` is the swiss army knife string matching operator. It allows string matching by using the wildcard characters similar to [globbing](https://en.wikipedia.org/wiki/Glob_(programming)). The `*` wildcard matches a sequence of characters, while the `?` wildcard matches a single character. 

- **Examples**

   To match events with file paths equal to `C:\\Windows\\System32\\lsass2.dmp` or `C:\\ProgramData\\Directory\\tmp\\anubis.dll`

   ```
   fibratus run file.name matches ('C:\\*\\lsass?.dmp', 'C:\\ProgramData\\*.dll')
   ```

   For filtering registry events with key names such as `HKEY_USERS\\S-1-5-21-2271034452-2606270099-984871569-1001\\Environment\\windir`

   ```
   fibratus run registry.key.name matches 'HKEY_USERS\\*\\Environment\\windir'
   ```

#### imatches

`imatches` is the case-insensitive variant of the `matches` operator.


