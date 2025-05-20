# Operators

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