# Operators

The filter engine supports logical, arithmetic, membership and string operators. Operator names are case-insensitive.

## Comparison binary operators {docsify-ignore}

The filtering query language supports the following  comparison binary operators:

- `=` (equal)
- `!=` (not equal)
- `<` (less than)
- `>` (greater than)
- `>=` (greater or equal)
- `<=` (less or equal)

## Logical binary operators {docsify-ignore}

 Logical operators are defined between two or more field evaluations.

 - `or` (union)
 - `and` (intersection)
 - `not` (negation)

## Membership operators {docsify-ignore}

The `in` operator validates the presence of a value in the string sequence. It can be applied to string literal sequences or dynamic string slices given by filter fields. Examples:

Tests if the process name producing the event is either `cmd.exe` or `powershell.exe`

```
$ fibratus run ps.name in ('cmd.exe', 'powershell.exe')
```

Checks if any of the process modules contains the `kernel32` dynamic linked object

```
$ fibratus run ps.modules in ('kernel32.dll')
```

## String operators {docsify-ignore}

String operators are applied to string field types or string literals.

- `contains` (checks whether a string field contains a sequence of characters)
- `icontains` (the case-insensitive variant of the `contains` operator)
- `startswith` (checks whether a string field starts with a specified prefix)
- `endswith` (checks whether a string field ends with a specified suffix)
