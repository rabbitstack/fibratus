# Filtering

### Anatomy of a filter {docsify-ignore}

At its simplest form, a filter is composed of the LHS (Left Hand Side) and RHS (Right Hand Side) expressions connected with an [operator](/filters/operators) that can pertain to binary, logical, or string operators. The LHS expression is usually a [field](/filters/fields) name, even though the use of fields is possible in Right Hand Side expressions as well.

```
    LHS          operator         RHS
kevt.category       =            'net'
```

The RHS expressions can be strings, numbers, IP addresses, boolean values, and fields. In the above snippet, the RHS is a simple string literal, but we could have written filters with the following RHS expressions:

- IP addresses: `net.sip = 127.0.0.1`
- Booleans: `kevt.nparams != false`
- Numbers: `ps.pid = 4`
- Fields: `kevt.pid != ps.pid`

### Running filters {docsify-ignore}

As previously mentioned, filters can be engaged in various stages of event collection and processing. The filter expression is given  to `run`, `capture`, and `replay` commands in form of the command line argument.

The `run` command applies the filter expression to each inbound kernel event and prevents upstream propagation if the event doesn't match the filter. The above command filters events that occur on `Monday` and are produced by `cmd.exe` and `svchost.exe` processes.

```
$ fibratus run kevt.date.weekday = 'Monday' and ps.name in ('cmd.exe', 'svchost.exe')
```

!> If you're using PowerShell, it is necessary to enclose the entire filter expression in quotes. For example, `fibratus run "kevt.category = 'net'"`


In a similar fashion, the `capture` command only dumps events that match the provided filter. In this case, the capture would boil down to  `registry` kernel events.

```
$ fibratus capture kevt.category = 'registry' -o events
```

When replaying events from the kcap file, you can also specify a filter to narrow down the replay context, for example, to filter out events that mutate registry values.

```
$ fibratus replay kevt.name = 'RegSetValue' -k events
```

Lastly, filtering is possible during filament execution. If the filter is set in both, the `run` command and through the `kfilter` function, the latter takes precedence. Filtering in filaments is thoroughly explained in [filaments](/filaments/introduction).

### Escaping characters {docsify-ignore}

As you might have noticed, string values are enclosed in single quotes `''`. If the string contains characters that would result in an illegal identifier, you'll have to escape the offending characters accordingly. For example, path delimiters (backslashes) or quotes need to be escaped:

```
$ fibratus run file.name = 'C:\\Windows\\System32'
$ fibratus run file.name contains '\"hosts\"'
```

Filter expressions can accept escape sequences, such as newline characters (`\n`).

### Invalid filters {docsify-ignore}

If a syntax error is present in the filter, a hint is given indicating the erroneous position in the expression.  

```
ps.name =          
         ^ expected field, string, number, bool, ip
```
