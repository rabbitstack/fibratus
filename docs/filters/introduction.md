# Needle In The Haystack

An overwhelming volume of kernel events makes it challenging to dig out valuable insights or to narrow down the scope of a particular investigation or postmortem scenario. To streamline day-to-day tasks and to propel your workflow, Fibratus delivers a powerful engine for building sophisticated filtering expressions. Let's assume you want to catch events originated from `cmd.exe`, `powershell.exe`, `winword.exe` processes, or processes that export the `WORKER=1` environment variable and whose current working directory contains the `Users\Public` path. We can write such a filter as:

```
ps.name in ('cmd.exe', 'powershell.exe', 'winword.exe')
        or ps.envs['WORKER'] = '1'
        and ps.cwd contains 'Users\\Public'
```

It may look intimidating at first glance, but once you get familiar with the syntax and the field names you'll be able to write even the most intricate filters.

Filters can be used in various places:

- the `run` command
- the `capture` command when dumping the event flow to the capture file
- the `replay` command when recovering the event flow from the capture file
- filaments
