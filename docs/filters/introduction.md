# Needle In The Haystack

An overwhelming volume of kernel events makes it challenging to dig out valuable insights or to narrow down the scope of a particular investigation or postmortem scenario. To streamline day-to-day tasks and to propel your workflow, Fibratus delivers a powerful engine for building sophisticated filtering expressions. Let's assume you want to catch events originated from `cmd.exe`, `powershell.exe`, `winword.exe` processes, or processes that export the `WORKER=1` environment variable and whose current working directory contains the `Users\Public` path. We can write such a filter as:

```
ps.name in ('cmd.exe', 'powershell.exe', 'winword.exe')
        or ps.envs['WORKER'] = '1'
        and ps.cwd contains 'Users\\Public'
```

It may look intimidating at first glance, but once you get familiar with the syntax and the field names you'll be able to write even the most intricate filters.

Filters represent the foundation of the [rule engine](/filters/rules) that provides threat detection capabilities. For example, the following stanza detects the outbound communication followed by the execution of the command shell within one-minute time window. The action invokes the [alert sender](/alerts/senders) to emit the security alert via email or Slack. 

```yaml
- group: remote connection and command shell execution
  policy: sequence
  rules:
    - name: establish remote connection
      condition: >
        kevt.name = 'Connect'
          and
          not
        cidr_contains(
          net.dip,
          '10.0.0.0/8',
          '172.16.0.0/12')
    - name: spawn command shell
      max-span: 1m
      condition: >
        kevt.name = 'CreateProcess'
          and
        ps.pid = $1.ps.pid
          and
        ps.sibling.name in ('cmd.exe', 'powershell.exe')
  action: >
    {{ emit "Command shell spawned after remote connection"
      (printf "%s process spawned a command shell after connecting to %s" .Kevts.k2.PS.Exe .Kevts.k1.Kparams.dip)
    }}
```
