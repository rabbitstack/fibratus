# Needle In The Haystack

An overwhelming volume of events makes it challenging to dig out valuable insights or to narrow down the scope of a particular investigation or postmortem scenario. To streamline day-to-day tasks and to propel your workflow, Fibratus delivers a powerful engine for building sophisticated filtering expressions. Let's assume you want to catch events originated from `cmd.exe`, `powershell.exe`, `winword.exe` processes, or processes that export the `WORKER=1` environment variable and whose current working directory contains the `Users\Public` path. We can write such a filter as:

```
ps.name in ('cmd.exe', 'powershell.exe', 'winword.exe')
        or ps.envs['WORKER'] = '1'
        and ps.cwd contains 'Users\\Public'
```

It may look intimidating at first glance, but once you get familiar with the syntax and the field names you'll be able to write even the most intricate filters.

Filters represent the foundation of the [rule engine](/filters/rules) that provides threat detection capabilities. For example, the following stanza detects the outbound communication followed by the execution of the command shell within one-minute time window. The action invokes the [alert sender](/alerts/senders) to emit the security alert via email, Slack, or a 
different supported channel. 

```yaml
name: Remote connection followed by command shell execution
id: eddace20-4962-4381-884e-40dcdde66626
version: 1.0.0

condition: >
  sequence
  maxspan 1m
  by ps.uuid
    |kevt.name = 'Connect'
      and
      not
     cidr_contains(
      net.dip,
      '10.0.0.0/8',
      '172.16.0.0/12'
     )
    |
    |kevt.name = 'CreateProcess'
      and
     ps.child.name in ('cmd.exe', 'powershell.exe') 
    |
    
output: > 
  Command shell spawned after remote connection %2.ps.exe 
  process spawned a command shell after connecting to %1.net.dip

severity: critical

min-engine-version: 2.0.0
```
