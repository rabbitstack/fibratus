# Isolate

##### The isolate action restricts the host’s network connectivity to contain potential threats.

When triggered, this action applies network isolation policies that block outbound and/or inbound connections, effectively quarantining the host from the network. The `isolate` action leverages [Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) (WFP) to define firewall policies. Here is an example of using the action in the rule definition.

```yaml
action:
  - name: isolate
