# Kill

##### The kill action terminates processes associated with the event that triggered the rule.

When a rule with the kill action matches, Fibratus attempts to stop the target process by its process identifier (PID). This is useful for halting malicious execution before it can propagate or cause further damage.

The action is defined in the rule `action` YAML field.

```yaml
action:
  - name: kill
```