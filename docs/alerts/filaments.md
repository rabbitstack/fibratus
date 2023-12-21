# Filament Alerting

Filaments produce alerts by invoking the `emit_alert` function. The alert is propagated to all active alert senders.

The `emit_alert` function accepts two positional and two keyword arguments. Here is the signature of the function:

```python
emit_alert(title, text, severity='normal', tags=[])
```

An example of calling the `emit_alert` function to generate an alert from the filament that detects registry persistence attacks:

```python
emit_alert(
        f'Registry persistence gained via {kevent.kparams.key_name}',
        text(kevent),
        severity='medium',
        tags=['registry persistence']
)
```
