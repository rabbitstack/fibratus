# Immortalizing The Event Flux

Captures or `kcap` files aim for the capture-once replay-anywhere workflow. Captures contain the full state of processes at the time capture was taken as well as the originated event flux. This makes them a great companion in post-mortem investigations - generate the capture in the honeypot machine, grab the `.kcap` file, and you're ready to dive into the attacker kill chain by replaying the capture file on your laptop.

With captures you "freeze" the shape of the event flux at a certain point in time. Do you need to troubleshoot an network issue and surface the root cause? Or maybe you need to determine what files were written by a malicious process? Replay the capture at any given time and drill down into the event flow to start investigating.

You can harness the power of the filtering engine when replaying captures or even execute a filament on top of captured events.
