# Evasions

##### The evasion scanner is a behavioral analysis component designed to detect techniques that attempt to bypass traditional monitoring and security controls. It introduces a modular architecture that leverages a set of pluggable *evasion detectors*, each responsible for identifying a specific class of evasion behavior at runtime.

At its core, the evasion scanner operates as a lightweight layer that integrates with the event processing pipeline. Rather than generating standalone alerts, it enriches existing events with additional context when suspicious behavior is observed. This design allows evasion signals to be correlated with other telemetry, preserving full execution context.

Each evasion scanner encapsulates logic for identifying a particular technique. Available scannners focus on detecting [direct](https://docs.redteamleaders.com/offensive-security/defense-evasion/direct-syscall-execution-in-windows) and [indirect](https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls) system call evasion, where user-mode hooks are bypassed by invoking system calls outside of standard API pathways.

### Evasion behaviour enrichment

When an event is captured, the evasion scanner passes it through the registered detectors. If a detector identifies a known evasion pattern, then the event is annotated with **evasion metadata**. This metadata describes the type of evasion technique observed.
The enrichment occurs inline, without interrupting the event flow ensuring minimal overhead while still surfacing high-value behavioral signals.
The evasion metadata is designed to be consumable by the **rule engine**, enabling **precise** and **expressive** detections.

### Direct syscall

**Direct** syscall scanner hunts for adversary techniques to bypass traditional user-mode API monitoring and security
hooks by invoking system calls directly, but does so in a way that evades detection or analysis.
A direct syscall bypasses Windows API functions and calls the underlying system call directly using the `syscall` instruction, skipping the `NTDLL` stub that normally performs the transition to kernel mode.

### Indirect syscall

**Indirect** syscall scanner flags attempts to execute the `syscall` instruction diverting the execution flow into a legitimate, clean ntdll stub that performs the syscall on process behalf. This achieves code origin legitimacy, since the execution lands in text of a signed Microsoft `NTDLL` module. Stack frames look identical to a normal API call, which achieves call stack normalization.
