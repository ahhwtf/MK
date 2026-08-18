# Manual CI Address Research

> **Research provenance and terminology:** This work has been used for
> authorized research associated with Colorado State University. These notes
> describe the relevant functionality as kernel code-integrity observation,
> compatibility analysis, and controlled enforcement-state experimentation.
> Existing command names are quoted literally where required for reproducible
> results.

Use the read-only validator to compare a lab-observed address with KVC's own
live `g_CiOptions` finder:

```text
kvc dse inspect-address <ci.dll-base> <candidate-address>
```

The supplied base and candidate address must come from the same dump/boot
session. In WinDbg:

```text
lm m ci
ln <candidate-address>
!pte <candidate-address>
```

The validator reports the candidate RVA, owning `ci.dll` PE section, static PE
protections, controller-discovered address, current live `ci.dll` base, and
current value. Absolute addresses normally change across boots because of ASLR,
so the dump and live results are compared by module-relative RVA. It fails closed
when the address is malformed, outside `ci.dll`, outside a mapped section,
non-writable in the PE image, unavailable to the controller, or different from
the controller's independently discovered RVA.

The supplied address is never passed to a controller read/write primitive, and
this command performs no kernel-memory modification.

## Crash guard

The standard `g_CiOptions` path fails closed before its RTC write whenever any
KMCI/IUM bit in mask `0x0001C000` is present, or the registry reports HVCI.
This includes `0x4000`: the lab crash showed `g_CiOptions = 0x00004006` while
the `CiPolicy` runtime page was read-only, producing bugcheck `0xBE`.

This guard concerns write safety, not merely the user-facing HVCI label. A
value can require the guard even when the narrower HVCI detector or registry
state does not call Memory Integrity active.
