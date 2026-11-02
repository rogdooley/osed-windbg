# Help system

`help()` is a compact, 80-column task index. Use `help("all")` for the
grouped full inventory, `help("name")` for the short RUN-first reference, and
`help("name", "full")` for purpose, usage, details, examples, and references.

The renderer is a pure formatter: it does not inspect or mutate debugger state.
Commands are emitted as indivisible lines so a copyable command is never wrapped
or truncated. Prose wraps at 80 columns.

Catalog examples deliberately support both legacy strings and labelled objects.
P0 only performs static validation: examples must parse after their WinDbg
prefix is normalized and their references must resolve in the help catalog.
This is not evidence that an example accepts its arguments or executes in
WinDbg; runtime example validation remains a separate, target-backed task.

Categories are display metadata only. They do not affect command registration,
dispatch, ROP corpus state, or debugger execution.
