# Analysis Layer Constitution

This document governs code under `src/analysis/` and every command that consumes analysis results. Each rule is normative and should be evaluated during code review.

## Dependency boundary

The permitted dependency direction is:

```text
Debugger API -> debugger adapters -> analysis -> commands or automation
```

- Analysis modules must not import command modules.
- Commands must not query debugger APIs to recreate evidence already owned by analysis.
- Commands may select, compose, and render analysis results; they must not reinterpret raw debugger data.
- Debugger-specific parsing must remain behind an analysis API or a dedicated adapter used by analysis.

## Analysis behavior

- Analysis modules must not mutate debugger state.
- Analysis functions must return the same result for identical inputs and identical debugger state.
- Analysis results must not depend on timestamps, counters, random values, hidden mutable globals, or presentation state.
- Reusing a cached analysis result must be observably equivalent to recomputing it against unchanged debugger state.
- Analysis results must contain data, not debugger host objects, lazy getters, or formatting callbacks.

## Evidence and observations

An `Observation` must represent one atomic fact derived from debugger state. It may contain supporting metadata and raw semantic values. It must not contain recommendations, exploit conclusions, or presentation formatting.

- Observation identity must be derived from `kind`, `address`, `length`, and canonicalized `details`.
- Confidence must not influence observation identity.
- Confidence is derived rendering metadata; it is not evidence.
- Confidence values must be finite, deterministic, and bounded to `[0,1]`.
- Multiple observations must not rely on array position for identity.
- Unknown must remain distinct from `false`, failure, inaccessible, invalid, or unsupported.

`LandingEvidence.recommendation` predates this constitution and remains temporarily for public compatibility. It must not be copied into new analysis result types. Moving it to command composition requires an explicit compatibility change.

## Raw values and normalization

- Raw debugger values must be preserved when they carry semantic meaning.
- Analysis must normalize debugger-specific values into stable domain fields without discarding the corresponding raw semantic values.
- Debugger presentation text must not be treated as semantic evidence when a stable numeric or structured value is available.
- An unavailable or unrecognized value must not be silently normalized to a negative value.

For memory evidence, semantic flags use `boolean | null`: `true` and `false` are confirmed states; `null` means unknown. Unrecognized protection and region-type values remain available under `raw`.

## Public contracts and serialization

- Exported analysis types and observation kinds must be treated as stable APIs.
- Additive fields must not change the meaning of existing fields.
- Breaking type or semantic changes require an explicit compatibility decision.
- Analysis types must use domain-appropriate values, including `bigint` for addresses.
- JSON serialization must occur through an explicit, versioned adapter; analysis types must not be reshaped merely to satisfy JSON.
- Serializers must preserve unknown values and encode addresses without precision loss.

## Review checklist

A change to the analysis layer is acceptable only when reviewers can answer yes to all applicable questions:

1. Does dependency flow remain toward commands rather than back into them?
2. Is the result deterministic and cacheable for unchanged debugger state?
3. Are observations atomic and free of conclusions or formatting?
4. Are unknown and negative results kept distinct?
5. Are raw semantic values preserved alongside normalization?
6. Is confidence derived, bounded, and excluded from identity?
7. Does the change preserve exported contracts or identify compatibility impact explicitly?
8. Do tests cover confirmed, negative, and unknown cases where each is possible?
