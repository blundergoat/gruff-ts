# Philosophy

gruff-ts governs AI-generated code. Every rule, threshold, and report exists to serve one goal: a human who did not write the code can read, review, and trust it.

## The reviewer is not the author

A coding agent holds the full context while it writes. The person who has to sign off on the change does not. Conventional linters optimise for the author - they assume someone who already understands the code and just wants it tidy. gruff-ts optimises for the reviewer of code they did not write, which is the position every human reviewing an agent's output is in.

Used as a hook on an agent's output, gruff-ts is a forcing function, not advice. A finding is friction the agent must resolve before the change reaches a human, so what finally lands is already shaped for sign-off. Because the agent will change code to clear a finding, the direction each rule pushes matters as much as the threshold it fires at: a rule should never push the agent toward code that is harder to verify or less safe.

## Three goals

- **Verifiable.** The change can be checked by reading, not by re-deriving what the agent was thinking. The complexity, size, naming, and documentation pillars push toward code whose intent is visible on its face.
- **Secure where the eye slips.** Human review reliably misses a known set of unsafe patterns - disabled TLS verification, `eval` and dynamic `Function` construction, injection-shaped string building, committed secrets. The security and sensitive-data pillars catch those mechanically so the reviewer does not have to.
- **Honestly tested.** A test suite should raise confidence, not just coverage. The test-quality pillar flags low-signal ceremony - mock-only, snapshot-only, assertion-free, and tautological tests - so an agent cannot satisfy a "write tests" instruction with padding.

## Why documentation is mandatory, even on a private one-liner

Coding agents routinely produce code that superficially works while misunderstanding the requirement. The implementation can be plausible and still solve the wrong problem, and that failure is invisible to a reviewer reading only the code.

Forcing the agent to state intent, usage, contract, and failure behaviour in prose gives the reviewer something to check the implementation against. The doc comment is a second, independent statement of what the code is meant to do, and a mismatch between that prose and the code is itself a signal that the change needs a deeper look. That is worth the friction even on a one-line private helper, because the cost of a confidently-wrong agent change is paid by the human who trusted it.
