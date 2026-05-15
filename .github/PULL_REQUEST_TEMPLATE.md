<!--
Thanks for contributing! Please complete every section. A PR with a vague
description is much harder to review on a security-sensitive protocol library.
-->

## What does this change?

<!-- One paragraph. Describe the behaviour change, not the diff. -->

## Why is it correct?

<!-- Reference: spec section, matter.js behaviour, captured test vector, etc. -->

## How was it tested?

- [ ] Unit tests added or updated
- [ ] Test vectors captured from matter.js (required for any wire-protocol change)
- [ ] Manual test against a real Matter device (if applicable)
- [ ] `cargo fmt --all`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`

## Crypto checklist (delete if not applicable)

- [ ] This PR touches `matter-crypto/` or otherwise changes PASE / CASE wire bytes
- [ ] I have labelled the PR `crypto`
- [ ] I understand this PR blocks a release of `matter-crypto` until external
      cryptographic review has signed off

## Related issues / milestones

<!-- e.g. "Part of #N (Milestone 1)" -->
