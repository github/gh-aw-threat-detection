# gh-aw-threat-detection Scratchpad

This directory contains design references copied from the parent `gh-aw` project that are still useful for this repository.

The focus here is narrower than the parent project:

- threat detection inputs and agent artifacts
- downstream `safe-outputs` behavior that threat detection protects
- shared styles, patterns, and engineering best practices

For the canonical behavior of this repository, start with the threat detection spec in [../specs/threat-detection-spec.md](../specs/threat-detection-spec.md).

## Detection Inputs And Agent Artifacts

| Document | Why it matters here |
|----------|---------------------|
| [artifact-naming-compatibility.md](./artifact-naming-compatibility.md) | Explains how agent artifacts such as `agent_output.json`, prompts, and related files are named and flattened for downstream consumers. |
| [security_review.md](./security_review.md) | Relevant security review material for prompt and template handling around agent-generated content. |

## Downstream Safe Outputs

| Document | Why it matters here |
|----------|---------------------|
| [safe-outputs-specification.md](./safe-outputs-specification.md) | Defines the downstream safe-outputs system that threat detection is intended to protect. |
| [safe-output-environment-variables.md](./safe-output-environment-variables.md) | Documents the runtime contract used by safe-output jobs when consuming agent output. |
| [safe-output-messages.md](./safe-output-messages.md) | Describes safe-output messaging and presentation behavior downstream from detection. |
| [github-actions-security-best-practices.md](./github-actions-security-best-practices.md) | Useful guardrail and workflow-security context for detection and safe-output integration. |

## Styles And Best Practices

| Document | Why it matters here |
|----------|---------------------|
| [code-organization.md](./code-organization.md) | Shared guidance for organizing implementation files and responsibilities. |
| [validation-architecture.md](./validation-architecture.md) | Shared guidance for structuring validation logic and keeping rules maintainable. |
| [go-type-patterns.md](./go-type-patterns.md) | Go design and typing patterns that are still applicable in this repository. |
| [styles-guide.md](./styles-guide.md) | Shared style reference to preserve output and presentation consistency. |
| [errors.md](./errors.md) | Error-message guidance that remains useful when adding validation or CLI behavior. |
| [testing.md](./testing.md) | Testing patterns and conventions worth preserving in this repo. |

## Notes

- This index intentionally omits parent-project topics that do not map cleanly to `gh-aw-threat-detection`.
- Some retained documents still describe the broader `gh-aw` system. Keep them as reference material, not as the source of truth for this repository's package layout.

## Contributing

When adding a scratchpad document that is relevant to this repository:

1. Prefer docs that explain threat detection inputs, artifact handling, safe-output integration, or shared engineering patterns.
2. Avoid indexing parent-project-only documents unless they are directly useful here.
3. Update this README when a new scratchpad doc becomes part of the expected contributor workflow.

---

**Last Updated**: 2026-05-01
