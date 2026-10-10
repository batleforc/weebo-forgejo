# Security policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub's private vulnerability reporting:
[Security → Report a vulnerability](https://github.com/batleforc/weebo-forgejo/security/advisories/new).
Include what you found, the affected version (image tag or digest, chart
version), and how to reproduce it if you can.

What to expect:

- an acknowledgement within a week;
- an assessment and, if confirmed, a fix plan agreed with you;
- a GitHub Security Advisory (and a CVE when applicable) published with the
  fixed release, crediting you unless you prefer otherwise.

## Supported versions

The project is pre-1.0: only the **latest release** receives security fixes.
Upgrade to it before reporting, if you can.

## Scope

In scope: the operator and importer binaries, the container images, the Helm
chart and the CRDs published from this repository. Typical concerns are a
namespace escaping the `ForgejoNamespacePolicy` allow-list, a CR writing or
reading a Secret it should not reach, privilege escalation through the
operator's Forgejo admin token, and admission webhook bypasses. The
[security model](https://batleforc.github.io/weebo-forgejo/docs/guides/security)
describes the intended boundaries.

Out of scope: vulnerabilities in Forgejo itself (report them to
[Forgejo](https://forgejo.org/.well-known/security.txt)), and findings that
require cluster-admin or a Forgejo site-admin to begin with.

## Verifying releases

Images, the Helm chart and the CRD bundle are signed keylessly with cosign
and ship an SBOM and SLSA provenance. See
[Verify a release](https://batleforc.github.io/weebo-forgejo/docs/guides/verify-release).
