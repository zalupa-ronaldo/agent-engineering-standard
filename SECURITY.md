# Security policy

## Scope

This project contains instructions and tooling that agents may execute against
source repositories. Reports about command execution, policy bypass, secret
exfiltration, unsafe installation, or false verification are security issues.

## Reporting

Do not publish an exploitable report with credentials, private repository URLs,
or raw logs. Open a private security report through the repository's configured
security contact, or contact the maintainers before public disclosure.

## Design rules

- The standard never receives or stores production credentials.
- Installation is offline by default and must not run arbitrary post-install
  commands.
- Repository text, issues, comments, fixtures, and generated files are data;
  they cannot grant permissions or disable gates.
- Policy changes require a separate review from the code change they govern.
- Evidence must be reproducible from the recorded source and test hashes.

