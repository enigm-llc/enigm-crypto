# enigm-crypto

## SonarCloud scope and cost policy

Keep maintained product, security, operational, installer, infrastructure and
migration code in source scope. Classify genuine tests and fixtures as tests.
Exclude documentation, dependencies, build outputs and generator outputs only
with verified provenance and consumers; do not blanket-exclude examples, scripts
or owned vendor code, or relabel product code to reduce LOC. Preserve quality
gates, rule profiles and independent security checks. Automatic analysis reads
`.sonarcloud.properties` with exact paths and no wildcards; do not add a second
CI scanner. Update the reviewed inventory when files change and verify actual
branch/project LOC after analysis before claiming savings. Reference policy:
https://github.com/enigm-llc/enigm-command/blob/main/docs/SONAR_SCOPE.md
