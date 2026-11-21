## Summary

<!-- Describe what changed and link the relevant issue (e.g. Closes #123 or Advances #123). -->

## Verification

- [ ] `dotnet build --configuration Release`
- [ ] `dotnet test --configuration Release`
- [ ] `dotnet format --verify-no-changes`
- [ ] UI checks (`cd ui/Bower.Management.Web && npm run lint && npm test && npm run build`) if UI changed
- [ ] Docs checks (`python3 -I tools/docs/generate_cli_reference.py --check`, `python3 -I tools/docs/generate_config_and_api_reference.py --check`, `python3 -I tools/docs/generate_glossary.py --check`, `python3 -m unittest tools/docs/tests/test_build_tools.py`)

## Documentation & security checklist

- [ ] **Docs updated?** (CLI, API, configuration, schema, or console changes include matching docs updates, or a `documentation` waiver is explained below)
- [ ] Australian English spelling used in user-facing text and docs
- [ ] Only synthetic data and example domains (`example.gov.au`, `example.com`, `192.0.2.x`) appear in examples and tests
- [ ] Security and compatibility impact explained below

## Security and compatibility impact

<!-- Explain any new trust boundary, RBAC rule, schema addition, or breaking-change consideration. -->
