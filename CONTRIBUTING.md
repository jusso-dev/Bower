# Contributing

Read root and nearest scoped `AGENTS.md`. Open an issue for material contract,
policy, persistence, dependency, or Azure resource changes. Keep pull requests
small, include tests and document security/compatibility effects.

Required checks:

```bash
dotnet restore
dotnet build --configuration Release
dotnet test --configuration Release
dotnet format --verify-no-changes
```
