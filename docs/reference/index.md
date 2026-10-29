# Technical reference

Use the guides for a task-oriented walkthrough. Use these references when you need
to understand the contract, implementation or operating assumptions.

## Interfaces and configuration

- [Configuration schemas](https://github.com/jusso-dev/Bower/tree/main/schemas): versioned JSON schemas in the repository.
- [CLI implementation](https://github.com/jusso-dev/Bower/tree/main/src/Bower.Cli): current C# command definitions. Run `bower --help` for the installed version's commands.
- [Rust data plane and CLI](https://github.com/jusso-dev/Bower/tree/main/rust): the port follows the C# specification; check runtime support before deployment.
- [Management API](https://github.com/jusso-dev/Bower/tree/main/src/Bower.Management.Api): endpoint definitions, role enforcement and management contracts.
- [Collector API](https://github.com/jusso-dev/Bower/tree/main/src/Bower.Collector): intake and collector host implementation.
- [PowerShell reference](../operations/powershell.md): management and deployment modules.

These are links to the implementation, not generated API or CLI documentation.
Generated references and staleness checks remain tracked in
[the documentation issue](https://github.com/jusso-dev/Bower/issues/139).

## Design and contracts

- [Architecture](../architecture/overview.md)
- [Collector enrolment](../architecture/collector-enrolment.md)
- [Heartbeat v2](../architecture/heartbeat-v2.md)
- [Transform language](../architecture/transform-language.md)
- [Event catalogue](../security/default-event-catalogue.md)
- [Dependency decisions](../architecture/dependencies.md)

## About this documentation

[Site architecture and publishing](../architecture/documentation-site.md) explains
the build. The [accessibility statement](accessibility.md) describes supported
navigation and how to report a problem.
