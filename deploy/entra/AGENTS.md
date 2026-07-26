# Entra deployment instructions

Keep app registrations single-tenant by default. Interactive users receive Bower
app roles through Entra group assignment. Collector identities receive only the
machine-specific `Bower.Collector` role. Never place client secrets in manifests,
examples or deployment output. Treat role IDs and exposed scope IDs as stable
contract identifiers once deployed.
