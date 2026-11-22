# Microsoft cloud source fixtures

Synthetic API responses for the Microsoft cloud source tests. They follow the response
shapes in Microsoft's Graph v1.0 reference pages, with every value invented: the tenant,
users (`contoso.example`), device names, ids (`0000-4000-8000` GUIDs) and addresses
(RFC 5737 and RFC 3849 documentation ranges). No real tenant data. Never replace them with
captured responses; scrub any captured shape to this standard first.

`{{start}}`, `{{mid}}` and `{{end}}` are replaced by the tests with times inside the window
being read.
