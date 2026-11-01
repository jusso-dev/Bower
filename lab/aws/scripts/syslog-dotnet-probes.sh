# .NET socket and TLS facts behind the syslog delivery-reliability guide, on a disposable
# Linux lab host (run through syslog-lab.py). Loopback only, throwaway self-signed key.
# Prints one JSON object; no secrets.
set -euo pipefail
command -v dotnet >/dev/null || dnf -y -q install dotnet-sdk-10.0 >/dev/null
work=$(mktemp -d /root/bower-dotnet-probes.XXXXXX)
trap 'rm -rf "$work"' EXIT
cd "$work"
dotnet new console -o . --force >/dev/null 2>&1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout key.pem -out cert.pem -days 1 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost >/dev/null 2>&1
# OpenSSL configuration for the server only: the system file plus NumTickets = 0.
src=/etc/pki/tls/openssl.cnf; [ -f "$src" ] || src=/etc/ssl/openssl.cnf
section=$(awk -F= '/^[[:space:]]*system_default[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$src")
python3 - "$src" "$section" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
text, n = re.subn(r"(^\[\s*" + re.escape(sys.argv[2]) + r"\s*\][^\n]*\n)", r"\1NumTickets = 0\n", text, count=1, flags=re.M)
assert n == 1
open("bower-openssl.cnf", "w").write(text)
PY
cat > Program.cs <<'CS'
using System.Net; using System.Net.Security; using System.Net.Sockets;
using System.Security.Authentication; using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
var results = new Dictionary<string, object>();
// 1. Data received before a peer's reset: still readable?
{
    using var l = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
    l.Bind(new IPEndPoint(IPAddress.Loopback, 0)); l.Listen();
    var c = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
    await c.ConnectAsync(l.LocalEndPoint!);
    using var s = await l.AcceptAsync();
    c.Send(new byte[100]); await Task.Delay(100);
    c.LingerState = new LingerOption(true, 0); c.Dispose(); await Task.Delay(200);
    string first; try { first = $"{s.Receive(new byte[1000])} bytes"; } catch (SocketException e) { first = e.SocketErrorCode.ToString(); }
    string second; try { second = $"{s.Receive(new byte[1000])} bytes"; } catch (SocketException e) { second = e.SocketErrorCode.ToString(); }
    results["readsAfterPeerResetWithDataQueued"] = new[] { first, second };
}
// 2. TLS 1.3 session tickets the server sends after the handshake.
using var pem = X509Certificate2.CreateFromPemFile("cert.pem", "key.pem");
var cert = X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null);
foreach (bool resume in new[] { true, false })
{
    using var l = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
    l.Bind(new IPEndPoint(IPAddress.Loopback, 0)); l.Listen();
    var server = Task.Run(async () => {
        var ssl = new SslStream(new NetworkStream(await l.AcceptAsync(), true));
        await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions {
            ServerCertificate = cert, EnabledSslProtocols = SslProtocols.Tls13, AllowTlsResume = resume });
        await Task.Delay(3000); return ssl; });
    var port = ((IPEndPoint)l.LocalEndPoint!).Port;
    var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("bash",
        $"-c \"(sleep 1.5) | env -u OPENSSL_CONF openssl s_client -connect 127.0.0.1:{port} -tls1_3 -msg 2>&1 | grep -c NewSessionTicket\"")
        { RedirectStandardOutput = true })!;
    results[$"tls13TicketsAllowTlsResume{resume}"] = int.Parse((await p.StandardOutput.ReadToEndAsync()).Trim());
    (await server).Dispose();
}
results["openSslConf"] = Environment.GetEnvironmentVariable("OPENSSL_CONF") ?? "";
results["runtime"] = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription;
Console.WriteLine(JsonSerializer.Serialize(results));
CS
dotnet build -c Release -o out >/dev/null
default=$(dotnet out/*.dll | tail -1)
numtickets=$(OPENSSL_CONF="$work/bower-openssl.cnf" dotnet out/*.dll | tail -1)
printf '{"os":"%s","openssl":"%s","default":%s,"withNumTickets0":%s}\n' \
  "$(. /etc/os-release && echo "$PRETTY_NAME")" "$(openssl version)" "$default" "$numtickets"
