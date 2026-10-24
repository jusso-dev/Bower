// Generates C# parity vectors for the Rust bower-redaction crate.
//
// The C# implementation is the specification: every expected value in csharp.json.gz is
// produced by Bower.Redaction itself, never hand-written. Regenerate after changing
// src/Bower.Redaction:
//
//   dotnet build src/Bower.Redaction -c Release
//   dotnet fsi rust/crates/bower-redaction/tests/vectors/generate.fsx
//
// Build from a clean checkout of the commit under test (for example a `git worktree`)
// so local edits never leak into the vectors. In sandboxes without MSBuild node
// reuse, add `-m:1 -nodeReuse:false -p:UseSharedCompilation=false`. New cases are
// appended so existing vectors (and the seeded fuzz corpus) stay stable.
//
// YamlDotNet is resolved at runtime from the NuGet cache populated by the build.
#r "../../../../../src/Bower.Redaction/bin/Release/net10.0/Bower.Contracts.dll"
#r "../../../../../src/Bower.Redaction/bin/Release/net10.0/Bower.Abstractions.dll"
#r "../../../../../src/Bower.Redaction/bin/Release/net10.0/Bower.Redaction.dll"

open System
open System.Collections.Generic
open System.IO
open System.Text.Json
open Bower.Redaction
open Bower.Redaction.Privacy
open Bower.Redaction.Validation

let nugetRoot =
    match Environment.GetEnvironmentVariable "NUGET_PACKAGES" with
    | null | "" -> Path.Combine(Environment.GetFolderPath Environment.SpecialFolder.UserProfile, ".nuget", "packages")
    | value -> value

AppDomain.CurrentDomain.add_AssemblyResolve(ResolveEventHandler(fun _ args ->
    if args.Name.StartsWith("YamlDotNet,", StringComparison.Ordinal) then
        Reflection.Assembly.LoadFrom(Path.Combine(nugetRoot, "yamldotnet", "18.1.0", "lib", "net10.0", "YamlDotNet.dll"))
    else
        null))

let repoRoot = Path.GetFullPath(Path.Combine(__SOURCE_DIRECTORY__, "..", "..", "..", "..", ".."))
let outPath = Path.Combine(__SOURCE_DIRECTORY__, "csharp.json.gz")

let defaults = PrivacyPolicy.CreateDefault()
let defaultActions () = Dictionary<string, PrivacyAction>(defaults.DetectorActions, StringComparer.Ordinal)
let noActions () = Dictionary<string, PrivacyAction>(StringComparer.Ordinal)
let optIn () =
    HashSet<string>([ DetectorIds.IpAddress; DetectorIds.Hostname; DetectorIds.Username; DetectorIds.Address; DetectorIds.Gps; DetectorIds.SecurityMarking ], StringComparer.Ordinal)
let hmacKey = Array.create 32 7uy

let policies: (string * PrivacyPolicy) list =
    [ "default", defaults
      "optin", PrivacyPolicy(DetectorActions = defaultActions (), EnabledOptInDetectors = optIn ())
      "maskall", PrivacyPolicy(DefaultAction = PrivacyAction.Mask, DetectorActions = noActions (), EnabledOptInDetectors = optIn ())
      "sha256", PrivacyPolicy(DefaultAction = PrivacyAction.Sha256, DetectorActions = noActions (), EnabledOptInDetectors = optIn ())
      "hmac", PrivacyPolicy(DefaultAction = PrivacyAction.Hmac, DetectorActions = noActions (), HmacKey = hmacKey, HmacKeyId = "k9")
      "replace", PrivacyPolicy(DefaultAction = PrivacyAction.Replace, DetectorActions = noActions (), ReplacementText = "[x]")
      "alert", PrivacyPolicy(DefaultAction = PrivacyAction.AlertOnly, DetectorActions = noActions ())
      "truncact", PrivacyPolicy(DefaultAction = PrivacyAction.Truncate, DetectorActions = noActions ())
      "encnokey", PrivacyPolicy(DefaultAction = PrivacyAction.Encrypt, DetectorActions = noActions ())
      "short", PrivacyPolicy(DetectorActions = defaultActions (), MaximumFieldLength = 10)
      "nometa", PrivacyPolicy(DetectorActions = defaultActions (), EmitMetadata = false)
      "disabled",
      PrivacyPolicy(DetectorActions = defaultActions (), DisabledDetectors = HashSet<string>([ DetectorIds.Email; DetectorIds.FieldNameSecret ], StringComparer.Ordinal))
      "rules",
      PrivacyPolicy(
          DetectorActions = defaultActions (),
          HmacKey = hmacKey,
          HmacKeyId = "k9",
          FieldRules =
              [| PrivacyFieldRule("actor.username", PrivacyAction.Hmac)
                 PrivacyFieldRule("request.userAgent", PrivacyAction.Truncate, 10)
                 PrivacyFieldRule("*.code", PrivacyAction.Sha256)
                 PrivacyFieldRule("meta.*", PrivacyAction.Mask)
                 PrivacyFieldRule("drop", PrivacyAction.Remove)
                 PrivacyFieldRule("rep", PrivacyAction.Replace)
                 PrivacyFieldRule("keep", PrivacyAction.Allow)
                 PrivacyFieldRule("enc", PrivacyAction.Encrypt)
                 PrivacyFieldRule("trunc", PrivacyAction.Truncate)
                 PrivacyFieldRule("num", PrivacyAction.Mask) |]) ]

let engines = policies |> List.map (fun (name, policy) -> name, PrivacyEngine(policy))

let findingText (f: AppliedFinding) =
    String.Join("|", [| f.DetectorId; f.Category; f.Path; string f.Action; (if f.Validated then "true" else "false"); (if isNull f.SubKind then "" else f.SubKind) |])

let metadataVector (m: PrivacyMetadata) =
    List.ofSeq m.Detected, [ for kv in m.Actions -> [ kv.Key; kv.Value ] ]

// ---------------------------------------------------------------- JSON corpus
let emoji = "\U0001F600"
let jsonCases =
    [ """{ "actor": { "email": "alice@example.test", "password": "do-not-store" }, "http": { "request": { "headers": { "Authorization": "Bearer secret" } } } }"""
      ""; "   "; "[]"; "{ invalid"; "null"; "1"; "\"s\""; "﻿{}"; """{"a":1,}"""; """{"a":01}"""; "{\"a\":\"x\u0001\"}"
      "{\"a\":\"x\u007f\"}"; """{"a":1.}"""; """{"a":-}"""; """{"a":1} x"""; """{"a":1} """; " \t\r\n{} "; """{"a":1 /* c */}"""; """{'a':1}"""
      """{"a":"\x"}"""; """{"a":"\u00G1"}"""; """{"a":tru}"""; """{"a":1}}"""; """{"a" 1}"""; """{"a":[1 2]}"""; """{"a":.5}"""; """{"a":+1}"""; """{"a":1e}"""
      """{"a":"\/\u0041\u00e9\u00E9\b\f\n\r\t\"\\"}"""; """{"a":1E5,"b":1e-0,"c":-0.0e+00,"d":12345678901234567890123,"e":0.1,"f":-12}"""
      "{\"a\":" + String.replicate 31 "[" + String.replicate 31 "]" + "}"
      "{\"a\":" + String.replicate 32 "[" + String.replicate 32 "]" + "}"
      "{\"a\":\"" + String.replicate 40 "[" + "\"}"
      """{"a":"1","a":"2"}"""; """{"password":{"a":1,"a":2}}"""; """{"x":{"y":{"a":1,"A":2,"a":3}}}"""; """{"a":1,"\u0061":2}"""
      """{"\uD800":1}"""; """{"password":{"\uD800":1}}"""; """{"a":"\uDC00\uD800"}"""; """{"a":["\uD83D\uDE00", "\uD83D"]}"""; """{"a":["\uD83D\uDE00"]}"""
      """{"tfn": "100000001", "abn": "51 824 753 556", "medicare": "2123 45670 1", "ihi": "8003600000000007", "crn": "123 456 789A"}"""
      """{ "tfn": "123456789" }"""
      """{ "awsKey": "AKIAIOSFODNN7EXAMPLE", "detail": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature", "password": "do-not-store", "pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----" }"""
      """{ "pan": "4111111111111111" }"""; """{ "owner": "alice@example.test" }"""
      """{ "openai": "sk-abcdefghijklmnopqrstuvwxyz12", "github": "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "stripe": "sk_live_abcdefghijklmnopqrstuv" }"""
      """{ "tfn": "100000001", "email": "bob@example.test" }"""
      """{ "attributes": { "card": 4111111111111111 } }"""; """{ "attributes": { "values": [[4111111111111111]] } }"""
      """{ "attributes": { "4111111111111111": "x" } }"""; """{ "attributes": { "nested": { "4111111111111111": { "ok": true } } } }"""
      """{ "alice@example.test": "member" }"""; """{ "4111111111111111": 1, "5555555555554444": 2 }"""
      """{ "statusCode": 401, "port": 443, "score": 87.5 }"""
      """{"":1,"4111111111111111":"x"}"""; """{"redacted-key-1":0,"4111111111111111":1,"redacted-key-2":2,"5555555555554444":3}"""
      """{"a***@example.test":1,"alice@example.test":2}"""; """{"privacy":"keep","owner":"alice@example.test"}"""
      """{"x":{"y":[1,[2,{"z":"bob@example.test"}]],"n":null,"t":true,"f":false}}"""
      """{"dbPassword":"v","sessionToken":"v","idToken":"v","setCookie":"v","pwd":"v","xApiKey":"v","client_secret":"v","userPass":"v","mfa_otp":"v","AWS_SECRET_ACCESS_KEY":"v"}"""
      """{"tokenType":"kept","passwordLastChanged":"kept","bypass":"kept","eventType":"kept","sessionId":"kept","compass":"k","spin":"k","pin":"x","otp":"x","myPin":"x","pass-word":"x","PASS_WORD":"x"}"""
      "{\"passाword\":\"x\",\"passİword\":\"x\",\"toKen\":\"x\",\"ſecret\":\"x\",\"pass\U0001D400word\":\"x\",\"body\":{\"a\":1},\"headers\":[1],\"payload\":null,\"cookie\":5}"
      "{\"x\":\"pass٣word\",\"pass٣word\":1,\"pássword\":1,\"PASSⅠWORD\":1,\"pass²word\":1}"
      """{"a":"PayID: a\uD83D\uDE00bc","b":"PayID: \uD83D\uDE00\uD83D\uDE00\uD83D\uDE00"}"""
      """{"msg":"card 4111 1111 1111 1111 and 5555-5555-5555-4444 and 378282246310005 and 30569309025904 and 6011111111111117 and 3530111333300000 and 2221000000000009"}"""
      """{"msg":"TFN: 123 456 782, Tax File Number 876 543 210 and 12345678"}"""
      """{"msg":"BSB 062-000 account 12345678 / 062 000/1234"}"""
      """{"msg":"IBAN GB82WEST12345698765432 and gb82west12345698765432 swift DEUTDEFF500 DEUTDEFF"}"""
      """{"msg":"PayID: alice@example.test PayID=0412345678"}"""
      """{"msg":"call +61 412 345 678 or 0412345678 or (02) 9876 5432 or +14155552671"}"""
      """{"msg":"DOB: 01/02/1990 born 1-2-90 Date of Birth 12.12.2000"}"""
      """{"msg":"12 Smith Street, 3 Long Bay Road and -33.8688, 151.2093 at 192.168.1.10 host.internal username: bob.smith"}"""
      """{"msg":"passport PA1234567 and N1234567 Australian passport: E1234567"}"""
      """{"msg":"N1234567 without context"}"""
      """{"msg":"DVA QX123456 Veterans Affairs NX12345A and W1234 and V123456"}"""
      """{"msg":"QX123456"}"""
      """{"msg":"driver licence 12345678 AB123456 1234567 1234567890 12345678A"}"""
      """{"msg":"aws_secret_access_key=abc/123 secret_key: zz aws_session_token: tok AKIAIOSFODNN7EXAMPLE ASIAIOSFODNN7EXAMPLE secret_key=SESSIONx"}"""
      """{"msg":"DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCD== sv=2020-01-01&sp=r&sig=abc%2Fdef SharedAccessSignature=sig123;x AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"}"""
      """{"msg":"device_code=abcdefghij12345 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlMTIz"}"""
      """{"msg":"\"type\": \"service_account\" \"private_key\": \"-----BEGIN AIzaSyA1234567890abcdefghijklmnopqrstuv ya29.a0AfH6SM"}"""
      """{"msg":"access_token=abc.def~ghi+jkl/mno== refresh_token: rrr id_token=iii"}"""
      ("""{"msg":"sk-ant-abcdefghijklmnopqrstuvwxyz glpat-abcdefghijklmnopqrst xoxb-1234567890-abc S""" + """K0123456789abcdef0123456789abcdef cfxabcdefghijklmnopqrstu v1.0-abcdefghijklmnopqrstu ATATT3abcdefghijklmnopqrstu 00abcdefghijklmnopqrstuvwxyz0123456789ABCD mongodb+srv://u:p@host/db acct1234-abcd.region.snowflakecomputing.com"}""")
      """{"msg":"datadog 0123456789abcdef0123456789abcdef ddog_api_key", "other":"0123456789abcdef0123456789abcdef", "k":"api_key 0123456789abcdef0123456789abcdef", "p":"PAGERDUTY 0123456789abcdef0123456789abcdef"}"""
      """{"msg":"kubeconfig kind: Config\napiVersion: v1\nusers: Bearer eyJabc.def"}"""
      """{"msg":"docker login -u x auths { \"auth\": \"dXNlcjpwYXNzd29yZDEyMzQ1Ng==\" } registry.example.com password=hunter2"}"""
      """{"msg":"Server=db;Database=x;User Id=u;Password=p; jdbc:mysql://h:3306/db postgresql://u:p@h/db mysql://u:p@h Driver={SQL Server};Pwd=x"}"""
      """{"msg":"PASSWORD=hunter2 API_KEY = abc TOKEN=t CLIENT_SECRET=s password=lower"}"""
      """{"msg":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE----- -----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK----- -----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl\n-----END OPENSSH PRIVATE KEY----- -----BEGIN EC PRIVATE KEY-----\nx\n-----END EC PRIVATE KEY----- -----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY----- -----BEGIN PGP PUBLIC KEY BLOCK-----\ny\n-----END PGP PUBLIC KEY BLOCK-----"}"""
      """{"msg":"OFFICIAL: Sensitive and TOP SECRET and top  secret and PROTECTED and CABINET-IN-CONFIDENCE and SECRET and official:sensitive"}"""
      "{\"msg\":\"top　secret OFFICIAL: Sensitive\"}"
      "{\"msg\":\"ना4111111111111111 Ⓐ4111111111111111 \U0001D4004111111111111111 ‍4111111111111111 Ⅰ4111111111111111 ҈4111111111111111 é4111111111111111\"}"
      "{\"msg\":\"paſſport PA1234567 Kubeconfig aws_ſecret_key=x ſk-abcdefghijklmnopqrstuvwxyz12 kind: Config \U0001F600\U0001F600 users: AKIAK234567890123456 KQ123456\"}"
      "{\"msg\":\"\U0001D7CE\U0001D7CF\U0001D7CE100000001 ١٠٠٠٠٠٠٠١ 41١1111111111111 TFN 100 000　001\"}"
      "{\"msg\":\"kind: Config" + String.replicate 39 emoji + "users: x\",\"m2\":\"kind: Config" + String.replicate 41 emoji + "users: x\"}"
      "{\"msg\":\"registry" + String.replicate 19 emoji + "password=x\",\"m2\":\"registry" + String.replicate 21 emoji + "password=x\"}"
      """{"actor":{"username":"alice","userId":"u1"},"request":{"userAgent":"Mozilla/5.0 something long"},"a":{"code":"c1"},"b":{"code":42},"meta":{"x":"abcdef","y":"ab","z":{"n":1}},"drop":"d","rep":"r","keep":"k","enc":"e","trunc":"t","num":4111111111111111}"""
      """{"actor":{"username":"   "}}"""; """{"actor":{"username":""}}"""; """{"actor":{"username":["alice"]}}"""; """{"actor":[{"username":"alice"}]}"""
      """{"actor":{"username":"alice@example.test"},"meta":{"q":"\uD83D\uDE00x\uD83D\uDE00"},"trunc":"0123456789abcdefghijklmnopqrstuvwxyz"}"""
      """{"a":"0123456789ABCDEF","b":"\uD83D\uDE00\uD83D\uDE00\uD83D\uDE00\uD83D\uDE00\uD83D\uDE00\uD83D\uDE00","c":["0123456789\uD83D\uDE00x"],"d":12345678901234567,"e":"abcdefghi\uD83D\uDE00"}"""
      """{"note":"Contact alice@example.test, TFN 100000001, card 4111111111111111, key AKIAIOSFODNN7EXAMPLE, PROTECTED"}"""
      """{"emails":["a@b.co","x.y+z@sub.example.com.au","no-at-sign","@nolocal.com"]}"""
      // Context keywords with long s (.NET OrdinalIgnoreCase and IgnoreCase regexes never fold it),
      // Kelvin sign in case-insensitive literals, ZWNJ word boundaries.
      "{\"msg\":\"paſſport N1234567\",\"m2\":\"licenſe 12345678\",\"m3\":\"secret_key=ſession\",\"m4\":\"aws_secret_Key=x\",\"m5\":\"dva X1234 Dva Q1234 veteran T12345\",\"m6\":\"‌4111111111111111 ‌100000001\"}"
      "{\"m\":\"Kate@example.test Kubeconfig TOKEN=x driver KA123456 DVA K1234\"}"
      // Numbers in every JSON form; NUL escapes; whitespace that is not JSON whitespace.
      """{"a":-4111111111111111,"b":4111111111111111.0,"c":4111111111111111e0,"d":1e400,"e":-1E-400,"f":100000001,"g":[-0,0.5e-3]}"""
      """{"a":"x\u0000y 4111111111111111","b":"\u0000"}"""; " {}"; " "; " "; "{} "
      """{"privacy":{"a":1},"e":"bob@example.test"}"""; """{"e":"bob@example.test","privacy":null}"""
      // Masks next to surrogate pairs inside keys and near the truncation boundary (formerly split).
      "{\"PayID: a\U0001F600bc\":1,\"PayID: a\U0001F300bc\":2}"
      "{\"a\":\" PayID: a\U0001F600bcdefgh\",\"b\":\" PayID: \U0001F600abcdefgh\"}"
      // Overlap ranking counts UTF-16 units, not bytes.
      "{\"a\":\"PayID: éééé+61412345678 x@ab.co\",\"b\":\"PayID:ééééééx@ab.co\"}"
      // Masks never split a surrogate pair at either end, in keys or values.
      "{\"PayID: abc\U0001F600x\":1,\"PayID: abc\U0001F300x\":2,\"v\":\"PayID: \U0001F600\U0001F600x\",\"w\":\"PayID: ab\U0001F600\"}"
      // Every PEM label is classified by its BEGIN header; body text never changes the kind.
      """{"msg":"-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY----- -----BEGIN EC PRIVATE KEY-----\nx\n-----END EC PRIVATE KEY----- -----BEGIN DSA PRIVATE KEY-----\nx\n-----END DSA PRIVATE KEY----- -----BEGIN ENCRYPTED PRIVATE KEY-----\nx\n-----END ENCRYPTED PRIVATE KEY----- -----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY----- -----BEGIN PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----"}"""
      """{"msg":"-----BEGIN CERTIFICATE-----\nRSA PRIVATE KEY ECDSA PGP BEGIN SSH2\n-----END CERTIFICATE----- -----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK----- -----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK----- -----BEGIN PGP KEY BLOCK-----\nx\n-----END PGP KEY BLOCK-----"}""" ]

// Large payloads run under the default policy only, to keep the vector file small.
let largeCases =
    [ "{\"a\":\"" + String.replicate 40000 "y" + "\",\"list\":[\"" + String.replicate 33000 "z" + "\"],\"e\":\"" + String.replicate 32767 "q" + emoji + "\"}" ]

let jsonVectors =
    [ for (policyName, engine) in engines do
        for input in (if policyName = "default" then jsonCases @ largeCases else jsonCases) do
            let result = engine.RedactJson(input)
            let detected, actions = metadataVector result.Metadata
            yield dict [ "policy", box policyName
                         "input", box input
                         "succeeded", box result.Succeeded
                         "failureCode", box result.FailureCode
                         "redactedJson", box result.RedactedJson
                         "removedPaths", box (List.ofSeq result.RemovedPaths)
                         "maskedPaths", box (List.ofSeq result.MaskedPaths)
                         "detected", box detected
                         "actions", box actions
                         "findings", box [ for f in result.Findings -> findingText f ] ] ]

// ---------------------------------------------------------------- text fuzz corpus
let tokens =
    [| "TFN "; "Tax File Number: "; "100000001"; "123 456 782"; "123-456-782"; "12345678"; "CRN "; "123 456 789A"; "2123 45670 1"; "2123456701"
       "8003600000000007"; "passport "; "PA1234567"; "N1234567"; "51 824 753 556"; "51824753556"; "000 000 019"; "DVA "; "QX123456"; "Veterans Affairs "
       "licence "; "driver "; "AB123456"; "4111111111111111"; "4111 1111 1111 1111"; "5555-5555-5555-4444"; "378282246310005"; "062-000 "; "account "
       "GB82WEST12345698765432"; "DEUTDEFF500"; "PayID: "; "alice@example.test"; "+61 412 345 678"; "0412345678"; "+14155552671"; "DOB: 01/02/1990"
       "12 Smith Street"; "-33.8688, 151.2093"; "192.168.1.10"; "host.internal"; "username: bob"; "AKIAIOSFODNN7EXAMPLE"; "aws_secret_access_key=abc/123"
       "aws_session_token: zz"; "AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"; "sv=2020-01-01&sig=abc%2F"
       "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlMTIz"; "device_code=abcdefghij12"; "AIzaSyA1234567890abcdefghijklmnopqrstuv"; "ya29.abc"
       "\"type\": \"service_account\""; "access_token=abc.def"; "sk-abcdefghijklmnopqrstuvwxyz12"; "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
       "xoxb-1234567890-abc"; "sk_live_abcdefghijklmnopqrstuv"; "0123456789abcdef0123456789abcdef"; "datadog "; "api_key "; "mongodb+srv://u:p@h/db"
       "kubeconfig"; "kind: Config\nusers:"; "Bearer eyJabc."; "docker login"; "\"auth\": \"dXNlcjpwYXNzd29yZDEyMzQ1Ng==\""; "registry x password=abc"
       "Server=a;Database=b;Password=c"; "jdbc:mysql://h/db"; "postgres://u:p@h"; "PASSWORD=hunter2"; "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"
       "-----BEGIN CERTIFICATE-----x-----END CERTIFICATE-----"; "OFFICIAL: Sensitive"; "TOP SECRET"; "PROTECTED"; "secret"
       " "; "  "; "-"; ":"; "#"; "/"; "\n"; "\t"; "ſ"; "K"; "ा"; "Ⓐ"; "\U0001D400"; emoji; "٣"; " "; "　"; "é"; "_"; "."
       "@"; "a"; "Z"; "0"; "7"; "x"; "="; ";"; "\""; "‍"; "҈"; "Ⅰ"; "\U0001D7CE"; "paſſport "; "Kubeconfig"; "ſecret_key=x"
       "1"; "2"; "3"; "4"; "5"; "6"; "8"; "9"; "00"; "000"; "e"; "E"; "k"; "K"; "s"; "S"; "i"; "İ"; "ı" |]

let rng = Random(20261017)
let textCases =
    [ yield "user email alice@example.test pan 4111111111111111"
      yield ""
      for _ in 1..700 do
          let count = rng.Next(1, 8)
          yield String.Join("", [| for _ in 1..count -> tokens.[rng.Next(tokens.Length)] |])
      // Long-s and Kelvin context keywords next to bare identifiers.
      yield "paſſport N1234567"
      yield "licenſe 12345678 driver"
      yield "aws_secret_key=ſession"
      yield "Kubeconfig Kate@example.test"
      // Second fuzz pass with longer strings (appended so earlier vectors stay stable).
      for _ in 1..500 do
          let count = rng.Next(4, 14)
          yield String.Join("", [| for _ in 1..count -> tokens.[rng.Next(tokens.Length)] |]) ]

let textVectors =
    [ for (policyName, engine) in engines |> List.filter (fun (name, _) -> name = "optin" || name = "maskall") do
        for input in textCases do
            let result = engine.RedactText(input)
            yield dict [ "policy", box policyName
                         "input", box input
                         "succeeded", box result.Succeeded
                         "redactedText", box result.RedactedText
                         "findings", box [ for f in result.Findings -> findingText f ] ] ]

// ---------------------------------------------------------------- checksums
let crng = Random(42)
let digits (n: int) = String(Array.init n (fun _ -> char (int '0' + crng.Next(10))))
let checksumInputs =
    [ for _ in 1..300 -> digits 9 ] @ [ for _ in 1..100 -> digits 8 ] @ [ for _ in 1..300 -> digits 11 ]
    @ [ for _ in 1..200 -> "800360" + digits 10 ] @ [ for _ in 1..300 -> string (char (int '2' + crng.Next(6))) + digits 9 ]
    @ [ for _ in 1..300 -> digits (13 + crng.Next(7)) ]
    @ [ ""; "0"; "00000000"; "000000000"; "1000000O1"; "١٠٠٠٠٠٠٠١"; "51824753556"
        "000000019"; "2123456701"; "8003600000000007"; "4111111111111111"; "0000000000"; "2123456700" ]
let checksumVectors =
    [ for s in checksumInputs ->
        dict [ "input", box s
               "tfn", box (ChecksumAlgorithms.IsValidTfn(s.AsSpan()))
               "abn", box (ChecksumAlgorithms.IsValidAbn(s.AsSpan()))
               "acn", box (ChecksumAlgorithms.IsValidAcn(s.AsSpan()))
               "medicare", box (ChecksumAlgorithms.IsValidMedicare(s.AsSpan()))
               "ihi", box (ChecksumAlgorithms.IsValidIhi(s.AsSpan()))
               "luhn", box (ChecksumAlgorithms.Luhn(s.AsSpan())) ] ]

// ---------------------------------------------------------------- keyed hasher
let hasherKey = Array.init 32 byte
let hasherVectors =
    let hasher = KeyedFieldHasher(ReadOnlySpan<byte>(hasherKey))
    [ for value in [ "alice"; "é" + emoji; "x"; " a " ] do
        for keyId in [ null; ""; "k1" ] ->
            dict [ "value", box value; "keyId", box keyId; "hash", box (hasher.Hash(value, keyId)) ] ]

// ---------------------------------------------------------------- privacy profiles
let header = "apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n  id: t\n  version: 1\n"

// ---------------------------------------------------------------- custom detectors (appended)
let customDetector (id: string) (pattern: string) (action: string) (extra: string) (tests: string) =
    "customDetectors:\n  - id: " + id + "\n    pattern: '" + pattern + "'\n    action: " + action + "\n" + extra + "    tests:\n      match: " + tests + "\n"
let emp = """EMP-\d{6}"""
let validDetector (id: string) =
    "  - id: " + id + "\n    pattern: 'EMP-\\d{6}'\n    action: mask\n    tests:\n      match: [EMP-123456]\n"
let longText (n: int) = String.replicate n "x"
let customProfileCases =
    [ // Every error message, in loader order.
      header + "customDetectors:\n" + String.Join("", [ for i in 0..32 -> validDetector (sprintf "custom.d%d" i) ])
      header + "customDetectors:\n" + String.Join("", [ for i in 0..31 -> validDetector (sprintf "custom.d%d" i) ])
      header + "customDetectors: ~\n"; header + "customDetectors: []\n"; header + "customDetectors:\n  - ~\n"
      header + customDetector "Custom.X" emp "mask" "" "[EMP-123456]"
      header + customDetector "custom." emp "mask" "" "[EMP-123456]"
      header + customDetector "custom" emp "mask" "" "[EMP-123456]"
      header + customDetector "custom.a--b" emp "mask" "" "[EMP-123456]"
      header + customDetector "custom.-a" emp "mask" "" "[EMP-123456]"
      header + customDetector "custom.a-" emp "mask" "" "[EMP-123456]"
      header + customDetector "custom.a_b" emp "mask" "" "[EMP-123456]"
      header + customDetector "custom.éa" emp "mask" "" "[EMP-123456]"
      header + customDetector "custom.a.b" emp "mask" "" "[EMP-123456]"
      header + customDetector ("custom." + String.replicate 57 "a") emp "mask" "" "[EMP-123456]"
      header + customDetector ("custom." + String.replicate 58 "a") emp "mask" "" "[EMP-123456]"
      header + customDetector "custom.a-1-b2" emp "mask" "" "[EMP-123456]"
      header + "customDetectors:\n  - pattern: 'x'\n    action: mask\n    tests:\n      match: [x]\n"
      header + "customDetectors:\n  - id: ~\n    pattern: 'x'\n    action: mask\n    tests:\n      match: [x]\n"
      header + "customDetectors:\n" + validDetector "custom.dup" + validDetector "custom.other" + validDetector "custom.dup"
      header + customDetector "custom.d" emp "mask" ("    description: " + longText 257 + "\n") "[EMP-123456]"
      header + customDetector "custom.d" emp "mask" ("    description: " + longText 256 + "\n") "[EMP-123456]"
      header + customDetector "custom.d" emp "mask" "    description: ~\n" "[EMP-123456]"
      header + "customDetectors:\n  - id: custom.d\n    action: mask\n    tests:\n      match: [x]\n"
      header + "customDetectors:\n  - id: custom.d\n    pattern: ~\n    action: mask\n    tests:\n      match: [x]\n"
      header + customDetector "custom.d" "" "mask" "" "[x]"
      header + customDetector "custom.d" (String.replicate 513 "x") "mask" "" ("[" + String.replicate 513 "x" + "]")
      header + customDetector "custom.d" (String.replicate 512 "x") "mask" "" ("[" + String.replicate 512 "x" + "]")
      header + customDetector "custom.d" "a(?=b)" "mask" "" "[ab]"
      header + customDetector "custom.d" "(a{1000}){5}" "mask" "" "[a]"
      header + customDetector "custom.d" "a*" "mask" "" "[a]"
      header + customDetector "custom.d" "^" "mask" "" "[a]"
      header + "customDetectors:\n  - id: custom.d\n    pattern: 'x'\n    tests:\n      match: [x]\n"
      header + customDetector "custom.d" "x" "~" "" "[x]"
      header + customDetector "custom.d" "x" "obliterate" "" "[x]"
      header + customDetector "custom.d" "x" "Alert-Only" "" "[x]"
      header + customDetector "custom.d" "x" "hmac" "" "[x]"
      header + customDetector "custom.d" "x" "truncate" "" "[x]"
      header + "customDetectors:\n  - id: custom.d\n    pattern: 'x'\n    action: mask\n"
      header + "customDetectors:\n  - id: custom.d\n    pattern: 'x'\n    action: mask\n    tests: ~\n"
      header + "customDetectors:\n  - id: custom.d\n    pattern: 'x'\n    action: mask\n    tests: {}\n"
      header + "customDetectors:\n  - id: custom.d\n    pattern: 'x'\n    action: mask\n    tests:\n      noMatch: [y]\n"
      header + customDetector "custom.d" "x" "mask" "" "[]"
      header + customDetector "custom.d" "x" "mask" "" "~"
      header + customDetector "custom.d" "x" "mask" "" ("[" + String.Join(", ", List.replicate 17 "x") + "]")
      header + customDetector "custom.d" "x" "mask" "" ("[" + String.Join(", ", List.replicate 16 "x") + "]")
      header + customDetector "custom.d" "x" "mask" "" ("[x]\n      noMatch: [" + String.Join(", ", List.replicate 17 "y") + "]")
      header + customDetector "custom.d" "x" "mask" "" ("[x]\n      noMatch: [" + String.Join(", ", List.replicate 16 "y") + "]")
      header + customDetector "custom.d" "x" "mask" "" "[x, '']"
      header + customDetector "custom.d" "x" "mask" "" "[x, ~]"
      header + customDetector "custom.d" "x" "mask" "" ("[" + String.replicate 1025 "x" + "]")
      header + customDetector "custom.d" "x" "mask" "" ("[" + String.replicate 1024 "x" + "]")
      header + customDetector "custom.d" "x" "mask" "" "[x]\n      noMatch: ~"
      header + customDetector "custom.d" "x" "mask" "" "[x]\n      noMatch: ['']"
      header + customDetector "custom.d" "x" "mask" "" "[x, y, z]"
      header + customDetector "custom.d" "x" "mask" "" "[x]\n      noMatch: [y, axb]"
      header + customDetector "custom.d" emp "mask" "    wholeWord: true\n" "[EMP-123456, 'id EMP-000001.']\n      noMatch: [XEMP-123456, EMP-1234567, EMP-123456_]"
      header + customDetector "custom.d" emp "mask" "    wholeWord: true\n" "[XEMP-123456]"
      header + customDetector "custom.d" emp "mask" "    wholeWord: yes\n    ignoreCase: on\n" "[emp-123456]"
      header + customDetector "custom.d" emp "mask" "    wholeWord: off\n    ignoreCase: ~\n" "[XEMP-123456]\n      noMatch: [emp-123456]"
      header + customDetector "custom.d" emp "mask" "    ignoreCase: maybe\n" "[EMP-123456]"
      header + customDetector "custom.d" emp "mask" "    unknownKey: 1\n" "[EMP-123456]"
      header + customDetector "custom.d" emp "mask" "" "[EMP-123456]\n      extra: [x]"
      header + customDetector "custom.d" """\d{6}""" "mask" "" "[123456]\n      noMatch: [12345]"
      header + customDetector "custom.d" "x" "mask" "" "[x]" + "detectors:\n  custom.d: remove\n"
      header + customDetector "custom.d" "x" "mask" "" "[x]" + "detectors:\n  custom.other: remove\n"
      header + customDetector "custom.d" "x" "mask" "" "[x]" + "disabled: [custom.d, id.email]\n"
      header + customDetector "custom.d" "x" "mask" "" "[x]" + "disabled: [custom.other]\n"
      header + customDetector "custom.d" "x" "mask" "" "[x]" + "enableOptIn: [custom.d]\n"
      header + "detectors:\n  custom.d: remove\n"
      // Secret field names.
      header + "secretFieldNames: ~\n"; header + "secretFieldNames: []\n"
      header + "secretFieldNames: [sessionKey, x-contoso-signature, SESSION_KEY, Session-Key, 'Пароль', ÜberSecret, a1]\n"
      header + "secretFieldNames: [" + String.Join(", ", [ for i in 0..64 -> sprintf "n%d" i ]) + "]\n"
      header + "secretFieldNames: [" + String.Join(", ", [ for i in 0..63 -> sprintf "n%d" i ]) + "]\n"
      header + "secretFieldNames: [ok, '']\n"; header + "secretFieldNames: [ok, ~]\n"
      header + "secretFieldNames: [" + String.replicate 129 "a" + "]\n"; header + "secretFieldNames: [" + String.replicate 128 "a" + "]\n"
      header + "secretFieldNames: [ok, '---', '  ']\n"; header + "secretFieldNames: ['_']\n"
      header + "secretFieldNames: [\"pass\\U0001F600word\", \"İd\", \"KKey\"]\n"
      header + "secretFieldNames: {a: b}\n"
      // Syntax variety that must load identically.
      header + "customDetectors:\n"
      + "  - id: custom.employee-id\n    description: Contoso employee numbers\n    pattern: 'EMP-\\d{6}'\n    wholeWord: true\n    action: mask\n    tests:\n      match: [EMP-123456, 'user EMP-000001 logged in']\n      noMatch: [EMP-12345]\n"
      + "  - id: custom.customer-ref\n    pattern: 'CUST-[A-Z]{2}\\d{4}'\n    ignoreCase: true\n    action: hmac\n    tests:\n      match: [cust-ab1234, CUST-ZZ0000]\n      noMatch: [CUST-A1234]\n"
      + "  - id: custom.ticket\n    pattern: '(?:INC|CHG)[0-9]{7}|^TKT-\\w+$'\n    action: Replace\n    tests:\n      match: [INC0012345, TKT-abc]\n      noMatch: [' TKT-abc', inc0012345]\n"
      + "secretFieldNames: [sessionKey]\nfields:\n  - path: actor.username\n    action: hmac\n"
      // Council round 1 (appended): allow rejected, wholeWord canonical form, unsupported characters.
      header + customDetector "custom.d" "x" "allow" "" "[x]"
      header + customDetector "custom.d" "x" "Allow" "" "[x]"
      header + customDetector "custom.d" "x" "alert-only" "" "[x]"
      header + customDetector "custom.d" emp "mask" "    wholeWord: true\n    ignoreCase: true\n" "[emp-123456]"
      header + customDetector "custom.d" "TKN-[A-Z0-9]+?" "mask" "    wholeWord: true\n" "['issued TKN-ABC123 today']"
      header + customDetector "custom.d" "ORD-\\d{4}|ORD-\\d{4}[A-Z]" "mask" "    wholeWord: true\n" "[ORD-1234X]\n      noMatch: [ORD-1234XY]"
      header + customDetector "custom.d" "key=.{8}" "mask" "" "['key=s3cr3tk\U0001F600 rest']" ]
    @ [ for code in [ 0x0; 0x8; 0xB; 0xC; 0xE; 0x1F; 0x7F; 0x80; 0x85; 0x9F; 0x2028; 0x2029 ] do
          let c = string (char code)
          yield header + "# comment " + c + "\n"
          yield header + customDetector "custom.d" ("a" + c + "b") "mask" "" "[x]" ]
    @ [ for scalar in [ "\"a\\x0Cb\""; "\"a\\Lb\""; "\"a\\Nb\""; "\"a\\Pb\""; "\"a\\0b\""; "\"a\\eb\""; "\"a\\x7Fb\""
                        "\"\\uD83D\\uDE00\""; "\"\\udfff\""; "\"\\U0000DE00\""; "'\\uD800'"; "\"\\\\uD800\""
                        "\"\\U0001F600x\""; "\"a\\tb\""; "\"a\\u00e9b\""; "\"\\uD7FF\\uE000\"" ] ->
          header + "secretFieldNames: [" + scalar + "]\n" ]
    @ [ header.Replace("\n", "\r\n") + "secretFieldNames: [ab]\r\n# tab\there\n"
        header + "metadata:\n  id: t\n  version: 1\n  description: \"x\\x0Cy\"\n"
        header + "detectors:\n  \"au.tfn\\L\": mask\n"
        header + "fields:\n  - path: \"a\\Nb\"\n    action: mask\n" ]

// ---------------------------------------------------------------- custom pattern translation (appended)
let patternCorpus =
    [ // Accepted syntax.
      """EMP-\d{6}"""; """\w+@\w+\.com"""; """[A-Z]{2}\d{4}"""; "(?:ab|cd)+"; "(ab)*c"; "a{3,}"; "a{2,5}?"; "a+?b"; "x.y"; "^start"; "end$"
      """^\d+$"""; """[^\s]+"""; """\S+"""; """\D\W"""; """[\d\w\s]"""; """[a\-z]"""; "[-a]"; "[a-]"; """[\]\[\^\\&~]"""; """[\t\n\r]"""; """\t\n\r"""
      """\.\-\/\#\ \_\!\"\%\'\,\:\;\=\@\`\}\]\{\[\(\)\*\+\?\|\$\^\&\~"""; "a}b]c"; "café"; "[à-ÿ]+"; "[一-\uFFFC]"; "[ -~]"; "日本語"; "Ω+"; "a|b|c"; "(a|)b"
      "x()y"; "x(?:)y"; "(((a)))"; "a{0}b"; "a{1000}"; "(a{1000}){4}"; "((a{64}){64})"; "(?:a|b|c){1000}"; ".{1000}"; "(.{1000}){4}"; "[^a]{4096}"
      "a{0,1000}"; "a{01}"; "a{1,01}"; "a{00}b"; "[a-a]"; "[\u0000-\uFFFE]"; "[\uD7FF-\uE000]"; "[\uE000-\uFFFE]"; "\uFFFE"; "[\t- ]"; "a\u0001b"; "x y"
      "Hello"; "[a-z]+"; "[A-Fa-f0-9]{8}"; "[Z-b]"; "[^q]"; "ſK"; "[ſ]"; "Straße"; "[@-`]"; "[a-zA-Z]"; "İı"; "[^\\n]"
      // Rejected syntax: one case per reason and position.
      "(?=a)"; "(?!a)"; "(?<=a)b"; "(?<!a)b"; """\1"""; """(a)\2"""; """\k<x>"""; """\p{L}"""; """\P{L}"""; "(?i)a"; "(?i:a)"; "(?-i)a"; "(?s)a"
      "(?<n>a)"; "(?'n'a)"; "(?P<n>a)"; "(?>a)"; "(?#c)a"; "(?(a)b|c)"; "(?"; "(?)"; "(?:"; "(a"; "a)"; "((a)"; "a(b(c)"; "[a"; "[^"; "["; "[]"; "[^]"
      "[]a]"; "[[a]]"; "[a[b]]"; "[[:alpha:]]"; "[a[:alpha:]]"; "[a&&b]"; "[a--b]"; "[a~~b]"; "[a-z-[aeiou]]"; "[a-[b]]"; "[z-a]"; """[a-\d]"""; """[\d-z]"""
      """[\D]"""; """[\W]"""; """[\S]"""; "a{"; "a{x}"; "a{1"; "a{1,"; "a{,2}"; "a{2,1}"; "a{1, 2}"; "a{1001}"; "a{1,1001}"; "a{99999999999}"; "a{1001"
      "{2}a"; "{x"; "*a"; "+a"; "?a"; "a|*"; "(*a)"; "^*"; "$+"; "^{2}"; "a**"; "a+*"; "a*??"; "a{2}{3}"; "a??+"; "a?{2}"
      """\b"""; """\B"""; """\<"""; """\>"""; """\A"""; """\z"""; """\Z"""; """\G"""; """\x41"""; """\u0041"""; """\0"""; """\a"""; """\e"""; """\f"""
      """\v"""; """\c"""; """\q"""; """\é"""; "\\"; "a\\"; "[a\\"; """[\b]"""; """[\1]"""; """[\p{L}]"""; """[\x41]"""; "\U0001F600"; "a\U0001F600"
      "[\U0001F600]"; "[a-\U0001F600]"; "\uFFFF"; "[a-\uFFFF]"; "x\uFFFF"
      // Empty-matching and too complex (translated, then rejected by the loader).
      "a*"; "a?"; "^"; "$"; "^$"; "(a|)"; "a|"; "|a"; "()"; "(?:)*"; "a{0}"; "(a*)+"; "a*b?"; "(a{1000}){5}"; "((a{10}){10}){41}"; "(a{64}){65}"
      "(a{100}){10}"; "(a{100}){11}"; "((a{10}){10}){10}"; "(?:a|b){500}"; "(?:a|b){501}"; "x[^\\n]{999}"; "x[^\\n]{1000}"; "(?:[^\\n]+){1000}"
      "(a{64}){8}"; "(a{64}){9}"; "(?:[^\\n]?){511}x"; "(?:[^\\n]?){512}x"; "(?:[^\\n]{1,4}){128}"; "x[^\\n]{511}"
      "((((((((((a{1000}){1000}){1000}){1000}){1000}){1000}){1000}){1000}){1000}){1000})" ]

let patternVectors =
    [ for pattern in patternCorpus do
        for ignoreCase in [ false; true ] ->
            let translation: obj list =
                try
                    let t = CustomPatternTranslator.Translate(pattern, ignoreCase)
                    [ box true; box t.CanonicalPattern; box t.Complexity; box t.MatchesEmpty ]
                with :? CustomPatternSyntaxException as e -> [ box false; box e.Position; box e.Reason ]
            let created =
                try
                    let d = CustomDetectorDefinition.Create("custom.t", pattern, PrivacyAction.Mask, ignoreCase)
                    "ok:" + d.CanonicalPattern
                with :? InvalidDataException as e -> e.Message
            dict [ "pattern", box pattern; "ignoreCase", box ignoreCase; "translation", box translation; "created", box created ] ]

let reasonVector = List.ofSeq CustomPatternReasons.All

// wholeWord translations (appended): negated classes exclude the sentinel, anchors rejected.
let wholeWordPatternVectors =
    [ for pattern in patternCorpus @ [ "x\uFFFE"; "[^a]"; "\\D\\W\\S."; "a$"; "(a|^b)" ] do
        for ignoreCase in [ false; true ] ->
            let translation: obj list =
                try
                    let t = CustomPatternTranslator.Translate(pattern, ignoreCase, true)
                    [ box true; box t.CanonicalPattern; box t.Complexity; box t.MatchesEmpty ]
                with :? CustomPatternSyntaxException as e -> [ box false; box e.Position; box e.Reason ]
            let created =
                try
                    let d = CustomDetectorDefinition.Create("custom.t", pattern, PrivacyAction.Mask, ignoreCase, true)
                    "ok:" + d.CanonicalPattern
                with :? InvalidDataException as e -> e.Message
            dict [ "pattern", box pattern; "ignoreCase", box ignoreCase; "translation", box translation; "created", box created ] ]

// ---------------------------------------------------------------- custom detector engine (appended)
let customEngineProfiles =
    [ "contoso",
      header + """customDetectors:
  - id: custom.employee-id
    pattern: 'EMP-\d{6}'
    wholeWord: true
    action: mask
    tests:
      match: [EMP-123456]
      noMatch: [XEMP-123456]
  - id: custom.customer-ref
    pattern: 'cust-[a-z]{3}\d{4}'
    ignoreCase: true
    action: hmac
    tests:
      match: [CUST-abc1234]
  - id: custom.mail-local
    pattern: '[a-z]+@example\.test'
    action: remove
    tests:
      match: [alice@example.test]
  - id: custom.long-number
    pattern: '\d{9,}'
    action: replace
    tests:
      match: ['100000001']
  - id: custom.disabled-one
    pattern: 'ZZZ'
    action: remove
    tests:
      match: [ZZZ]
  - id: custom.alert
    pattern: 'ALERT\d'
    action: alert-only
    tests:
      match: [ALERT1]
  - id: custom.sha
    pattern: 'K[A-Z]{3}'
    action: sha256
    tests:
      match: [KABC]
disabled: [custom.disabled-one]
detectors:
  id.email: mask
secretFieldNames: [sessionKey, x-contoso-signature, 'Пароль', ÜberSecret, ok]
fields:
  - path: actor.username
    action: hmac
"""
      "nonbmp",
      header + """customDetectors:
  - id: custom.one
    pattern: 'P[^a]Q'
    action: mask
    tests:
      match: [PxQ]
  - id: custom.two
    pattern: 'R[^a][^a]S'
    action: mask
    tests:
      match: [RxyS]
  - id: custom.dot-after
    pattern: 'x.'
    action: replace
    tests:
      match: [xy]
  - id: custom.dot-before
    pattern: '.y'
    action: replace
    tests:
      match: [ay]
  - id: custom.run
    pattern: '[^\s]{3}'
    wholeWord: true
    action: mask
    tests:
      match: [abc]
  - id: custom.word
    pattern: 'Z\W+Z'
    wholeWord: true
    action: remove
    tests:
      match: [Z-Z]
  - id: custom.cjk
    pattern: '[一-龥]+'
    action: mask
    tests:
      match: [日本]
  - id: custom.anchored
    pattern: '^A.{2}$'
    action: mask
    tests:
      match: [Abc]
"""
      "thirtytwo",
      header + "customDetectors:\n" + String.Join("", [ for i in 0..31 -> sprintf "  - id: custom.rule-%d\n    pattern: 'R%02d-[A-Z0-9]{4,8}'\n    wholeWord: %b\n    ignoreCase: %b\n    action: mask\n    tests:\n      match: [R%02d-ABCD]\n" i i (i % 2 = 0) (i % 3 = 0) i ])
      // Council round 1 (appended).
      "trace",
      header + """customDetectors:
  - id: custom.trace-line
    pattern: 'trace: .+'
    action: alert-only
    tests:
      match: ['trace: x']
  - id: custom.employee-id
    pattern: 'EMP-\d{6}'
    wholeWord: true
    action: mask
    tests:
      match: [EMP-123456]
detectors:
  id.email: mask
"""
      "wholeword",
      header + """customDetectors:
  - id: custom.token
    pattern: 'TKN-[A-Z0-9]+?'
    wholeWord: true
    action: mask
    tests:
      match: ['issued TKN-ABC123 today']
  - id: custom.order
    pattern: 'ORD-\d{4}|ORD-\d{4}[A-Z]'
    wholeWord: true
    action: replace
    tests:
      match: [ORD-1234X]
  - id: custom.dash
    pattern: '-\d-'
    wholeWord: true
    action: remove
    tests:
      match: ['-1--2-']
  - id: custom.short
    pattern: 'E\d'
    wholeWord: true
    ignoreCase: true
    action: sha256
    tests:
      match: ['e1 E2']
"""
      "widen",
      header + """customDetectors:
  - id: custom.key
    pattern: 'key=.{8}'
    action: replace
    tests:
      match: ['key=s3cr3tk😀 rest']
  - id: custom.before
    pattern: '[^a]b'
    action: remove
    tests:
      match: [xb]
  - id: custom.both
    pattern: '[^a]{3}'
    wholeWord: true
    action: mask
    tests:
      match: [xyz]
""" ]

let loadedCustom =
    [ for (name, yaml) in customEngineProfiles -> name, yaml, PrivacyEngine(PrivacyProfileLoader.Load(yaml, Array.create 32 9uy, "kp").Policy) ]

let customJsonCases =
    [ """{"msg":"user EMP-123456 and XEMP-123456 and EMP-1234567 and EMP-654321_x and (EMP-000001)"}"""
      """{"ref":"cust-abc1234 CUST-XyZ9876 cust-ab1234","mail":"alice@example.test","n":100000001,"m":"tfn 100000001 card 4111111111111111"}"""
      """{"sessionKey":"s","SESSION_KEY":"s","session-key":"s","xContosoSignature":"s","пароль":"s","ПАРОЛЬ":"s","überSecret":"s","UBERSECRET":"s","ok":1,"oK":2,"notSecret":"v"}"""
      """{"EMP-123456":"key","nested":{"ALERT1 cust-abc9999":"v","ZZZ":"disabled","KABC":"hash me"}}"""
      """{"actor":{"username":"EMP-123456"},"list":["EMP-111111",123456789012,["ALERT2"]]}"""
      """{"a":"P😀Q P😀😀Q PxQ","b":"R😀S R😀😀S RxyS","c":"x😀 😀y xy ay","d":"😀😀 ab😀 😀ab abc a😀c","e":"Z😀Z Z-Z aZ-Z","f":"日本😀語 中文","g":"A😀","h":"Ab😀"}"""
      """{"a":"PxQ","emoji":"😀😀😀😀😀😀","mixed":"EMP-123456😀EMP-654321"}"""
      """{"r":"R01-ABCD r00-abcd R03-abcd R02-ABCD9 xR04-ABCD R31-ABCDEFGH R30-abcdefgh"}"""
      """{"none":"nothing to see","num":42,"t":true}"""
      // Council round 1 (appended).
      """{"msg":"trace: card 4111111111111111 key AKIAIOSFODNN7EXAMPLE mail alice@example.test EMP-123456"}"""
      """{"a":"issued TKN-ABC123 today","b":"ORD-1234X ORD-1234 ORD-1234XY","c":"-1--2- x-3-","d":"e1 E2 xE3 E4_","e":"EMP-1 EMP-2 EMP-123456 EMP-654321"}"""
      "{\"a\":\"key=s3cr3tk\U0001F600 rest\",\"b\":\"\U0001F600b \u00E9b xb\",\"c\":\"\U0001F600\U0001F600 a\U0001F600 \U0001F600xy\",\"\U0001F600b\":1}" ]

// Council A2 probes: bounded work. Inputs are rebuilt from prefix + unit x count.
let probeProfiles =
    let probe i (p: string) (sample: string) = sprintf "  - id: custom.p%d\n    pattern: '%s'\n    action: mask\n    tests:\n      match: ['%s']\n" i p sample
    [ "quadratic", header + "customDetectors:\n" + probe 0 "a+z|a" "a"
      "token", header + "customDetectors:\n" + probe 0 "token=.+" "token=x"
      "dotx", header + "customDetectors:\n" + probe 0 ".+x.+" "axb"
      "mixed", header + "customDetectors:\n" + String.Join("", [ for i in 0..31 -> probe i ([| "a+z|a"; "token=.+"; ".+x.+"; "x[^a]{3}" |].[i % 4]) ([| "a"; "token=x"; "axb"; "xbcd" |].[i % 4]) ]) ]

let probeInputs =
    [ for n in [ 1024; 2048; 4096; 4097; 8192; 16384; 32768; 65536; 65537; 131072; 262144; 524288; 1_000_000 ] do
        yield "quadratic", "", "a", n
        yield "token", "token=", "x", n
        yield "token", "", "token=a ", n / 8
        yield "dotx", "", "x", n
        yield "mixed", "", "ab x", n / 4 ]

let probeVectors =
    let engines = dict [ for (name, yaml) in probeProfiles -> name, PrivacyEngine(PrivacyProfileLoader.Load(yaml, Array.create 32 9uy, "kp").Policy) ]
    [ for (profile, prefix, unit, count) in probeInputs ->
        let input = "{\"v\":\"" + prefix + String.replicate count unit + "\"}"
        let result = engines[profile].RedactJson(input)
        dict [ "profile", box profile
               "prefix", box prefix
               "unit", box unit
               "count", box count
               "succeeded", box result.Succeeded
               "failureCode", box result.FailureCode
               "redactedJson", box result.RedactedJson
               "findings", box result.Findings.Count ] ]

let customEngineVectors =
    [ for (name, _, engine) in loadedCustom do
        for input in customJsonCases ->
            let result = engine.RedactJson(input)
            let detected, actions = metadataVector result.Metadata
            dict [ "profile", box name
                   "input", box input
                   "succeeded", box result.Succeeded
                   "failureCode", box result.FailureCode
                   "redactedJson", box result.RedactedJson
                   "removedPaths", box (List.ofSeq result.RemovedPaths)
                   "maskedPaths", box (List.ofSeq result.MaskedPaths)
                   "detected", box detected
                   "actions", box actions
                   "findings", box [ for f in result.Findings -> findingText f ] ] ]

let customTextVectors =
    let crng = Random(20261024)
    let pieces =
        [| "EMP-123456"; "XEMP-1"; "_"; " "; "-"; "😀"; "P"; "Q"; "R"; "S"; "x"; "y"; "a"; "Z"; "日本"; "A"; "cust-abc1234"; "100000001"; "4111111111111111"
           "alice@example.test"; "ALERT3"; "KABC"; "R05-ABCD"; "r06-abcd"; "\n"; "\t"; "é"; "ſ"; "K"; "1"; "." |]
    [ for (name, _, engine) in loadedCustom do
        for _ in 1..150 do
            let input = String.Join("", [| for _ in 1..crng.Next(1, 12) -> pieces.[crng.Next(pieces.Length)] |])
            let result = engine.RedactText(input)
            yield dict [ "profile", box name
                         "input", box input
                         "succeeded", box result.Succeeded
                         "redactedText", box result.RedactedText
                         "findings", box [ for f in result.Findings -> findingText f ] ] ]

// ---------------------------------------------------------------- field-name normalisation (appended)
let normalizationVectors =
    let all = [| for code in 0..0xFFFF do if code < 0xD800 || code > 0xDFFF then yield char code |]
    [ for chunk in Array.chunkBySize 1024 all ->
        let input = String(chunk)
        dict [ "input", box input; "normalized", box (FieldNameNormalizer.Normalize input) ] ]

let profileCases =
    [ File.ReadAllText(Path.Combine(repoRoot, "deploy", "privacy", "cloud-identities.yaml"))
      File.ReadAllText(Path.Combine(repoRoot, "packs", "linux-ssh-gateway", "privacy.yaml"))
      """
apiVersion: bower.security/v1
kind: PrivacyProfile
metadata:
  id: test
  version: 1.0.0
fields:
  - path: actor.username
    action: hmac
  - path: request.userAgent
    action: truncate
    maxLength: 10
maximumFieldLength: 1024
"""
      header + "detectors:\n  not.a.detector: mask\n"
      header + "fields:\n  - path: actor.username\n    action: obliterate\n"
      header + "unexpectedKey: true\n"
      header + "maximumFieldLength: 10\n"
      header; header.Replace("\n", "\r\n"); header.Replace("\n", "\r"); header + "\u0085# nel # ls \f"
      header + "defaultAction: Alert-Only\ndetectors:\n  au.tfn: SHA256\n  fin.credit-card: mask\n  au.tfn: remove\ndisabled: [id.email]\nenableOptIn:\n  - id.ip\n"
      header + "detectors:\n  au.tfn: 5\n"; header + "disabled: [au.tfn, bad.id]\n"; header + "enableOptIn: [nope]\n"
      header + "fields:\n  - path: a..b\n    action: mask\n"; header + "fields:\n  - path: a.b\n    action: truncate\n"
      header + "fields:\n  - path: a.b\n    action: truncate\n    maxLength: 70000\n"; header + "fields:\n  - path: a.b\n    action: truncate\n    maxLength: 0\n"
      header + "fields:\n  - path: " + String.replicate 65 "a" + "\n    action: mask\n"; header + "fields:\n  - path: " + String.replicate 64 "a" + ".*\n    action: mask\n"
      header + "fields:\n  - path: '  '\n    action: mask\n"; header + "fields:\n  - action: mask\n"
      header + "defaultAction: hmac\n"; header + "fields:\n  - path: a\n    action: HMAC\n"; header + "defaultAction: alertonly\n"; header + "defaultAction: alert_only\n"
      header + "maximumFieldLength: \"300\"\n"; header + "maximumFieldLength: 0x200\n"; header + "maximumFieldLength: 01000\n"; header + "maximumFieldLength: +300\n"
      header + "maximumFieldLength: 1_000\n"; header + "maximumFieldLength: 0b100000000\n"; header + "maximumFieldLength: 300.0\n"; header + "maximumFieldLength: 3e2\n"
      header + "maximumFieldLength: 65537\n"; header + "maximumFieldLength: 255\n"; header + "maximumFieldLength: 256\n"; header + "maximumFieldLength: 65536\n"
      header + "maximumFieldLength: ~\n"; header + "maximumFieldLength: 2147483648\n"; header + "maximumFieldLength: -300\n"
      header + "emitMetadata: yes\n"; header + "emitMetadata: off\n"; header + "emitMetadata: False\n"; header + "emitMetadata: N\n"; header + "emitMetadata: 1\n"
      header + "emitMetadata: ~\n"; header + "emitMetadata: 'no'\n"
      header + "defaultAction:\n"; header + "detectors: {}\n"
      header + "metadata:\n  id: x\n  version: 2\n  extra: 1\n"; header + "metadata: {id: y, version: 3, description: d}\n"
      "apiVersion: \"bower.security/v1\"\nkind: 'PrivacyProfile'\nmetadata:\n  id: 12\n  version: 1.0\n"
      "apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n  id: t\n"
      "kind: PrivacyProfile\nmetadata:\n  id: t\n  version: 1\n"; "apiVersion: bower.security/v2\nkind: PrivacyProfile\nmetadata:\n  id: t\n  version: 1\n"
      "ApiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n  id: t\n  version: 1\n"
      "---\n"; "# only a comment\n"; "apiVersion: [a]\n"; header + "---\nfoo: 1\n"
      "  "
      // YAML nulls where the model is required fail the load with a clear message.
      "apiVersion: bower.security/v1\nkind: PrivacyProfile\n"; "apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata: ~\n"
      "apiVersion: bower.security/v1\nkind: PrivacyProfile\nmetadata:\n"; "apiVersion: bower.security/v1\nkind: PrivacyProfile\ndetectors:\n  au.tfn: nope\n"
      header + "detectors: ~\n"; header + "detectors:\n  au.tfn: ~\n"; header + "disabled: ~\n"; header + "enableOptIn: ~\n"; header + "disabled: [~]\n"
      header + "fields: ~\n"; header + "fields:\n  - ~\n"; header + "fields:\n  - path: a\n"; header + "fields:\n  - path: a\n    action: ~\n" ]
    @ customProfileCases

let customDetectorVector (d: CustomDetectorDefinition) =
    [ d.Id; (if isNull d.Description then "" else d.Description); d.Pattern; d.CanonicalPattern
      (if d.IgnoreCase then "true" else "false"); (if d.WholeWord then "true" else "false"); string d.Action ]

let profileVectors =
    [ for yaml in profileCases ->
        try
            let loaded = PrivacyProfileLoader.Load(yaml, Array.create 32 9uy, "kp")
            let p = loaded.Policy
            dict [ "yaml", box yaml
                   "ok", box true
                   "id", box loaded.Id
                   "version", box loaded.Version
                   "hash", box loaded.Hash
                   "defaultAction", box (string p.DefaultAction)
                   "detectorActions", box [ for kv in p.DetectorActions -> [ kv.Key; string kv.Value ] ]
                   "disabled", box (p.DisabledDetectors |> Seq.sort |> List.ofSeq)
                   "enabledOptIn", box (p.EnabledOptInDetectors |> Seq.sort |> List.ofSeq)
                   "fieldRules", box [ for r in p.FieldRules -> [ r.Path; string r.Action; (if r.MaxLength.HasValue then string r.MaxLength.Value else "") ] ]
                   "maximumFieldLength", box p.MaximumFieldLength
                   "emitMetadata", box p.EmitMetadata
                   "hmacKeyId", box p.HmacKeyId
                   "customDetectors", box [ for d in p.CustomDetectors -> customDetectorVector d ]
                   "secretFieldNames", box (List.ofSeq p.SecretFieldNames) ]
        with ex ->
            dict [ "yaml", box yaml; "ok", box false; "error", box (ex.GetType().Name); "message", box ex.Message ] ]

let withoutKey =
    [ for yaml in [ header + "defaultAction: hmac\n"; header + "fields:\n  - path: a\n    action: hmac\n"; header
                    header + customDetector "custom.h" "EMP-\\d{6}" "hmac" "" "[EMP-123456]" ] ->
        try
            PrivacyProfileLoader.Load(yaml) |> ignore
            dict [ "yaml", box yaml; "ok", box true ]
        with ex -> dict [ "yaml", box yaml; "ok", box false; "error", box (ex.GetType().Name); "message", box ex.Message ] ]

// ---------------------------------------------------------------- policy validation
let policyErrorVectors =
    [ for path in [ ""; "."; ".."; "a"; "a..b"; "*" ] ->
        try
            PrivacyEngine(PrivacyPolicy(FieldRules = [| PrivacyFieldRule(path, PrivacyAction.Mask) |])) |> ignore
            dict [ "path", box path; "ok", box true ]
        with ex -> dict [ "path", box path; "ok", box false; "error", box (ex.GetType().Name); "message", box ex.Message ] ]

// ---------------------------------------------------------------- key files
let keyFileCases: (string * byte[]) list =
    [ "base64", Text.Encoding.UTF8.GetBytes(Convert.ToBase64String(Array.init 32 byte))
      "base64-whitespace", Text.Encoding.UTF8.GetBytes("  " + Convert.ToBase64String(Array.init 33 byte).Insert(8, "\n").Insert(20, " \t") + "\r\n")
      "base64-short", Text.Encoding.UTF8.GetBytes(Convert.ToBase64String(Array.init 31 byte))
      "base64-trailing-bits", Text.Encoding.UTF8.GetBytes(String.replicate 40 "QUFB" + "QR==")
      "raw-40", Array.init 40 (fun i -> byte (200 + i % 50))
      "raw-31", Array.init 31 (fun i -> byte (200 + i))
      "raw-text-40", Text.Encoding.UTF8.GetBytes(String.replicate 40 "!")
      "unpadded", Text.Encoding.UTF8.GetBytes(String.replicate 11 "QUFB" + "QUF") ]
let keyFileVectors =
    [ for (name, content) in keyFileCases ->
        let path = Path.GetTempFileName()
        File.WriteAllBytes(path, content)
        try
            try
                dict [ "name", box name; "content", box (Convert.ToBase64String content); "ok", box true
                       "key", box (Convert.ToHexStringLower(PrivacyProfileLoader.ReadKeyFile(path))) ]
            with ex -> dict [ "name", box name; "content", box (Convert.ToBase64String content); "ok", box false; "error", box (ex.GetType().Name) ]
        finally
            File.Delete(path) ]

// ---------------------------------------------------------------- facade
let facadeVectors =
    let detector = SensitiveDataDetector()
    [ for input in [ """{ "awsKey": "AKIAIOSFODNN7EXAMPLE", "detail": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature", "owner": "alice@example.test", "password": "do-not-store" }"""
                     """{ "pan": "4111111111111111", "x": "Server=a;Password=b", "c": "PROTECTED", "pem": "-----BEGIN CERTIFICATE-----x-----END CERTIFICATE-----", "t": "100000001" }"""
                     "[]" ] ->
        let result = detector.ScanAndRedact(input)
        dict [ "input", box input
               "succeeded", box result.Succeeded
               "failureCode", box result.FailureCode
               "redactedJson", box result.RedactedJson
               "findings", box [ for f in result.Findings -> String.Join("|", [| string f.Kind; f.Path; f.Preview; f.Action |]) ] ] ]

let document =
    dict [ "engine", box jsonVectors
           "text", box textVectors
           "checksums", box checksumVectors
           "hasher", box hasherVectors
           "profiles", box profileVectors
           "profilesWithoutKey", box withoutKey
           "keyFiles", box keyFileVectors
           "facade", box facadeVectors
           "policyErrors", box policyErrorVectors
           "customPatterns", box patternVectors
           "customPatternReasons", box reasonVector
           "customPatternsWholeWord", box wholeWordPatternVectors
           "customEngineProfiles", box [ for (name, yaml) in customEngineProfiles -> [ name; yaml ] ]
           "customEngine", box customEngineVectors
           "customText", box customTextVectors
           "fieldNameNormalization", box normalizationVectors
           "customProbeProfiles", box [ for (name, yaml) in probeProfiles -> [ name; yaml ] ]
           "customProbes", box probeVectors ]

// Gzipped so synthetic fuzzed credentials in the corpus do not trip secret scanning.
do
    use gzip = new IO.Compression.GZipStream(File.Create(outPath), IO.Compression.CompressionLevel.SmallestSize)
    let bytes =
        Text.Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(document, JsonSerializerOptions(WriteIndented = false, Encoder = Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping))
            + "\n")
    gzip.Write(bytes, 0, bytes.Length)
printfn "wrote %s (%d engine, %d text vectors)" outPath jsonVectors.Length textVectors.Length
