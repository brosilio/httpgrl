using Httpgrl.Tests;

if (args is ["--fuzz", ..]) return Fuzz.RunCli(args);
if (args is ["--soak", ..]) return Soak.RunCli(args);
if (args is ["--bench", ..]) return Bench.RunCli(args);

UnitTests.Register();
IntegrationTests.Register();
ProxyTests.Register();
ClientAuthTests.Register();
ReloadTests.Register();
ScriptTests.Register();
LimitTests.Register();
OpsTests.Register();
StaplingTests.Register();
ProxyProtocolTests.Register();
CompressionTests.Register();
TunnelTests.Register();
Http2Tests.Register();
Http2SessionTests.Register();
Fuzz.Register();
return await T.RunAsync(args.Length > 0 ? args[0] : null);
