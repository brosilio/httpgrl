using Httpgrl.Tests;

if (args is ["--fuzz", ..]) return Fuzz.RunCli(args);
if (args is ["--soak", ..]) return Soak.RunCli(args);

UnitTests.Register();
IntegrationTests.Register();
ProxyTests.Register();
ClientAuthTests.Register();
ReloadTests.Register();
ScriptTests.Register();
LimitTests.Register();
Fuzz.Register();
return await T.RunAsync(args.Length > 0 ? args[0] : null);
