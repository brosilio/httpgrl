using Httpgrl.Tests;

UnitTests.Register();
IntegrationTests.Register();
ProxyTests.Register();
return await T.RunAsync(args.Length > 0 ? args[0] : null);
