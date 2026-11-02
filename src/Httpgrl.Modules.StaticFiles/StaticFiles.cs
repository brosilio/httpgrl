namespace Httpgrl.Modules.StaticFiles;

public static class StaticFiles
{
    /// <summary>index, autoindex and static, in their content-phase order.</summary>
    public static IModule[] Modules() => [new IndexModule(), new AutoIndexModule(), new StaticModule()];
}
