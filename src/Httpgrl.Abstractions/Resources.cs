namespace Httpgrl;

/// <summary>What a request path names under the current location's root/alias.</summary>
public enum ResourceKind : byte
{
    /// <summary>Nothing there, or the path cannot be mapped (outside root/alias, unsafe on this OS).</summary>
    Missing,
    File,
    Directory,
}

public enum OpenResult : byte
{
    Ok,
    NotFound,
    Forbidden,
    /// <summary>The path names a directory; nothing was opened.</summary>
    IsDirectory,
    /// <summary>A FIFO, socket or similar; refused rather than served.</summary>
    NotRegularFile,
    Error,
}

/// <summary>
/// An open file handed out by the core (<see cref="HttpContext.OpenFile"/>). Modules never learn its
/// filesystem location; they read it or pass it to <see cref="HttpResponse.SendFileAsync"/>.
/// </summary>
public abstract class FileResource : IDisposable
{
    public abstract long Length { get; }
    /// <summary>Truncated to whole seconds (the resolution of Last-Modified).</summary>
    public abstract DateTime LastModifiedUtc { get; }
    /// <summary>Resolved by the core from the file name and the location's <c>types</c>.</summary>
    public abstract string ContentType { get; }
    /// <summary>Positional read; returns 0 at end of file.</summary>
    public abstract int Read(Span<byte> buffer, long offset);
    public abstract void Dispose();
}

public readonly record struct DirectoryEntry(string Name, bool IsDirectory, long Size, DateTime LastModifiedUtc);
