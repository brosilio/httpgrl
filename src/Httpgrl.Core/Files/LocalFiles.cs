using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Httpgrl.Core.Files;

/// <summary>
/// The only code that touches the filesystem on behalf of requests. Callers pass paths that
/// <c>HttpContextImpl.MapPath</c> already contained within a root/alias; policy for opening lives here.
/// </summary>
internal static partial class LocalFiles
{
    public static ResourceKind Probe(string path)
    {
        if (Directory.Exists(path)) return ResourceKind.Directory;
        if (File.Exists(path)) return ResourceKind.File;
        return ResourceKind.Missing;
    }

    /// <summary>
    /// Open for reading. On Unix with O_NONBLOCK, so a FIFO can't park the thread in open(2), and
    /// O_CLOEXEC, so descriptors never leak into child processes. Only seekable (regular) files are returned.
    /// </summary>
    public static OpenResult Open(string path, out SafeFileHandle? handle, out long length, out DateTime mtimeUtc)
    {
        handle = null;
        length = 0;
        mtimeUtc = default;
        SafeFileHandle h;
        if (OperatingSystem.IsWindows())
        {
            if (Directory.Exists(path)) return OpenResult.IsDirectory;
            try { h = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete); }
            catch (FileNotFoundException) { return OpenResult.NotFound; }
            catch (DirectoryNotFoundException) { return OpenResult.NotFound; }
            catch (UnauthorizedAccessException) { return OpenResult.Forbidden; }
            catch (IOException) { return OpenResult.Error; }
        }
        else
        {
            int flags = OperatingSystem.IsLinux() ? 0x800 | 0x80000         // O_NONBLOCK | O_CLOEXEC
                      : OperatingSystem.IsFreeBSD() ? 0x4 | 0x100000
                      : 0x4 | 0x1000000;                                     // macOS
            int fd = Open(path, flags);
            if (fd < 0)
            {
                return Marshal.GetLastPInvokeError() switch
                {
                    2 or 20 or 36 or 63 => OpenResult.NotFound,  // ENOENT, ENOTDIR, ENAMETOOLONG (linux, bsd)
                    1 or 13 or 40 or 62 => OpenResult.Forbidden, // EPERM, EACCES, ELOOP (linux, bsd)
                    _ => OpenResult.Error,
                };
            }
            h = new SafeFileHandle(fd, ownsHandle: true);
        }

        try
        {
            if ((File.GetAttributes(h) & FileAttributes.Directory) != 0) { h.Dispose(); return OpenResult.IsDirectory; }
            length = RandomAccess.GetLength(h);
            var t = File.GetLastWriteTimeUtc(h);
            mtimeUtc = new DateTime(t.Ticks - t.Ticks % TimeSpan.TicksPerSecond, DateTimeKind.Utc);
        }
        catch (NotSupportedException) { h.Dispose(); return OpenResult.NotRegularFile; } // unseekable: FIFO, socket
        catch (IOException) { h.Dispose(); return OpenResult.Error; }
        handle = h;
        return OpenResult.Ok;
    }

    public static OpenResult List(string path, int max, List<DirectoryEntry> into, out bool truncated)
    {
        truncated = false;
        if (!Directory.Exists(path)) return OpenResult.NotFound;
        try
        {
            var opts = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = 0, ReturnSpecialDirectories = false, RecurseSubdirectories = false };
            foreach (var fi in new DirectoryInfo(path).EnumerateFileSystemInfos("*", opts))
            {
                if (into.Count >= max) { truncated = true; break; }
                try
                {
                    if (fi.LinkTarget is not null)
                    {
                        if (fi.ResolveLinkTarget(true) is not { Exists: true } target) continue; // broken link
                        into.Add(new DirectoryEntry(fi.Name, target is DirectoryInfo, target is FileInfo tf ? tf.Length : 0, target.LastWriteTimeUtc));
                    }
                    else
                    {
                        bool dir = (fi.Attributes & FileAttributes.Directory) != 0;
                        into.Add(new DirectoryEntry(fi.Name, dir, fi is FileInfo f ? f.Length : 0, fi.LastWriteTimeUtc));
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
        catch (UnauthorizedAccessException) { return OpenResult.Forbidden; }
        catch (IOException) { return OpenResult.Error; }
        return OpenResult.Ok;
    }

    [LibraryImport("libc", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Open(string path, int flags);
}

internal sealed class LocalFileResource(SafeFileHandle handle, long length, DateTime mtimeUtc, string contentType) : FileResource
{
    public override long Length => length;
    public override DateTime LastModifiedUtc => mtimeUtc;
    public override string ContentType => contentType;

    // Blocking pread: page-cache hits cost microseconds; a thread-pool hop per block costs more.
    public override int Read(Span<byte> buffer, long offset) => RandomAccess.Read(handle, buffer, offset);

    public override void Dispose() => handle.Dispose();
}
