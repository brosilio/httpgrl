using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Httpgrl.Core.Files;

/// <summary>
/// The only code that touches the filesystem on behalf of requests. Callers pass paths that
/// <c>HttpContextImpl.MapPath</c> already contained within a root/alias; policy for opening lives here.
/// </summary>
internal static partial class LocalFiles
{
    public static ResourceKind Probe(string path, string? noSymlinksFrom)
    {
        if (noSymlinksFrom is not null)
        {
            // Resolve through the same no-follow walk as Open: a path that walks into a symlink doesn't exist.
            int fd = WalkNoFollow(path, noSymlinksFrom, finalIsDirectory: null, out _);
            if (fd < 0) return ResourceKind.Missing;
            using var h = new SafeFileHandle(fd, ownsHandle: true);
            try { return (File.GetAttributes(h) & FileAttributes.Directory) != 0 ? ResourceKind.Directory : ResourceKind.File; }
            catch (IOException) { return ResourceKind.Missing; }
        }
        if (Directory.Exists(path)) return ResourceKind.Directory;
        if (File.Exists(path)) return ResourceKind.File;
        return ResourceKind.Missing;
    }

    /// <summary>
    /// Open for reading. On Unix with O_NONBLOCK, so a FIFO can't park the thread in open(2), and
    /// O_CLOEXEC, so descriptors never leak into child processes. Only seekable (regular) files are returned.
    /// </summary>
    public static OpenResult Open(string path, string? noSymlinksFrom, out SafeFileHandle? handle, out long length, out DateTime mtimeUtc)
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
            int fd, errno = 0;
            if (noSymlinksFrom is null)
            {
                fd = Open(path, F.NonBlock | F.CloExec);
                if (fd < 0) errno = Marshal.GetLastPInvokeError();
            }
            else fd = WalkNoFollow(path, noSymlinksFrom, finalIsDirectory: false, out errno);
            if (fd < 0)
            {
                return errno switch
                {
                    2 or 20 or 36 or 63 => OpenResult.NotFound,  // ENOENT, ENOTDIR, ENAMETOOLONG (linux, bsd)
                    1 or 13 or 40 or 62 => OpenResult.Forbidden, // EPERM, EACCES, ELOOP (linux, bsd)
                    31 when OperatingSystem.IsFreeBSD() => OpenResult.Forbidden, // EMLINK: O_NOFOLLOW hit a symlink
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

    public static OpenResult List(string path, string? noSymlinksFrom, int max, List<DirectoryEntry> into, out bool truncated)
    {
        truncated = false;
        int dirFd = -1;
        if (noSymlinksFrom is not null)
        {
            dirFd = WalkNoFollow(path, noSymlinksFrom, finalIsDirectory: true, out int errno);
            if (dirFd < 0) return errno is 2 or 20 ? OpenResult.NotFound : OpenResult.Forbidden;
            // Enumerate the directory we just verified, not the path again: a component swapped for a symlink after the
            // walk must not redirect the listing. /proc/self/fd/N names the open descriptor itself (and entries under it
            // resolve relative to that directory). Without procfs there's no safe way to do this with .NET's
            // enumerator, so refuse rather than list racily.
            var viaFd = $"/proc/self/fd/{dirFd}";
            if (!OperatingSystem.IsLinux() || !Directory.Exists(viaFd)) { Close(dirFd); return OpenResult.Forbidden; }
            path = viaFd;
        }
        try { return ListPath(path, noSymlinksFrom is not null, max, into, out truncated); }
        finally { if (dirFd >= 0) Close(dirFd); }
    }

    private static OpenResult ListPath(string path, bool noSymlinks, int max, List<DirectoryEntry> into, out bool truncated)
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
                        if (noSymlinks) continue; // couldn't be opened anyway: don't list it
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

    /// <summary>open(2) flags for this platform (Linux values are those of x86-64 and arm64).</summary>
    private static class F
    {
        public static readonly int NonBlock = OperatingSystem.IsLinux() ? 0x800 : 0x4;
        public static readonly int CloExec = OperatingSystem.IsLinux() ? 0x80000 : OperatingSystem.IsFreeBSD() ? 0x100000 : 0x1000000;
        public static readonly int NoFollow = OperatingSystem.IsLinux() ? 0x20000 : 0x100;
        public static readonly int Directory = OperatingSystem.IsLinux() ? 0x10000 : OperatingSystem.IsFreeBSD() ? 0x20000 : 0x100000;
    }

    /// <summary>
    /// disable_symlinks: open <paramref name="path"/> without following a symlink in any component after
    /// <paramref name="from"/> (symlinks inside the prefix itself are followed). One openat(O_NOFOLLOW) per component,
    /// each relative to the directory just opened, so there's no window for a symlink to be swapped in between a check
    /// and the open (what nginx does too). Returns a descriptor, or -1 with errno.
    /// </summary>
    private static int WalkNoFollow(string path, string from, bool? finalIsDirectory, out int errno)
    {
        errno = 0;
        int dir = Open(from.Length == 0 ? "/" : from, F.Directory | F.CloExec);
        if (dir < 0) { errno = Marshal.GetLastPInvokeError(); return -1; }
        var rest = path.AsSpan(from.Length).Trim('/');
        int consumed = path.Length - path.AsSpan(from.Length).TrimStart('/').Length;
        while (true)
        {
            int slash = rest.IndexOf('/');
            var name = (slash < 0 ? rest : rest[..slash]).ToString();
            bool last = slash < 0;
            int flags = F.NoFollow | F.CloExec | F.NonBlock;
            bool wantDir = !last || finalIsDirectory == true;
            if (wantDir) flags |= F.Directory;
            int fd = name.Length == 0 ? Dup(dir) : OpenAt(dir, name, flags);
            if (fd < 0)
            {
                errno = Marshal.GetLastPInvokeError();
                // With O_DIRECTORY, Linux reports a symlink as ENOTDIR: tell it apart from a real non-directory, so a
                // symlink is always "forbidden" (ELOOP) and a missing directory stays "not found". (Only to classify a
                // refusal, so checking after the fact is fine.)
                if (errno == 20 && wantDir && new FileInfo(path[..(consumed + name.Length)]).LinkTarget is not null)
                    errno = OperatingSystem.IsLinux() ? 40 : 62;
            }
            Close(dir);
            if (fd < 0 || last) return fd;
            dir = fd;
            consumed += name.Length + 1;
            rest = rest[(slash + 1)..];
        }
    }

    [LibraryImport("libc", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Open(string path, int flags);

    [LibraryImport("libc", EntryPoint = "openat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int OpenAt(int dirfd, string path, int flags);

    [LibraryImport("libc", EntryPoint = "dup", SetLastError = true)]
    private static partial int Dup(int fd);

    [LibraryImport("libc", EntryPoint = "close")]
    private static partial int Close(int fd);
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
