using System.Text;

namespace Httpgrl.Core.Config;

/// <summary>
/// nginx-syntax parser. Dispatches each statement to the owning module's <see cref="Directive"/>;
/// handles <c>include</c> itself.
/// </summary>
internal sealed class ConfigParser(IReadOnlyDictionary<string, List<Directive>> directives, VariableRegistry vars) : IConfigServices
{
    private const int MaxIncludeDepth = 16;
    private const long MaxFileSize = 16 << 20;
    private string _baseDir = "";
    private int _depth;

    public ConfigScope ParseFile(string path)
    {
        var full = Path.GetFullPath(path);
        _baseDir = Path.GetDirectoryName(full) ?? "";
        var root = new ConfigScope(ContextKind.Main, null, [], new SourceLocation(full, 0));
        ParseInto(full, root, null);
        return root;
    }

    public ConfigScope ParseText(string text, string virtualPath = "<string>", string? baseDir = null)
    {
        _baseDir = baseDir ?? Directory.GetCurrentDirectory();
        var root = new ConfigScope(ContextKind.Main, null, [], new SourceLocation(virtualPath, 0));
        var lx = new Lexer(text, virtualPath);
        ParseBlock(lx, root, inBraces: false);
        return root;
    }

    public ComplexValue Compile(string raw) => vars.Compile(raw, _current);

    public void AddVariable(string name, VariableGetter getter) => vars.Add(name, getter);

    /// <summary>The directive being handled (for errors about variables resolved after parsing).</summary>
    private SourceLocation _current;

    public byte[] ReadFile(string path, long maxBytes)
    {
        var full = Path.GetFullPath(path, _baseDir);
        var info = new FileInfo(full);
        if (!info.Exists) throw new IOException("not found");
        if (info.Length > maxBytes) throw new IOException($"larger than {maxBytes} bytes");
        return File.ReadAllBytes(full);
    }

    private void ParseInto(string file, ConfigScope scope, SourceLocation? from)
    {
        if (++_depth > MaxIncludeDepth) throw new ConfigException("include nesting too deep", from);
        try
        {
            string text;
            try
            {
                var info = new FileInfo(file);
                if (!info.Exists) throw new ConfigException($"cannot open \"{file}\": not found", from);
                if (info.Length > MaxFileSize) throw new ConfigException($"\"{file}\" is too large", from);
                text = File.ReadAllText(file, Encoding.UTF8);
            }
            catch (IOException e) { throw new ConfigException($"cannot read \"{file}\": {e.Message}", from); }
            catch (UnauthorizedAccessException e) { throw new ConfigException($"cannot read \"{file}\": {e.Message}", from); }
            ParseBlock(new Lexer(text, file), scope, inBraces: false);
        }
        finally { _depth--; }
    }

    private void ParseBlock(Lexer lx, ConfigScope scope, bool inBraces)
    {
        var words = new List<string>(8);
        int line = 0;
        while (true)
        {
            var t = lx.Next();
            switch (t.Kind)
            {
                case TokenKind.Word:
                    if (words.Count == 0) line = t.Line;
                    words.Add(t.Text!);
                    continue;
                case TokenKind.Eof:
                    if (words.Count > 0) throw new ConfigException("unexpected end of file, expecting \";\" or \"}\"", lx.At(t.Line));
                    if (inBraces) throw new ConfigException("unexpected end of file, expecting \"}\"", lx.At(t.Line));
                    return;
                case TokenKind.BlockClose:
                    if (words.Count > 0 || !inBraces) throw new ConfigException("unexpected \"}\"", lx.At(t.Line));
                    return;
                case TokenKind.Semicolon:
                case TokenKind.BlockOpen:
                    if (words.Count == 0) throw new ConfigException($"unexpected \"{(t.Kind == TokenKind.Semicolon ? ';' : '{')}\"", lx.At(t.Line));
                    Dispatch(lx, scope, words, t.Kind == TokenKind.BlockOpen, lx.At(line));
                    words.Clear();
                    continue;
            }
        }
    }

    private void Dispatch(Lexer lx, ConfigScope scope, List<string> words, bool hasBlock, SourceLocation src)
    {
        string name = words[0];
        string[] args = words.Count == 1 ? [] : words.GetRange(1, words.Count - 1).ToArray();

        if (name == "include")
        {
            if (hasBlock || args.Length != 1) throw new ConfigException("invalid \"include\"", src);
            foreach (var f in ExpandInclude(args[0], src)) ParseInto(f, scope, src);
            return;
        }

        if (!directives.TryGetValue(name, out var candidates)) throw new ConfigException($"unknown directive \"{name}\"", src);
        // One name may mean different directives in different blocks (nginx's "server" in http vs upstream).
        var d = candidates.Find(c => Array.IndexOf(c.Contexts, scope.Kind) >= 0)
            ?? throw new ConfigException($"\"{name}\" directive is not allowed in \"{scope.Kind}\"", src);
        if (args.Length < d.MinArgs || (d.MaxArgs >= 0 && args.Length > d.MaxArgs))
            throw new ConfigException($"invalid number of arguments in \"{name}\" directive", src);
        if (d.Block is null && hasBlock) throw new ConfigException($"\"{name}\" directive does not take a block", src);
        if (d.Block is not null && !hasBlock) throw new ConfigException($"\"{name}\" directive requires a block", src);
        if (!d.Repeatable && !scope.Seen.Add(name)) throw new ConfigException($"\"{name}\" directive is duplicate", src);

        ConfigScope? child = null;
        RawStatement[]? raw = null;
        if (d.Block is not null)
        {
            if (d.RawBlock) raw = ParseRaw(lx);
            else
            {
                child = new ConfigScope(d.Block, scope, args, src);
                ParseBlock(lx, child, inBraces: true);
                scope.AddChild(child);
            }
        }

        _current = src;
        var inv = new DirectiveInvocation(name, args, src, scope, child, raw, this);
        try { d.Handler(inv); }
        catch (ConfigException) { throw; }
        catch (Exception e) when (e is ArgumentException or FormatException or InvalidOperationException or IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
        {
            throw new ConfigException($"\"{name}\": {e.Message}", src);
        }
    }

    private static RawStatement[] ParseRaw(Lexer lx)
    {
        var list = new List<RawStatement>();
        var words = new List<string>(8);
        int line = 0;
        while (true)
        {
            var t = lx.Next();
            switch (t.Kind)
            {
                case TokenKind.Word:
                    if (words.Count == 0) line = t.Line;
                    words.Add(t.Text!);
                    break;
                case TokenKind.Semicolon:
                    if (words.Count == 0) throw new ConfigException("unexpected \";\"", lx.At(t.Line));
                    list.Add(new RawStatement(words[0], words.GetRange(1, words.Count - 1).ToArray(), lx.At(line)));
                    words.Clear();
                    break;
                case TokenKind.BlockClose:
                    if (words.Count > 0) throw new ConfigException("unexpected \"}\"", lx.At(t.Line));
                    return list.ToArray();
                case TokenKind.BlockOpen:
                    throw new ConfigException("unexpected \"{\"", lx.At(t.Line));
                default:
                    throw new ConfigException("unexpected end of file, expecting \"}\"", lx.At(t.Line));
            }
        }
    }

    private IEnumerable<string> ExpandInclude(string pattern, SourceLocation src)
    {
        var p = Path.IsPathRooted(pattern) ? pattern : Path.Combine(_baseDir, pattern);
        var dir = Path.GetDirectoryName(p) ?? ".";
        var file = Path.GetFileName(p);
        if (dir.IndexOfAny(['*', '?', '[']) >= 0) throw new ConfigException("wildcards are only supported in the file name of \"include\"", src);
        if (file.IndexOfAny(['*', '?']) < 0) return [p];
        if (!Directory.Exists(dir)) return [];
        var files = Directory.GetFiles(dir, file);
        Array.Sort(files, StringComparer.Ordinal);
        return files;
    }
}

internal enum TokenKind : byte { Word, Semicolon, BlockOpen, BlockClose, Eof }

internal readonly record struct Token(TokenKind Kind, string? Text, int Line);

internal sealed class Lexer(string text, string file)
{
    private int _pos;
    private int _line = 1;

    public SourceLocation At(int line) => new(file, line);

    public Token Next()
    {
        while (true)
        {
            if (_pos >= text.Length) return new Token(TokenKind.Eof, null, _line);
            char c = text[_pos];
            if (c == '\n') { _line++; _pos++; continue; }
            if (c is ' ' or '\t' or '\r') { _pos++; continue; }
            if (c == '#')
            {
                while (_pos < text.Length && text[_pos] != '\n') _pos++;
                continue;
            }
            break;
        }
        char ch = text[_pos];
        int line = _line;
        switch (ch)
        {
            case ';': _pos++; return new Token(TokenKind.Semicolon, null, line);
            case '{': _pos++; return new Token(TokenKind.BlockOpen, null, line);
            case '}': _pos++; return new Token(TokenKind.BlockClose, null, line);
            case '"' or '\'': return new Token(TokenKind.Word, ReadQuoted(ch), line);
        }

        var sb = new StringBuilder();
        while (_pos < text.Length)
        {
            char c = text[_pos];
            if (c is ' ' or '\t' or '\r' or '\n' or ';' or '}') break;
            if (c == '{')
            {
                // "${var}" is part of the word; any other brace ends it.
                if (sb.Length == 0 || sb[^1] != '$') break;
                int close = text.IndexOf('}', _pos);
                if (close < 0) throw new ConfigException("unterminated \"${\"", At(_line));
                sb.Append(text, _pos, close - _pos + 1);
                _pos = close + 1;
                continue;
            }
            if (c == '\\' && _pos + 1 < text.Length)
            {
                AppendEscape(sb, text[_pos + 1]);
                _pos += 2;
                continue;
            }
            sb.Append(c);
            _pos++;
        }
        return new Token(TokenKind.Word, sb.ToString(), line);
    }

    private string ReadQuoted(char quote)
    {
        int startLine = _line;
        _pos++;
        var sb = new StringBuilder();
        while (_pos < text.Length)
        {
            char c = text[_pos];
            if (c == quote)
            {
                _pos++;
                // ')' closes an if condition: if ($a = "x")
                if (_pos < text.Length && text[_pos] is not (' ' or '\t' or '\r' or '\n' or ';' or '{' or '}' or ')'))
                    throw new ConfigException($"unexpected \"{text[_pos]}\" after quoted string", At(_line));
                return sb.ToString();
            }
            if (c == '\n') _line++;
            if (c == '\\' && _pos + 1 < text.Length)
            {
                AppendEscape(sb, text[_pos + 1]);
                _pos += 2;
                continue;
            }
            sb.Append(c);
            _pos++;
        }
        throw new ConfigException("unterminated quoted string", At(startLine));
    }

    // nginx semantics: only these escapes are unescaped; "\." etc. stay verbatim (regexes need them).
    private static void AppendEscape(StringBuilder sb, char next)
    {
        switch (next)
        {
            case '"': sb.Append('"'); break;
            case '\'': sb.Append('\''); break;
            case '\\': sb.Append('\\'); break;
            case 't': sb.Append('\t'); break;
            case 'r': sb.Append('\r'); break;
            case 'n': sb.Append('\n'); break;
            default: sb.Append('\\').Append(next); break;
        }
    }
}
