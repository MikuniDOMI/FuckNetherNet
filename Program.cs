namespace FuckNetherNet;

internal static class Program
{
    private const string DefaultFileName = "bedrock_server.exe";

    private static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return 1;
        }

        if (IsHelp(args[0]))
        {
            PrintUsage();
            return 0;
        }

        string command = args[0].ToLowerInvariant();
        if (command is not ("check" or "patch" or "restore"))
        {
            Console.Error.WriteLine($"error: unknown command '{args[0]}'");
            Console.Error.WriteLine();
            PrintUsage();
            return 1;
        }

        string? path = null;
        for (int i = 1; i < args.Length; i++)
        {
            string arg = args[i];

            if (arg is "-f" or "--file")
            {
                if (i + 1 >= args.Length)
                {
                    Console.Error.WriteLine("error: --file requires a path");
                    return 1;
                }

                path = args[++i];
            }
            else if (path is null && !arg.StartsWith('-'))
            {
                path = arg;
            }
            else
            {
                Console.Error.WriteLine($"error: unexpected argument '{arg}'");
                return 1;
            }
        }

        string target;
        try
        {
            target = ResolveTarget(path);
        }
        catch (FileNotFoundException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }

        try
        {
            return command switch
            {
                "check" => Patcher.Check(target),
                "patch" => Patcher.Patch(target),
                "restore" => Patcher.Restore(target),
                _ => 1,
            };
        }
        catch (PatchException ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
        catch (IOException ex)
        {
            Console.Error.WriteLine($"error: cannot access '{target}': {ex.Message}");
            Console.Error.WriteLine("       stop the server (and any debugger) before patching.");
            return 1;
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.Error.WriteLine($"error: access denied for '{target}': {ex.Message}");
            return 1;
        }
    }

    private static bool IsHelp(string arg) => arg is "-h" or "--help" or "-?" or "/?" or "help";

    private static string ResolveTarget(string? path)
    {
        if (!string.IsNullOrWhiteSpace(path))
        {
            string full = Path.GetFullPath(path);
            if (!File.Exists(full))
            {
                throw new FileNotFoundException($"file not found: {full}");
            }

            return full;
        }

        string[] candidates =
        [
            Path.Combine(AppContext.BaseDirectory, DefaultFileName),
            Path.Combine(Environment.CurrentDirectory, DefaultFileName),
        ];

        foreach (string candidate in candidates)
        {
            if (File.Exists(candidate))
            {
                return Path.GetFullPath(candidate);
            }
        }

        throw new FileNotFoundException(
            $"'{DefaultFileName}' was not found next to this tool or in the current directory; pass a path with --file");
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            FuckNetherNet - disables the forced NetherNet transport check in bedrock_server.exe

            Usage:
              FuckNetherNet <command> [path] [--file <path>]

            Commands:
              check      show the current state of the binary (never writes)
              patch      rewrite the transport check so the error block is unreachable
              restore    revert the binary from the '<file>.orig' backup

            Arguments:
              path, --file <path>   path to bedrock_server.exe
                                    (default: next to this tool, then the current directory)

            Exit codes:
              0   success (for check: the binary is ORIGINAL or PATCHED)
              1   failure (for check: unrecognised bytes)

            Patch applied (bedrock_server.exe 1.26.50.5, ImageBase 0x140000000):
              VA 0x140091346    je 0x1400914FC   ->   jmp 0x1400914FC + nop
            """);
    }
}
