using System.Buffers.Binary;

namespace FuckNetherNet;

internal sealed class PatchException(string message) : Exception(message);

internal static class Patcher
{
    // bedrock_server.exe 1.26.50.5 (ImageBase 0x140000000)
    //
    //   0x14009133F   cmp dword ptr [rax + 0x104], 2     ; transport enum: 0 = raknet, 2 = nethernet
    //   0x140091346   je  0x1400914FC                    ; taken only when the transport is NetherNet
    //   0x14009134C   ... 8 log calls ("TRANSPORT TYPE ERROR"), no side effects ...
    //   0x1400914FC   <----------------------------------- both paths converge here
    //
    // The block is pure logging, so turning the conditional jump into an unconditional one drops the
    // forced NetherNet requirement and changes nothing else.
    private const ulong ExpectedImageBase = 0x140000000UL;
    private const uint PatchRva = 0x00091346;
    private const ulong PatchVa = ExpectedImageBase + PatchRva;
    private const ulong JumpTargetVa = 0x1400914FCUL;

    private static readonly byte[] OriginalBytes = [0x0F, 0x84, 0xB0, 0x01, 0x00, 0x00]; // je  0x1400914FC
    private static readonly byte[] PatchedBytes = [0xE9, 0xB1, 0x01, 0x00, 0x00, 0x90];  // jmp 0x1400914FC ; nop

    private enum State
    {
        Original,
        Patched,
        Unknown,
    }

    private static string BackupPath(string file) => file + ".orig";

    public static int Check(string file)
    {
        Console.WriteLine($"target   : {file}");

        var (offset, imageBase, bytes) = ReadPatchSite(file);
        State state = Classify(bytes);

        Console.WriteLine($"version  : {GetVersionString(file)}");
        Console.WriteLine($"imagebase: 0x{imageBase:X}");
        Console.WriteLine($"patch VA : 0x{PatchVa:X}   (file offset 0x{offset:X})");

        switch (state)
        {
            case State.Original:
                Console.WriteLine("state    : ORIGINAL - the transport check is still enforced");
                return 0;

            case State.Patched:
                Console.WriteLine("state    : PATCHED - the transport error block is unreachable");
                return 0;

            default:
                Console.WriteLine("state    : UNKNOWN - bytes match neither state");
                Console.WriteLine($"           expected {Hex(OriginalBytes)} (original)");
                Console.WriteLine($"                    {Hex(PatchedBytes)} (patched)");
                Console.WriteLine($"           found    {Hex(bytes)}");
                Console.WriteLine("           this is a different build or the file has already been modified.");
                return 1;
        }
    }

    public static int Patch(string file)
    {
        Console.WriteLine($"target   : {file}");
        Console.WriteLine($"version  : {GetVersionString(file)}");

        var (offset, _, bytes) = ReadPatchSite(file);
        State state = Classify(bytes);

        if (state == State.Patched)
        {
            Console.WriteLine($"state    : already patched (file offset 0x{offset:X}) - nothing to do");
            return 0;
        }

        if (state != State.Original)
        {
            Console.Error.WriteLine($"error: unexpected bytes at VA 0x{PatchVa:X} (file offset 0x{offset:X})");
            Console.Error.WriteLine($"       expected {Hex(OriginalBytes)} (original)");
            Console.Error.WriteLine($"       found    {Hex(bytes)}");
            Console.Error.WriteLine("       this is a different build or the file has already been modified; aborting.");
            return 1;
        }

        string backup = BackupPath(file);
        if (File.Exists(backup) && IsPristine(backup, offset))
        {
            Console.WriteLine($"backup   : reusing {backup}");
        }
        else
        {
            File.Copy(file, backup, overwrite: true);
            Console.WriteLine($"backup   : {backup}");
        }

        using (var fs = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.None))
        {
            fs.Position = offset;
            fs.Write(PatchedBytes);
            fs.Flush(flushToDisk: true);
        }

        if (Classify(ReadPatchSite(file).Bytes) != State.Patched)
        {
            Console.Error.WriteLine("error: verification failed - the file was not modified as expected");
            return 1;
        }

        Console.WriteLine($"bytes    : {Hex(OriginalBytes)} -> {Hex(PatchedBytes)}   (je -> jmp 0x{JumpTargetVa:X})");
        Console.WriteLine("state    : PATCHED");
        Console.WriteLine("done     : 'TRANSPORT TYPE ERROR' will no longer be printed.");
        return 0;
    }

    public static int Restore(string file)
    {
        string backup = BackupPath(file);
        Console.WriteLine($"target   : {file}");
        Console.WriteLine($"backup   : {backup}");

        if (!File.Exists(backup))
        {
            Console.Error.WriteLine($"error: backup '{backup}' does not exist");
            return 1;
        }

        var (offset, _, bytes) = ReadPatchSite(backup);
        if (Classify(bytes) != State.Original)
        {
            Console.Error.WriteLine($"error: '{backup}' is not a pristine copy (bytes at 0x{offset:X}: {Hex(bytes)})");
            return 1;
        }

        File.Copy(backup, file, overwrite: true);

        if (Classify(ReadPatchSite(file).Bytes) != State.Original)
        {
            Console.Error.WriteLine("error: verification failed after restore");
            return 1;
        }

        Console.WriteLine("state    : ORIGINAL - the transport check is enforced again");
        Console.WriteLine("done     : restored from backup.");
        return 0;
    }

    private static (long Offset, ulong ImageBase, byte[] Bytes) ReadPatchSite(string file)
    {
        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

        if (!TryResolveRvaOffset(fs, PatchRva, out long offset, out ulong imageBase, out string error))
        {
            throw new PatchException($"{file}: {error}");
        }

        byte[] bytes = new byte[OriginalBytes.Length];
        fs.Position = offset;
        fs.ReadExactly(bytes);
        return (offset, imageBase, bytes);
    }

    private static bool IsPristine(string file, long offset)
    {
        try
        {
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] bytes = new byte[OriginalBytes.Length];
            fs.Position = offset;
            fs.ReadExactly(bytes);
            return Classify(bytes) == State.Original;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static State Classify(byte[] bytes) =>
        bytes.AsSpan().SequenceEqual(OriginalBytes) ? State.Original
        : bytes.AsSpan().SequenceEqual(PatchedBytes) ? State.Patched
        : State.Unknown;

    private static string Hex(byte[] bytes) => string.Join(' ', bytes.Select(b => b.ToString("X2")));

    private static string GetVersionString(string file)
    {
        try
        {
            var info = System.Diagnostics.FileVersionInfo.GetVersionInfo(file);
            return (info.FileVersion ?? info.ProductVersion ?? "unknown").Trim();
        }
        catch (IOException)
        {
            return "unknown";
        }
    }

    /// <summary>Maps an RVA to a file offset using the PE section table.</summary>
    private static bool TryResolveRvaOffset(
        FileStream fs,
        uint rva,
        out long fileOffset,
        out ulong imageBase,
        out string error)
    {
        fileOffset = 0;
        imageBase = 0;
        error = string.Empty;

        if (fs.Length < 0x40)
        {
            error = "file is too small to be a PE image";
            return false;
        }

        Span<byte> dos = stackalloc byte[0x40];
        fs.Position = 0;
        fs.ReadExactly(dos);

        if (dos[0] != (byte)'M' || dos[1] != (byte)'Z')
        {
            error = "missing MZ signature";
            return false;
        }

        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(dos[0x3C..]);
        if (peOffset <= 0 || peOffset > fs.Length - 0x18)
        {
            error = $"invalid e_lfanew (0x{peOffset:X})";
            return false;
        }

        Span<byte> coff = stackalloc byte[0x18];
        fs.Position = peOffset;
        fs.ReadExactly(coff);

        if (coff[0] != (byte)'P' || coff[1] != (byte)'E' || coff[2] != 0 || coff[3] != 0)
        {
            error = "missing PE signature";
            return false;
        }

        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(coff[4..]);
        ushort sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(coff[6..]);
        ushort optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(coff[0x14..]);

        long optionalStart = peOffset + 0x18;
        if (optionalSize < 0x70 || optionalStart + optionalSize > fs.Length)
        {
            error = $"invalid optional header (size 0x{optionalSize:X})";
            return false;
        }

        Span<byte> optional = stackalloc byte[0x70];
        fs.Position = optionalStart;
        fs.ReadExactly(optional);

        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(optional);
        if (magic != 0x20B)
        {
            error = $"not a PE32+ image (magic 0x{magic:X4}, machine 0x{machine:X4})";
            return false;
        }

        imageBase = BinaryPrimitives.ReadUInt64LittleEndian(optional[0x18..]);
        if (imageBase != ExpectedImageBase)
        {
            error = $"unexpected ImageBase 0x{imageBase:X} (expected 0x{ExpectedImageBase:X})";
            return false;
        }

        long sectionTable = optionalStart + optionalSize;
        if (sectionTable + (long)sectionCount * 40 > fs.Length)
        {
            error = "section table is truncated";
            return false;
        }

        Span<byte> section = stackalloc byte[40];
        for (int i = 0; i < sectionCount; i++)
        {
            fs.Position = sectionTable + (long)i * 40;
            fs.ReadExactly(section);

            uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(section[0x08..]);
            uint virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(section[0x0C..]);
            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(section[0x10..]);
            uint rawPointer = BinaryPrimitives.ReadUInt32LittleEndian(section[0x14..]);

            uint span = Math.Max(virtualSize, rawSize);
            if (rva < virtualAddress || rva >= virtualAddress + span)
            {
                continue;
            }

            long offset = rawPointer + (rva - virtualAddress);
            if (offset < 0 || offset + OriginalBytes.Length > fs.Length)
            {
                error = $"resolved file offset 0x{offset:X} is out of range";
                return false;
            }

            fileOffset = offset;
            return true;
        }

        error = $"RVA 0x{rva:X} is not inside any section";
        return false;
    }
}
