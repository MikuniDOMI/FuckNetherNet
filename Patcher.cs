using System.Buffers.Binary;

namespace FuckNetherNet;

internal sealed class PatchException(string message) : Exception(message);

internal static class Patcher
{
    // bedrock_server.exe - the forced "NetherNet" transport check.
    //
    //   83 B8 04 01 00 00 02   cmp dword ptr [rax + 0x104], 2   ; 0 = raknet, 2 = nethernet
    //   0F 84 <rel32>          je  <error block>                 ; taken only when the transport is NetherNet
    //   <error block>          ... 8 log calls ("TRANSPORT TYPE ERROR"), no side effects ...
    //   <error block end>      <--- both paths converge here
    //
    // The error block is pure logging, so turning the conditional jump into an unconditional one drops
    // the forced NetherNet requirement and changes nothing else.
    //
    // The site is located by scanning for the byte signature above instead of a hardcoded address, so a
    // single build of this tool keeps working when Mojang ships a new server version (verified on both
    // 1.26.50.5 and 1.26.60.28, which share the exact same signature).
    private const ulong ExpectedImageBase = 0x140000000UL;

    // cmp dword ptr [rax + 0x104], 2
    private static readonly byte[] Signature = [0x83, 0xB8, 0x04, 0x01, 0x00, 0x00, 0x02];
    private const int JeLength = 6;   // 0F 84 <rel32>

    private enum State
    {
        Original,
        Patched,
        Unknown,
    }

    private sealed record Site(long JumpOffset, ulong JumpVa, State State, byte[] OriginalBytes, byte[] PatchedBytes);

    private readonly record struct Section(string Name, uint VirtualAddress, uint RawPointer, uint RawSize);

    private static string BackupPath(string file) => file + ".orig";

    public static int Check(string file)
    {
        Console.WriteLine($"target   : {file}");

        Site site = LocateSite(file);

        Console.WriteLine($"version  : {GetVersionString(file)}");
        Console.WriteLine($"patch VA : 0x{site.JumpVa:X}   (file offset 0x{site.JumpOffset:X})");

        switch (site.State)
        {
            case State.Original:
                Console.WriteLine("state    : ORIGINAL - the transport check is still enforced");
                return 0;

            case State.Patched:
                Console.WriteLine("state    : PATCHED - the transport error block is unreachable");
                return 0;

            default:
                Console.WriteLine("state    : UNKNOWN - the jump after the signature is neither 'je' nor 'jmp'");
                Console.WriteLine($"           found    {Hex(site.OriginalBytes)}");
                Console.WriteLine("           this build differs from the one this tool was written for.");
                return 1;
        }
    }

    public static int Patch(string file)
    {
        Console.WriteLine($"target   : {file}");
        Console.WriteLine($"version  : {GetVersionString(file)}");

        Site site = LocateSite(file);

        if (site.State == State.Patched)
        {
            Console.WriteLine($"state    : already patched (file offset 0x{site.JumpOffset:X}) - nothing to do");
            return 0;
        }

        if (site.State != State.Original)
        {
            Console.Error.WriteLine($"error: unexpected bytes at VA 0x{site.JumpVa:X} (file offset 0x{site.JumpOffset:X})");
            Console.Error.WriteLine($"       found    {Hex(site.OriginalBytes)}");
            Console.Error.WriteLine("       this build differs from the one this tool was written for; aborting.");
            return 1;
        }

        string backup = BackupPath(file);
        if (File.Exists(backup) && IsOriginal(backup))
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
            fs.Position = site.JumpOffset;
            fs.Write(site.PatchedBytes);
            fs.Flush(flushToDisk: true);
        }

        if (LocateSite(file).State != State.Patched)
        {
            Console.Error.WriteLine("error: verification failed - the file was not modified as expected");
            return 1;
        }

        Console.WriteLine($"bytes    : {Hex(site.OriginalBytes)} -> {Hex(site.PatchedBytes)}   (je -> jmp)");
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

        if (LocateSite(backup).State != State.Original)
        {
            Console.Error.WriteLine($"error: '{backup}' is not a pristine copy");
            return 1;
        }

        File.Copy(backup, file, overwrite: true);

        if (LocateSite(file).State != State.Original)
        {
            Console.Error.WriteLine("error: verification failed after restore");
            return 1;
        }

        Console.WriteLine("state    : ORIGINAL - the transport check is enforced again");
        Console.WriteLine("done     : restored from backup.");
        return 0;
    }

    /// <summary>Finds the transport check by signature and classifies the jump that follows it.</summary>
    private static Site LocateSite(string file)
    {
        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

        var (imageBase, sections) = ReadPe(fs);

        int index = sections.FindIndex(s => s.Name == ".text");
        if (index < 0)
        {
            throw new PatchException($"{file}: no .text section");
        }

        Section text = sections[index];
        List<long> hits = FindSignature(fs, text);

        if (hits.Count == 0)
        {
            throw new PatchException($"{file}: transport check signature not found (unsupported build?)");
        }

        if (hits.Count > 1)
        {
            throw new PatchException($"{file}: transport check signature is ambiguous ({hits.Count} matches)");
        }

        long jumpOffset = hits[0] + Signature.Length;
        ulong jumpVa = imageBase + text.VirtualAddress + (ulong)(jumpOffset - text.RawPointer);

        byte[] op = new byte[JeLength];
        fs.Position = jumpOffset;
        try
        {
            fs.ReadExactly(op);
        }
        catch (EndOfStreamException)
        {
            throw new PatchException($"{file}: truncated jump instruction");
        }

        if (op[0] == 0x0F && op[1] == 0x84)
        {
            int displacement = BinaryPrimitives.ReadInt32LittleEndian(op.AsSpan(2));
            return new Site(jumpOffset, jumpVa, State.Original, op, BuildJump(displacement));
        }

        if (op[0] == 0xE9 && op[5] == 0x90)
        {
            int displacement = BinaryPrimitives.ReadInt32LittleEndian(op.AsSpan(1));
            return new Site(jumpOffset, jumpVa, State.Patched, BuildConditionalJump(displacement - 1), op);
        }

        return new Site(jumpOffset, jumpVa, State.Unknown, op, []);
    }

    /// <summary>je &lt;rel32&gt; (6 bytes) -> jmp &lt;rel32 + 1&gt; ; nop (5 + 1 bytes), same target.</summary>
    private static byte[] BuildJump(int displacement)
    {
        byte[] bytes = new byte[JeLength];
        bytes[0] = 0xE9;
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(1), displacement + 1);
        bytes[5] = 0x90;
        return bytes;
    }

    private static byte[] BuildConditionalJump(int displacement)
    {
        byte[] bytes = new byte[JeLength];
        bytes[0] = 0x0F;
        bytes[1] = 0x84;
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(2), displacement);
        return bytes;
    }

    private static bool IsOriginal(string file)
    {
        try
        {
            return LocateSite(file).State == State.Original;
        }
        catch (PatchException)
        {
            return false;
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

    /// <summary>Scans the raw bytes of a section for the signature, returning every match.</summary>
    private static List<long> FindSignature(FileStream fs, Section section)
    {
        const int ChunkSize = 4 * 1024 * 1024;

        byte[] buffer = new byte[ChunkSize + Signature.Length - 1];
        var hits = new List<long>();

        long start = section.RawPointer;
        long end = start + section.RawSize;
        long position = start;
        int carry = 0;

        while (position < end)
        {
            int want = (int)Math.Min(ChunkSize, end - position);
            fs.Position = position;

            int read = 0;
            while (read < want)
            {
                int n = fs.Read(buffer, carry + read, want - read);
                if (n <= 0)
                {
                    break;
                }

                read += n;
            }

            int total = carry + read;
            for (int i = 0; i <= total - Signature.Length; i++)
            {
                if (Matches(buffer, i))
                {
                    hits.Add(position - carry + i);
                }
            }

            carry = Math.Min(Signature.Length - 1, total);
            Array.Copy(buffer, total - carry, buffer, 0, carry);
            position += read;

            if (read == 0)
            {
                break;
            }
        }

        return hits;
    }

    private static bool Matches(byte[] buffer, int offset)
    {
        for (int i = 0; i < Signature.Length; i++)
        {
            if (buffer[offset + i] != Signature[i])
            {
                return false;
            }
        }

        return true;
    }

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

    /// <summary>Reads the PE32+ headers: ImageBase plus the section table.</summary>
    private static (ulong ImageBase, List<Section> Sections) ReadPe(FileStream fs)
    {
        if (fs.Length < 0x40)
        {
            throw new PatchException("file is too small to be a PE image");
        }

        Span<byte> dos = stackalloc byte[0x40];
        fs.Position = 0;
        fs.ReadExactly(dos);

        if (dos[0] != (byte)'M' || dos[1] != (byte)'Z')
        {
            throw new PatchException("missing MZ signature");
        }

        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(dos[0x3C..]);
        if (peOffset <= 0 || peOffset > fs.Length - 0x18)
        {
            throw new PatchException($"invalid e_lfanew (0x{peOffset:X})");
        }

        Span<byte> coff = stackalloc byte[0x18];
        fs.Position = peOffset;
        fs.ReadExactly(coff);

        if (coff[0] != (byte)'P' || coff[1] != (byte)'E' || coff[2] != 0 || coff[3] != 0)
        {
            throw new PatchException("missing PE signature");
        }

        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(coff[4..]);
        ushort sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(coff[6..]);
        ushort optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(coff[0x14..]);

        long optionalStart = peOffset + 0x18;
        if (optionalSize < 0x70 || optionalStart + optionalSize > fs.Length)
        {
            throw new PatchException($"invalid optional header (size 0x{optionalSize:X})");
        }

        Span<byte> optional = stackalloc byte[0x70];
        fs.Position = optionalStart;
        fs.ReadExactly(optional);

        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(optional);
        if (magic != 0x20B)
        {
            throw new PatchException($"not a PE32+ image (magic 0x{magic:X4}, machine 0x{machine:X4})");
        }

        ulong imageBase = BinaryPrimitives.ReadUInt64LittleEndian(optional[0x18..]);
        if (imageBase != ExpectedImageBase)
        {
            throw new PatchException($"unexpected ImageBase 0x{imageBase:X} (expected 0x{ExpectedImageBase:X})");
        }

        long sectionTable = optionalStart + optionalSize;
        if (sectionTable + (long)sectionCount * 40 > fs.Length)
        {
            throw new PatchException("section table is truncated");
        }

        var sections = new List<Section>(sectionCount);
        Span<byte> entry = stackalloc byte[40];

        for (int i = 0; i < sectionCount; i++)
        {
            fs.Position = sectionTable + (long)i * 40;
            fs.ReadExactly(entry);

            string name = System.Text.Encoding.ASCII.GetString(entry[..8]).TrimEnd('\0');
            uint virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(entry[0x0C..]);
            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(entry[0x10..]);
            uint rawPointer = BinaryPrimitives.ReadUInt32LittleEndian(entry[0x14..]);

            sections.Add(new Section(name, virtualAddress, rawPointer, rawSize));
        }

        return (imageBase, sections);
    }
}
