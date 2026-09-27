#!/usr/bin/env python3
"""简化版补丁脚本：只处理当前目录下的 bedrock_server.exe。

通过特征码定位强制 NetherNet 的传输检查，把它改成无条件跳转，使 8 行
"TRANSPORT TYPE ERROR" 日志块变成死代码。该日志块没有任何副作用，两条分支
原本就汇合到同一地址，所以除日志外行为完全不变。

特征码（1.26.50.5 与 1.26.60.28 完全一致，因此不再依赖固定版本地址）：

    83 B8 04 01 00 00 02   cmp dword ptr [rax+0x104], 2   ; 0 = raknet, 2 = nethernet
    0F 84 <rel32>          je  <日志块>
                  ->  E9 <rel32+1> 90   (jmp <日志块> ; nop)

首次运行会把原文件备份为 bedrock_server.exe.orig，需要还原时直接用它覆盖回去：

    copy /y bedrock_server.exe.orig bedrock_server.exe
"""
from pathlib import Path
import mmap
import shutil
import struct
import sys

TARGET = Path("bedrock_server.exe")
BACKUP = Path("bedrock_server.exe.orig")

# cmp dword ptr [rax+0x104], 2
SIGNATURE = bytes.fromhex("83b80401000002")
JE_LEN = 6  # 0F 84 <rel32>


def build_patch(displacement: int) -> bytes:
    """je(6 字节) -> jmp(5 字节) + nop：目标地址不变，位移需加 1。"""
    return b"\xe9" + struct.pack("<i", displacement + 1) + b"\x90"


def find_sites(mm: mmap.mmap) -> list[int]:
    hits = []
    start = 0
    while True:
        i = mm.find(SIGNATURE, start)
        if i < 0:
            return hits
        hits.append(i)
        start = i + 1


def main() -> int:
    if not TARGET.is_file():
        print(f"error  : {TARGET.resolve()} not found")
        print("         run this script from the directory containing bedrock_server.exe")
        return 1

    with TARGET.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        hits = find_sites(mm)

        if not hits:
            print("error  : transport check signature not found (unsupported build?)")
            return 1

        if len(hits) > 1:
            print(f"error  : transport check signature is ambiguous ({len(hits)} matches)")
            return 1

        patch_offset = hits[0] + len(SIGNATURE)
        current = mm[patch_offset:patch_offset + JE_LEN]

    if len(current) == JE_LEN and current[:2] == b"\x0f\x84":
        patched = build_patch(struct.unpack_from("<i", current, 2)[0])
    elif len(current) == JE_LEN and current[:1] == b"\xe9" and current[5:6] == b"\x90":
        print("state  : already patched - nothing to do")
        return 0
    else:
        print(f"error  : unexpected bytes at file offset 0x{patch_offset:X}")
        print(f"         found    {current.hex(' ')}")
        print("         this build differs from the one this script was written for")
        return 1

    if not BACKUP.exists():
        shutil.copyfile(TARGET, BACKUP)
        print(f"backup : {BACKUP.resolve()}")

    with TARGET.open("r+b") as f:
        f.seek(patch_offset)
        f.write(patched)

    with TARGET.open("rb") as f:
        f.seek(patch_offset)
        if f.read(len(patched)) != patched:
            print("error  : verification failed - the file was not modified as expected")
            return 1

    print(f"offset : 0x{patch_offset:X}")
    print(f"bytes  : {current.hex(' ')} -> {patched.hex(' ')}   (je -> jmp)")
    print("state  : PATCHED")
    print("done   : 'TRANSPORT TYPE ERROR' will no longer be printed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except OSError as exc:
        print(f"error: {exc}")
        print("       stop the server (and any debugger) before patching")
        sys.exit(1)
