#!/usr/bin/env python3
"""简化版补丁脚本：只处理当前目录下的 bedrock_server.exe。

把 bedrock_server.exe 1.26.50.5 中强制 NetherNet 的检查改成无条件跳转，
使 8 行 "TRANSPORT TYPE ERROR" 日志块变成死代码。该日志块没有任何副作用，
两条分支原本就汇合到同一地址，所以除日志外行为完全不变。

    VA 0x140091346   0F 84 B0 01 00 00   (je  0x1400914FC)
                  -> E9 B1 01 00 00 90   (jmp 0x1400914FC ; nop)

首次运行会把原文件备份为 bedrock_server.exe.orig，需要还原时直接用它覆盖回去：

    copy /y bedrock_server.exe.orig bedrock_server.exe
"""
from pathlib import Path
import shutil
import sys

TARGET = Path("bedrock_server.exe")
BACKUP = Path("bedrock_server.exe.orig")

# .text 段 RVA 0x1000 对应文件偏移 0x400，补丁 VA 0x140091346（ImageBase 0x140000000）
PATCH_OFFSET = 0x90746
ORIGINAL = bytes.fromhex("0f84b0010000")
PATCHED = bytes.fromhex("e9b101000090")


def main() -> int:
    if not TARGET.is_file():
        print(f"error: {TARGET.resolve()} not found")
        print("       run this script from the directory containing bedrock_server.exe")
        return 1

    with TARGET.open("rb") as f:
        f.seek(PATCH_OFFSET)
        current = f.read(len(ORIGINAL))

    if current == PATCHED:
        print("state  : already patched - nothing to do")
        return 0

    if current != ORIGINAL:
        print(f"error  : unexpected bytes at file offset 0x{PATCH_OFFSET:X}")
        print(f"         expected {ORIGINAL.hex(' ')}")
        print(f"         found    {current.hex(' ')}")
        print("         this is a different build or the file has already been modified")
        return 1

    if not BACKUP.exists():
        shutil.copyfile(TARGET, BACKUP)
        print(f"backup : {BACKUP.resolve()}")

    with TARGET.open("r+b") as f:
        f.seek(PATCH_OFFSET)
        f.write(PATCHED)

    with TARGET.open("rb") as f:
        f.seek(PATCH_OFFSET)
        if f.read(len(PATCHED)) != PATCHED:
            print("error: verification failed - the file was not modified as expected")
            return 1

    print(f"bytes  : {ORIGINAL.hex(' ')} -> {PATCHED.hex(' ')}   (je -> jmp 0x1400914FC)")
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
