"""Keep roothide's plist rewriting while removing the unavailable userswitch API."""

import struct


API = b"_launch_active_user_switch"
COMMAND = b"_userswitch_cmd"
MOV_W0_ENOTSUP = 0x528005A0


def patch_launchctl(data: bytes) -> bytes:
    def read(fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(data):
            raise ValueError("Truncated launchctl Mach-O")
        return struct.unpack_from(fmt, data, offset)

    def string(offset, end):
        if offset < 0 or end > len(data) or offset >= end:
            raise ValueError("Invalid launchctl string table")
        stop = data.find(b"\0", offset, end)
        if stop < 0:
            raise ValueError("Unterminated launchctl symbol")
        return data[offset:stop]

    magic, cpu, _, filetype, count, command_bytes, _, _ = read("<8I", 0)
    if magic != 0xFEEDFACF or cpu != 0x100000C or filetype != 2:
        raise ValueError("Expected the bundled thin ARM64 launchctl executable")
    command_end = 32 + command_bytes
    if command_end > len(data) or count > command_bytes // 8:
        raise ValueError("Invalid launchctl load commands")

    commands, sections, segments = {}, [], []
    offset = 32
    for _ in range(count):
        command, size = read("<II", offset)
        if size < 8 or offset + size > command_end:
            raise ValueError("Invalid launchctl load command size")
        commands[command] = offset
        if command == 0x19:
            _, _, _, vmaddr, _, fileoff, filesize, _, _, nsects, _ = read("<II16sQQQQiiII", offset)
            if fileoff + filesize > len(data) or 72 + nsects * 80 > size:
                raise ValueError("Invalid launchctl segment")
            segments.append((vmaddr, fileoff, filesize))
            for index in range(nsects):
                sections.append(read("<16s16sQQIIIIIIII", offset + 72 + index * 80))
        offset += size
    if offset != command_end or not {2, 0xB, 0x80000034}.issubset(commands):
        raise ValueError("Unexpected launchctl symbol/binding layout")

    def file_offset(address):
        for vmaddr, fileoff, filesize in segments:
            if vmaddr <= address < vmaddr + filesize:
                return fileoff + address - vmaddr
        raise ValueError("Launchctl code is outside its file-backed segments")

    symoff, nsyms, stroff, strsize = read("<4I", commands[2] + 8)
    if symoff + nsyms * 16 > len(data) or stroff + strsize > len(data):
        raise ValueError("Invalid launchctl symbol table")
    symbols = []
    for index in range(nsyms):
        name, kind, section, desc, address = read("<IBBHQ", symoff + index * 16)
        symbols.append((string(stroff + name, stroff + strsize), kind, section, desc, address))
    api_indices = [i for i, symbol in enumerate(symbols) if symbol[0] == API]
    functions = [symbol for symbol in symbols if symbol[0] == COMMAND and symbol[1] & 0xE == 0xE]
    if len(api_indices) != 1 or len(functions) != 1:
        raise ValueError("Missing or ambiguous launchctl compatibility symbols")
    api_index = api_indices[0]
    if symbols[api_index][3] & 0x40:
        raise ValueError("Launchctl import is already weak; refusing an unknown/already-patched build")

    indirect, indirect_count = read("<II", commands[0xB] + 56)
    if indirect + indirect_count * 4 > len(data):
        raise ValueError("Invalid launchctl indirect-symbol table")
    stubs = []
    for section in sections:
        if section[8] & 0xFF != 8:
            continue
        address, size, first, stride = section[2], section[3], section[9], section[10]
        if not stride or size % stride or first + size // stride > indirect_count:
            raise ValueError("Invalid launchctl import stubs")
        for index in range(size // stride):
            if read("<I", indirect + (first + index) * 4)[0] == api_index:
                stubs.append(address + index * stride)
    if len(stubs) != 1:
        raise ValueError("The removed launch API must have exactly one import stub")

    function = functions[0]
    start = function[4]
    ends = [symbol[4] for symbol in symbols if symbol[2] == function[2] and symbol[4] > start]
    if not ends:
        raise ValueError("Cannot bound launchctl userswitch command")
    calls = []
    for address in range(start, min(ends), 4):
        position = file_offset(address)
        instruction = read("<I", position)[0]
        if instruction & 0xFC000000 == 0x94000000:
            immediate = instruction & 0x3FFFFFF
            if immediate & 0x2000000:
                immediate -= 0x4000000
            if address + immediate * 4 == stubs[0]:
                calls.append(position)
    if len(calls) != 1:
        raise ValueError("Expected one userswitch call to the unavailable launch API")

    base, size = read("<II", commands[0x80000034] + 8)
    version, _, imports, strings, nimports, form, compression = read("<7I", base)
    if base + size > len(data) or version or form != 1 or compression:
        raise ValueError("Unsupported launchctl chained-import format")
    if imports + nimports * 4 > size or strings >= size:
        raise ValueError("Invalid launchctl chained-import bounds")
    matches = []
    for index in range(nimports):
        position = base + imports + index * 4
        value = read("<I", position)[0]
        if string(base + strings + (value >> 9), base + size) == API:
            matches.append((position, value))
    if len(matches) != 1 or matches[0][1] & 0x100:
        raise ValueError("Expected one mandatory runtime import for the removed launch API")

    patched = bytearray(data)
    struct.pack_into("<H", patched, symoff + api_index * 16 + 6, symbols[api_index][3] | 0x40)
    struct.pack_into("<I", patched, matches[0][0], matches[0][1] | 0x100)
    # This package is selected only on iOS 26+, where upstream also returns ENOTSUP.
    struct.pack_into("<I", patched, calls[0], MOV_W0_ENOTSUP)
    return bytes(patched)
