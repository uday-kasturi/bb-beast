#!/usr/bin/env python3
"""Extract raw (uncompressed) protobuf file descriptors from a Go binary.

Google's internal Go binaries embed proto descriptors as raw bytes in
the data section. This script finds them by searching for the name field
pattern and then incrementally parsing to find the correct boundary.
"""
import os
import sys
from google.protobuf import descriptor_pb2, text_format

binary_path = sys.argv[1] if len(sys.argv) > 1 else \
    "/Applications/Antigravity.app/Contents/Resources/app/extensions/antigravity/bin/language_server_macos_arm"

output_dir = "/Users/lazerwild/Desktop/bb-beast/research/antigravity/protos/extracted"
os.makedirs(output_dir, exist_ok=True)

print(f"[*] Reading {binary_path}...")
with open(binary_path, 'rb') as f:
    data = f.read()
print(f"[*] {len(data)} bytes loaded")

# Find all occurrences of proto file name field:
# 0x0a (tag: field 1, wire type 2) + varint length + name ending in ".proto"
# followed by 0x12 (tag: field 2 = package, wire type 2)

descriptors = {}
search_start = 0

while True:
    # Find .proto followed eventually by package field
    idx = data.find(b'.proto', search_start)
    if idx < 0:
        break
    search_start = idx + 1

    # Walk backwards to find the 0x0a length prefix
    # The name field starts with 0x0a + varint_len + name_string
    # name_string ends with ".proto"
    proto_end = idx + 6  # end of ".proto"

    # Try different name lengths (10 to 200 chars)
    found = False
    for name_len in range(10, 201):
        name_start = proto_end - name_len
        tag_pos = name_start - 1  # position of length varint

        if tag_pos < 1:
            continue

        # Check for single-byte varint length
        if name_len < 128 and tag_pos >= 1:
            if data[tag_pos] == name_len and data[tag_pos - 1] == 0x0a:
                candidate_start = tag_pos - 1
                name = data[tag_pos + 1:proto_end].decode('ascii', errors='replace')
                if '/' not in name or '\x00' in name or not name.endswith('.proto'):
                    continue
                found = True
                break

        # Check for two-byte varint length
        if name_len >= 128 and tag_pos >= 2:
            low = name_len & 0x7f | 0x80
            high = name_len >> 7
            if data[tag_pos - 1] == low and data[tag_pos] == high and data[tag_pos - 2] == 0x0a:
                candidate_start = tag_pos - 2
                name = data[tag_pos + 1:proto_end].decode('ascii', errors='replace')
                if '/' not in name or '\x00' in name or not name.endswith('.proto'):
                    continue
                found = True
                break

    if not found:
        continue

    # Now try to parse incrementally from candidate_start
    # FileDescriptorProto can be quite large. Try increasingly large chunks.
    best_fd = None
    best_size = 0

    for size in [256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
                 131072, 262144, 524288, 1048576]:
        chunk = data[candidate_start:candidate_start + size]
        try:
            fd = descriptor_pb2.FileDescriptorProto()
            consumed = fd._InternalParse(chunk, 0, len(chunk))
            if fd.name and fd.name.endswith('.proto'):
                # Verify it consumed a reasonable amount
                if consumed > best_size:
                    best_fd = fd
                    best_size = consumed
        except Exception:
            # If parsing fails, the previous successful parse was likely the right one
            if best_fd:
                break
            continue

    if best_fd and best_fd.name not in descriptors:
        descriptors[best_fd.name] = best_fd
        n_msg = len(best_fd.message_type)
        n_svc = len(best_fd.service)
        n_enum = len(best_fd.enum_type)
        print(f"[+] {best_fd.name} — {n_svc} services, {n_msg} messages, {n_enum} enums ({best_size} bytes)")

print(f"\n[*] Total: {len(descriptors)} proto files extracted")

# Filter and save interesting ones
interesting_prefixes = [
    'third_party/jetski/', 'third_party/gemini_coder/',
    'google/internal/cloud/code/', 'devtools/jetski/',
    'exa/'
]

for name in sorted(descriptors.keys()):
    fd = descriptors[name]
    is_interesting = any(name.startswith(p) for p in interesting_prefixes)

    if not is_interesting and len(fd.service) == 0:
        continue

    safe_name = name.replace('/', '_').replace('.proto', '')

    # Save readable proto reconstruction
    out_path = os.path.join(output_dir, safe_name + '.proto')
    with open(out_path, 'w') as f:
        f.write(f'// Extracted from: {name}\n')
        f.write(f'syntax = "{fd.syntax or "proto3"}";\n')
        f.write(f'package {fd.package};\n\n')

        for dep in fd.dependency:
            f.write(f'import "{dep}";\n')
        if fd.dependency:
            f.write('\n')

        for enum in fd.enum_type:
            write_enum(f, enum, 0)

        for msg in fd.message_type:
            write_message(f, msg, 0)

        for svc in fd.service:
            f.write(f'service {svc.name} {{\n')
            for method in svc.method:
                in_stream = "stream " if method.client_streaming else ""
                out_stream = "stream " if method.server_streaming else ""
                f.write(f'  rpc {method.name}({in_stream}{method.input_type}) returns ({out_stream}{method.output_type});\n')
            f.write('}\n\n')

    # Also save binary descriptor for use with grpcurl
    binpb_path = os.path.join(output_dir, safe_name + '.binpb')
    with open(binpb_path, 'wb') as f:
        f.write(fd.SerializeToString())

    if is_interesting:
        print(f"  Saved: {out_path}")


FIELD_TYPES = {
    1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32",
    6: "fixed64", 7: "fixed32", 8: "bool", 9: "string", 10: "group",
    11: "message", 12: "bytes", 13: "uint32", 14: "enum", 15: "sfixed32",
    16: "sfixed64", 17: "sint32", 18: "sint64"
}

LABELS = {1: "optional", 2: "required", 3: "repeated"}

def write_enum(f, enum, indent):
    prefix = "  " * indent
    f.write(f'{prefix}enum {enum.name} {{\n')
    for val in enum.value:
        f.write(f'{prefix}  {val.name} = {val.number};\n')
    f.write(f'{prefix}}}\n\n')

def write_message(f, msg, indent):
    prefix = "  " * indent
    f.write(f'{prefix}message {msg.name} {{\n')

    for enum in msg.enum_type:
        write_enum(f, enum, indent + 1)

    for nested in msg.nested_type:
        if not nested.options or not nested.options.map_entry:
            write_message(f, nested, indent + 1)

    # Group fields by oneof
    oneof_fields = {}
    for field in msg.field:
        if field.HasField('oneof_index'):
            oneof_fields.setdefault(field.oneof_index, []).append(field)

    written_oneofs = set()
    for field in msg.field:
        if field.HasField('oneof_index'):
            oi = field.oneof_index
            if oi not in written_oneofs:
                written_oneofs.add(oi)
                oneof_name = msg.oneof_decl[oi].name if oi < len(msg.oneof_decl) else f"_oneof_{oi}"
                f.write(f'{prefix}  oneof {oneof_name} {{\n')
                for of in oneof_fields[oi]:
                    type_str = get_type_str(of)
                    f.write(f'{prefix}    {type_str} {of.name} = {of.number};\n')
                f.write(f'{prefix}  }}\n')
        else:
            label = "repeated " if field.label == 3 else ""
            type_str = get_type_str(field)
            f.write(f'{prefix}  {label}{type_str} {field.name} = {field.number};\n')

    f.write(f'{prefix}}}\n\n')


def get_type_str(field):
    if field.type in (11, 14):  # message or enum
        return field.type_name.lstrip('.')
    return FIELD_TYPES.get(field.type, f"unknown_{field.type}")
