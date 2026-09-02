#!/usr/bin/env python3
"""Extract protobuf file descriptors from a Go binary (v2).

Go embeds compressed proto file descriptors. In modern Go (proto v2 API),
they're stored as gzip-compressed bytes registered via init().

Strategy: scan for gzip streams (1f 8b) that decompress to valid
FileDescriptorProto messages (first field is name, tag 0x0a).
"""
import gzip
import io
import json
import os
import struct
import sys
import zlib

# Must have protobuf installed
from google.protobuf import descriptor_pb2, descriptor_pool, text_format


def find_gzip_streams(data, min_size=50, max_size=500000):
    """Find all gzip-compressed regions in binary data."""
    results = []
    i = 0
    while i < len(data) - 10:
        # gzip magic: 1f 8b 08
        if data[i] == 0x1f and data[i+1] == 0x8b and data[i+2] == 0x08:
            # Try decompressing from here
            for chunk_size in [1024, 4096, 16384, 65536, 262144, max_size]:
                end = min(i + chunk_size, len(data))
                try:
                    decompressed = gzip.decompress(data[i:end])
                    if len(decompressed) >= min_size:
                        results.append((i, decompressed))
                    break
                except Exception:
                    continue
            i += 1
        else:
            i += 1
    return results


def find_zlib_streams(data, min_size=50, max_size=500000):
    """Find all zlib-compressed regions."""
    results = []
    zlib_headers = [b'\x78\x01', b'\x78\x5e', b'\x78\x9c', b'\x78\xda']
    i = 0
    while i < len(data) - 10:
        if data[i:i+2] in zlib_headers:
            for chunk_size in [1024, 4096, 16384, 65536, 262144, max_size]:
                end = min(i + chunk_size, len(data))
                try:
                    decompressed = zlib.decompress(data[i:end])
                    if len(decompressed) >= min_size:
                        results.append((i, decompressed))
                    break
                except Exception:
                    continue
            i += 1
        else:
            i += 1
    return results


def try_parse_file_descriptor(raw_bytes):
    """Try to parse bytes as a FileDescriptorProto."""
    try:
        fd = descriptor_pb2.FileDescriptorProto()
        fd.ParseFromString(raw_bytes)
        # Validate: must have a name that looks like a proto file
        if fd.name and (fd.name.endswith('.proto') or '/' in fd.name):
            return fd
    except Exception:
        pass
    return None


def main():
    binary_path = sys.argv[1] if len(sys.argv) > 1 else \
        "/Applications/Antigravity.app/Contents/Resources/app/extensions/antigravity/bin/language_server_macos_arm"

    output_dir = "/Users/lazerwild/Desktop/bb-beast/research/antigravity/protos/extracted"
    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] Reading {binary_path} ({os.path.getsize(binary_path) / 1024 / 1024:.1f} MB)...")
    with open(binary_path, 'rb') as f:
        data = f.read()

    print(f"[*] Scanning for gzip streams...")
    gzip_streams = find_gzip_streams(data)
    print(f"[*] Found {len(gzip_streams)} gzip streams")

    print(f"[*] Scanning for zlib streams...")
    zlib_streams = find_zlib_streams(data)
    print(f"[*] Found {len(zlib_streams)} zlib streams")

    all_streams = gzip_streams + zlib_streams

    descriptors = {}  # name -> FileDescriptorProto

    print(f"[*] Parsing {len(all_streams)} compressed streams as protobuf...")
    for offset, decompressed in all_streams:
        fd = try_parse_file_descriptor(decompressed)
        if fd and fd.name not in descriptors:
            descriptors[fd.name] = fd

    print(f"\n[*] Found {len(descriptors)} proto file descriptors")

    # Filter to interesting ones
    interesting_prefixes = [
        'exa/', 'third_party/jetski/', 'third_party/gemini_coder/',
        'google/internal/cloud/code/', 'devtools/jetski/',
        'google/cloud/aiplatform/'
    ]

    for name in sorted(descriptors.keys()):
        fd = descriptors[name]
        is_interesting = any(name.startswith(p) for p in interesting_prefixes)

        marker = "***" if is_interesting else "   "
        svc_count = len(fd.service)
        msg_count = len(fd.message_type)

        if is_interesting or svc_count > 0:
            print(f"  {marker} {name} ({svc_count} services, {msg_count} messages)")

            for svc in fd.service:
                print(f"       Service: {fd.package}.{svc.name}")
                for method in svc.method:
                    streaming = ""
                    if method.server_streaming:
                        streaming += " [server-streaming]"
                    if method.client_streaming:
                        streaming += " [client-streaming]"
                    print(f"         {method.name}({method.input_type}) -> {method.output_type}{streaming}")

            # Save interesting descriptors
            if is_interesting:
                safe_name = name.replace('/', '_')

                # Save as text proto
                txt_path = os.path.join(output_dir, safe_name + '.txt')
                with open(txt_path, 'w') as f:
                    f.write(text_format.MessageToString(fd))

                # Save as binary descriptor
                bin_path = os.path.join(output_dir, safe_name + '.binpb')
                with open(bin_path, 'wb') as f:
                    f.write(fd.SerializeToString())

                # Generate human-readable proto-like output
                proto_path = os.path.join(output_dir, safe_name + '.readable')
                with open(proto_path, 'w') as f:
                    f.write(f"// Extracted from: {name}\n")
                    f.write(f"// Package: {fd.package}\n\n")

                    for msg in fd.message_type:
                        write_message(f, msg, 0)

                    for svc in fd.service:
                        f.write(f"\nservice {svc.name} {{\n")
                        for method in svc.method:
                            stream_in = "stream " if method.client_streaming else ""
                            stream_out = "stream " if method.server_streaming else ""
                            f.write(f"  rpc {method.name}({stream_in}{method.input_type}) returns ({stream_out}{method.output_type});\n")
                        f.write("}\n")

    print(f"\n[*] Saved {sum(1 for n in descriptors if any(n.startswith(p) for p in interesting_prefixes))} interesting descriptors to {output_dir}")


FIELD_TYPES = {
    1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32",
    6: "fixed64", 7: "fixed32", 8: "bool", 9: "string", 10: "group",
    11: "message", 12: "bytes", 13: "uint32", 14: "enum", 15: "sfixed32",
    16: "sfixed64", 17: "sint32", 18: "sint64"
}

LABELS = {1: "optional", 2: "required", 3: "repeated"}


def write_message(f, msg, indent):
    prefix = "  " * indent
    f.write(f"{prefix}message {msg.name} {{\n")

    for field in msg.field:
        label = LABELS.get(field.label, "")
        type_name = FIELD_TYPES.get(field.type, "unknown")
        if field.type in (11, 14):  # message or enum
            type_name = field.type_name
        repeated = "repeated " if field.label == 3 else ""
        f.write(f"{prefix}  {repeated}{type_name} {field.name} = {field.number};")
        if field.json_name and field.json_name != field.name:
            f.write(f"  // json: {field.json_name}")
        f.write("\n")

    for nested in msg.nested_type:
        write_message(f, nested, indent + 1)

    for enum in msg.enum_type:
        f.write(f"{prefix}  enum {enum.name} {{\n")
        for val in enum.value:
            f.write(f"{prefix}    {val.name} = {val.number};\n")
        f.write(f"{prefix}  }}\n")

    # Oneofs
    for oneof in msg.oneof_decl:
        f.write(f"{prefix}  oneof {oneof.name} {{ ... }}\n")

    f.write(f"{prefix}}}\n\n")


if __name__ == '__main__':
    main()
