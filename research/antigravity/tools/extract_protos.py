#!/usr/bin/env python3
"""Extract protobuf file descriptors from a Go binary.

Go embeds compressed proto file descriptor sets. This script finds and
extracts them by looking for the proto file descriptor registration pattern.
"""
import sys
import zlib
import struct
from google.protobuf import descriptor_pb2

def extract_proto_descriptors(binary_path):
    with open(binary_path, 'rb') as f:
        data = f.read()

    # Go proto file descriptors are gzip/zlib compressed and registered
    # Look for proto file descriptor signatures
    # The compressed data starts after a varint length prefix

    descriptors = []

    # Strategy: scan for valid zlib-compressed protobuf FileDescriptorProto
    # Zlib magic bytes: 0x78 (0x01, 0x5e, 0x9c, 0xda)
    zlib_headers = [b'\x78\x01', b'\x78\x5e', b'\x78\x9c', b'\x78\xda']

    for i in range(len(data) - 10):
        if data[i:i+2] not in zlib_headers:
            continue

        # Try decompressing
        for end_offset in [4096, 8192, 16384, 32768, 65536]:
            try:
                chunk = data[i:i+end_offset]
                decompressed = zlib.decompress(chunk)

                # Try to parse as FileDescriptorProto
                fd = descriptor_pb2.FileDescriptorProto()
                fd.ParseFromString(decompressed)

                # Must have a name and look like a real proto file
                if fd.name and ('exa.' in fd.name or 'exa/' in fd.name or
                               'google/' in fd.name or '.proto' in fd.name):
                    if fd.name not in [d.name for d in descriptors]:
                        descriptors.append(fd)
                        print(f"[+] Found: {fd.name} ({len(fd.service)} services, {len(fd.message_type)} messages)")
                break
            except (zlib.error, Exception):
                continue

    return descriptors


def main():
    binary_path = sys.argv[1] if len(sys.argv) > 1 else \
        "/Applications/Antigravity.app/Contents/Resources/app/extensions/antigravity/bin/language_server_macos_arm"

    print(f"[*] Scanning {binary_path}...")
    print(f"[*] This may take a few minutes for a 143MB binary...")

    descriptors = extract_proto_descriptors(binary_path)

    print(f"\n[*] Found {len(descriptors)} proto descriptors")

    # Save interesting ones
    for fd in descriptors:
        if 'exa' in fd.name.lower() or 'cloudcode' in fd.name.lower():
            safe_name = fd.name.replace('/', '_').replace('.proto', '')
            outpath = f"/Users/lazerwild/Desktop/bb-beast/research/antigravity/protos/{safe_name}.descriptor"

            # Print service methods
            for svc in fd.service:
                print(f"\n  Service: {fd.package}.{svc.name}")
                for method in svc.method:
                    print(f"    {method.name}({method.input_type}) -> {method.output_type}")

if __name__ == '__main__':
    main()
