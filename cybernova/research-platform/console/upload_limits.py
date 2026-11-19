"""Shared Cybernova artifact upload ceilings (bytes).

JSON-encoded classic PCAP is base64 (~4/3 file bytes), so the gateway body
limit is larger than the actual attached-file cap. These bounds apply only to
single-user, offline artifact imports, not to ChatGPT/Qwen chat messages.
"""
MAX_UPLOAD_FILE_BYTES = 50 * 1024 * 1024
MAX_UPLOAD_FILE_MIB = MAX_UPLOAD_FILE_BYTES // (1024 * 1024)
MAX_PCAP_BASE64_CHARS = 4 * ((MAX_UPLOAD_FILE_BYTES + 2) // 3)
# JSON envelope, escaping and metadata headroom for a 50 MiB base64 PCAP.
MAX_IMPORT_HTTP_BODY_BYTES = 80 * 1024 * 1024
# Do not increase the maximum response size alongside uploads.
MAX_PROXY_RESPONSE_BYTES = 7_000_000
