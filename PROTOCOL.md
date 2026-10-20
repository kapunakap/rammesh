# RAMMesh protocol version 1

Transport is TCP with TLS 1.3, mandatory CA-validated client certificates, CA-validated server certificates, server-name validation, and ALPN `rammesh/1`. No plaintext mode, unauthenticated health endpoint, TLS session resumption or 0-RTT is supported.

Each request and response is `u32be body_length` followed by a body. Length must be 1 through 1,048,640 bytes inclusive, checked before reading or allocating the body. The first body byte is the request opcode or response status. Integers are unsigned big-endian. RPCs are sequential and have one response each, with no request multiplexing.

| Opcode | Operation | Request bytes after opcode | Successful response after status |
|---:|---|---|---|
| 1 | ALLOC | requested bytes: u64 | handle: u64, charged bytes: u64 |
| 2 | READ | handle: u64, offset: u64, length: u32 | Exactly `length` bytes |
| 3 | WRITE | handle: u64, offset: u64, data: remaining bytes | Empty |
| 4 | FREE | handle: u64 | Empty |
| 5 | VERIFY | handle: u64, offset: u64, length: u32, expected SHA-256: 32 raw bytes | Actual SHA-256: 32 bytes, only if equal |
| 6 | STATS | Empty | UTF-8 JSON |
| 7 | PING | Empty | Empty |

READ, WRITE and VERIFY ranges are limited to 1,048,576 bytes each. READ and VERIFY length zero and empty WRITE are allowed for a valid in-bounds position. ALLOC length zero is rejected. Offset and length must fit inside the originally requested allocation, excluding page-rounded padding. Exact request sizes are required except for WRITE's data.

| Status | Meaning |
|---:|---|
| 0 | Success |
| 1 | Invalid operation/length or transfer size |
| 2 | Unknown handle, wrong session, freed handle or out-of-bounds range |
| 3 | Allocation size, quota, capacity, fragmentation or handle-count limit |
| 4 | Memory-pressure/reserve guard or native statistics failure |
| 5 | SHA-256 mismatch |

Nonzero replies contain a short UTF-8 explanation instead of the successful payload. Wrong ownership intentionally returns the same unknown-handle class. Invalid outer lengths close the connection without reading a body. TLS errors, I/O deadline, lease expiry and rate violations also close the connection.

Every handle belongs to one authenticated TCP/TLS session, including when multiple sessions use the same client certificate. Handles are monotonically allocated on the donor and are not process addresses or transferable capabilities. Free invalidates the handle and wipes its pages before reuse. Connection teardown wipes and frees every handle owned by that session. There is no durable namespace or resume token.

STATS reports the global pool, global counters, active connections, process ID, system memory snapshot and RAM evidence. All clients trusted by the configured CA can read these operational statistics. It includes the mapping's virtual address for independent local VM inspection; it never exposes payload bytes from another session.

A request's deadline starts before its first frame byte is read and also covers the response. Sending bytes slowly does not renew it. The absolute session lease begins after successful authentication and is not renewable by PING. A borrower must account for these lifetime rules and treat failed RPCs as possible loss of every handle in that connection. WRITE acknowledgment means data was copied to the donor's RAM pool; it does not mean durable persistence.
