"""Offline generated QPACK allocation probe; run in a fresh process on Linux.

mallinfo2 includes native malloc allocations; tracemalloc alone does not.
The measured deltas are evidence, not a universal RSS upper bound.
"""
import ctypes
import gc
import importlib.metadata
import json
from pathlib import Path
import resource
import sys
import tracemalloc

import pylsqpack
from hpack.huffman import HuffmanEncoder
from hpack.huffman_constants import REQUEST_CODES, REQUEST_CODES_LENGTH
from prism_tls_bridge.qpack_guard import Guard


class Mallinfo(ctypes.Structure):
    _fields_=[(n,ctypes.c_size_t) for n in ('arena','ordblks','smblks','hblks','hblkhd',
               'usmblks','fsmblks','uordblks','fordblks','keepcost')]


def prefix(value,bits,mask=0):
    maximum=(1<<bits)-1
    if value<maximum:return bytes([mask|value])
    out=bytearray([mask|maximum]);value-=maximum
    while value>=128:out.append((value&127)|128);value>>=7
    out.append(value);return bytes(out)


def run(count):
    libc=ctypes.CDLL(None);libc.mallinfo2.restype=Mallinfo
    def malloc_used():
        m=libc.mallinfo2();return m.uordblks+m.hblkhd
    def rss():
        return int(Path('/proc/self/statm').read_text().split()[1])*resource.getpagesize()
    gc.collect();tracemalloc.start();before_malloc=malloc_used();before_rss=rss()
    pairs=[(Guard(capacity=65536),pylsqpack.Decoder(65536,0)) for _ in range(count)]
    max_malloc=malloc_used();max_rss=rss()
    huffman=HuffmanEncoder(REQUEST_CODES,REQUEST_CODES_LENGTH)
    value=huffman.encode(b'x'*10000)
    large=b'\xc0'+prefix(len(value),7,128)+value
    wide=huffman.encode(b'\xff'*3000)
    wide=b'\xc0'+prefix(len(wide),7,128)+wide
    for guard,native in pairs:
        native.feed_encoder(guard.feed_encoder(prefix(65536,5,32)))
        for _ in range(4):
            native.feed_encoder(guard.feed_encoder(b'\x40\x00'*2048))
        # Many small entries and large Huffman entries exercise different
        # native allocation layouts and transient insertion-before-eviction.
        for _ in range(8):
            native.feed_encoder(guard.feed_encoder(large))
        for _ in range(32):
            native.feed_encoder(guard.feed_encoder(wide))
        max_malloc=max(max_malloc,malloc_used());max_rss=max(max_rss,rss())
    # Refill simultaneously resident tables with maximum entry counts.
    for guard,native in pairs:
        native.feed_encoder(guard.feed_encoder(b'\x40\x00'*2048))
    max_malloc=max(max_malloc,malloc_used());max_rss=max(max_rss,rss())
    # Exercise decoding at the unchanged field-section byte limit while all
    # tables remain resident. Bridge processes one header block at a time.
    block=b'\x00\x00\x50'+prefix(16340,7)+b'x'*16340
    for guard,native in pairs:
        assert guard.check(block)
        _,headers=native.feed_header(0,block)
        assert len(headers[0][1])==16340
        max_malloc=max(max_malloc,malloc_used());max_rss=max(max_rss,rss())
        del headers
    current,peak=tracemalloc.get_traced_memory()
    result={'connections':count,'pylsqpack':importlib.metadata.version('pylsqpack'),
            'python':sys.version.split()[0],'pointer_bytes':ctypes.sizeof(ctypes.c_void_p),
            'metadata_bytes_per_flow':sys.getsizeof(pairs[0][0].entries.data),
            'malloc_sampled_peak_delta':max_malloc-before_malloc,
            'rss_sampled_peak_delta':max_rss-before_rss,
            'tracemalloc_current':current,'tracemalloc_peak':peak,
            'rss_process_high_water':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024}
    print(json.dumps(result))


if __name__=='__main__':
    run(int(sys.argv[1]) if len(sys.argv)>1 else 16)
