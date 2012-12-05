/**
 * Copyright (c) 2012, The Linux Foundation. All rights reserved.
 * Not a Contribution, Apache license notifications and license are retained
 * for attribution purposes only.
 *
 * Copyright (c) 2005-2008, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 *
 * Support files for dump Dalvik info during crash from debuggerd
 **/

#include <Dalvik.h>
#include <sys/ptrace.h>
#include <corkscrew/map_info.h>

#include "DalvikCrashDump.h"

/* Copied from system/core/debuggerd/utility.h */
#ifndef HAS_LIBDVM
void _LOG(log_t* log, bool in_tombstone_only, const char *fmt, ...) {
    char buf[512];

    va_list ap;
    va_start(ap, fmt);

    if (log && log->tfd >= 0) {
        int len;
        vsnprintf(buf, sizeof(buf), fmt, ap);
        len = strlen(buf);
        write(log->tfd, buf, len);
    }

    if (!in_tombstone_only && (!log || !log->quiet)) {
        __android_log_vprint(ANDROID_LOG_INFO, "DEBUG", fmt, ap);
    }
    va_end(ap);
}
#endif

/* Used from mterp/common/asm-constants.h */
#define _OFFSETS(name, type, field, offset)   int name = offset;

/* struct Method */
_OFFSETS(offsetMethod_clazz,           Method, clazz, 0)
_OFFSETS(offsetMethod_name,            Method, name, 16)
_OFFSETS(offsetMethod_shorty,          Method, shorty, 28)
_OFFSETS(offsetMethod_insns,           Method, insns, 32)

/* struct ClassObject */
_OFFSETS(offsetClassObject_descriptor, ClassObject, descriptor, 24)

/* struct Thread fields */
_OFFSETS(offsetThread_pc,                Thread, interpSave.pc, 0)
_OFFSETS(offsetThread_curFrame,          Thread, interpSave.curFrame, 4)
_OFFSETS(offsetThread_method,            Thread, interpSave.method, 8)
_OFFSETS(offsetThread_methodClassDex,    Thread, interpSave.methodClassDex, 12)
_OFFSETS(offsetThread_threadId,          Thread, threadId, 36)
_OFFSETS(offsetThread_inJitCodeCache,    Thread, inJitCodeCache, 124)

/*
 * Dalvik info for the crash
 *
 * Translation layout in the code cache.
 *
 *      +----------------------------+
 *      | Trace Profile Counter addr |  -> 4 bytes (PROF_COUNTER_ADDR_SIZE)
 *      +----------------------------+
 *   +--| Offset to chain cell counts|  -> 2 bytes (CHAIN_CELL_OFFSET_SIZE)
 *   |  +----------------------------+
 *   |  | Trace profile code         |  <- entry point when profiling
 *   |  .  -   -   -   -   -   -   - .
 *   |  | Code body                  |  <- entry point when not profiling
 *   |  .                            .
 *   |  |                            |
 *   |  +----------------------------+
 *   |  | Chaining Cells             |  -> 12/16 bytes, 4 byte aligned
 *   |  .                            .
 *   |  .                            .
 *   |  |                            |
 *   |  +----------------------------+
 *   |  | Gap for large switch stmt  |  -> # cases >= MAX_CHAINED_SWITCH_CASES
 *   |  +----------------------------+
 *   +->| Chaining cell counts       |  -> 12 bytes, chain cell counts by type
 *      +----------------------------+
 *      | Trace description          |  -> variable sized
 *      .                            .
 *      |                            |
 *      +----------------------------+
 *      | # Class pointer pool size  |  -> 4 bytes
 *      +----------------------------+
 *      | Class pointer pool         |  -> 4-byte aligned, variable size
 *      .                            .
 *      .                            .
 *      |                            |
 *      +----------------------------+
 *      | Literal pool               |  -> 4-byte aligned, variable size
 *      .                            .
 *      .                            .
 *      |                            |
 *      +----------------------------+
 *
 * Trace profile code (10 bytes)
 *       ldr   r0, [pc-8]   @ get prof count addr    [4 bytes]
 *       ldr   r1, [r0]     @ load counter           [2 bytes]
 *       add   r1, #1       @ increment              [2 bytes]
 *       str   r1, [r0]     @ store                  [2 bytes]
 */

#define PROF_COUNTER_ADDR_SIZE  4
#define CHAIN_CELL_OFFSET_SIZE  2
#define PROF_CODE_PIECE_SIZE   10
#define CHAIN_CELL_SIZE         8   /* struct ChainCellCounts */

/* read a word from child process memory */
#define READ_WORD(pid, addr) ptrace(PTRACE_PEEKTEXT, pid, (void*)(addr), NULL)

#define MAX_NAME_LEN 97

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Dumps memory region, starting from a specified address.
 */
static void dump_memory_region(log_t *log, int pid, uintptr_t addr, unsigned size,
        bool at_fault)
{
    bool only_in_tombstone = !at_fault;
    char code_buffer[100];
    uintptr_t start ,end;
    int count = 0;
    char *buf = code_buffer;

    start = addr & ~3;
    end = start + size;

    _LOG(log, only_in_tombstone, "dump memory region: %08x --> %08x\n", start, end);

    while (start < end) {
        if ((count % 4) == 0) {
            buf = code_buffer;
            sprintf(buf, "%08x  ", start);
            buf += 10;
        }

        /*
         * If we see (data == -1 && errno != 0), we know that the ptrace
         * call failed, probably because we're dumping memory in an
         * unmapped or inaccessible page.  I don't know if there's
         * value in making that explicit in the output -- it likely
         * just complicates parsing and clarifies nothing for the
         * enlightened reader.
         */
        long data = ptrace(PTRACE_PEEKTEXT, pid, (void*)start, NULL);
        sprintf(buf, "%08lx ", data);
        start += 4;
        buf += 9;

        if ((count % 4) == 3) {
            _LOG(log, only_in_tombstone, "%s\n", code_buffer);
        }
        count++;
    }

    if ((count % 4) != 0) {
        _LOG(log, only_in_tombstone, "%s\n", code_buffer);
    }
}

/* Test if the current address points to the trace start address
 * looking for the following code piece installed at the head of
 * each trace code:
 *       ldr   r0, [pc-8]   @ get prof count addr    [4 bytes]
 *       ldr   r1, [r0]     @ load counter           [2 bytes]
 *       add   r1, #1       @ increment              [2 bytes]
 *       str   r1, [r0]     @ store                  [2 bytes]
 * the encoding of the 4 thumb instructions in memory is:
 * f85f0000 68010000 60013101
 */
static bool test_trace_address(int pid, uintptr_t trace_addr)
{
    trace_addr = trace_addr & ~3;

    long data = READ_WORD(pid, (trace_addr - 4));
    if (data != 0x60013101) {
        return false;
    }

    data = READ_WORD(pid, (trace_addr - 8));
    if (data != 0x68010008) {
        return false;
    }

    data = READ_WORD(pid, (trace_addr - 12));
    if ((data & 0xffff0000) != 0xf85f0000) {
        return false;
    }

    return true;
}

#define MAX_SEARCH_LENGTH   1024
/* find the starting address of current trace in code cache from the given PC */
static uintptr_t find_trace_address(int pid, uintptr_t pc)
{
    pc = pc & ~3;
    int count = 0;
    uintptr_t trace_addr = pc;

    /* search backwards from current PC */
    while (!test_trace_address(pid, trace_addr) && count < MAX_SEARCH_LENGTH) {
        trace_addr -= 4;
        count ++;
    }

    if (count == MAX_SEARCH_LENGTH) {
        return 0;
    } else {
        return trace_addr;
    }
}

/* get the size of trace */
static unsigned get_trace_body_size(int pid, uintptr_t trace_addr)
{
    trace_addr = trace_addr & ~3;

    uintptr_t chain_cell_offset_addr = trace_addr - (PROF_CODE_PIECE_SIZE +
                                                     CHAIN_CELL_OFFSET_SIZE);

    long data = READ_WORD(pid, chain_cell_offset_addr);

    return ((data & 0x0000ffff) - (PROF_CODE_PIECE_SIZE + CHAIN_CELL_OFFSET_SIZE));
}

/* dump string beginning at "addr" into "buffer" with maximum size of "size" */
static void dump_string(int pid, uintptr_t addr, char *buffer, int size)
{
    int count = 0;
    bool name_end = false;

    while (count < (size - 1)) {
        unsigned data = (unsigned) READ_WORD(pid, addr+count);
        int i;

        for (i = 0; i < 4; i++) {
            char my_c = (data >> (i * 8)) & 0xff;
            buffer[count++] = my_c;
            if (my_c == '\0') {
                name_end = true;
                break;
            }
        }

        if (name_end) {
            break;
        }
    }

    if (count == (size - 1)) {
        buffer[count] = '\0';
    }
}

/* dump trace information from JitTraceDescription struct */
static void dump_trace_description(log_t* log, int pid, uintptr_t trace_addr, bool at_fault)
{
    uintptr_t trace_desc_addr;
    uintptr_t method_addr;
    uintptr_t method_name_addr;
    uintptr_t shorty_name_addr;
    uintptr_t class_addr;
    uintptr_t class_descriptor_addr;

    char method_name[MAX_NAME_LEN];
    char shorty_name[MAX_NAME_LEN];
    char class_descriptor[MAX_NAME_LEN];

    /* trace info */
    unsigned int trace_body_size;
    unsigned int num_trace_runs = 0;
    bool is_last_run = false;

    trace_addr = trace_addr & ~3;
    trace_body_size = get_trace_body_size(pid, trace_addr);

    if(trace_body_size <= 0) {
        _LOG(log, !at_fault, "[Dalvik] Invalid trace_size. Skip dalvik trace dump.\n");
        return;
    }

    /* trace_desc_addr = JitTraceDescription */
    trace_desc_addr = trace_addr + trace_body_size + CHAIN_CELL_SIZE;

    /* method_addr = JitTraceDescription.method */
    method_addr = (uintptr_t) READ_WORD(pid, trace_desc_addr);
    if (method_addr <= 0) {
        goto bail;
    }

    /* method_name_addr = Method.name */
    method_name_addr = (uintptr_t) READ_WORD(pid, (method_addr + offsetMethod_name));
    if (method_name_addr <= 0) {
        goto bail;
    }

    dump_string(pid, method_name_addr, method_name, MAX_NAME_LEN);

    /* shorty_name_addr = Method.shorty */
    shorty_name_addr = (uintptr_t) READ_WORD(pid, (method_addr + offsetMethod_shorty));
    if (shorty_name_addr <= 0) {
        goto bail;
    }

    dump_string(pid, shorty_name_addr, shorty_name, MAX_NAME_LEN);

    /* class_addr = Method.clazz */
    class_addr = (uintptr_t) READ_WORD(pid, (method_addr + offsetMethod_clazz));
    if(class_addr <= 0) {
        goto bail;
    }

    /* class_descriptor_addr = Class.descriptor */
    class_descriptor_addr =
        (uintptr_t) READ_WORD(pid, (class_addr + offsetClassObject_descriptor));
    if (class_descriptor_addr <= 0) {
        goto bail;
    }

    dump_string(pid, class_descriptor_addr, class_descriptor, MAX_NAME_LEN);

    _LOG(log, !at_fault, "[Dalvik] Trace description dump\n");
    _LOG(log, !at_fault, "  Class descriptor: %s\n", class_descriptor);
    _LOG(log, !at_fault, "  Method name: %s(%s)\n",method_name, shorty_name);
    _LOG(log, !at_fault, "[Dalvik] First 4 trace runs (if any):\n");

    do {
        /* cur_trace_run = JitTraceDescription.trace[num_trace_runs] */
        unsigned cur_trace_run = (unsigned) READ_WORD(pid,((trace_desc_addr + 4)
                                                           + (num_trace_runs * 8)
                                                           ));
        if (cur_trace_run <= 0) {
            _LOG (log, !at_fault, "  No more trace runs found, cur_trace_run: %u \n",
                  cur_trace_run);
            return;
        }

        unsigned start_offset = (cur_trace_run >> 16) & 0xffff;
        unsigned num_insns = cur_trace_run & 0xff;

        is_last_run = (cur_trace_run >> 8) & 0x1;

        _LOG(log, !at_fault, "  Trace %u start offset: 0x%x len: %u\n",
             num_trace_runs, start_offset, num_insns);

        num_trace_runs++;
    } while (!is_last_run && num_trace_runs < 4);

    return;

bail:
    _LOG(log,
         !at_fault,
         "[Dalvik] trace information read error! errno: %s. Skip dalvik trace dump.\n",
         strerror(errno));
}

/* dump the DEX for the crashing method */
static void dump_method_body(log_t* log, int pid, uintptr_t trace_addr, bool at_fault)
{
    unsigned int trace_body_size;
    unsigned int method_insns_size;
    uintptr_t trace_desc_addr;
    uintptr_t method_addr;
    uintptr_t method_insns_addr;

    trace_addr = trace_addr & ~3;
    trace_body_size = get_trace_body_size(pid, trace_addr);

    if(trace_body_size <= 0) {
        _LOG(log, !at_fault, "[Dalvik] Invalid trace_size. Skip dalvik trace dump.\n");
        return;
    }

    /* trace_desc_addr = JitTraceDescription */
    trace_desc_addr = trace_addr + trace_body_size + CHAIN_CELL_SIZE;

    /* method_addr = JitTraceDescription.method */
    method_addr = (uintptr_t) READ_WORD(pid, trace_desc_addr);
    if (method_addr <= 0) {
        goto bail;
    }

    method_insns_addr = (uintptr_t) READ_WORD(pid, (method_addr +
                                                              offsetMethod_insns));
    if (method_insns_addr <= 0) {
        goto bail;
    }

    /* method->insns actually points to DexCode->insns which
     * has insnsSize u4 bytes behind in the structure. Hence,
     * (method_insns_addr - 4)
     */
    method_insns_size = (unsigned) READ_WORD(pid, (method_insns_addr - 4));
    if (method_insns_size <= 0) {
        goto bail;
    }

    _LOG(log, !at_fault, "[Dalvik] Dumping method DEX\n");

    /* The DEX code is stored as half words. Hence the
     * multiplication by 2 to method_insns_size
     */
    dump_memory_region(log, pid, method_insns_addr, method_insns_size*2, at_fault);
    return;

bail:
    _LOG(log, !at_fault, "[Dalvik] Error dumping method body! errno: %s. \n",
         strerror(errno));
}

/* dump dalvik crash information */
void dump_dalvik(ptrace_context_t* context, log_t* log, pid_t tid, bool at_fault)
{
    const char codecache_name[] = "/dev/ashmem/dalvik-jit-code-cache";
    struct pt_regs r;

    if (ptrace(PTRACE_GETREGS, tid, 0, &r)) {
        _LOG(log, !at_fault, "[Dalvik] tid %d not responding!\n", tid);
        return;
    }

    map_info_t *mi = (map_info_t*) find_map_info((const map_info_t*)context->map_info_list,
                                                 r.ARM_pc);
    if (mi) {
        /* only in dalvik code cache */
        if (strncmp(mi->name, codecache_name, strlen(codecache_name)) != 0)
            return;
    }

    /*
     * Try to recover the starting address of the crashed trace
     * in case of chaining traces, the code cache address stored
     * in current thread struct may not point to the current trace,
     * so we first use current PC to find the trace address
     */
    uintptr_t thread_self = (uintptr_t)(r.ARM_r6);
    uintptr_t rPC = (uintptr_t)(r.ARM_pc);

    /* thread_id = thread_self->threadId */
    unsigned int thread_id = (unsigned) READ_WORD(tid, (thread_self
                                                        + offsetThread_threadId));
    uintptr_t jit_code_cache_addr = 0;
    uintptr_t trace_address_from_pc = find_trace_address(tid, rPC);

    if (trace_address_from_pc != 0) {
        jit_code_cache_addr = trace_address_from_pc;
    } else if (thread_id > 0) {
        _LOG(log,
             !at_fault,
             "[Dalvik] Cannot find trace address from PC, use thread ptr in r6\n");

        jit_code_cache_addr = (uintptr_t) READ_WORD(tid, (thread_self
                                                          + offsetThread_inJitCodeCache));

        jit_code_cache_addr = jit_code_cache_addr & ~0x3;

        if ((jit_code_cache_addr == 0) || !test_trace_address(tid, jit_code_cache_addr)) {

            _LOG(log,
                 !at_fault,
                 "[Dalvik] Address %08x does not look like a trace start address\n",
                 jit_code_cache_addr);
            return;
        }
    } else {
        _LOG(log, !at_fault, "[Dalvik] Both PC and r6 in stale. Skip dalvik trace dump.\n");
        return;
    }

    unsigned int trace_size = get_trace_body_size(tid, jit_code_cache_addr);

    if (trace_size <= 0) {
        _LOG(log, !at_fault, "[Dalvik] Invalid trace_size. Skip dalvik trace dump.\n");
        return;
    }

    _LOG(log, !at_fault,
         "[Dalvik] Crash in thread %d at trace address %08x trace size %u\n",
         thread_id, jit_code_cache_addr, trace_size);

    _LOG(log, !at_fault, "[Dalvik] Trace content dump:\n");

    dump_memory_region(log, tid, jit_code_cache_addr, trace_size, at_fault);
    dump_trace_description(log, tid, jit_code_cache_addr, at_fault);
    dump_method_body(log, tid, jit_code_cache_addr, at_fault);
}

#ifdef __cplusplus
}
#endif
