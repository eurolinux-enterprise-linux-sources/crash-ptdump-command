/*
 * Extension module to dump log buffer of Intel(R) Processor Trace
 *
 * Copyright (C) 2016 FUJITSU LIMITED
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define _GNU_SOURCE
#include <sys/file.h>

#include "defs.h"

#ifdef DEBUG
#define dbgprintf(...) fprintf(__VA_ARGS__)
#else
#define dbgprintf(...) {}
#endif

#define TOPA_SHIFT 12

extern int fastdecode(char *, char *);

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct topa_entry {
	u64	end	: 1;
	u64	rsvd0	: 1;
	u64	intr	: 1;
	u64	rsvd1	: 1;
	u64	stop	: 1;
	u64	rsvd2	: 1;
	u64	size	: 4;
	u64	rsvd3	: 2;
	u64	base	: 36;
	u64	rsvd4	: 16;
};

struct pt_info {
	ulong aux_pages;
	int aux_nr_pages;
	ulong pt_buffer;

	ulong topa_base;
	uint topa_idx;
	ulong output_off;

	ulong *buffer_ptr;
	int curr_buf_idx;

	ulong *pt_caps;
	u32 *cap_regs;
} *pt_info_list;

static inline int
get_member(ulong addr, char *name, char *member, void* buf)
{
	ulong offset, size;

	offset = MEMBER_OFFSET(name, member);
	size = MEMBER_SIZE(name, member);


	if (!readmem(addr + offset, KVADDR, buf, size, name, FAULT_ON_ERROR))
		return FALSE;

	return TRUE;
}

int init_pt_info(int cpu)
{

	ulong struct_pt, struct_handle, struct_ring_buffer;
	ulong aux_pages, aux_priv;
	int aux_nr_pages, buf_len;
	int i, current_buf_idx;
	struct topa_entry topa;
	ulong topa_base, output_off, output_base;
	uint topa_idx;
	struct pt_info *pt_info_ptr = pt_info_list + cpu;

	/* Get pointer to struct pt */
	if (!symbol_exists("pt_ctx")) {
		fprintf(fp, "[%d] symbol not found: pt_ctx\n", cpu);
		return FALSE;
	}
	struct_pt = symbol_value("pt_ctx") + kt->__per_cpu_offset[cpu];

	/* Get pointer to struct perf_output_handle, struct ring_buffer */
	struct_handle = struct_pt + MEMBER_OFFSET("pt", "handle");
	if(!get_member(struct_handle, "perf_output_handle", "rb",
		       &struct_ring_buffer))
		return FALSE;
	if (!struct_ring_buffer) {
		fprintf(fp, "[%d] ring buffer is zero\n", cpu);
		return FALSE;
	}

	dbgprintf(fp, "[%d] struct pt=0x%016lx\n", cpu, struct_pt);
	dbgprintf(fp, "[%d] struct perf_output_handle=0x%016lx\n", cpu,
		struct_handle);
	dbgprintf(fp, "[%d] struct ring_buffer=0x%016lx\n", cpu,
		struct_ring_buffer);

	/* symbol access check */
	if (STRUCT_EXISTS("ring_buffer") &&
	    !MEMBER_EXISTS("ring_buffer", "aux_pages")) {
		fprintf(fp, "[%d] invalid ring_buffer\n", cpu);
		return FALSE;
	}

	/* array of struct pages for pt buffer */
	if(!get_member(struct_ring_buffer, "ring_buffer", "aux_pages",
		       &aux_pages))
		return FALSE;

	/* number of pages */
	if(!get_member(struct_ring_buffer, "ring_buffer", "aux_nr_pages",
		       &aux_nr_pages))
		return FALSE;

	/* private data (struct pt_buffer) */
	if(!get_member(struct_ring_buffer, "ring_buffer", "aux_priv",
		       &aux_priv))
		return FALSE;

	if (!aux_nr_pages) {
		fprintf(fp, "No aux pages\n");
		return FALSE;
	}

	pt_info_ptr->aux_pages = aux_pages;
	pt_info_ptr->aux_nr_pages = aux_nr_pages;
	pt_info_ptr->pt_buffer = aux_priv;

	dbgprintf(fp, "[%d] rb.aux_pages=0x%016lx\n", cpu, aux_pages);
	dbgprintf(fp, "[%d] rb.aux_nr_pages=0x%d\n", cpu, aux_nr_pages);
	dbgprintf(fp, "[%d] rb.aux_priv=0x%016lx\n", cpu, aux_priv);

	/* Get address of pt buffer */
	buf_len = sizeof(void*)*aux_nr_pages;
	pt_info_ptr->buffer_ptr = (ulong *)malloc(buf_len);
	if (pt_info_ptr->buffer_ptr == NULL) {
		fprintf(fp, "malloc failed\n");
		return FALSE;
	}
	memset(pt_info_ptr->buffer_ptr, 0, buf_len);

	for (i=0; i<aux_nr_pages; i++) {
		ulong pgaddr = aux_pages + i*sizeof(void*);
		ulong page;

		if (!readmem(pgaddr, KVADDR, &page, sizeof(ulong),
			     "struct page", FAULT_ON_ERROR))
			continue;

		pt_info_ptr->buffer_ptr[i] = page;

		if (!i)
			dbgprintf(fp, "[%d] Dump aux pages\n", cpu);
		dbgprintf(fp, "  %d: 0x%016lx\n", i, page);
	}

	/* Get pt registes saved on panic */
	if(!get_member(pt_info_ptr->pt_buffer, "pt_buffer", "cur",
		       &topa_base))
		goto out_error;
	if(!get_member(pt_info_ptr->pt_buffer, "pt_buffer", "cur_idx",
		       &topa_idx))
		goto out_error;
	if(!get_member(pt_info_ptr->pt_buffer, "pt_buffer", "output_off",
		       &output_off))
		goto out_error;

	dbgprintf(fp, "[%d] buf.cur=0x%016lx\n", cpu, topa_base);
	dbgprintf(fp, "[%d] buf.cur_idx=0x%08x\n", cpu, topa_idx);
	dbgprintf(fp, "[%d] buf.output_off=0x%016lx\n", cpu, output_off);

	pt_info_ptr->topa_base = topa_base;
	pt_info_ptr->topa_idx = topa_idx;
	pt_info_ptr->output_off = output_off;

	/* Read topa entry */
	if (!readmem((topa_base) + topa_idx*(sizeof(struct topa_entry)),
		     KVADDR, &topa, sizeof(topa),
		     "struct topa_entry", FAULT_ON_ERROR)) {
		fprintf(fp, "Cannot read topa table\n");
		goto out_error;
	}

	dbgprintf(fp, "[%d] topa.end=%d\n", cpu, topa.end);
	dbgprintf(fp, "[%d] topa.intr=%d\n", cpu, topa.intr);
	dbgprintf(fp, "[%d] topa.stop=%d\n", cpu, topa.stop);
	dbgprintf(fp, "[%d] topa.size=%d\n", cpu, topa.size);
	dbgprintf(fp, "[%d] topa.base=0x%016lx\n", cpu, (ulong)topa.base);

	/*
	 * Find buffer page which is currently used.
	 */
	output_base = (u64)(topa.base)<<TOPA_SHIFT;
	current_buf_idx = -1;
	for (i=0; i<aux_nr_pages; i++) {
		if (VTOP(pt_info_ptr->buffer_ptr[i]) == output_base) {
			current_buf_idx = i;
			break;
		}
	}

	if (current_buf_idx == -1) {
		fprintf(fp, "current buffer not found\n");
		goto out_error;
	}

	pt_info_ptr->curr_buf_idx = current_buf_idx;
	dbgprintf(fp, "[%d] current bufidx=%d\n", cpu, current_buf_idx);

	return TRUE;

out_error:
	if (pt_info_ptr->buffer_ptr != NULL)
		free(pt_info_ptr->buffer_ptr);
		return FALSE;
}

static inline int is_zero_page(ulong page, int offset)
{
	ulong read_addr = page + offset;
	ulong read_size = PAGESIZE() - offset;
	char *buf = malloc(PAGESIZE());
	int i;

	if (buf == NULL) {
		fprintf(fp, "malloc failed\n");
		return FALSE;
	}

	memset(buf, 0, PAGESIZE());
	dbgprintf(fp, "zero page chk: 0x%016lx, %lu\n", read_addr, read_size);
	readmem(read_addr, KVADDR, buf, read_size, "zero page check",
	        FAULT_ON_ERROR);

	for (i = 0; i < PAGESIZE() - offset; i++) {
		if (buf[i]) {
			free(buf);
			return FALSE;
		}
	}

	free(buf);
	return TRUE;
}

int check_wrap_around(int cpu)
{
	struct pt_info *pt_info_ptr = pt_info_list + cpu;
	int wrapped = 0, i, page_idx;
	ulong offset, mask, page;

	mask = (((ulong)1)<<PAGESHIFT()) - 1;
	offset = pt_info_ptr->output_off & mask;
	page_idx = pt_info_ptr->curr_buf_idx +
		   (pt_info_ptr->output_off >> PAGESHIFT());

	dbgprintf(fp, "[%d] buf: mask=0x%lx\n", cpu, mask);
	dbgprintf(fp, "[%d] buf: offset=0x%lx\n", cpu, offset);
	dbgprintf(fp, "[%d] buf: page_idx=%d\n", cpu, page_idx);

	for (i=page_idx; i<pt_info_ptr->aux_nr_pages; i++) {
		page = pt_info_ptr->buffer_ptr[i];

		if (!is_zero_page(page, offset)) {
			wrapped = 1;
			break;
		}

		offset = 0;
	}

	return wrapped;
}

int write_buffer_wrapped(int cpu, FILE *out_fp)
{
	struct pt_info *pt_info_ptr = pt_info_list + cpu;
	int start_idx, idx, len, ret;
	ulong mask, offset, page;
	char *buf = malloc(PAGESIZE());

	if (buf == NULL) {
		fprintf(fp, "malloc failed\n");
		return FALSE;
	}

	mask = (((ulong)1)<<PAGESHIFT()) - 1;
	offset = pt_info_ptr->output_off & mask;

	start_idx = pt_info_ptr->curr_buf_idx +
	   (pt_info_ptr->output_off >> PAGESHIFT());

	for (idx = start_idx; idx<pt_info_ptr->aux_nr_pages; idx++) {
		page = pt_info_ptr->buffer_ptr[idx];
		len = PAGESIZE() - offset;

		readmem(page + offset, KVADDR, buf, len, "read page for write",
			FAULT_ON_ERROR);

		dbgprintf(fp, "[%d] R/W1 buff: p=0x%lx, i=%d, o=%lu, l=%d\n",
			cpu, page + offset, idx, offset, len);

		ret = fwrite(buf, len, 1, out_fp);
		if (!ret) {
			fprintf(fp, "[%d] Cannot write file\n", cpu);
			free(buf);
			return FALSE;
		}

		offset = 0;
	}

	for (idx = 0; idx < start_idx; idx++) {
		page = pt_info_ptr->buffer_ptr[idx];
		len = PAGESIZE() - offset;

		readmem(page + offset, KVADDR, buf, len, "read page for write",
			FAULT_ON_ERROR);

		dbgprintf(fp, "[%d] R/W2 buff: p=0x%lx, i=%d, o=%lu, l=%d\n",
			cpu, page + offset, idx, offset, len);

		ret = fwrite(buf, len, 1, out_fp);
		if (!ret) {
			fprintf(fp, "[%d] Cannot write file\n", cpu);
			free(buf);
			return FALSE;
		}
	}

	idx = start_idx;
	page = pt_info_ptr->buffer_ptr[idx];
	offset = pt_info_ptr->output_off & mask;
	len = offset;

	readmem(page, KVADDR, buf, len, "read page for write",
		FAULT_ON_ERROR);

	dbgprintf(fp, "[%d] R/W3 buff: p=0x%lx, i=%d, o=%lu, l=%d\n", cpu,
		page, idx, offset, len);

	ret = fwrite(buf, len, 1, out_fp);
	if (!ret) {
		fprintf(fp, "[%d] Cannot write file\n", cpu);
		free(buf);
		return FALSE;
	}

	free(buf);
	return TRUE;
}

int write_buffer_nowrapped(int cpu, FILE *out_fp)
{
	struct pt_info *pt_info_ptr = pt_info_list + cpu;
	int last_idx, idx, len, ret;
	ulong mask, page;
	char *buf = malloc(PAGESIZE());

	if (buf == NULL) {
		fprintf(fp, "malloc failed\n");
		return FALSE;
	}

	mask = (((ulong)1)<<PAGESHIFT()) - 1;
	last_idx = pt_info_ptr->curr_buf_idx +
	   (pt_info_ptr->output_off >> PAGESHIFT());

	for (idx = 0; idx < last_idx; idx++) {
		page = pt_info_ptr->buffer_ptr[idx];
		len = PAGESIZE();

		readmem(page, KVADDR, buf, len, "read page for write",
			FAULT_ON_ERROR);

		dbgprintf(fp, "[%d] R/W1 buff: p=0x%lx, i=%d, o=%lu, l=%d\n",
			cpu, page, idx, (ulong)0, len);

		ret = fwrite(buf, len, 1, out_fp);
		if (!ret) {
			fprintf(fp, "[%d] Cannot write file\n", cpu);
			free(buf);
			return FALSE;
		}
	}

	idx = last_idx;
	page = pt_info_ptr->buffer_ptr[idx];
	len = pt_info_ptr->output_off & mask;

	readmem(page, KVADDR, buf, len, "read page for write",
		FAULT_ON_ERROR);

	dbgprintf(fp, "[%d] R/W2 buff: p=0x%lx, i=%d, o=%lu, l=%d\n", cpu,
		page, idx, (ulong)0, len);

	ret = fwrite(buf, len, 1, out_fp);
	if (!ret) {
		fprintf(fp, "[%d] Cannot write file\n", cpu);
		free(buf);
		return FALSE;
	}

	free(buf);
	return TRUE;
}

int write_pt_log_buffer_cpu(int cpu, char *fname)
{
	int wrapped, ret;
	FILE *out_fp;

	wrapped = check_wrap_around(cpu);

	if ((out_fp = fopen(fname, "w")) == NULL) {
		fprintf(fp, "[%d] Cannot open file: %s\n", cpu, fname);
		return FALSE;
	}
	dbgprintf(fp, "[%d] Open file: %s\n", cpu, fname);

	/*
	 * Write buffer to file
	 *
	 * Case 1: Not wrapped around
	 *
	 *   start       end
	 *   |           |
	 *   v           v
	 *   +------+  +------+     +------+  +------+
	 *   |buffer|  |buffer| ... |buffer|  |buffer|
	 *   +------+  +------+     +------+  +------+
	 *
	 *   In this case, just write data between 'start' and 'end'
	 *
	 * Case 2: Wrapped around
	 *
	 *            end start
	 *             |  |
	 *             v  v
	 *   +------+  +------+     +------+  +------+
	 *   |buffer|  |buffer| ... |buffer|  |buffer|
	 *   +------+  +------+     +------+  +------+
	 *
	 *   In this case, at first write data between 'start' and end of last
	 *   buffer, and then write data between beginning of first buffer and
	 *   'end'.
	 */
	if (wrapped) {
		dbgprintf(fp, "[%d] wrap around: true\n", cpu);
		ret = write_buffer_wrapped(cpu, out_fp);
	} else {
		dbgprintf(fp, "[%d] wrap around: false\n", cpu);
		ret = write_buffer_nowrapped(cpu, out_fp);
	}

	fclose(out_fp);
	return ret;
}

void
cmd_ptdump(void)
{
	int i, ret, list_len;
	int online_cpus;
	char* outdir;
	char dumpfile[16];
	char decodefile[16];
	mode_t mode = S_IRUSR | S_IWUSR | S_IXUSR |
		      S_IRGRP | S_IXGRP |
		      S_IROTH | S_IXOTH; /* 0755 */
	struct pt_info *pt_info_ptr;

	if (argcnt != 2)
		cmd_usage(pc->curcmd, SYNOPSIS);

	outdir = args[1];
	if ((ret = mkdir(outdir, mode))) {
		fprintf(fp, "Cannot create directory %s: %d\n", outdir, ret);
		return;
	}

	if ((ret = chdir(outdir))) {
		fprintf(fp, "Cannot chdir %s: %d\n", outdir, ret);
		return;
	}

	online_cpus = get_cpus_online();
	list_len = sizeof(struct pt_info)*kt->cpus;
	pt_info_list = malloc(list_len);
	if (pt_info_list == NULL) {
		fprintf(fp, "Cannot alloc pt_info_list\n");
		return;
	}
	memset(pt_info_list, 0, list_len);

	for (i = 0; online_cpus > 0; i++) {
		if (!in_cpu_map(ONLINE_MAP, i))
			continue;

		online_cpus--;

		if (!init_pt_info(i))
			continue;

		sprintf(dumpfile, "dump.%d", i);
		if (write_pt_log_buffer_cpu(i, dumpfile))
			fprintf(fp, "[%d] buffer dump: %s\n", i, dumpfile);

		sprintf(decodefile, "decode.%d", i);
		if (fastdecode(dumpfile, decodefile))
			fprintf(fp, "[%d] packet decode: %s\n", i, decodefile);

		pt_info_ptr = pt_info_list + i;
		if (pt_info_ptr->buffer_ptr != NULL)
			free(pt_info_ptr->buffer_ptr);
	}
	free(pt_info_list);
	chdir("..");
}

char *help_ptdump[] = {
	"ptdump",
	"Dump log buffer of Intel(R) Processor Trace",
	"<output-dir>",
	"This command extracts log buffer of PT to the directory",
	"specified by <output-dir>",
	NULL
};

static struct command_table_entry command_table[] = {
	{ "ptdump", cmd_ptdump, help_ptdump, 0},
	{ NULL },
};

void __attribute__((constructor))
ptdump_init(void)
{
	register_extension(command_table);
}

void __attribute__((destructor))
ptdump_fini(void) { }

