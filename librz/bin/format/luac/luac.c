// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

// Implement Functions declared in luac_specs.h

#include "luac_specs.h"

void luaLoadBlock(void *src, void *dest, size_t size) {
	memcpy(dest, src, size);
}

LUA_INTEGER luaLoadInteger(ut8 *src) {
	LUA_INTEGER x;
	luaLoadVar(src, x);
	return x;
}

LUA_NUMBER luaLoadNumber(ut8 *src) {
	LUA_NUMBER x;
	luaLoadVar(src, x);
	return x;
}

/* Luac load method , defined in lua source code lundump.c */
size_t luaLoadUnsigned(ut8 *src, size_t src_buf_limit, size_t limit) {
	size_t x = 0;
	ut32 b;
	int i = 0;
	limit >>= 7;
	do {
		b = src[i++];
		if (x >= limit) {
			eprintf("integer overflow\n");
			return 0;
		}
		x = (x << 7) | (b & 0x7f);
	} while (((b & 0x80) == 0) && (i < src_buf_limit));
	return x;
}

size_t luaLoadSize(ut8 *src, size_t src_buf_limit) {
	return luaLoadUnsigned(src, src_buf_limit, ~(size_t)0);
}

/* load a null-terminated string, return a malloced string */
char *luaLoadString(ut8 *src, size_t src_buf_limit) {
	/* size is the buffer's size */
	size_t size = luaLoadSize(src, src_buf_limit);
	char *ret;

	/* no string */
	if (size == 0) {
		return NULL;
	}

	/* skip size byte */
	void *string_start = src + 1;
	size -= 1;

	if ((ret = RZ_NEWS(char, size)) == NULL) {
		eprintf("error in string init\n");
		return NULL;
	}

	memcpy(ret, string_start, size);
	ret[size] = 0x00;

	return ret;
}
