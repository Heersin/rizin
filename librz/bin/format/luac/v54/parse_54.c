#include "luac_specs_54.h"

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

        if ((ret = RZ_NEWS(char, size + 1)) == NULL) {
                eprintf("error in string init\n");
                return NULL;
        }

        memcpy(ret, string_start, size);
        ret[size] = 0x00;

        return ret;
}

// return an offset to skip string, return 1 if no string (0x80)
// TODO : clean type related issues
static ut64 lua_parse_szint(ut8 *data, int *size, ut64 offset, ut64 data_size){
	int x = 0;
        int b;
        int i = 0;
	int limit = (~(int)0);
        limit >>= 7;

	// 1 byte at least
	if (offset + 1 >= data_size){
		eprintf("Truncated read sz int\n");
		return 0;
	}

	data += offset;

        do {
                b = data[i++];
                if (x >= limit) {
                        eprintf("integer overflow\n");
                        return 0;
                }
                x = (x << 7) | (b & 0x7f);
        } while (((b & 0x80) == 0) && (i + offset < data_size));

	*size = x;
        return i;
}

static ut64 lua_parse_string(ut8 *data, ut8 **dest, int *str_len, ut64 offset, ut64 data_size){
        rz_return_val_if_fail(data, 0);

	ut64 size_offset;
	ut64 total_offset;
        ut8 *string_start;
	int string_buf_size;
	int string_len;
	ut8 *ret;

	size_offset = lua_parse_szint(data, &string_buf_size, offset, data_size);

        /* no string */
        if (string_buf_size == 0) {
		ret = NULL;
		string_len = 0;
        } else{
                /* skip size byte */
                string_start = size_offset + data;
                string_len = string_buf_size - 1;
                if ((ret = RZ_NEWS(ut8, string_buf_size)) == NULL) {
                        eprintf("error in string init\n");
			string_len = 0;
                } else {
			memcpy(ret, string_start, string_len);
			ret[string_len] = 0x00;
		}
        }

	/* set to outside vars */
	if (dest && str_len){
		*dest = ret;
		*str_len = string_len;
	} else {
		eprintf("nowhere to parse string\n");
	}

	total_offset = size_offset + string_len;
	return total_offset;
}

static ut64 lua_parse_name(LuaProto *proto, ut8 *data, ut64 offset, ut64 data_size){
	return lua_parse_string(data, &proto->proto_name, &proto->name_size, offset, data_size);
}

static ut64 lua_parse_line_defined(LuaProto *proto, ut8 *data, ut64 offset, ut64 data_size){
	ut64 size_offset;
	int line_defined;
	int last_line_defined;

	size_offset = lua_parse_szint(data, &line_defined, offset, data_size);
	size_offset += lua_parse_szint(data, &last_line_defined, offset + size_offset, data_size);

	/* Set Proto Member */
	proto->line_defined = line_defined;
	proto->lastline_defined = last_line_defined;

	return size_offset;
}

static ut64 lua_parse_code(LuaProto *proto, ut8 *data, ut64 offset, ut64 data_size){
	ut64 size_offset;
	ut64 total_size;
	int code_size;

	size_offset = lua_parse_szint(data, &code_size, offset, data_size);
	total_size = code_size + size_offset;

	/* Set Proto Member */
	proto->code_size = code_size;

	return total_size;
}

static ut64 lua_parse_const_entry(LuaProto *proto, ut8 *data, ut64 offset, ut64 data_size){
	LuaConstEntry *current_entry;
	ut64 base_offset;
	ut8 *recv_data;
	int data_len;

	current_entry = lua_new_const_entry();
	base_offset = offset;

	/* read TAG byte */
	current_entry->tag = data[offset];
	offset += 1;

	/* read data */
        // TODO : check NULL & replace luaLoadBlock with mem copy
        // TODO : replace 8 with Macro
	switch (current_entry->tag) {
        case LUA_VNUMFLT:
        case LUA_VNUMINT:
                data_len = 8;
                recv_data = RZ_NEWS(ut8, data_len);
		luaLoadBlock(data, recv_data, data_len);
		offset += data_len;
                break;
	case LUA_VSHRSTR:
	case LUA_VLNGSTR:
		offset += lua_parse_string(data, &recv_data, &data_len, offset, data_size);
		break;
	case LUA_VNIL:
	case LUA_VFALSE:
	case LUA_VTRUE:
		break;
	}

	current_entry->data = recv_data;
	current_entry->data_len = data_len;

	/* add to list */
	rz_list_append(proto->const_entries, current_entry);

	return offset - base_offset;
}

static ut64 lua_parse_consts(LuaProto *proto, ut8 *data, ut64 offset, ut64 data_size){
	int consts_cnt;
	int i;
	ut64 base_offset;

	base_offset = offset;
	offset += lua_parse_szint(data, &consts_cnt, offset, data_size);

	for (i = 0; i < consts_cnt; ++i){
		// TODO check NULL
		// add an entry of constant
		offset += lua_parse_const_entry(proto, data, offset, data_size);
        }

	return offset - base_offset;
}

static ut64 lua_parse_upvalue_entry(LuaProto *proto, ut8 *data, ut64 offset, ut64 data_size){
	LuaUpvalueEntry *current_entry;
	ut64 base_offset;

	base_offset = offset;
	current_entry = lua_new_upvalue_entry();
	current_entry->offset = base_offset;

	if (offset + 3 > data_size){
		eprintf("Truncated upvalue\n");
		lua_free_upvalue_entry(current_entry);
		return 0;
	}

	/* read instack/idx/kind attr */
	current_entry->instack = data[offset + 0];
	current_entry->idx = data[offset + 1];
	current_entry->kind = data[offset + 2];

	offset += 3;

	/* add to list */
	rz_list_append(proto->upvalue_entries, current_entry);

	return offset - base_offset;
}

static ut64 lua_parse_upvalues(LuaProto *proto, ut8 *data, ut64 offset, ut64 data_size){
	int upvalues_cnt;
	int i;
	ut64 base_offset;

	base_offset = offset;
	offset += lua_parse_szint(data, &upvalues_cnt, offset, data_size);

	for (i = 0; i < upvalues_cnt; ++i){
		offset += lua_parse_upvalue_entry(proto, data, offset, data_size);
	}

	return offset - base_offset;
}
static ut64 lua_parse_debug(LuaProto *proto, ut8 *data, ut64 offset, ut64 data_size){
	int entries_cnt;
	int i;
	ut64 base_offset;

	base_offset = offset;

        /* parse line info */
        offset += lua_parse_szint(data, &entries_cnt, offset, data_size);
	LuaLineinfoEntry *info_entry;
	for (i = 0; i < entries_cnt; ++i){
                info_entry = lua_new_lineinfo_entry();
		info_entry->offset = offset;
		info_entry->info_data = data[offset];
		rz_list_append(proto->line_info_entries, info_entry);
		offset += 1;
        }

	/* parse absline info */
        offset += lua_parse_szint(data, &entries_cnt, offset, data_size);
        LuaAbsLineinfoEntry *abs_info_entry;
        for (i = 0; i < entries_cnt; ++i){
		abs_info_entry = lua_new_abs_lineinfo_entry();
		abs_info_entry->offset = offset;

		offset += lua_parse_szint(data, &abs_info_entry->pc, offset, data_size);
		offset += lua_parse_szint(data, &abs_info_entry->line, offset, data_size);

		rz_list_append(proto->abs_line_info_entries, abs_info_entry);
        }

	/* parse local vars */
	offset += lua_parse_szint(data, &entries_cnt, offset, data_size);
	LuaLocalVarEntry *var_entry;
	for (i = 0; i < entries_cnt; ++i){
		var_entry = lua_new_local_var_entry();
		var_entry->offset = offset;

		offset += lua_parse_string(
			data,
			&var_entry->varname, &var_entry->varname_len,
			offset, data_size);

		offset += lua_parse_szint(data, &var_entry->start_pc, offset, data_size);
		offset += lua_parse_szint(data, &var_entry->end_pc, offset, data_size);

		rz_list_append(proto->local_var_info_entries, var_entry);
	}

	/* parse upvalue */
	offset += lua_parse_szint(data, &entries_cnt, offset, data_size);
	LuaDbgUpvalueEntry *dbg_upvalue_entry;
	for (i = 0; i < entries_cnt; ++i){
		dbg_upvalue_entry = lua_new_dbg_upvalue_entry();
		dbg_upvalue_entry->offset = offset;

		offset += lua_parse_string(
			data,
			&dbg_upvalue_entry->upvalue_name, &dbg_upvalue_entry->name_len,
			offset, data_size);

		rz_list_append(proto->dbg_upvalue_entries, dbg_upvalue_entry);
	}

	proto->debug_size = offset - base_offset + 1;
	return offset - base_offset;
}


static ut64 lua_parse_protos(LuaProto *proto, ut8 *data, ut64 offset, ut64 data_size){
	rz_return_val_if_fail(proto, 0);
	rz_return_val_if_fail(data, 0);

	int proto_cnt;
	int i;
	ut64 base_offset;

	base_offset = offset;                   // store origin offset
	offset += lua_parse_szint(data, &proto_cnt, offset, data_size); // skip size bytes

	LuaProto *current_proto;
	for (i = 0; i < proto_cnt; ++i){
		current_proto = lua_parse_body_54(data, offset, data_size);
                rz_list_append(proto->proto_entries, current_proto);
		offset += current_proto->size + 1;                         // update offset
	}

	// return the delta between offset and base_offset
	return offset - base_offset;
}

LuaProto *lua_parse_body_54(ut8 *data, ut64 base_offset, ut64 data_size){
	LuaProto *ret_proto;            /* construted proto for return */
	ut64 offset;                    /* record offset */
	rz_return_val_if_fail((ret_proto = lua_new_proto_entry()), NULL);

        // start parsing
	offset = base_offset;

        // skip luac header
	if (offset + data_size >= LUAC_54_HDRSIZE){
		lua_free_proto_entry(ret_proto);
		return NULL;
	}
	offset += LUAC_54_HDRSIZE;

	/* record offset of main proto */
	ret_proto->offset = offset;

	/* parse proto name of main proto */
	offset += lua_parse_name(ret_proto, data, offset, data_size);

	/* parse line defined info */
	offset += lua_parse_line_defined(ret_proto, data, offset, data_size);

	/* parse num params max_stack_size */
	if (offset + 3 >= data_size){
		lua_free_proto_entry(ret_proto);
		return NULL;
	}
	ret_proto->num_params = data[offset + 0];
	ret_proto->is_vararg = data[offset + 1];
	ret_proto->max_stack_size = data[offset + 2];
	offset += 3;

	/* parse code */
	ret_proto->code_offset = offset;
	offset += lua_parse_code(ret_proto, data, offset, data_size);

	/* parse constants */
	ret_proto->const_offset = offset;
	offset += lua_parse_consts(ret_proto, data, offset, data_size);

	/* parse upvalues */
	ret_proto->upvalue_offset = offset;
	offset += lua_parse_upvalues(ret_proto, data, offset, data_size);

	/* parse inner protos */
	ret_proto->inner_proto_offset = offset;
	offset += lua_parse_protos(ret_proto, data, offset, data_size);

	/* parse debug */
	ret_proto->debug_offset = offset;
	offset += lua_parse_debug(ret_proto, data, offset, data_size);

	ret_proto->size = offset - base_offset + 1;

	return ret_proto;
}
