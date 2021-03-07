//
// Created by heersin on 3/6/21.
//

#include "luac_dis.h"
int luac_disasm(RzAsm *a, RzAsmOp *opstruct, const ut8 *buf, int len){
        // switch version here ?

        int r = _lua54_disasm(opstruct, buf, len);
	opstruct->size = r;
	return r;
}