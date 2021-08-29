// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>
#include <rz_util.h>
#include "minunit.h"

static bool test_rzil_vm_init() {
	RzILVM vm = RZ_NEW0(struct rz_il_vm_t);
	mu_assert_notnull(vm, "Create VM");
	rz_il_vm_init(vm, 0, 8, 8);
	mu_assert_eq(vm->addr_size, 8, "VM Init");
	rz_il_vm_close(vm);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rzil_vm_init);
	return tests_passed != tests_run;
}

mu_main(all_tests)