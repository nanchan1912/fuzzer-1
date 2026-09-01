#ifndef LLVM_SHAREDMEM_PASS_RUNTIME_ASSERT_H
#define LLVM_SHAREDMEM_PASS_RUNTIME_ASSERT_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void __VERIFY_STORE_VAR(const char *name, bool value);
bool __VERIFY_ASSERT(const char *expr);

#ifdef __cplusplus
}
#endif

#endif
