/* Stage 3 verification: weak CAS spurious failure.
 *
 * This is the test that proves InstrumentWMM.cpp no longer reconstructs
 * success as `old == compare` on the client side. The graph says CAS_FAIL
 * while the values DO match, so a weak CAS must:
 *
 *   - report success == false, and
 *   - leave memory unchanged.
 *
 * With the old client-side CreateICmpEQ the reported success would have been
 * true (the values match) while the runtime refused the store -- the program
 * would take its success branch over memory that still held the old value.
 * That divergence is exactly what this checks.
 *
 * Calls the hooks directly so the check does not depend on the LLVM pass
 * having run; a companion end-to-end check compiles a real cmpxchg through
 * the pass.
 *
 * Note: this tree's runtime lazily self-initializes on the first
 * __instrument_* call (see __wmm_init_internal in wmm_hooks.c), so there is no
 * separate "notify main start" call to make here, unlike upstream.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

extern void *__instrument_store(uint64_t uid, void *addr, uint64_t value,
                                uint32_t order, uint64_t thread_id,
                                uint64_t loc_id, uint64_t value_size);
extern uint64_t __instrument_cmpxchg_weak(uint64_t uid, void *addr, uint64_t compare_val,
                                          uint64_t new_val, uint32_t order,
                                          uint64_t thread_id, uint64_t loc_id,
                                          uint64_t value_size, uint8_t *success_out);
extern uint64_t __instrument_cmpxchg_strong(uint64_t uid, void *addr, uint64_t compare_val,
                                            uint64_t new_val, uint32_t order,
                                            uint64_t thread_id, uint64_t loc_id,
                                            uint64_t value_size, uint8_t *success_out);

#define UID_INIT_STORE  1
#define UID_CAS         2
#define LOC_ID          12345
#define ORDER_SC        5

static uint64_t shared;

int main(int argc, char **argv) {
    /* argv[1]: "weak" or "strong"; argv[2]: compare operand */
    const char *flavour = (argc > 1) ? argv[1] : "weak";
    uint64_t compare_val = (argc > 2) ? strtoull(argv[2], NULL, 0) : 42;

    __instrument_store(UID_INIT_STORE, &shared, 42, ORDER_SC,
                       /*thread_id=*/0, LOC_ID, sizeof(shared));

    uint8_t success = 0xFF;   /* poisoned: the hook must overwrite it */
    uint64_t old;
    if (flavour[0] == 'w') {
        old = __instrument_cmpxchg_weak(UID_CAS, &shared, compare_val, 99, ORDER_SC,
                                        0, LOC_ID, sizeof(shared), &success);
    } else {
        old = __instrument_cmpxchg_strong(UID_CAS, &shared, compare_val, 99, ORDER_SC,
                                          0, LOC_ID, sizeof(shared), &success);
    }

    const int values_matched = (old == compare_val);
    printf("[test] flavour=%s old=%llu compare=%llu values_matched=%s "
           "reported_success=%s shared_after=%llu stored=%s\n",
           flavour,
           (unsigned long long)old, (unsigned long long)compare_val,
           values_matched ? "yes" : "no",
           success ? "yes" : "no",
           (unsigned long long)shared,
           shared == 99 ? "yes" : "no");

    /* The invariant that matters: the reported outcome and what actually
     * happened to memory must agree, whatever the comparison said. */
    if ((success != 0) != (shared == 99)) {
        fprintf(stderr, "[test] INCONSISTENT: reported success=%d but stored=%d\n",
                success != 0, shared == 99);
        return 3;
    }
    return 0;
}
