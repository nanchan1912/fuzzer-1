/* Stage 2 verification: the CAS decision table, driven through the real
 * scheduler with a real input graph.
 *
 * The graph is supplied via FUZZ_INPUT and names one write (the initial store)
 * and one cmpxchg event. By varying only the cmpxchg node's `kind` and the
 * compare operand, each row of the decision table becomes an expected exit
 * code:
 *
 *   20 (WMM_EXIT_INSTANTIATED_BUT_NOT_DONE)  schedule was realisable
 *   21 (WMM_EXIT_NOT_INSTANTIABLE)           graph demanded an impossible outcome
 *
 * The caller (run_cas_semantics.sh) supplies the graph and the expected code;
 * this program only performs the accesses. It also prints whether the swap
 * actually happened, which is what distinguishes a spurious weak failure from
 * a comparison failure.
 *
 * Note: this tree's runtime lazily self-initializes on the first
 * __instrument_* call (see __wmm_init_internal in wmm_hooks.c), so there is no
 * separate "notify main start" call to make here, unlike upstream.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* Hooks normally injected by the LLVM pass. Declared by hand here so the test
 * exercises exactly the same entry points a instrumented binary would. */
extern void *__instrument_store(uint64_t uid, void *addr, uint64_t value,
                                uint32_t order, uint64_t thread_id,
                                uint64_t loc_id, uint64_t value_size);
extern uint64_t __instrument_cmpxchg(uint64_t uid, void *addr, uint64_t compare_val,
                                     uint64_t new_val, uint32_t order,
                                     uint64_t thread_id, uint64_t loc_id,
                                     uint64_t value_size);

/* Must match the instruction_id / loc_id values in the graph fixtures. */
#define UID_INIT_STORE  1
#define UID_CAS         2
#define LOC_ID          12345
#define ORDER_SC        5

static uint64_t shared;

int main(int argc, char **argv) {
    /* The value the CAS compares against: 42 makes the comparison succeed,
     * anything else makes it fail. */
    uint64_t compare_val = (argc > 1) ? strtoull(argv[1], NULL, 0) : 42;

    __instrument_store(UID_INIT_STORE, &shared, 42, ORDER_SC,
                       /*thread_id=*/0, LOC_ID, sizeof(shared));

    uint64_t old = __instrument_cmpxchg(UID_CAS, &shared, compare_val, 99,
                                        ORDER_SC, /*thread_id=*/0, LOC_ID,
                                        sizeof(shared));

    /* `shared` changing is the observable proof of whether the swap happened,
     * independent of what the hook reported. */
    printf("[test] old=%llu shared_after=%llu swapped=%s\n",
           (unsigned long long)old, (unsigned long long)shared,
           shared == 99 ? "yes" : "no");
    return 0;
}
