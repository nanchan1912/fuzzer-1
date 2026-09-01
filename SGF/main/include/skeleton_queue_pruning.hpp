#ifndef SKELETON_QUEUE_PRUNING_HPP
#define SKELETON_QUEUE_PRUNING_HPP

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sgf_state;

/**
 * @brief Prunes the SGF queue in memory after all mutation phases have completed,
 * keeping up to `keep_per_edge` highest-scoring (by perf_score) queue entries for
 * each unique MO edge and each unique RF edge, plus the initial seed.
 *
 * Also resets the dynamic cutoff score and rebuilds the Potential NN index from scratch.
 * Global skeleton hash sets, MO/RF footprints, and on-disk files are preserved.
 *
 * @param sgf SGF state pointer.
 * @param keep_per_edge Maximum entries to preserve per unique edge (default: 10).
 */
void clear_and_compact_queue_after_phases(struct sgf_state *sgf, uint32_t keep_per_edge);

#ifdef __cplusplus
}
#endif

#endif // SKELETON_QUEUE_PRUNING_HPP
