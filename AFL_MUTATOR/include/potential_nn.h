#ifndef POTENTIAL_NN_H
#define POTENTIAL_NN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*potential_nn_is_active_fn)(const void* entry, void* user_data);

/**
 * @brief Nearest-neighbor index API.
 */

/**
 * @brief Clear the nearest-neighbor index.
 */
void potential_nn_index_reset(void);

/**
 * @brief Check whether an owner entry is already indexed.
 *
 * @param entry Opaque owner pointer used as the index key.
 * @return Non-zero if present, zero otherwise.
 */
int potential_nn_index_contains(const void* entry);

/**
 * @brief Add a potential to the nearest-neighbor index.
 *
 * @param entry Opaque owner pointer used as the index key.
 * @param potential Opaque pointer to a SkeletonPotential object.
 */
void potential_nn_index_add(const void* entry, void* potential);

/**
 * @brief Find the closest active indexed neighbor.
 *
 * @param entry Opaque owner pointer of the query entry (excluded from matches).
 * @param potential Opaque pointer to query SkeletonPotential.
 * @param is_active Optional callback to filter candidates (`NULL` accepts all).
 * @param user_data Opaque context passed to `is_active`.
 * @param out_diff Output for the best difference score.
 * @param out_neighbor Optional output for matched neighbor owner pointer.
 * @return Non-zero on success, zero if no candidate is found.
 */
int potential_nn_find_diff(const void* entry,
                           void* potential,
                           potential_nn_is_active_fn is_active,
                           void* user_data,
                           double* out_diff,
                           const void** out_neighbor);

#ifdef __cplusplus
}
#endif

#endif /* POTENTIAL_NN_H */
