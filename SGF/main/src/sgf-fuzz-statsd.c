/*
 * This implements rpc.statsd support, see docs/rpc_statsd.md
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include "sgf-fuzz.h"

#define MAX_STATSD_PACKET_SIZE 4096
#define MAX_TAG_LEN 200
#define METRIC_PREFIX "fuzzing"

/* Tags format for metrics
  DogStatsD:
  metric.name:<value>|<type>|#key:value,key2:value2

  InfluxDB
  metric.name,key=value,key2=value2:<value>|<type>

  Librato
  metric.name#key=value,key2=value2:<value>|<type>

  SignalFX
  metric.name[key=value,key2=value2]:<value>|<type>

*/

// after the whole metric.
#define DOGSTATSD_TAGS_FORMAT "|#banner:%s,sgf_version:%s"

// just after the metric name.
#define LIBRATO_TAGS_FORMAT "#banner=%s,sgf_version=%s"
#define INFLUXDB_TAGS_FORMAT ",banner=%s,sgf_version=%s"
#define SIGNALFX_TAGS_FORMAT "[banner=%s,sgf_version=%s]"

// For DogstatsD
#define STATSD_TAGS_TYPE_SUFFIX 1
#define STATSD_TAGS_SUFFIX_METRICS                                       \
  METRIC_PREFIX                                                          \
  ".cycle_done:%llu|g%s\n" METRIC_PREFIX                                 \
  ".cycles_wo_finds:%llu|g%s\n" METRIC_PREFIX                            \
  ".execs_done:%llu|g%s\n" METRIC_PREFIX                                 \
  ".execs_per_sec:%0.02f|g%s\n" METRIC_PREFIX                            \
  ".corpus_count:%u|g%s\n" METRIC_PREFIX                                 \
  ".corpus_favored:%u|g%s\n" METRIC_PREFIX                               \
  ".corpus_found:%u|g%s\n" METRIC_PREFIX                                 \
  ".corpus_imported:%u|g%s\n" METRIC_PREFIX                              \
  ".max_depth:%u|g%s\n" METRIC_PREFIX ".cur_item:%u|g%s\n" METRIC_PREFIX \
  ".pending_favs:%u|g%s\n" METRIC_PREFIX                                 \
  ".pending_total:%u|g%s\n" METRIC_PREFIX                                \
  ".corpus_variable:%u|g%s\n" METRIC_PREFIX                              \
  ".saved_crashes:%llu|g%s\n" METRIC_PREFIX                              \
  ".saved_hangs:%llu|g%s\n" METRIC_PREFIX                                \
  ".total_crashes:%llu|g%s\n" METRIC_PREFIX                              \
  ".slowest_exec_ms:%u|g%s\n" METRIC_PREFIX                              \
  ".edges_found:%u|g%s\n" METRIC_PREFIX                                  \
  ".var_byte_count:%u|g%s\n" METRIC_PREFIX ".havoc_expansion:%u|g%s\n"

// For Librato, InfluxDB, SignalFX
#define STATSD_TAGS_TYPE_MID 2
#define STATSD_TAGS_MID_METRICS                                          \
  METRIC_PREFIX                                                          \
  ".cycle_done%s:%llu|g\n" METRIC_PREFIX                                 \
  ".cycles_wo_finds%s:%llu|g\n" METRIC_PREFIX                            \
  ".execs_done%s:%llu|g\n" METRIC_PREFIX                                 \
  ".execs_per_sec%s:%0.02f|g\n" METRIC_PREFIX                            \
  ".corpus_count%s:%u|g\n" METRIC_PREFIX                                 \
  ".corpus_favored%s:%u|g\n" METRIC_PREFIX                               \
  ".corpus_found%s:%u|g\n" METRIC_PREFIX                                 \
  ".corpus_imported%s:%u|g\n" METRIC_PREFIX                              \
  ".max_depth%s:%u|g\n" METRIC_PREFIX ".cur_item%s:%u|g\n" METRIC_PREFIX \
  ".pending_favs%s:%u|g\n" METRIC_PREFIX                                 \
  ".pending_total%s:%u|g\n" METRIC_PREFIX                                \
  ".corpus_variable%s:%u|g\n" METRIC_PREFIX                              \
  ".saved_crashes%s:%llu|g\n" METRIC_PREFIX                              \
  ".saved_hangs%s:%llu|g\n" METRIC_PREFIX                                \
  ".total_crashes%s:%llu|g\n" METRIC_PREFIX                              \
  ".slowest_exec_ms%s:%u|g\n" METRIC_PREFIX                              \
  ".edges_found%s:%u|g\n" METRIC_PREFIX                                  \
  ".var_byte_count%s:%u|g\n" METRIC_PREFIX ".havoc_expansion%s:%u|g\n"

void statsd_setup_format(sgf_state_t *sgf) {

  if (sgf->sgf_env.sgf_statsd_tags_flavor &&
      strcmp(sgf->sgf_env.sgf_statsd_tags_flavor, "dogstatsd") == 0) {

    sgf->statsd_tags_format = DOGSTATSD_TAGS_FORMAT;
    sgf->statsd_metric_format = STATSD_TAGS_SUFFIX_METRICS;
    sgf->statsd_metric_format_type = STATSD_TAGS_TYPE_SUFFIX;

  } else if (sgf->sgf_env.sgf_statsd_tags_flavor &&

             strcmp(sgf->sgf_env.sgf_statsd_tags_flavor, "librato") == 0) {

    sgf->statsd_tags_format = LIBRATO_TAGS_FORMAT;
    sgf->statsd_metric_format = STATSD_TAGS_MID_METRICS;
    sgf->statsd_metric_format_type = STATSD_TAGS_TYPE_MID;

  } else if (sgf->sgf_env.sgf_statsd_tags_flavor &&

             strcmp(sgf->sgf_env.sgf_statsd_tags_flavor, "influxdb") == 0) {

    sgf->statsd_tags_format = INFLUXDB_TAGS_FORMAT;
    sgf->statsd_metric_format = STATSD_TAGS_MID_METRICS;
    sgf->statsd_metric_format_type = STATSD_TAGS_TYPE_MID;

  } else if (sgf->sgf_env.sgf_statsd_tags_flavor &&

             strcmp(sgf->sgf_env.sgf_statsd_tags_flavor, "signalfx") == 0) {

    sgf->statsd_tags_format = SIGNALFX_TAGS_FORMAT;
    sgf->statsd_metric_format = STATSD_TAGS_MID_METRICS;
    sgf->statsd_metric_format_type = STATSD_TAGS_TYPE_MID;

  } else {

    // No tags at all.
    sgf->statsd_tags_format = "";
    // Still need to pick a format. Doesn't change anything since if will be
    // replaced by the empty string anyway.
    sgf->statsd_metric_format = STATSD_TAGS_MID_METRICS;
    sgf->statsd_metric_format_type = STATSD_TAGS_TYPE_MID;

  }

}

int statsd_socket_init(sgf_state_t *sgf) {

  /* Default port and host.
  Will be overwritten by SGF_STATSD_PORT and SGF_STATSD_HOST environment
  variable, if they exists.
  */
  u16   port = STATSD_DEFAULT_PORT;
  char *host = STATSD_DEFAULT_HOST;

  if (sgf->sgf_env.sgf_statsd_port) {

    port = atoi(sgf->sgf_env.sgf_statsd_port);

  }

  if (sgf->sgf_env.sgf_statsd_host) { host = sgf->sgf_env.sgf_statsd_host; }

  int sock;
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {

    FATAL("Failed to create socket");

  }

  memset(&sgf->statsd_server, 0, sizeof(sgf->statsd_server));
  sgf->statsd_server.sin_family = AF_INET;
  sgf->statsd_server.sin_port = htons(port);

  struct addrinfo *result;
  struct addrinfo  hints;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;

  if ((getaddrinfo(host, NULL, &hints, &result))) {

    FATAL("Fail to getaddrinfo");

  }

  memcpy(&(sgf->statsd_server.sin_addr),
         &((struct sockaddr_in *)result->ai_addr)->sin_addr,
         sizeof(struct in_addr));
  freeaddrinfo(result);

  return sock;

}

int statsd_send_metric(sgf_state_t *sgf) {

  char buff[MAX_STATSD_PACKET_SIZE] = {0};

  /* sgf->statsd_sock is set once in the initialisation of sgf-fuzz and reused
  each time If the sendto later fail, we reset it to 0 to be able to recreates
  it.
  */
  if (!sgf->statsd_sock) {

    sgf->statsd_sock = statsd_socket_init(sgf);
    if (!sgf->statsd_sock) {

      WARNF("Cannot create socket");
      return -1;

    }

  }

  statsd_format_metric(sgf, buff, MAX_STATSD_PACKET_SIZE);
  if (sendto(sgf->statsd_sock, buff, strlen(buff), 0,
             (struct sockaddr *)&sgf->statsd_server,
             sizeof(sgf->statsd_server)) == -1) {

    if (!close(sgf->statsd_sock)) { PFATAL("Cannot close socket"); }
    sgf->statsd_sock = 0;
    WARNF("Cannot sendto");
    return -1;

  }

  return 0;

}

int statsd_format_metric(sgf_state_t *sgf, char *buff, size_t bufflen) {

  char tags[MAX_TAG_LEN * 2] = {0};
  if (sgf->statsd_tags_format) {

    snprintf(tags, MAX_TAG_LEN * 2, sgf->statsd_tags_format, sgf->sync_id,
             VERSION);

  }

  /* Sends multiple metrics with one UDP Packet.
  bufflen will limit to the max safe size.
  */
  if (sgf->statsd_metric_format_type == STATSD_TAGS_TYPE_SUFFIX) {

    snprintf(
        buff, bufflen, sgf->statsd_metric_format,
        sgf->queue_cycle ? (sgf->queue_cycle - 1) : 0, tags,
        sgf->cycles_wo_finds, tags, sgf->fsrv.total_execs, tags,
        sgf->fsrv.total_execs /
            ((double)(get_cur_time() + sgf->prev_run_time - sgf->start_time) /
             1000),
        tags, sgf->queued_items, tags, sgf->queued_favored, tags,
        sgf->queued_discovered, tags, sgf->queued_imported, tags,
        sgf->max_depth, tags, sgf->current_entry, tags, sgf->pending_favored,
        tags, sgf->pending_not_fuzzed, tags, sgf->queued_variable, tags,
        sgf->saved_crashes, tags, sgf->saved_hangs, tags, sgf->total_crashes,
        tags, sgf->slowest_exec_ms, tags,
        count_non_255_bytes(sgf, sgf->virgin_bits), tags, sgf->var_byte_count,
        tags, sgf->expand_havoc, tags);

  } else if (sgf->statsd_metric_format_type == STATSD_TAGS_TYPE_MID) {

    snprintf(
        buff, bufflen, sgf->statsd_metric_format, tags,
        sgf->queue_cycle ? (sgf->queue_cycle - 1) : 0, tags,
        sgf->cycles_wo_finds, tags, sgf->fsrv.total_execs, tags,
        sgf->fsrv.total_execs /
            ((double)(get_cur_time() + sgf->prev_run_time - sgf->start_time) /
             1000),
        tags, sgf->queued_items, tags, sgf->queued_favored, tags,
        sgf->queued_discovered, tags, sgf->queued_imported, tags,
        sgf->max_depth, tags, sgf->current_entry, tags, sgf->pending_favored,
        tags, sgf->pending_not_fuzzed, tags, sgf->queued_variable, tags,
        sgf->saved_crashes, tags, sgf->saved_hangs, tags, sgf->total_crashes,
        tags, sgf->slowest_exec_ms, tags,
        count_non_255_bytes(sgf, sgf->virgin_bits), tags, sgf->var_byte_count,
        tags, sgf->expand_havoc);

  }

  return 0;

}

