/*
 * ndpiReader_category_ndb_reload.c
 *
 * The monitor does not guarantee atomic reload across all ndpi_struct pointers;
 * it attempts to converge every instance to the same newest valid file version.
 * Partial failure after some threads succeeded is accepted; the poll
 * returns failure and the snapshot is not advanced.
 */
#include "ndpiReader_category_ndb_reload.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static void snap_copy_from_stat(ndpi_reader_category_ndb_snap_t *snap, const struct stat *st) {
  snap->snap_dev = st->st_dev;
  snap->snap_ino = st->st_ino;
  snap->snap_mtime = st->st_mtime;
  snap->snap_size = st->st_size;
  snap->valid = 1;
}

static int snap_identity_unchanged(const struct stat *st, const ndpi_reader_category_ndb_snap_t *snap) {
  return st->st_dev == snap->snap_dev && st->st_ino == snap->snap_ino && st->st_mtime == snap->snap_mtime &&
    st->st_size == snap->snap_size;
}

int ndpi_reader_category_ndb_snap_init(const char *path, ndpi_reader_category_ndb_snap_t *snap) {
  struct stat st;

  if(!path || !snap)
    return -1;
  memset(snap, 0, sizeof(*snap));
  if(stat(path, &st) != 0)
    return -1;
  snap_copy_from_stat(snap, &st);
  return 0;
}

int ndpi_reader_category_ndb_poll_reload(const char *path,
    ndpi_category_backend_mode_t mode,
    struct ndpi_detection_module_struct *const *ndpi_strs,
    unsigned num_threads,
    ndpi_reader_category_ndb_snap_t *snap) {
  struct stat st;
  const char *modestr =
    (mode == NDPI_CATEGORY_BACKEND_HYBRID) ? "HYBRID" : (mode == NDPI_CATEGORY_BACKEND_NDB_ONLY ? "NDB_ONLY" : "?");

  if(!path || !snap || !snap->valid || !ndpi_strs || num_threads == 0)
    return NDPI_READER_NDB_POLL_ERR_STAT;

  if(stat(path, &st) != 0) {
    fprintf(stderr, "[category-ndb] stat failed for %s: %s\n", path, strerror(errno));
    return NDPI_READER_NDB_POLL_ERR_STAT;
  }

  if(snap_identity_unchanged(&st, snap))
    return NDPI_READER_NDB_POLL_NOCHANGE;

  fprintf(stderr, "[category-ndb] change detected for %s, attempting reload\n", path);

  for(unsigned i = 0; i < num_threads; i++) {
    int rc = ndpi_load_category_ndb_file(ndpi_strs[i], path, mode);
    if(rc != 0) {
      fprintf(stderr,
          "[category-ndb] reload failed for %s (thread=%u mode=%s err=%d), keeping previous database active\n",
          path, i, modestr, rc);
      return NDPI_READER_NDB_POLL_ERR_RELOAD;
    }
  }

  {
    struct stat st2;

    if(stat(path, &st2) == 0)
      snap_copy_from_stat(snap, &st2);
    else {
      fprintf(stderr, "[category-ndb] reload succeeded but post-reload stat failed for %s: %s\n", path,
          strerror(errno));
      snap_copy_from_stat(snap, &st);
    }
  }

  fprintf(stderr, "[category-ndb] reload successful for %s\n", path);
  return NDPI_READER_NDB_POLL_RELOADED;
}
