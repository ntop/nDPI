/*
 * ndpiReader_category_ndb_reload.h — periodic .ndb hot-reload helper.
 *
 * Goal: converge all ndpi_struct instances to the latest valid on-disk file;
 *       does not guarantee atomic swap across threads (see comments in .c).
 *
 * Return convention for ndpi_reader_category_ndb_poll_reload():
 *   0  = no change vs snapshot (does not call ndpi_load_category_ndb_file)
 *   1  = file changed and reload succeeded on all threads
 *   <0 = operational error (use logs or future distinct negative codes to
 *        distinguish stat failure vs reload failure)
 */
#ifndef NDPI_READER_CATEGORY_NDB_RELOAD_H
#define NDPI_READER_CATEGORY_NDB_RELOAD_H

#include <sys/stat.h>

#include "ndpi_api.h"

struct ndpi_detection_module_struct;

/* Field names avoid st_* members (e.g. st_mtime is a macro on some platforms). */
typedef struct {
  dev_t snap_dev;
  ino_t snap_ino;
  time_t snap_mtime;
  off_t snap_size;
  int valid;
} ndpi_reader_category_ndb_snap_t;

#define NDPI_READER_NDB_POLL_NOCHANGE   0
#define NDPI_READER_NDB_POLL_RELOADED   1
#define NDPI_READER_NDB_POLL_ERR_STAT   -1
#define NDPI_READER_NDB_POLL_ERR_RELOAD -2

int ndpi_reader_category_ndb_snap_init(const char *path, ndpi_reader_category_ndb_snap_t *snap);

int ndpi_reader_category_ndb_poll_reload(const char *path,
    ndpi_category_backend_mode_t mode,
    struct ndpi_detection_module_struct *const *ndpi_strs,
    unsigned num_threads,
    ndpi_reader_category_ndb_snap_t *snap);

#endif /* NDPI_READER_CATEGORY_NDB_RELOAD_H */
