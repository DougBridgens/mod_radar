/** 
 * Copyright 2011 Doug Bridgens (doug.bridgens@soogate.com)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * mod_radar: a request monitoring module.
 *
 * writes pre content_handler times to a db file,
 * removes db entries once the request has completed.
 * using a db viewer (eg dump.pl), requests currently
 * being processed can be displayed, with the duration
 * spent in the content handler.
 *
 * stages -
 * post_config    : setup mutex lock, remove old db file
 * child_init     : attach to mutex
 * post_read      : record time
 * translate_name : record time
 * map_to_storage : record time
 * header_parser  : record time
 * access_checker : record time
 * check_user_id  : record time
 * auth_checker   : record time
 * type_checker   : record time
 * fixups         : record time, write times to db
 * content_handler: <nothing>
 * log_transaction: record time, remove record from db
 * 
 * author  : doug.bridgens@soogate.com
 * date    : 15/06/2011
 * version : 0.1 (very beta)
 *
 * change history:
 *
 * added flag req_stats->remove_from_database, only try
 * and remove keys we know we've added
 * - 15/06/2011 doug.bridgens@soogate.com
 *
 * intial code
 * - 10/06/2011 doug.bridgens@soogate.com
 */ 

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_config.h"
#include "apr_dbm.h"
#include "apr_file_info.h"
#include "apr_file_io.h"
#include "apr_global_mutex.h"
#include "apr_hash.h"
#include "apr_strings.h"
#include "apr_strmatch.h"
#include "apr_time.h"

#if APR_HAS_THREADS
#include "apr_thread_mutex.h"
#endif

#ifdef AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif


#define DATABASE "/tmp/radar.db"
#define LOCKFILE "/tmp/radar.lock"
#define DB_TYPE "DB"
#define DB_STORE 0
#define DB_REMOVE 1

extern module AP_MODULE_DECLARE_DATA radar_module;
static void checkpoint(int action, request_rec *r);

typedef struct req_stats {
  long dur_ms_post_read;
  long dur_ms_translate_name;
  long dur_ms_map_to_storage;
  long dur_ms_header_parser;
  long dur_ms_access_checker;
  long dur_ms_check_user_id;
  long dur_ms_auth_checker;
  long dur_ms_type_checker;
  long dur_ms_fixups;
  long dur_ms_log_transaction;
  int remove_from_database;
} req_stats;

static const char *lockname = LOCKFILE;
static apr_global_mutex_t *radar_mutex = NULL;

static int my_post_config(apr_pool_t *pool, apr_pool_t *plog,
                apr_pool_t *ptemp, server_rec *s)
{
 /**
  * FIXME: this function is called twice during startup,
  * some logic to skipped the first (config test) pass is required.
  */

  apr_status_t rv;

 /** 
  * create the global lock used when writing to the database
  * file. if we fail to create the lock should we bail out, or 
  * let apache continue to function ?
  */
  rv = apr_global_mutex_create(&radar_mutex, lockname, APR_LOCK_DEFAULT, pool);
  if (rv != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                  "mod_radar [post_config]: failed to create global mutex (%s), errno: %d", lockname, rv);
    return HTTP_INTERNAL_SERVER_ERROR;
  }

#ifdef AP_NEED_SET_MUTEX_PERMS
  rv = unixd_set_global_mutex_perms(radar_mutex);
  if (rv != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                  "mod_radar [post_config]: could not set permissions on lockfile (%s).", lockname);
    return HTTP_INTERNAL_SERVER_ERROR;
  }
#endif


 /**
  * remove the old database file, if it exists. the keys are
  * pid's, which will be reused on a restart.
  */

  FILE *fp;

  if ((fp = fopen(DATABASE, "r"))) {
    fclose(fp);
    if((apr_file_remove(DATABASE, pool)) != APR_SUCCESS) {
      ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                  "mod_radar [post_config]: failed to remove database file (%s)."
                   "results may be inconsistent.",
                   DATABASE);
    }
  }
  return DECLINED;
}

static void my_child_init(apr_pool_t *pool, server_rec *s)
{
 /**
  * attach this child process to the global mutex
  *
  */
  apr_status_t rv;

  rv = apr_global_mutex_child_init(&radar_mutex, lockname, pool);
  if (rv != APR_SUCCESS) {
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                  "mod_radar [child_init]:failed to attach to global mutex (%s).", lockname);
  }
}
static int my_post_read(request_rec *r)
{
 /**
  * setup the timing struct in the request config, 
  * initializing the values.
  */

  req_stats *my_stats;
  my_stats = apr_palloc(r->pool, sizeof(req_stats)) ;
  ap_set_module_config(r->request_config, &radar_module, my_stats);

  /* set defaults */
  my_stats->dur_ms_post_read = 0;
  my_stats->dur_ms_translate_name = 0;
  my_stats->dur_ms_map_to_storage = 0;
  my_stats->dur_ms_header_parser = 0;
  my_stats->dur_ms_access_checker = 0;
  my_stats->dur_ms_check_user_id = 0;
  my_stats->dur_ms_auth_checker = 0;
  my_stats->dur_ms_type_checker = 0;
  my_stats->dur_ms_fixups = 0;
  my_stats->dur_ms_log_transaction = 0;
  my_stats->remove_from_database = 0;

  return DECLINED;
}

static int my_translate_name(request_rec *r)
{
  /* r->main != NULL means we are in a subrequest */
  if (r->main == NULL) {
    req_stats *my_stats = ap_get_module_config(r->request_config, &radar_module);
    my_stats->dur_ms_translate_name = apr_time_now() - r->request_time;
  }
  return DECLINED;
}
static int my_map_to_storage(request_rec *r)
{
  if (r->main == NULL) {
    req_stats *my_stats = ap_get_module_config(r->request_config, &radar_module);
    my_stats->dur_ms_map_to_storage = apr_time_now() - r->request_time;
  }
  return DECLINED;
}
static int my_header_parser(request_rec *r)
{
  if (r->main == NULL) {
    req_stats *my_stats = ap_get_module_config(r->request_config, &radar_module);
    my_stats->dur_ms_header_parser = apr_time_now() - r->request_time;
  }
  return DECLINED;
}
static int my_access_checker(request_rec *r)
{
  if (r->main == NULL) {
    req_stats *my_stats = ap_get_module_config(r->request_config, &radar_module);
    my_stats->dur_ms_access_checker = apr_time_now() - r->request_time;
  }
  return DECLINED;
}

static int my_check_user_id(request_rec *r)
{
  if (r->main == NULL) {
    req_stats *my_stats = ap_get_module_config(r->request_config, &radar_module);
    my_stats->dur_ms_check_user_id = apr_time_now() - r->request_time;
  }
  return DECLINED;
}
static int my_auth_checker(request_rec *r)
{
  if (r->main == NULL) {
    req_stats *my_stats = ap_get_module_config(r->request_config, &radar_module);
    my_stats->dur_ms_auth_checker = apr_time_now() - r->request_time;
  }
  return DECLINED;
}
static int my_type_checker(request_rec *r)
{
  if (r->main == NULL) {
    req_stats *my_stats = ap_get_module_config(r->request_config, &radar_module);
    my_stats->dur_ms_type_checker = apr_time_now() - r->request_time;
  }
  return DECLINED;
}
static int my_fixups(request_rec *r)
{

  if (r->main == NULL && r->prev == NULL) {
    req_stats *my_stats = ap_get_module_config(r->request_config, &radar_module);
    my_stats->dur_ms_fixups = apr_time_now() - r->request_time;

    checkpoint(DB_STORE, r);
  }
  return DECLINED;
}

static int my_log_transaction(request_rec *r)
{

  if (r->main == NULL && r->prev == NULL) {
    req_stats *my_stats = ap_get_module_config(r->request_config, &radar_module);
    my_stats->dur_ms_log_transaction = apr_time_now() - r->request_time;

    checkpoint(DB_REMOVE, r);
  }
  return DECLINED;
}
static void radar_register_hooks(apr_pool_t *p)
{
  ap_hook_post_config(my_post_config, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_child_init(my_child_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_post_read_request(my_post_read, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_translate_name(my_translate_name, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_map_to_storage(my_map_to_storage, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_header_parser(my_header_parser, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_access_checker(my_access_checker, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_check_user_id(my_check_user_id, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_auth_checker(my_auth_checker, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_type_checker(my_type_checker, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_fixups(my_fixups, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_log_transaction(my_log_transaction, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA radar_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    radar_register_hooks   /* register hooks                      */
};

static void checkpoint(int action, request_rec *r)
{
  apr_dbm_t *dbm;
  apr_datum_t key;
  apr_datum_t val;
  apr_status_t rv;
  char errbuf[120];
  char *tmp;

  req_stats *my_stats = ap_get_module_config(r->request_config, &radar_module);

  /* don't try and remove data that's not there */
  if (action == DB_REMOVE && my_stats->remove_from_database == 0) {
    return;
  }

  tmp = apr_psprintf(r->pool, "%s", ap_append_pid(r->pool, "", ""));
  key.dptr = tmp;
  key.dsize = strlen(tmp);

  /* store in the database */
  if (action == 0) {
    tmp = apr_psprintf(r->pool, "%s, %li, %li, %li, %li, %li, %li, %li, %li, %li, %li, %li, %s",
                 r->connection->remote_ip,
                 r->request_time,
                 my_stats->dur_ms_post_read,
                 my_stats->dur_ms_translate_name,
                 my_stats->dur_ms_map_to_storage,
                 my_stats->dur_ms_header_parser,
                 my_stats->dur_ms_access_checker,
                 my_stats->dur_ms_check_user_id,
                 my_stats->dur_ms_auth_checker,
                 my_stats->dur_ms_type_checker,
                 my_stats->dur_ms_fixups,
                 my_stats->dur_ms_log_transaction,
                 r->uri
                      );
      val.dptr = tmp;
      val.dsize = strlen(tmp);
  }

 /**
  * FIXME: switch to a 'try' request for the lock, possibly have two attempts
  * before failure; don't want to hold up the request processing.
  *
  */

  /* request global mutex before opening the database */
  rv = apr_global_mutex_lock(radar_mutex);
  if (rv != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                 "mod_radar [checkpoint]: pid %s failed to acquire global mutex. error: %s",
                  ap_append_pid(r->pool, "", ""),
                  apr_strerror(rv, errbuf, sizeof(errbuf)));
  }
  else {

    /* try to open the database */
    rv = apr_dbm_open_ex(&dbm, DB_TYPE, DATABASE, APR_DBM_RWCREATE,
                         APR_OS_DEFAULT, r->pool);
    if (rv != APR_SUCCESS) {
      ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                   "mod_radar [checkpoint]: failed to open database (%s), conn id %li, %s. error: %s",
                    ap_append_pid(r->pool, "", ""),
                    r->connection->id,
                    r->uri,
                    apr_strerror(rv, errbuf, sizeof(errbuf)));
    }
    else {
      /* success opening the database */
      if (action == DB_STORE) {
        /* try writing our key=>value */
        rv = apr_dbm_store(dbm, key, val);
        if (rv != APR_SUCCESS) {
          /* database write failed */
          ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                       "mod_radar [checkpoint]: pid %s failed to write to the database. error: %s",
                        ap_append_pid(r->pool, "", ""),
                        apr_strerror(rv, errbuf, sizeof(errbuf)));
        }
        else {
          my_stats->remove_from_database = 1;
        }
      } 
      else {
        /* try deleting the key */
        rv = apr_dbm_delete(dbm, key);
        if (rv != APR_SUCCESS) {
          /* database write failed */
          ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                       "mod_radar [checkpoint]: pid %s failed to delete itself from the database. error: %s",
                        ap_append_pid(r->pool, "", ""),
                        apr_strerror(rv, errbuf, sizeof(errbuf)));
        }
      }

      /* close the database before releasing the lock */
      apr_dbm_close(dbm);
    }

    /* release the global mutex */
    rv = apr_global_mutex_unlock(radar_mutex);
    if (rv != APR_SUCCESS) {
      ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r,
                   "mod_radar [checkpoint]: pid %s failed to release the global mutex. error: %s", 
                    ap_append_pid(r->pool, "", ""),
                    apr_strerror(rv, errbuf, sizeof(errbuf)));
    }
  }
}
