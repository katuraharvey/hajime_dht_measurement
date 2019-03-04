
#ifndef _EXT_RESULTS_H_
#define _EXT_RESULTS_H_

#ifdef AUTH
#include <sodium.h>
#define CHALLENGE_BIN_LENGTH 16
#endif

#include "dht.h"

#define MAX_RESULTS_PER_SEARCH 16384
#define MAX_SEARCHES 2048
#define MAX_SEARCH_LIFETIME (32*60)
#define DATE_LEN 10
#define MAX_FILENAME_LEN 256

/* An address that was received as a result of an id search */
struct result_t {
	struct result_t *next;
	IP addr;
#ifdef AUTH
	UCHAR *challenge;
	int challenges_send;
#endif
};

/* A bucket of results received when searching of an id */
struct results_t {
	struct results_t *next;
	/* The value id to search for */
	UCHAR id[SHA1_BIN_LENGTH];
#ifdef AUTH
	UCHAR *pkey;
#endif
	time_t start_time;
	struct result_t *entries;
	int done;
    char filename[MAX_FILENAME_LEN + 1]; //name of payload file
    char file_hash_date_str[DATE_LEN + 1]; //YYYY-MM-DD used with filename to produce id
};

struct results_t *results_get( void );
struct results_t *results_find( const UCHAR id[] );
void result_nodes_done(struct search *sr, int done);

/* Register a handler to call results_expire in intervalls */
void results_setup( void );
void results_free( void );

/* Create and append a new results item */
struct results_t *results_add( const char query[], int *is_new, char *payload,
        char *date_str);

/* Add an address to a result bucket */
int results_add_addr( struct results_t *results, const IP *addr );

/* Collect addresses */
int results_collect( struct results_t *results, IP addr_array[], size_t addr_num );

/* Mark as done */
int results_done( struct results_t *results, int done );

/* Count (valid) result entries */
int results_entries_count( struct results_t *result );

void results_debug( int fd );

#endif /* _EXT_RESULTS_H_ */
