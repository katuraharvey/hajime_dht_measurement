
#define _WITH_DPRINTF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "log.h"
#include "main.h"
#include "conf.h"
#include "utils.h"
#include "net.h"
#ifdef AUTH
#include "ext-auth.h"
#endif
#include "results.h"
#include "dht.h"
#include "kad.h"

#define IP_STR_LEN 15
/*
* The DHT implementation in KadNode does not store
* results from value searches. Therefore, results for value
* searches are collected and stored here until they expire.
*/

static struct results_t *g_results = NULL;
static size_t g_results_num = 0;
static time_t g_results_expire = 0;

void log_lookup_results(struct results_t *results, int done);

struct results_t* results_get( void ) {
	return g_results;
}

/* Find a value search result */
struct results_t *results_find( const UCHAR id[] ) {
	struct results_t *results;

	results = g_results;
	while( results != NULL ) {
		if( id_equal( results->id, id ) ) {
			return results;
		}
		results = results->next;
	}

	return NULL;
}

int results_count( struct results_t *results ) {
	struct result_t *result;
	int count;

	count = 0;
	result = results->entries;
	while( result ) {
		count++;
		result = result->next;
	}
	return count;
}

int results_entries_count( struct results_t *result ) {
	struct result_t *entry;
	int count;

	count = 0;
	entry = result->entries;
	while( entry ) {
#ifdef AUTH
		/* Omit unverified results */
		if( entry->challenge ) {
			entry = entry->next;
			continue;
		}
#endif
		count++;
		entry = entry->next;
	}

	return count;
}

/* Free a results_t item and all its result_t entries */
void results_item_free( struct results_t *results ) {
	struct result_t *cur;
	struct result_t *next;

	cur = results->entries;
	while( cur ) {
		next = cur->next;
#ifdef AUTH
		free( cur->challenge );
#endif
		free( cur );
		cur = next;
	}

#ifdef AUTH
	free( results->pkey );
#endif
	free( results );
}

void results_debug( int fd ) {
	char buf[256+1];
	struct results_t *results;
	struct result_t *result;
	int results_counter;
	int result_counter;

    fflush(stdout); 
	results_counter = 0;
	results = g_results;
	dprintf( fd, "Result buckets:\n" );
	while( results != NULL ) {
		dprintf( fd, " id: %s\n", str_id( results->id, buf ) );
		dprintf( fd, "  done: %d\n", results->done );
#ifdef AUTH
		if( results->pkey ) {
			dprintf( fd, "  pkey: %s\n", bytes_to_hex( buf, results->pkey, crypto_sign_PUBLICKEYBYTES ) );
		}
#endif
		result_counter = 0;
		result = results->entries;
		while( result ) {
			//dprintf( fd, "   addr: %s\n", str_addr( &result->addr, buf ) );
#ifdef AUTH
			if( results->pkey ) {
				dprintf( fd, "    challenge: %s\n",  result->challenge ? bytes_to_hex( buf, result->challenge, CHALLENGE_BIN_LENGTH ) : "done" );
				dprintf( fd, "    challenges_send: %d\n", result->challenges_send );
			}
#endif
			result_counter++;
			result = result->next;
		}
		dprintf( fd, "  Found %d results.\n", result_counter );
		results_counter++;
		results = results->next;
	}
	dprintf( fd, " Found %d result buckets. Global results counter: %zu.\n\n", 
            results_counter, g_results_num);
    fflush(stdout); 
}

void results_remove( struct results_t *target ) {
	struct results_t *pre;
	struct results_t *cur;
    char buf[257];

    results_debug_print("Removing %s results. %zu total result buckets\n", 
            str_id(target->id, buf), g_results_num);
	cur = g_results;
	pre = NULL;
	while( cur ) {
		if( cur == target ) {
			if( pre ) {
				pre->next = cur->next;
			} else {
				g_results = cur->next;
			}
			results_item_free( target );
			break;
		}
		pre = cur;
		cur = cur->next;
	}
    //This next line was missing in Kadnode, which seemed to be a bug 
    //that limited total number of lookups ever executed rather than 
    //lookups concurrently running
    g_results_num--; 
}

void results_expire( void ) {
	struct results_t *results;
	time_t now;
    char buf[257];

	now = time_now_sec();
	results = g_results;
	while( results ) {
		if( results->start_time < (now - MAX_SEARCH_LIFETIME) ) {
            results_debug_print("Expiring results %s\n",
                    str_id(results->id, buf));
			results_remove( results );
			return;
		}
		results = results->next;
	}
}

/* Hajime
 * Remember the Hajime payload name and date corresponding to the
 * infohash to add to logged results.
 * Clear any existing results data and always create a new bucket
 */
/* Add a new bucket to collect results */
struct results_t* results_add( const char query[], int *is_new,
        char *payload, char *date_str) {
	char hexbuf[SHA1_HEX_LENGTH+1];
	UCHAR id[SHA1_BIN_LENGTH];
	struct results_t* new;
	struct results_t* results;

	if( g_results_num > MAX_SEARCHES ) {
		return NULL;
	}

#ifdef AUTH
	UCHAR pkey[crypto_sign_PUBLICKEYBYTES];
	UCHAR *pkey_ptr = auth_handle_pkey( pkey, id, query );
#else
	id_compute( id, query );
#endif

	/* Search already exists */
    /* Hajime
     *  If result bucket exists, log any partial results then remove.
     */
    if( (results = results_find( id )) != NULL ) {
        results_debug_print("found existing results for %s. Logging then removing.\n",
                str_id((const UCHAR *)query, hexbuf));
        results_done(results, 0);
        *is_new = 1;
        assert((results = results_find( id )) == NULL);
        //return results;
    } else {
        *is_new = 1;
    }

	/* Hajime
     * Add payload and date info to results struct
     */
    new = calloc( 1, sizeof(struct results_t) );
	memcpy( new->id, id, SHA1_BIN_LENGTH );
	new->start_time = time_now_sec();
    if(payload)
        strncpy(new->filename, payload, MAX_FILENAME_LEN);
    if(date_str)
        memcpy(new->file_hash_date_str, date_str, DATE_LEN);

	/* Prepend to list */
	new->next = g_results;
	g_results = new;

	g_results_num++;
	results_debug_print( "Results: Add results bucket for query '%s', id '%s' "
            "filname %s date %s. Total results buckets: %zu\n", query, str_id( id, hexbuf ), new->filename, 
            new->file_hash_date_str, g_results_num);

	return new;
    
}

/* Add an address to an array if it is not already contained in there */
int results_add_addr( struct results_t *results, const IP *addr ) {
	struct result_t *result;
	struct result_t *new;

	if( results->done == 1 ) {
		return -1;
	}

	/* Check if result already exists */
	result = results->entries;
	while( result ) {
		if( addr_equal( &result->addr, addr ) ) {
			return 0;
		}

		if( result->next == NULL ) {
			break;
		}

		result = result->next;
	}

	new = calloc( 1, sizeof(struct result_t) );
	memcpy( &new->addr, addr, sizeof(IP) );

	/* Append new entry */
	if( result ) {
		result->next = new;
	} else {
		results->entries = new;
	}

	return 1;
}

/*
int get_ignore_addrs(char *ignore_addrs){
    errno = 0;
    int num_addrs = 0;
    FILE *f = fopen(IGNORE_ADDRS_FILENAME, "r");
    if(!f){
        log_print("Error %d \n", errno);
        return 0;
    }
    
    char *line = NULL;
    size_t len = 0;
    ssize_t read = 0;
    
    while ((read = getline(&line, &len, f)) != -1) {
        //remove trailing newline
        line[strcspn(line, "\n")] = 0;
        if(strlen(line) == 0){
            continue;
        }
        strncpy(ignore_addrs + (num_addrs * (IP_STR_LEN + 1)), line, IP_STR_LEN);
        num_addrs++;
    }
    free(line);
    fclose(f);
    return num_addrs;
}
*/
/*
int ip_ignore(char *ip, char *ignore_addrs, int num_ignore_addrs){
    int i;

    for(i = 0; i < num_ignore_addrs; i++){
        if(strncmp(ip, ignore_addrs + (i * (IP_STR_LEN + 1)), IP_STR_LEN) == 0){
            //lookup_debug_print("Ignoring %s\n", ip);
            return 1;
        }
    }
    return 0;
}
*/

/* Hajime
 * Log results to file.
 * Open a new file for each day, appending the date to the log filename
 */
void log_lookup_results(struct results_t *results, int done){
    char buf[256+1];
    struct result_t *result;
    int count = 0;
    //int num_ignore_addrs = 0;
    char time_str[26];
	char ipbuf[INET6_ADDRSTRLEN+1];
	unsigned short port;
    //char ignore_addrs[MAX_IGNORE_ADDRS][IP_STR_LEN + 1];
    //memset(ignore_addrs, 0, MAX_IGNORE_ADDRS * (IP_STR_LEN + 1));

    //Get IPs we're announcing on to filter out
    //num_ignore_addrs = get_ignore_addrs(ignore_addrs[0]);
    
    // Get the current time in utc for timestamp
    time_t now;
    struct tm *utc_time;
    time(&now);
    utc_time = gmtime(&now);
    strftime(time_str, 26, "%F", utc_time); 
    
    //open logfile for result infohash
    char filename[257];
    errno = 0;
    snprintf(filename, sizeof(filename), "%s/%s.log", LOOKUP_DATA_DIR, time_str);
    FILE *log = fopen(filename, "a");
    

    if(!log) {
        log_print("Error %d \n", errno);
        //sleep 1 second and try again
        sleep(1);
        errno = 0;
        log = fopen(filename, "a");
        if (!log){
            log_print("ERROR: Failed to open log file %s. printing to stdout\n", filename);
            log_print("Error %d \n", errno);
            log = stdout;
        }
    }

    result = results->entries;
    while( result ) {
		inet_ntop( AF_INET, &((IP4 *)&result->addr)->sin_addr, ipbuf, sizeof(ipbuf) );
        //if(!ip_ignore(ipbuf, ignore_addrs[0], num_ignore_addrs)){
            port = ntohs( ((IP4 *)&result->addr)->sin_port );
            // timestamp payload_filename payload_hash_date infohash [seeder|leecher] ip port
            fprintf(log, "%ld %s %s %s seeder %s %hu\n", 
                    now, results->filename, results->file_hash_date_str,
                    str_id( results->id, buf), ipbuf, port);
            count++;
        //}
      if( result->next == NULL ) {
        break;
      }

      result = result->next;
    }
    
    fflush(log);
    if (log != stdout) 
        fclose(log);

}

static void result_node_free(struct result_node *rn){
    results_item_free(rn->results);
    free(rn->from_node);
    free(rn);
}

/* Hajime
 * Log result node data to file then free the result node structs
 * All results from all result nodes, plus a summary line, are written
 * to file (these files get huge)
 */
void result_nodes_done(struct search *sr, int done){
    char buf0[257], buf1[256+1], buf2[256+1];
    struct result_t *result;
    int count = 0;
    //int num_ignore_addrs;
    //char ignore_addrs[MAX_IGNORE_ADDRS][IP_STR_LEN + 1];
    //memset(ignore_addrs, 0, MAX_IGNORE_ADDRS * (IP_STR_LEN + 1));
    char time_str[26];

    // Get the current time in utc for timestamp
    time_t now;
    struct tm *utc_time;
    time(&now);
    utc_time = gmtime(&now);
    strftime(time_str, 26, "%F", utc_time); 

    //Get IPs we're announcing on to filter out
    //num_ignore_addrs = get_ignore_addrs(ignore_addrs[0]);

    search_debug_print("result nodes done for search %s: %d\n",
           str_id(sr->id, buf0), done); 
    //open logfile for result infohash
    char filename[256];
    snprintf(filename, sizeof(filename), "%s/result_node_responses_%s.log", 
            RESULT_NODE_DATA_DIR, time_str);
    errno = 0;
    FILE *log = fopen(filename, "a");
	char ipbuf[INET6_ADDRSTRLEN+1];
	unsigned short port;


    if(!log) {
        log_print("Error %d \n", errno);
        //sleep 1 second and try again
        sleep(1);
        log = fopen(filename, "a");
        if (!log){
            log_print("ERROR: Failed to open log file %s. printing to stdout\n", filename);
        log_print("Error %d \n", errno);
            log = stdout;
        }
    }

    struct result_node *rn, *next;
    rn = sr->result_nodes;

    while(rn){
        result = rn->results->entries;
        count = 0;
        while( result ) {
		    inet_ntop( AF_INET, &((IP4 *)&result->addr)->sin_addr, ipbuf, sizeof(ipbuf) );
            //if(!ip_ignore(ipbuf, ignore_addrs[0], num_ignore_addrs)){
                // %seeder_addr timestamp infohash from_node_id from_node_addr complete new_result_responses no_new_result_responses
                port = ntohs( ((IP4 *)&result->addr)->sin_port );
                fprintf(log, "%ld %s %s %s %s %hu\n", 
                        now,
                        str_id(sr->id, buf0),
                        str_addr(&rn->from_node->ss, buf1),
                        str_id(rn->from_node->id, buf2),
                        ipbuf, port);
                count++;
            //}
            result = result->next;
        }
        fprintf(log, "#%ld %s %s %s Total seeders: %d new_results_responses: %d "
                "no_new_results_responses: %d (%d sequential)\n", 
                now, str_id(sr->id, buf2), str_id(rn->from_node->id, buf0), 
                str_addr(&rn->from_node->ss, buf1),
                count,
                rn->num_new_results_responses, rn->num_no_new_results_responses,
                rn->sequential_no_new_results_responses);
        
        //free the result_node
        next = rn->next;
        result_node_free(rn);
        rn = next;
    }
    
    //clean up search
    sr->result_nodes = NULL;
    fflush(log); 
    if(log != stdout) 
        fclose(log);

}

int results_done( struct results_t *results, int done ) {
    char buf[257];
	results_debug_print("results_done %s: %d\n", str_id(results->id, buf), done);
    if( done ) {
		results->done = 1;
	
        /*Hajime 
         * Log results, then remove search
         */
        log_lookup_results(results, done);
		results_remove( results );
	} else {
        /*Hajime
         * We get here if we're starting a new search for this infohash
         * when the old one hasn't finished. Log partial results then 
         * restart
         */
        log_lookup_results(results, done);
		results_remove( results );
		//results->start_time = time_now_sec();
		//results->done = 0;
	}
	return 0;
}

int results_collect( struct results_t *results, IP addr_array[], size_t addr_num ) {
	struct result_t *result;
	size_t i;

	if( results == NULL ) {
		return 0;
	}

	i = 0;
	result = results->entries;
	while( result && i < addr_num ) {
#ifdef AUTH
		/* If there is a challenge - then the address is not verified yet */
		if( results->pkey && result->challenge ) {
			result = result->next;
			continue;
		}
#endif
		memcpy( &addr_array[i], &result->addr, sizeof(IP) );
		i++;
		result = result->next;
	}

	return i;
}

void results_handle( int _rc, int _sock ) {
	/* Expire value search results */
	if( g_results_expire <= time_now_sec() ) {
		results_expire();

		/* Try again in ~2 minutes */
		g_results_expire = time_add_min( 2 );
	}
}

void results_setup( void ) {
	net_add_handler( -1, &results_handle );
}

void results_free( void ) {
	struct results_t *cur;
	struct results_t *next;

	cur = g_results;
	while( cur ) {
		next = cur->next;
		results_item_free( cur );
		cur = next;
	}

	g_results = NULL;
}
