
#define _WITH_DPRINTF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include "log.h"
#include "conf.h"
#include "utils.h"
#include "net.h"
#include "kad.h"
#ifdef AUTH
#include "ext-auth.h"
#endif
#include "values.h"

/* Announce values every 10 minutes */
#define ANNOUNCE_INTERVAL (10*60)

//static time_t g_values_expire = 0;
static time_t g_values_announce = 0;
static struct value_t *g_values = NULL;
#ifdef ANNOUNCEMENTS
static int running_port_num = MIN_PORT;
#endif

struct value_t* values_get( void ) {
	return g_values;
}

struct value_t* values_find( UCHAR id[] ) {
	struct value_t *value;

	value = g_values;
	while( value ) {
		if( id_equal( id, value->id ) ) {
			return value;
		}
		value = value->next;
	}
	return NULL;
}

int values_count( void ) {
	struct value_t *value;
	int count;

	count = 0;
	value = g_values;
	while( value ) {
		count++;
		value = value->next;
	}

	return count;
}

void values_debug( int fd ) {
	char hexbuf[SHA1_HEX_LENGTH+1];
	struct value_t *value;
	time_t now;
	int value_counter;

	now = time_now_sec();
	value_counter = 0;
	value = g_values;
	dprintf( fd, "Announced values:\n" );
	while( value ) {
		dprintf( fd, " id: %s\n", str_id( value->id, hexbuf ) );
		dprintf( fd, "  port: %d\n", value->port );
		if( value->refresh < now ) {
			dprintf( fd, "  refresh: now\n" );
		} else {
			dprintf( fd, "  refresh: in %ld min\n", (value->refresh - now) / 60 );
		}

		if( value->lifetime == LONG_MAX ) {
			dprintf( fd, "  lifetime: infinite\n" );
		} else {
			dprintf( fd, "  lifetime: %ld min left\n", (value->lifetime -  now) / 60 );
		}

#ifdef AUTH
		if( value->skey ) {
			char sbuf[2*crypto_sign_SECRETKEYBYTES+1];
			dprintf( fd, "  skey: %s\n", bytes_to_hex( sbuf, value->skey, crypto_sign_SECRETKEYBYTES ) );
		}
#endif

		value_counter++;
		value = value->next;
	}

	dprintf( fd, " Found %d values.\n", value_counter );
}

struct value_t *values_add( const char query[], int port, time_t lifetime,
        char *payload, char *date_str) {
	char hexbuf[SHA1_HEX_LENGTH+1];
	UCHAR id[SHA1_BIN_LENGTH];
	struct value_t *cur;
	struct value_t *new;
	time_t now;

#ifdef AUTH
	UCHAR skey[crypto_sign_SECRETKEYBYTES];
	UCHAR *skey_ptr = auth_handle_skey( skey, id, query );

	if( skey_ptr ) {
		if( port == 0 ) {
			/* Authenticationis is done over the DHT port */
			port = atoi( gconf->dht_port );
		} else {
			return NULL;
		}
	}
#else
	id_compute( id, query );
#endif
/*
	if( port == 0 ) {
		port = port_random();
	}
*/
	if( port < 1 || port > 65535 ) {
		return NULL;
	}

	now = time_now_sec();

	/* Value already exists - refresh */
	if( (cur = values_find( id )) != NULL ) {
		cur->refresh = now - 1;

		if( lifetime > now ) {
			cur->lifetime = lifetime;
		}

		/* Trigger immediate handling */
		g_values_announce= 0;

		return cur;
	}

	/* Prepend new entry */
	new = (struct value_t*) calloc( 1, sizeof(struct value_t) );
	memcpy( new->id, id, SHA1_BIN_LENGTH );
#ifdef AUTH
	if( skey_ptr ) {
		new->skey = memdup( skey_ptr, crypto_sign_SECRETKEYBYTES );
	}
#endif
	new->port = port;
	new->refresh = now - 1;
	new->lifetime = (lifetime > now) ? lifetime : (now + 100);

	log_debug( "VAL: Add value id %s:%hu.",  str_id( id, hexbuf ), port );
    ap_debug_print("%ld adding announcement for %s %d\n", 
            time_now_sec(), str_id(id, hexbuf), port);

	/* Prepend to list */
	new->next = g_values;
	g_values = new;

	/* Trigger immediate handling */
	g_values_announce= 0;
#ifdef ANNOUNCEMENTS
	// Log port mapping
    FILE *port_map_file = fopen(PORT_MAP_FILENAME, "a");
    if(!port_map_file){
        //sleep 1 second and try again
        sleep(1);
        port_map_file = fopen(PORT_MAP_FILENAME, "a");
        if (!port_map_file){
            dprintf(1, "ERROR: Failed to open log file %s\n", PORT_MAP_FILENAME);
            return NULL;
        }
    }
    fprintf(port_map_file, "%d %s %s %s\n", 
            port, str_id(id, hexbuf), payload, date_str);
    fclose(port_map_file); 
#endif
    return new;
}

void value_free( struct value_t *value ) {
#ifdef AUTH
	/* Secure erase */
	if( value->skey ) {
		memset( value->skey, '\0', crypto_sign_SECRETKEYBYTES );
		free( value->skey );
	}
#endif
	free( value );
}

/* Remove an element from the list - internal use only */
void values_remove( struct value_t *value ) {
	struct value_t *pre;
	struct value_t *cur;

	pre = NULL;
	cur = g_values;
	while( cur ) {
		if( cur == value ) {
			if( pre ) {
				pre->next = cur->next;
			} else {
				g_values = cur->next;
			}
			value_free( cur );
			return;
		}
		pre = cur;
		cur = cur->next;
	}
}

void values_expire( void ) {
	struct value_t *pre;
	struct value_t *cur;
	time_t now;

	now = time_now_sec();
	pre = NULL;
	cur = g_values;
	while( cur ) {
		if( cur->lifetime < now ) {
			if( pre ) {
				pre->next = cur->next;
			} else {
				g_values = cur->next;
			}
			value_free( cur );
			return;
		}
		pre = cur;
		cur = cur->next;
	}
}

#ifdef ANNOUNCEMENTS
static int add_announcements(){
    FILE *hash_file = fopen(HASH_FILENAME, "r");
    if(!hash_file){
        printf("ERROR opening hash file %s\n", HASH_FILENAME);
        exit(1);
    }

    char *line;
    size_t len = 0;
    ssize_t read;
    int rc = 0;

    char *infohash, *payload, *date_str;
    
    //send announcement for each info hash in file
    //ports are incremented so each infohash has unique port starting at 6882
    while ((read = getline(&line, &len, hash_file)) != -1) {
        //remove trailing newline
        line[strcspn(line, "\n")] = 0;
        if(strlen(line) > 0){
            infohash = strtok(line, " ");
            payload = strtok(NULL, " ");
            date_str = strtok(NULL, " ");
    
            //add infohash and starting port number to values
            // multiple announcements taken care of in values_announce
            values_add( infohash, running_port_num, LONG_MAX,
                    payload, date_str);
            running_port_num += 100;
            
        }
    }
    free(line);
    fclose(hash_file);
    return rc;
}
#endif

void values_announce( void ) {
	struct value_t *value;
	time_t now;
    int i, port;
    //check the infohash file for new values to announce

	now = time_now_sec();
	value = g_values;
	while( value ) {
		if( value->refresh < now ) {
#ifdef DEBUG
			char hexbuf[SHA1_HEX_LENGTH+1];
			ap_debug_print( "%ld VAL: Announce %s:%hu",  
                    time_now_sec(), str_id( value->id, hexbuf ), value->port );
#endif
            port = value->port;
            // Announce multiple ports
            //TODO: do we want to make this smart and announce more ports
            //for the current day's hashes?
            for(i = 0; i < PORTS_PER_ANNOUNCE; i++){
    			kad_announce_once( value->id, port++);
            }
			value->refresh = now + ANNOUNCE_INTERVAL;
		}
		value = value->next;
	}
}

void values_handle( int _rc, int _sock ) {
	/* Expire search results */
    //Hajime - don't expire announcements
	/*if( g_values_expire <= time_now_sec() ) {
		values_expire();

		//Try again in ~1 minute 
		g_values_expire = time_add_min( 1 );
	}*/


	if( g_values_announce <= time_now_sec() && kad_count_nodes( 0 ) != 0 ) {
#ifdef ANNOUNCEMENTS
        //check for new payloads to announce
        add_announcements();
#endif
		values_announce();

		/* Try again in ~1 minute */
		g_values_announce = time_add_min( 1 );
	}
}

void values_setup( void ) {
	/* Cause the callback to be called in intervals */
	net_add_handler( -1, &values_handle );
}

void values_free( void ) {
	struct value_t *cur;
	struct value_t *next;

	cur = g_values;
	while( cur ) {
		next = cur->next;
		value_free( cur );
		cur = next;
	}
	g_values = NULL;
}
