#define _WITH_DPRINTF
#define _XOPEN_SOURCE 700
//#define __USE_XOPEN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#include "log.h"
#include "conf.h"
#include "utils.h"
#include "net.h"
#include "kad.h"
#ifdef AUTH
#include "ext-auth.h"
#endif
#include "values.h"

/* Announce values every 20 minutes */
#define ANNOUNCE_INTERVAL (20*60)
#define ANNOUNCE_MAINTENANCE_TIME 5
#define VALUE_LIFETIME (20 * 60)
#define PORT_INCREMENT 50

static time_t g_values_expire = 0;
static time_t g_values_announce = 0;
static struct value_t *g_values = NULL;

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

int values_add( const char query[], int port, time_t lifetime,
        char *payload, char *date_str) {
	char hexbuf[SHA1_HEX_LENGTH+1];
	UCHAR id[SHA1_BIN_LENGTH];
	struct value_t *cur;
	struct value_t *new;
	time_t now;

	id_compute( id, query );
	
    if( port < 0 || port > 65535 ) {
		return 0;
	}

	now = time_now_sec();

	/* Value already exists - refresh */
	if( (cur = values_find( id )) != NULL ) {
		cur->refresh = now - 1;

		if( lifetime > now ) {
			cur->lifetime = lifetime;
            log_print("%s exists. Reset lifetime to %ld\n", 
                    str_id(id, hexbuf), cur->lifetime);
		}

		/* Trigger immediate handling */
		g_values_announce= 0;

		return 0;
	}

    /*Hajime
     * Assign infohash to announce a port. This pretty ugly and ad hoc - 
     * designed to minimize interruptions to measurments already taking
     * place. Each infohash is announced on a range of ports (with the goal
     * of increasing the chances of bots connecting to us to download). Each
     * new announcement is assigned a new port range by incrementing the 
     * last used range, eventually wrapping around. Infohash to port mappings 
     * are maintained in a file also read by the uTP server listening for
     * connections, which maps a port for a received connection back to its
     * announced infohash. The port mapping file is periodically rewritten to
     * prevent conflicting infohash to port mappings when the port ranges wrap
     * around. Infohashes to announce are read in from the infohash file. 
     * Filenames and paths are configurable and defined in kad.h
     */
    char *line = NULL, *last_line = NULL;	
    size_t len = 0;
    ssize_t read;
    char *last_port;
    int next_port;
    FILE *port_map_file = fopen(PORT_MAP_FILENAME, "r+");

    // Log port mapping
    if(!port_map_file){
        //sleep 1 second and try again
        sleep(1);
        port_map_file = fopen(PORT_MAP_FILENAME, "r+");
        if (!port_map_file){
	// doesn't exist, start at min port and create file
        	port_map_file = fopen(PORT_MAP_FILENAME, "w");
        	next_port = MIN_PORT;
        }
    }
    else{
	    // go to last line to get last used port
	    while ((read = getline(&line, &len, port_map_file)) != -1) {
		last_line = line;
	    }
	    // otherwise incremenet the last used port
		last_port = strtok(line, " ");
		next_port = atoi(last_port) + PORT_INCREMENT;

		//wrap around
		if(next_port >= MAX_PORT)
		    next_port = MIN_PORT;
	    if(next_port < MIN_PORT){
		log_print("ERROR getting port from port_map\n");
		exit(1);
	    }    
    }

    /* Prepend new entry */
	new = (struct value_t*) calloc( 1, sizeof(struct value_t) );
	memcpy( new->id, id, SHA1_BIN_LENGTH );
	new->port = next_port;
	new->refresh = now - 1;
	new->lifetime = (lifetime > now) ? lifetime : (now + 100);

	log_debug( "VAL: Add value id %s:%hu.",  str_id( id, hexbuf ), new->port );
    ap_debug_print("adding announcement for %s %d\n", 
            str_id(id, hexbuf), new->port);
	/* Prepend to list */
	new->next = g_values;
	g_values = new;

	/* Trigger immediate handling */
	g_values_announce= 0;

    // Add to the port map file
    fprintf(port_map_file, "%d %s %s %s\n", 
            new->port, str_id(id, hexbuf), payload, date_str);
    fclose(port_map_file); 
    
    return 1;
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
/* Hajime 
 * Read infohashes from file and send announce_peer messages to the 
 * DHT that we are a seeder for the infohash.
 */
static int add_announcements(){
    FILE *hash_file = fopen(HASH_FILENAME, "r");
    if(!hash_file){
        log_print("ERROR opening hash file %s\n", HASH_FILENAME);
        exit(1);
    }

    char *line;
    size_t len = 0;
    ssize_t read;
    int rc = 0;

    char *infohash, *payload, *date_str;
    int new_value_added = 0;

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
            // Only increase the running port number if we actually added a new 
            //  value
            new_value_added += values_add( infohash, 0, time_now_sec() + VALUE_LIFETIME, 
                    payload, date_str);
        }
    }
    free(line);
    fclose(hash_file);

    // if a new value was added, rewrite port_map file to delete old entries
    char buf[1024];
    int buf_len = 1024;
    char *port;
    time_t now, line_t;
    struct tm line_tm;
    time(&now);
    int secs_in_3_days = 60 * 60 * 24 * 3;

    if(new_value_added){
        FILE *old_ports, *new_ports;
        old_ports = fopen(PORT_MAP_FILENAME, "r");
        new_ports = fopen(PORT_TMP_FILENAME, "w");
        while(fgets(buf, buf_len, old_ports)){
            buf[strcspn(buf, "\n")] = 0;
            if(strlen(buf) > 0){
                port = strtok(buf, " ");
                infohash = strtok(NULL, " ");
                payload = strtok(NULL, " ");
                date_str = strtok(NULL, " ");

                strptime(date_str, "%Y-%m-%d", &line_tm);
                line_t = mktime(&line_tm);
                //this is imprecise, but only copy over entries less than three days in the past
                if(now - secs_in_3_days < line_t)
                    fprintf(new_ports, "%s %s %s %s\n", port, infohash, payload, date_str);
            }
        }
        fclose(old_ports);
        fclose(new_ports);
        rename(PORT_TMP_FILENAME, PORT_MAP_FILENAME);
    }
                
    return rc;
}
#endif

void values_announce( void ) {
	struct value_t *value;
	time_t now;
    int i, port;

	now = time_now_sec();
	value = g_values;
	while( value ) {
		if( value->refresh < now ) {
#ifdef DEBUG
			char hexbuf[SHA1_HEX_LENGTH+1];
			ap_debug_print( "VAL: Announce %s:%hu",  
                    str_id( value->id, hexbuf ), value->port );
#endif
            /*Hajime
             * Send announce_peer for each port in port range
             */
            port = value->port;
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
	if( g_values_expire <= time_now_sec() ) {
		values_expire();

		//Try again in ~1 minute 
		g_values_expire = time_add_min( ANNOUNCE_MAINTENANCE_TIME );
	}

	if( g_values_announce <= time_now_sec() && kad_count_nodes( 0 ) != 0 ) {
        /*Hajime
         * Check infohash file for new payloads to announce
         */
#ifdef ANNOUNCEMENTS
        add_announcements();
#endif
		values_announce();

		/* Try again in ~1 minute */
		g_values_announce = time_add_min(ANNOUNCE_MAINTENANCE_TIME );
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
