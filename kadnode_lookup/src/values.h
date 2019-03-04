
#ifndef _EXT_VALUES_H_
#define _EXT_VALUES_H_

#include <sys/time.h>
#ifdef AUTH
#include <sodium.h>
#endif

/*
* Announce a value id / port pair in regular
* intervals until the lifetime expires.
*/

struct value_t {
	struct value_t *next;
	UCHAR id[SHA1_BIN_LENGTH];
#ifdef AUTH
	UCHAR *skey;
#endif
	int port;
	time_t lifetime; /* Keep entry refreshed until the lifetime expires */
	time_t refresh; /* Next time the entry need to be refreshed */
};

void values_setup( void );
void values_free( void );

struct value_t* values_get( void );
struct value_t* values_find( UCHAR id[] );

/* List all entries */
void values_debug( int fd );

/* Count all entries */
int values_count( void );

/* Add a value id / port that will be announced until lifetime is exceeded */
struct value_t *values_add( const char query[], int port, time_t lifetime,
       char *payload, char *date_str );


#endif /* _EXT_VALUES_H_ */
