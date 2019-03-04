
#ifndef _LPD_H
#define _LPD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
* Send multicast messages to discover
* new nodes if no other nodes are known.
*/

void lpd_setup( void );
void lpd_free( void );

#endif /* _LPD_H */
