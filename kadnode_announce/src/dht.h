/*
Copyright (c) 2009-2011 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
#ifndef DHT_H
#define DHT_H

#include <sys/socket.h>
#include <stdio.h>

struct node {
    unsigned char id[20];
    struct sockaddr_storage ss;
    int sslen;
    time_t time;                /* time of last message received */
    time_t reply_time;          /* time of last correct reply received */
    time_t pinged_time;         /* time of last request */
    int pinged;                 /* how many requests we sent since last reply */
    struct node *next;
};

struct bucket {
    int af;
    unsigned char first[20];
    int count;                  /* number of nodes */
    int time;                   /* time of last reply in this bucket */
    struct node *nodes;
    struct sockaddr_storage cached;  /* the address of a likely candidate */
    int cachedlen;
    struct bucket *next;
};

struct search_node {
    unsigned char id[20];
    struct sockaddr_storage ss;
    int sslen;
    time_t request_time;        /* the time of the last unanswered request */
    time_t reply_time;          /* the time of the last reply */
    int pinged;
    unsigned char token[40];
    int token_len;
    int replied;                /* whether we have received a reply */
    int acked;                  /* whether they acked our announcement */
};

/*Hajime
 * struct to track nodes that send us results
 */
struct result_node{
    struct node *from_node;
    struct results_t *results;
    int done;
    int handled;
    int outstanding_requests;
    int num_new_results_responses;
    int num_no_new_results_responses;
    int sequential_no_new_results_responses;
    time_t reply_time;          /* the time of the last reply */
    time_t request_time;        /* the time of the last unanswered request */
    struct result_node *next;
};

/* When performing a search, we search for up to SEARCH_NODES closest nodes
   to the destination, and use the additional ones to backtrack if any of
   the target 8 turn out to be dead. */
#define SEARCH_NODES 16

struct search {
    unsigned short tid;
    int af;
    time_t step_time;           /* the time of the last search_step */
    unsigned char id[20];
    unsigned short port;        /* 0 for pure searches */
    int done;
    struct search_node nodes[SEARCH_NODES];
    int numnodes;
    struct search *next;
    struct result_node *result_nodes;
};

struct peer {
    time_t time;
    unsigned char ip[16];
    unsigned short len;
    unsigned short port;
};

typedef void
dht_callback(void *closure, int event,
             struct search *sr,
             const void *data, size_t data_len,
             struct node *n);

#define REPLICATE_NUM 8

#define DHT_EVENT_NONE 0
#define DHT_EVENT_VALUES 1
#define DHT_EVENT_VALUES6 2
#define DHT_EVENT_SEARCH_DONE 3
#define DHT_EVENT_SEARCH_DONE6 4

extern FILE *dht_debug;

int dht_init(int s, int s6, const unsigned char *id, const unsigned char *v);
int dht_insert_node(const unsigned char *id, struct sockaddr *sa, int salen);
int dht_ping_node(struct sockaddr *sa, int salen);
int dht_periodic(const void *buf, size_t buflen,
                 const struct sockaddr *from, int fromlen,
                 time_t *tosleep, dht_callback *callback, void *closure);
int dht_search(const unsigned char *id, int port, int af,
               dht_callback *callback, void *closure);
int dht_nodes(int af,
              int *good_return, int *dubious_return, int *cached_return,
              int *incoming_return);
void dht_dump_tables(FILE *f);
int dht_get_nodes(struct sockaddr_in *sin, int *num,
                  struct sockaddr_in6 *sin6, int *num6);
int dht_uninit(void);

/* This must be provided by the user. */
int dht_blacklisted(const struct sockaddr *sa, int salen);
void dht_hash(void *hash_return, int hash_size,
              const void *v1, int len1,
              const void *v2, int len2,
              const void *v3, int len3);
int dht_random_bytes(void *buf, size_t size);

int result_node_send_get_peers(struct search *sr, struct result_node *rn);
#endif
