/*
 * transport.c 
 *
 * CS244a HW#3 (Reliable Transport)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

enum { CSTATE_ESTABLISHED, LISTEN, SYN_RCVD, SYN_SENT, FIN_WAIT_1,FIN_WAIT_2,CLOSE_WAIT,CLOSING,LAST_ACK,CLOSING,CLOSED } /* obviously you should have more states */
#define HEADER_SIZE = 5
#define WINDOW_SIZE 3072

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;
	tcp_seq seq_num;
	tcp_seq ack_num;
	tcp_seq base;
	uint16_t local_win;
	uint16_t remote win;
	uint16_t cong_win;
	uint16_t local_rem_win;
	


    /* any other connection-wide global variables go here */
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

	ctx->done == FALSE;
	ctx->cong_win = STCP_MSS;

	if (is_active) {
		ctx->local_win = STCP_MSS;
		ctx->local_rem_win = ctx->local_win;
		ctx->base = ctx->initial_sequence_num
		//send SYN
		struct tcphdr *SYN = (struct tcphdr *)calloc(1, sizeof(struct tcphdr));
		SYN->th_seq = htonl(ctx->initial_sequence_num);
		SYN->th_ack = htonl(1);
		SYN->th_off = htons (HEADER_SIZE);
		SYN->th_flags = TH_SYN;
		SYN->th_win = htons(local_win);
		ssize_t send_len = stcp_network_send(sd, SYN, sizeof(struct tcphdr),NULL);
		if (send_len > 0) {
			//wait SYN ACK
			ctx->connection_state = SYN_SENT;
			stcp_wait_for_event(sd, NETWORK_DATA, NULL);
			struct tcphdr *SYN_ACK = (struct tcphdr *)calloc(1,sizeof(struct tcphdr));
			ssize_t recv_len = stcp_network_recv(sd, SYN_ACK , sizeof(struct tcphdr));
			if (recv_len >= sizeof(struct tcphdr)) {
				if (SYN_ACK->th_flags == (TH_ACK | TH_SYN)) {
					ctx->ack_num = ntohl(SYN_ACK->th_seq);
					ctx->seq_num = ntohl(SYN_ACK->th_ack);
					ctx->remote_win = ntohs(SYN_ACK->th_win);
					ctx->base++;
					ctx->connection_state = SYN_RCVD;
					//send ACK
					struct tcphdr *ACK = (struct tcphdr *)calloc(1, sizeof(struct tcphdr));
					ACK->th_seq = htonl(ctx->seq_num);
					ACK->th_ack = htonl(ctx->ack_num + 1);
					ACK->th_off = htons(HEADER_SIZE);
					ACK->th_flags = TH_ACK;
					ACK->th_win = htons(local_win);
					ssize_t len = stcp_network_send(sd, ACK, sizeof(struct tcphdr),NULL);
					if (len < 0) {
						errno = ECONNREFUSED;
					}
					free(ACK);
				}
			}
			else {
				errno = ECONNREFUSED;
			}
			free(SYN_ACK);
		}
		else {
			errno = ECONNREFUSED;
		}
		free(SYN);
	}
	else {
		ctx->local_win = WINDOW_SIZE;
		ctx->local_rem_win = ctx->local_win;
		ctx->base = ctx->initial_sequence_num;
		//wait SYN
		ctx->connection_state = LISTEN;
		stcp_wait_for_event(sd, NETWORK_DATA, NULL);
		struct tcphdr *SYN = (struct tcphdr *)calloc(1, sizeof(struct tcphdr));
		ssize_t recv_len = stcp_network_recv(sd, SYN, sizeof(struct tcphdr));
		if (recv_len >= sizeof(struct tcphdr)) {
			if (SYN->th_flags == TH_SYN) {
				ctx->remote_win = ntohs(SYN_ACK->th_win);
				ctx->ack_num = ntohl(SYN_ACK->th_seq);
				ctx->seq_num = ntohl(SYN_ACK->th_ack);
				ctx->connection_state = SYN_RCVD;

				struct tcphdr *SYN_ACK = (struct tcphdr *)calloc(1, sizeof(struct tcphdr));
				SYN_ACK->th_seq = htonl(ctx->initial_sequence_num);
				SYN_ACK->th_ack = htonl(ack_num + 1);
				SYN_ACK->th_off = htons(HEADER_SIZE);
				SYN_ACK->th_flags = (TH_SYN | TH_ACK);
				SYN_ACK->th_win = htons(WINDOW_SIZE);
				ssize_t send_len = stcp_network_send(sd, SYN_ACK, sizeof(struct tcphdr), NULL);

				if (send_len > 0) {
					ctx->base++;
					ctx->seq_num++;
					stcp_wait_for_event(sd, NETWORK_DATA, NULL);
					struct tcphdr *ACK = (struct tcphdr *)calloc(1, sizeof(struct tcphdr));
					ssize_t len = stcp_network_recv(sd, ACK, sizeof(struct tcphdr));
					if (len >= sizeof(struct tcphdr)) {
						if (ACK->th_flags == TH_ACK) {
							ctx->connection_state = CSTATE_ESTABLISHED;
						}
						else {
							errno = ECONNREFUSED;
						}
					}
					else {
						errno = ECONNREFUSED;
					}
					free(ACK);
				}
				else {
					errno = ECONNREFUSED;
				}
				free(SYN_ACK);
			}
		}
		else {
			errno = ECONNREFUSED;
		}
		free(SYN);
	}
    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);

}


/* generate initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);
    ctx->initial_sequence_num = 1;
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);

    while (!ctx->done)
    {
        unsigned int event;
		size_t payload_size;
		struct tcphdr *hdr;
        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
			payload_size = MIN(STCP_MSS, Min(ctx->remote_win,ctx->local_rem_win));
			if (payload_size > 0) {
				char *payload = (char *)calloc(1, payload_size);
				ssize_t app_size = stcp_app_recv(sd, payload, payload_size);
				if (app_size > 0) {
					ctx->loca_rem_win -= payload;
					hdr = (struct tcphdr *)calloc(1, sizeof(struct tcphdr));
					hdr->th_seq = htonl(ctx->seq_num);
					hdr->th_ack = htonl(ctx->akc_num + 1);
					hdr->flags = TH_ACK;
					hdr->th_win = htons(ctx->local_rem_win);
					hdr->th_off = htons(HEADER_SIZE);
					ssize_t send_len = stcp_network_send(sd, hdr, sizeof(struct tcphdr), payload, payload_size, NULL);
					if (send_len > 0) {
						ctx->seq_num = ctx->seq_num + payload_size;
					}
					else {
						errno = ECONNREFUSED;
					}
					free(hdr);
				}
				else {
					errno = ECONNREFUSED;
				}
				free(payload);
			}
        }
		if (event & NETWORK_DATA) {
			payload_size = MIN(STCP_MSS, ctx->local_win);
			if (payload_size > 0){
				size_t pck_size = sizeof(struct tcphdr) + payload_size;
				char *pck = (char *)calloc(1, pck_size);
				ssize_t recv_size = stcp_app_recv(sd, pck, pck_size);
				if (recv_size >= sizeof(struct tcphdr)) {
					hdr = (struct tcphdr *)calloc(1, sizeof(struct tcphdr));
					memcpy(hdr, pck, payload_size);
					if((hdr->th_flags) & TH_ACK) {
						if (ctx->connection_state == FIN_WAIT_1) {
							ctx->connection_state == FIN_WAIT_2;
						}
						else {
							ctx->connection_state == CLOSED;
							ctx->done = TRUE;
						}
						size_t data_size = recv_size - ntohs(hdr->th_off) * 4;
						if (data_size > 0 && (ctx->connection_state == CSTATE_ESTABLISHED)) {
							ctx->local_rem_win -= data_size;
							char *data = (char *)calloc(l, data_size);
							memcpy(pck + TCP_DATA_START(pck), data, data_size);
							ctx->ack_num = ntohl(hdr->seq) + data_size - 1;
							stcp_app_send(sd, data, data_size);
							ctx->local_rem_win += data_size;
							//send ack
							struct tcphdr *ACK = (struct tcphdr *)calloc(1, sizeof(struct tcphdr));
							ACK->th_seq = htonl(ctx->seq_num);
							ACK->th_ack = htonl(ctx->ack_num + 1);
							ACK->th_off = htons(HEADER_SIZE);
							ACK->th_flags = TH_ACK;
							ACK->th_win = htons(local_rem_win);
							ssize_t len = stcp_network_send(sd, ACK, sizeof(struct tcphdr), NULL);
							if (len < 0) {
								errno = ECONNREFUSED;
							}
							free(ACK);
							ctx->base += data_size;
							ctx->seq_num += data_size;
						}
						else if (data_size == 0 && (ctx->connection_state == CSTATE_ESTABLISHED)) {
							if (ctx->cong_win < 4 * STCP_MSS) {
								ctx->cong_win += STCP_MSS;
							}
							else {
								ctx->cong_win = ctx->cong_win + (STCP_MSS * STCP_MSS) / (ctx->cong_win);
							}
							ctx->remote_win = ntohs(hdr->th_win);
							uint16_t cur_local_win = ctx->local_win;
							ctx->local_win = MIN(ctx->remote_win, ctx->cong_win);
							ctx->local_rem_win = ctx->local_win - ctx->cur_local_win + ctx->local_rem_win + ntohl(hdr->th_ack) - ctx->base;
							ctx->base = ntohl(hdr->th_ack);
							ctx->ack_num = ntohl(hdr->th_seq);

						}
					}
					if ((hdr->th_flags) & TH_FIN) {

					}
					


					
				}

				
			}

		}


        /* etc. */
    }
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}



