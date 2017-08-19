#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include "rlib.h"

#define PACKET_MAX_SIZE 512
#define PAYLOAD_MAX_SIZE 500
#define PACKET_HEADER_SIZE 12
#define EOF_PACKET_SIZE 12
#define ACK_PACKET_SIZE 8

typedef struct data_pkt_node {
	packet_t pkt;
	int is_acked;
	int is_slot_used;
	uint32_t pkt_size;
	uint32_t pkt_seq_no;
	int num_flushed_bytes;
	struct timeval last_transmission_time;

} data_pkt_node_t;

enum client_state {
	SEND_WINDOW_NOT_FULL, SEND_WINDOW_FULL, WAIT_FIN_ACK, CLIENT_FINISHED
};

enum server_state {
	RECEIVE_WINDOW_NOT_FULL, RECEIVE_WINDOW_FULL, SERVER_FINISHED
};

typedef struct client {
	enum client_state state;
	//packet_t last_packet_sent;
	data_pkt_node_t *sender_window_head;
	int sw_head;
	int sw_tail;
	int last_seqno_sent;
	int num_pkt_in_fly;
	int last_seqno_acked;
} client_t;

typedef struct server {
	enum server_state state;
	//packet_t last_packet_received;
	data_pkt_node_t *receiver_window_head;
	int last_seqno_outputed;
	int num_pkt_to_output;
	int rw_head;
	int rw_tail;
} server_t;


struct reliable_state {
  rel_t *next;			/* Linked list for traversing all connections */
  rel_t **prev;

  conn_t *c;			/* This is the connection object */

  /* Add your own data fields below this */
	int timeout;
	int window_size;
	client_t client;
	server_t server;
	struct sockaddr_storage *socket;
};
rel_t *rel_list;


/* helper function */
int is_packet_corrupted (packet_t *pkt, size_t received_len);
uint16_t calc_checksum(packet_t *pkt, int pkt_length);
void ntoh_packet(packet_t *pkt);
void hton_packet(packet_t *pkt);
void buffer_outgoing_pkt(rel_t *r, packet_t *pkt, int pkt_len, uint32_t pkt_seq_num);
data_pkt_node_t *create_data_pkt_window(rel_t *r);
int find_and_ack_pkt(rel_t *r, struct ack_packet * pkt);
data_pkt_node_t *sw_get_data_pkt_ptr_at_idx(rel_t *r, int idx);
data_pkt_node_t *rw_get_data_pkt_ptr_at_idx(rel_t *r, int idx);

// server side helper
int flush_data_to_output(rel_t *r, data_pkt_node_t *node);
void handle_ack_pkt(rel_t *r, packet_t *ack_pkt);
void handle_data_pkt(rel_t *r, packet_t *pkt);
void send_ack_pkt(rel_t *r, uint32_t ackno);
void buffer_incomming_pkt(rel_t *r, packet_t *pkt);
void empty_buffer(rel_t *r);
int check_pkt_exist_in_rw_buffer(rel_t *r, packet_t *pkt);

// client client helper
void handle_retransmission(rel_t *r);
int get_time_since_last_transmission (data_pkt_node_t *node);
packet_t * create_data_packet(rel_t *r);


/* debug function */
void print_rw_content(rel_t *r);
void print_rw_node(rel_t *r, data_pkt_node_t *node);


void print_rw_content(rel_t *r) {

	//if (r->server.num_pkt_to_output == 0) return;
	int start_idx = -1;
	fprintf(stderr, "===SW CONTENT===\n");
	fprintf(stderr, "rw_head:%d\n", r->server.rw_head);
	fprintf(stderr, "rw_tail:%d\n", r->server.rw_tail);
	fprintf(stderr, "rw size:%d\n", r->server.num_pkt_to_output);
	for (int i = 0; i < r->window_size; ++i) {
		start_idx = (start_idx + 1) % r->window_size;
		data_pkt_node_t *node = rw_get_data_pkt_ptr_at_idx(r,start_idx);
		print_rw_node(r,node);
	}
}

void print_rw_node(rel_t *r, data_pkt_node_t *node) {
		fprintf(stderr, "rw_size: %d, ptr: %p, pkt_no: %d, is_acked %d, is_used %d \n"\
				,r->server.num_pkt_to_output, node, node->pkt_seq_no, node->is_acked, node->is_slot_used);
}


/* Creates a new reliable protocol session, returns NULL on failure.
 * Exactly one of c and ss should be NULL.  (ss is NULL when called
 * from rlib.c, while c is NULL when this function is called from
 * rel_demux.) */
rel_t *
rel_create (conn_t *c, const struct sockaddr_storage *ss,
	    const struct config_common *cc)
{
  rel_t *r;

  r = xmalloc (sizeof (*r));
  memset (r, 0, sizeof (*r));

  if (!c) {
    c = conn_create (r, ss);
    if (!c) {
      free (r);
      return NULL;
    }
  }

	r->window_size = cc->window;
	r->timeout = cc->timeout;
  r->c = c;
  r->next = rel_list;
  r->prev = &rel_list;
  if (rel_list)
    rel_list->prev = &r->next;
  rel_list = r;

  /* Do any other initialization you need here */
	r->client.state = SEND_WINDOW_NOT_FULL;
	r->client.last_seqno_sent = 0;
	r->client.last_seqno_acked = 0;
	//init sender window
	r->client.sender_window_head = xmalloc(r->window_size * sizeof(data_pkt_node_t));
	memset(r->client.sender_window_head, 0, r->window_size * sizeof(data_pkt_node_t));
	r->client.sw_head = 0;
	r->client.sw_tail = r->window_size - 1;
	r->client.num_pkt_in_fly = 0;

	r->server.state = RECEIVE_WINDOW_NOT_FULL;
	r->server.last_seqno_outputed = 0;
	//init receiver window
	r->server.receiver_window_head = xmalloc(r->window_size * sizeof(data_pkt_node_t));
	memset(r->server.receiver_window_head, 0 , r->window_size * sizeof(data_pkt_node_t));
	r->server.num_pkt_to_output = 0;
	r->server.rw_head = 0;
	r->server.rw_tail = r->window_size - 1;
	if(ss){
		r->socket = xmalloc(sizeof(struct sockaddr_storage));
		memcpy(r->socket,ss,sizeof(struct sockaddr_storage));
	}
	else{
		r->socket = NULL;
	}

  return r;
}

void
rel_destroy (rel_t *r)
{
  if (r->next)
    r->next->prev = r->prev;
  *r->prev = r->next;
  conn_destroy (r->c);

  /* Free any other allocated memory here */
	free(r->client.sender_window_head);
	free(r->server.receiver_window_head);
	if (r->socket) free(r->socket);
	free(r);
}


/* This function only gets called when the process is running as a
 * server and must handle connections from multiple clients.  You have
 * to look up the rel_t structure based on the address in the
 * sockaddr_storage passed in.  If this is a new connection (sequence
 * number 1), you will need to allocate a new conn_t using rel_create
 * ().  (Pass rel_create NULL for the conn_t, so it will know to
 * allocate a new connection.)
 */
void
rel_demux (const struct config_common *cc,
	   const struct sockaddr_storage *ss,
	   packet_t *pkt, size_t len)
{
	if (is_packet_corrupted(pkt, len)) {
		return;
	}
	ntoh_packet(pkt);

	rel_t *r = rel_list;
	while (r) {
		if(addreq(r->socket,ss)) {
			hton_packet(pkt);
			rel_recvpkt(r,pkt,len);
			return;
		}
		r = r->next;
	}

	if (pkt->seqno == 1) {
		r = rel_create(NULL,ss,cc);
		hton_packet(pkt);
		rel_recvpkt(r,pkt,len);
	}
	return;
}

void
rel_recvpkt (rel_t *r, packet_t *pkt, size_t n)
{
	if (is_packet_corrupted(pkt, n)) {
		return;
	}

	ntoh_packet(pkt);

	if (pkt->len == ACK_PACKET_SIZE) {
		handle_ack_pkt(r, pkt);
	} else {
		handle_data_pkt(r,pkt);
	}

}


void
rel_read (rel_t *r)
{
	if (r->client.state == SEND_WINDOW_NOT_FULL) {
		packet_t *pkt = create_data_packet(r);
		if (pkt != NULL) {
			uint32_t pkt_seq_num = pkt->seqno;
			int pkt_len = pkt->len;
			// update the state machine to WAIT_FIN_ACK state
			if (pkt_len == EOF_PACKET_SIZE) {
				r->client.state = WAIT_FIN_ACK;
			}
			hton_packet(pkt);
			conn_sendpkt (r->c, pkt, (size_t) pkt_len);
			buffer_outgoing_pkt (r, pkt, pkt_len, pkt_seq_num);
			free(pkt);

		}
	}
}

void
rel_output (rel_t *r)
{
	if (r->server.num_pkt_to_output == 0) {
		return;
	}
	empty_buffer(r);
}

void
rel_timer ()
{
  /* Retransmit any packets that need to be retransmitted */
	rel_t *r = rel_list;
	while(r){
		handle_retransmission(r);
		r = r->next;
	}

}

// sender help function
void buffer_outgoing_pkt(rel_t *r, packet_t *pkt, int pkt_len, uint32_t pkt_seq_num) {


	if (r->client.state == CLIENT_FINISHED) {
		return;
	}
	int free_slot = r->client.sw_head;
	assert(r->client.sender_window_head[free_slot].is_slot_used == 0);
	r->client.sender_window_head[free_slot].is_acked  = 0;
	r->client.sender_window_head[free_slot].is_slot_used  = 1;
	r->client.sender_window_head[free_slot].pkt = *pkt;
	r->client.sender_window_head[free_slot].pkt_size = pkt_len;
	r->client.sender_window_head[free_slot].pkt_seq_no = pkt_seq_num;
	r->client.last_seqno_sent += 1;
	gettimeofday (&(r->client.sender_window_head[free_slot].last_transmission_time), NULL);
	assert (r->client.last_seqno_sent > r->client.last_seqno_acked);

	assert(r->client.num_pkt_in_fly >= 0);
	// advance the sw_window
	r->client.sw_head = (r->client.sw_head + 1) % r->window_size;
	r->client.num_pkt_in_fly += 1;
	assert(r->client.num_pkt_in_fly <= r->window_size);
	//state machine update
	if (r->client.state == WAIT_FIN_ACK) return;
	if (r->client.num_pkt_in_fly == r->window_size) {
		r->client.state = SEND_WINDOW_FULL;
	}
}

packet_t * create_data_packet(rel_t *r) {
	packet_t *pkt;
	pkt = xmalloc (sizeof (packet_t));
	int bytes_read = conn_input(r->c, pkt->data, PAYLOAD_MAX_SIZE);
	if (bytes_read == 0) {
		free(pkt);
		return NULL;
	}

	// data exist or EOF
	pkt->len = (bytes_read == -1) ? (uint16_t) PACKET_HEADER_SIZE : (uint16_t) (PACKET_HEADER_SIZE + bytes_read);
	pkt->ackno = (uint32_t) 1;
	pkt->seqno = (uint32_t) (r->client.last_seqno_sent + 1);
	return pkt;
}

// receiver helpper function

void handle_ack_pkt(rel_t *r, packet_t *ack_pkt) {
	struct ack_packet *pkt = (struct ack_packet *) ack_pkt;
	if (r->client.num_pkt_in_fly > 0) {
		// handle packet
		if (find_and_ack_pkt(r,pkt) == 0) {
			fprintf(stderr,"[handle_ack_pkt]: error ackno num %d, last_seqno_acked: %d, num_pkt_in_fly: %d\n", \
					pkt->ackno, r->client.last_seqno_acked, r->client.num_pkt_in_fly);
			exit(1);
		}
		// no pkt fly and
		if (r->client.state == CLIENT_FINISHED && r->server.state == SERVER_FINISHED && r->client.num_pkt_in_fly == 0) {
			rel_destroy(r);
		} else if (r->client.state == SEND_WINDOW_NOT_FULL){
			rel_read(r);
		}

	}

}

int find_and_ack_pkt(rel_t *r, struct ack_packet * pkt) {
	int send_seq_num = pkt->ackno - 1;
	assert (send_seq_num >= 0 );
	if (send_seq_num <= r->client.last_seqno_acked) {
		// do nothing
		return 1;
	}
	if (send_seq_num > r->client.last_seqno_acked + r->client.num_pkt_in_fly) {
		// wrong sequence number
		return 0;
	}

	int tail_idx = (r->client.sw_tail + 1) % r->window_size;
	data_pkt_node_t *sw_node = sw_get_data_pkt_ptr_at_idx(r,tail_idx);
	assert(sw_node->pkt_seq_no == r->client.last_seqno_acked + 1);
	// ack pkt
	assert(r->client.num_pkt_in_fly >= 0 && r->client.num_pkt_in_fly <= r->window_size);
	int total_fly = r->client.num_pkt_in_fly;
	for (int i = 0; i < total_fly; ++i) {
		int idx = (tail_idx + i) % r->window_size;
		data_pkt_node_t *cur = sw_get_data_pkt_ptr_at_idx(r, idx);
		assert(cur->is_slot_used == 1);
		if (cur->pkt_seq_no == send_seq_num) {
			cur->is_acked = 1;
			break;
		}
	}

	// shrink sw window
	int idx = 0;
	for (int i = 0; i < total_fly; ++i) {
		idx = (tail_idx + i) % r->window_size;
		data_pkt_node_t *cur = sw_get_data_pkt_ptr_at_idx(r, idx);
		assert(cur->is_slot_used == 1);
		if (cur->is_acked == 1) {
			// ack it decreate the number of pkt fly and shrink the tail
			cur->is_slot_used = 0;
			r->client.sw_tail = (r->client.sw_tail + 1) % r->window_size;
			r->client.num_pkt_in_fly -= 1;
			assert(cur->pkt_seq_no == r->client.last_seqno_acked + 1);
			r->client.last_seqno_acked += 1;
		} else {
			break;
		}
	}
	// handle  tear down
	if (r->client.state == WAIT_FIN_ACK) {
		if (r->client.num_pkt_in_fly == 0) {
			// it is he lask send seqnum
			r->client.state = CLIENT_FINISHED;
		}
	}

	// update state machine
	if (r->client.state == WAIT_FIN_ACK || r->client.state == CLIENT_FINISHED) return 1;
	assert(r->client.num_pkt_in_fly >= 0 && r->client.num_pkt_in_fly <= r->window_size);
	if (r->client.num_pkt_in_fly < r->window_size) {
		r->client.state = SEND_WINDOW_NOT_FULL;
	}

	return 1;
}


void handle_data_pkt(rel_t *r, packet_t *pkt) {
	// already processed packet
	int min_expected_seqno = r->server.last_seqno_outputed + 1;
	if (pkt->seqno < min_expected_seqno) {
		send_ack_pkt(r, pkt->seqno + 1);
		return;
	}

	if (r->server.state == SERVER_FINISHED) {
		// server terminate
		// if client state is finished, terminate the rel state
		if (r->client.state == CLIENT_FINISHED) {
			rel_destroy(r);
		}
		return;
	}
	// not ready for receiving pkt
	if (r->server.state == RECEIVE_WINDOW_FULL) {
		empty_buffer(r);
		return;
	}
	// out of range
	if (pkt->seqno > r->server.last_seqno_outputed + r->window_size) {
		return;
	}

	// new packet
	// handle EOF packet

	buffer_incomming_pkt(r, pkt);

	empty_buffer(r);
	//if (flush_data_to_output(r) > 0) {
	//	send_ack_pkt(r, pkt->seqno + 1);
	//}

}

int check_pkt_exist_in_rw_buffer(rel_t *r, packet_t *pkt) {
	if (r->server.num_pkt_to_output == 0) return 0;
	int start_idx = (r->server.rw_tail + 1) % r->window_size;
	for (int i = 0; i < r->server.num_pkt_to_output; ++i) {
		data_pkt_node_t *node = rw_get_data_pkt_ptr_at_idx(r,start_idx);
		if (node->pkt_seq_no == pkt->seqno) {
			return 1;
		}
	}

	return 0;
}

void buffer_incomming_pkt(rel_t *r, packet_t *pkt) {
	if (r->server.num_pkt_to_output == r->window_size) return;
	//already buffered
	if (check_pkt_exist_in_rw_buffer(r, pkt))  return;
	int empty_idx = r->server.rw_head;
	data_pkt_node_t *rw_node = rw_get_data_pkt_ptr_at_idx(r,empty_idx);
	assert (rw_node->is_slot_used == 0);
	// store the node
	rw_node->is_slot_used = 1;
	rw_node->is_acked = 0;
	rw_node->num_flushed_bytes = 0;
	rw_node->pkt_size = pkt->len;
	rw_node->pkt_seq_no = pkt->seqno;
	rw_node->pkt = *pkt;

	//update window
	r->server.rw_head = (r->server.rw_head + 1) % r->window_size;
	r->server.num_pkt_to_output += 1;


	if (r->server.num_pkt_to_output == r->window_size) {
		r->server.state = RECEIVE_WINDOW_FULL;
	}
}

void empty_buffer(rel_t *r) {
	if (r->server.num_pkt_to_output == 0) return;

	if (r->server.state == SERVER_FINISHED) {
		// server terminate
		// if client state is finished, terminate the rel state
		if (r->client.state == CLIENT_FINISHED) {
			rel_destroy(r);
		}
		return;
	}
	// find target slot
	uint32_t target_pkt_no = r->server.last_seqno_outputed + 1;
	data_pkt_node_t *target_node = NULL;
	int target_idx = r->server.rw_tail;
	int i;
	for (i = 0; i < r->server.num_pkt_to_output; ++i) {
		target_idx = (target_idx + 1) % r->window_size;
		target_node = rw_get_data_pkt_ptr_at_idx(r,target_idx);
		if (target_node->pkt_seq_no == target_pkt_no)
			break;
	}
	// if target not find return
	if (i == r->server.num_pkt_to_output) return;

	// we must assume the target can be find
	assert (target_pkt_no == target_node->pkt_seq_no);
	if (target_node->pkt_size == EOF_PACKET_SIZE ) {
		target_node->is_acked = 1;
		conn_output (r->c, NULL, 0);
		r->server.state = SERVER_FINISHED;
	} else {
		if (target_node->is_acked == 0 && flush_data_to_output(r, target_node) == 0) {
			return;
		}
	}
	target_node->is_acked = 1;
	send_ack_pkt(r, target_node->pkt_seq_no + 1);
	r->server.last_seqno_outputed = target_pkt_no;

	//shrink tail
	int shrink_idx = r->server.rw_tail;
	int total_need_to_shrink = r->server.num_pkt_to_output;
	for (int i = 0; i < total_need_to_shrink; ++i) {
		shrink_idx = (shrink_idx + 1) % r->window_size;
		data_pkt_node_t *node_to_delete = rw_get_data_pkt_ptr_at_idx(r,shrink_idx);
		assert(node_to_delete->is_slot_used == 1);
		if (node_to_delete->pkt_seq_no <= r->server.last_seqno_outputed  \
				||(node_to_delete->is_acked == 1 && node_to_delete->is_slot_used == 1)) {
			r->server.num_pkt_to_output -= 1;
			node_to_delete->is_slot_used = 0;
			node_to_delete->is_acked = 0;
			node_to_delete->pkt_seq_no = -1;
			r->server.rw_tail = (r->server.rw_tail + 1) % r->window_size;
		} else {
			break;
		}
	}

	// update state machine
	if (r->server.state == SERVER_FINISHED) return;
	assert(r->server.num_pkt_to_output >= 0);
	if (r->server.num_pkt_to_output < r->window_size) {
		r->server.state = RECEIVE_WINDOW_NOT_FULL;
	}
}

int flush_data_to_output(rel_t *r, data_pkt_node_t *node) {
	size_t buf_size = conn_bufspace (r->c);
	if (buf_size == 0) return 0;

	size_t paylod_size = node->pkt_size - PACKET_HEADER_SIZE;
	size_t bytes_left = paylod_size - node->num_flushed_bytes;
	size_t write_len = (bytes_left < buf_size) ? bytes_left : buf_size;
	uint16_t offset = node->num_flushed_bytes;
	char *data_ptr = node->pkt.data;

	int bytes_written = conn_output (r->c, &data_ptr[offset], write_len);
	assert(bytes_written >= 0);
	node->num_flushed_bytes += bytes_written;

	assert (node->num_flushed_bytes <= paylod_size);

	if (node->num_flushed_bytes == paylod_size) {
		return 1;
	}
	return 0;
}

void send_ack_pkt(rel_t *r, uint32_t ackno) {
	struct ack_packet *ack_pkt = xmalloc(sizeof (struct ack_packet));
	ack_pkt->len = ACK_PACKET_SIZE;
	ack_pkt->ackno = ackno;
	size_t pkt_size = ack_pkt->len;

	//prepare packet
	hton_packet((packet_t *)ack_pkt);

	conn_sendpkt (r->c, (packet_t *)ack_pkt, pkt_size);
	free(ack_pkt);
}

void handle_retransmission(rel_t *r) {
	if (r->client.num_pkt_in_fly > 0) {
		int start = r->client.sw_tail + 1;
		// scan over the sender window resend the not acked and timeout pkt
		for (int i = 0; i < r->client.num_pkt_in_fly; ++i) {
			int idx = (start + i) % r->window_size;
			data_pkt_node_t *sw_node = &(r->client.sender_window_head[idx]);
			assert (sw_node->is_slot_used == 1);
			int millisecond_sinc_transmission = get_time_since_last_transmission(sw_node);
			if (sw_node->is_acked == 0 && millisecond_sinc_transmission > r->timeout) {
				conn_sendpkt (r->c, &(sw_node->pkt), sw_node->pkt_size);
				gettimeofday(&(sw_node->last_transmission_time), NULL);
			}
		}
	}

}

// general helper function
data_pkt_node_t *sw_get_data_pkt_ptr_at_idx(rel_t *r, int idx) {
	assert (idx >= 0 && idx < r->window_size);
	data_pkt_node_t *sw_node = &(r->client.sender_window_head[idx]);
	return sw_node;
}

data_pkt_node_t *rw_get_data_pkt_ptr_at_idx(rel_t *r, int idx) {
	assert (idx >= 0 && idx < r->window_size);
	data_pkt_node_t *rw_node = &(r->server.receiver_window_head[idx]);
	return rw_node;
}

data_pkt_node_t *create_data_pkt_window(rel_t *r) {
	data_pkt_node_t * node = xmalloc (sizeof(data_pkt_node_t) * r->window_size);
	memset(node, 0, sizeof (data_pkt_node_t) * r->window_size);
	return node;
}

void hton_packet(packet_t *pkt) {
	size_t pkt_size = pkt->len;
	if (pkt->len != ACK_PACKET_SIZE) {
		pkt->seqno = htonl(pkt->seqno);
	}
	assert(pkt->len >= ACK_PACKET_SIZE);
	assert(pkt->len <= PACKET_MAX_SIZE);
	pkt->len = htons(pkt->len);
	pkt->ackno = htonl(pkt->ackno);
	pkt->cksum = calc_checksum(pkt, pkt_size);
}

void ntoh_packet(packet_t *pkt) {
	pkt->len = ntohs (pkt->len);
	pkt->ackno = ntohl (pkt->ackno);

	assert(pkt->len >= ACK_PACKET_SIZE);
	assert(pkt->len <= PACKET_MAX_SIZE);
	if (pkt->len != ACK_PACKET_SIZE) {
		//not ack packet
		pkt->seqno = ntohl (pkt->seqno);
	}

}

int get_time_since_last_transmission (data_pkt_node_t *node) {
	struct timeval now;
	gettimeofday (&now, NULL);
	return ( ( (int)now.tv_sec * 1000 + (int)now.tv_usec / 1000 ) -
			( (int)node->last_transmission_time.tv_sec * 1000 + (int)node->last_transmission_time.tv_usec / 1000 ) );
}


int is_packet_corrupted (packet_t *pkt, size_t received_len) {
	int pkt_len = (int) ntohs(pkt->len);

	if (received_len < pkt_len) {
		return 1;
	}

	uint16_t pkt_checksum = pkt->cksum;
	uint16_t computed_cksum = calc_checksum(pkt, pkt_len);
	return pkt_checksum != computed_cksum;
}

uint16_t calc_checksum(packet_t *pkt, int pkt_len) {
	memset (&(pkt->cksum), 0, sizeof(pkt->cksum));
	return cksum ((void*) pkt, pkt_len);
}

