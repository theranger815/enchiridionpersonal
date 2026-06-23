#ifndef DOWNLOAD_H
#define DOWNLOAD_H

#include <stddef.h>

// A download chunk payload queued by a worker thread for taskingLoop to send.
typedef struct OutgoingChunk {
    char *payload;
    size_t payload_len;
    int chunk_id;
    struct OutgoingChunk *next;
} OutgoingChunk;

// Called by download() to enqueue a chunk for taskingLoop to send.
void enqueueOutgoing(OutgoingChunk *msg);

// Called by taskingLoop to dequeue the next pending chunk (non-blocking, returns NULL if empty).
OutgoingChunk *dequeueOutgoing(void);

// Called by handleTask when a post_response ack arrives for a download task.
// Returns: 0 = in progress, 1 = all chunks complete, -1 = error.
int processDownloadAck(const char *task_uuid, const char *file_id, int status_ok);

#endif // !DOWNLOAD_H
