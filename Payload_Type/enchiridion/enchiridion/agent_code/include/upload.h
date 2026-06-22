#ifndef UPLOAD_H
#define UPLOAD_H

// Called by handleTask when a post_response upload chunk arrives from Mythic.
// Returns: 0 = in progress, 1 = all chunks written, -1 = error.
int processUploadChunk(const char *task_uuid, int total_chunks, int chunk_num,
                       const char *chunk_data, int status_ok);

#endif // !UPLOAD_H
