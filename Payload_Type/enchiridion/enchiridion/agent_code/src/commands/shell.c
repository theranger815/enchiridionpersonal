#include "commands.h"
#include "task_kill.h"
#include "utils.h"
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

void shellExecute(char *cmd, char *task_uuid, TaskResponse *resp) {
    int stdout_pipe[2];
    int stderr_pipe[2];

    if (pipe(stdout_pipe) == -1) {
        DBGPRINT("Failed to create stdout pipe: %s", strerror(errno));
        resp->output = malloc(ERR_MSG_SIZE);
        if (resp->output)
            memcpy(resp->output, "Failed to create pipes", sizeof("Failed to create pipes"));
        resp->status = -1;
        return;
    }

    if (pipe(stderr_pipe) == -1) {
        DBGPRINT("Failed to create stderr pipe: %s", strerror(errno));
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        resp->output = malloc(ERR_MSG_SIZE);
        if (resp->output)
            memcpy(resp->output, "Failed to create pipes", sizeof("Failed to create pipes"));
        resp->status = -1;
        return;
    }

    pid_t pid = fork();
    if (pid == -1) {
        DBGPRINT("Failed to fork: %s", strerror(errno));
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);
        resp->output = malloc(ERR_MSG_SIZE);
        if (resp->output)
            memcpy(resp->output, "Failed to fork", sizeof("Failed to fork"));
        resp->status = -1;
        return;
    }

    if (pid == 0) {
        close(stdout_pipe[0]);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        close(stdout_pipe[1]);

        close(stderr_pipe[0]);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stderr_pipe[1]);

        execve("/bin/sh", (char *[]){"/bin/sh", "-c", cmd, NULL}, NULL);
        _exit(1);
    }

    taskSetChildPid(task_uuid, pid);

    // Parent: close write ends
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    int buffer_size = BUFSIZ;
    int bytes_read = 0;

    resp->output = malloc(buffer_size);
    if (!resp->output) {
        DBGPRINT("Failed to allocate output buffer: %s", strerror(errno));
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        waitpid(pid, NULL, 0);
        resp->status = -1;
        return;
    }

    // Use poll() to drain both pipes concurrently — prevents deadlock when one
    // pipe buffer fills before the other is read.
    struct pollfd fds[2] = {
        {stdout_pipe[0], POLLIN, 0},
        {stderr_pipe[0], POLLIN, 0},
    };

    while (fds[0].fd != -1 || fds[1].fd != -1) {
        int ready = poll(fds, 2, -1);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            DBGPRINT("poll failed: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < 2; i++) {
            if (fds[i].fd == -1)
                continue;
            if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR)))
                continue;

            // Ensure at least BUFSIZ bytes remain before reading
            if (bytes_read + BUFSIZ > buffer_size) {
                char *grow = realloc(resp->output, buffer_size * 2);
                if (!grow) {
                    DBGPRINT("Failed to realloc output buffer: %s", strerror(errno));
                    memcpy(resp->output, "Memory allocation failed",
                           sizeof("Memory allocation failed"));
                    if (fds[0].fd != -1) { close(fds[0].fd); fds[0].fd = -1; }
                    if (fds[1].fd != -1) { close(fds[1].fd); fds[1].fd = -1; }
                    waitpid(pid, NULL, 0);
                    resp->status = -1;
                    return;
                }
                resp->output = grow;
                buffer_size *= 2;
            }

            ssize_t n = read(fds[i].fd, resp->output + bytes_read,
                             (size_t)(buffer_size - bytes_read - 1));
            if (n > 0) {
                bytes_read += (int)n;
            } else {
                close(fds[i].fd);
                fds[i].fd = -1;
            }
        }
    }

    resp->output[bytes_read] = '\0';

    int wstatus;
    waitpid(pid, &wstatus, 0);
    if (!WIFEXITED(wstatus))
        DBGPRINT("Child process did not exit normally");
    resp->status = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;
    DBGPRINT("Command exited with status: %d", resp->status);
}
