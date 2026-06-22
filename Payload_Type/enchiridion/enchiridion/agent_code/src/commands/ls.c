#include "cJSON.h"
#include "commands.h"
#include "utils.h"
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <libgen.h>
#include <linux/limits.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

void getOwnerGroup(struct stat file_info, char *owner, char *group) {
    struct passwd *pw = getpwuid(file_info.st_uid);
    struct group *gr = getgrgid(file_info.st_gid);

    if (pw) {
        size_t len = strlen(pw->pw_name);
        if (len > 255)
            len = 255;
        memcpy(owner, pw->pw_name, len);
        owner[len] = '\0';
    } else {
        uint_to_str(file_info.st_uid, owner);
    }

    if (gr) {
        size_t len = strlen(gr->gr_name);
        if (len > 255)
            len = 255;
        memcpy(group, gr->gr_name, len);
        group[len] = '\0';
    } else {
        uint_to_str(file_info.st_gid, group);
    }
}

void getPermissions(struct stat file_info, char *perms_string) {
    mode_t mode = file_info.st_mode;
    perms_string[0] = S_ISREG(mode)    ? '-'
                      : S_ISDIR(mode)  ? 'd'
                      : S_ISLNK(mode)  ? 'l'
                      : S_ISFIFO(mode) ? 'p'
                      : S_ISSOCK(mode) ? 's'
                      : S_ISBLK(mode)  ? 'b'
                      : S_ISCHR(mode)  ? 'c'
                                       : '?';

    perms_string[1] = (mode & S_IRUSR) ? 'r' : '-';
    perms_string[2] = (mode & S_IWUSR) ? 'w' : '-';
    perms_string[3] = (mode & S_ISUID) ? 's' : (mode & S_IXUSR) ? 'x' : '-';

    perms_string[4] = (mode & S_IRGRP) ? 'r' : '-';
    perms_string[5] = (mode & S_IWGRP) ? 'w' : '-';
    perms_string[6] = (mode & S_ISGID) ? 's' : (mode & S_IXGRP) ? 'x' : '-';

    perms_string[7] = (mode & S_IROTH) ? 'r' : '-';
    perms_string[8] = (mode & S_IWOTH) ? 'w' : '-';
    perms_string[9] = (mode & S_ISVTX) ? 't' : (mode & S_IXOTH) ? 'x' : '-';

    perms_string[10] = '\0';
}

cJSON *create_PermsObject(struct stat file_info, char *abs_path) {
    char perms[11];
    getPermissions(file_info, perms);

    char owner[256] = "";
    char group[256] = "";
    getOwnerGroup(file_info, owner, group);

    char symlink_target[PATH_MAX] = "";
    if (S_ISLNK(file_info.st_mode)) {
        ssize_t len = readlink(abs_path, symlink_target, sizeof(symlink_target) - 1);
        if (len != -1) {
            symlink_target[len] = '\0';
        } else {
            DBGPRINT("readlink failed for %s: %s", abs_path, strerror(errno));
        }
    }

    cJSON *permissions = cJSON_CreateObject();
    if (permissions == NULL) {
        DBGPRINT("cJSON_CreateObject failed for permissions");
        return NULL;
    }

    cJSON_AddStringToObject(permissions, "user", owner);
    cJSON_AddStringToObject(permissions, "group", group);
    cJSON_AddStringToObject(permissions, "permissions", perms);
    cJSON_AddStringToObject(permissions, "symlink", symlink_target);

    return permissions;
}

cJSON *create_FileObject(char *abs_path, char *filename) {
    struct stat lfile_info;
    if (lstat(abs_path, &lfile_info) == -1) {
        DBGPRINT("lstat failed for %s: %s", abs_path, strerror(errno));
        return NULL;
    }

    // Follow symlinks only to determine whether the final target is a
    // directory — all other metadata comes from lstat so symlinks are
    // reported accurately.
    struct stat sfile_info;
    bool use_stat = S_ISLNK(lfile_info.st_mode) && stat(abs_path, &sfile_info) == 0;
    bool is_dir = S_ISDIR(use_stat ? sfile_info.st_mode : lfile_info.st_mode);

    cJSON *permissions = create_PermsObject(lfile_info, abs_path);
    if (permissions == NULL) {
        DBGPRINT("create_PermsObject failed for %s", abs_path);
        return NULL;
    }

    cJSON *file = cJSON_CreateObject();
    if (file == NULL) {
        DBGPRINT("cJSON_CreateObject failed for file object %s", abs_path);
        cJSON_Delete(permissions);
        return NULL;
    }

    cJSON_AddStringToObject(file, "name", filename);
    cJSON_AddNumberToObject(file, "access_time",
                            (double)lfile_info.st_atim.tv_sec * 1000.0 + lfile_info.st_atim.tv_nsec / 1000000.0);
    cJSON_AddNumberToObject(file, "modify_time",
                            (double)lfile_info.st_mtim.tv_sec * 1000.0 + lfile_info.st_mtim.tv_nsec / 1000000.0);
    cJSON_AddNumberToObject(file, "size", lfile_info.st_size);
    cJSON_AddItemToObject(file, "permissions", permissions);
    cJSON_AddBoolToObject(file, "is_file", is_dir ? false : true);

    return file;
}

void fileListing(char *path, TaskResponse *resp) {
    // Allocate output buffer first so all error paths can write to it
    resp->output = malloc(ERR_MSG_SIZE);
    if (resp->output == NULL) {
        DBGPRINT("Failed to allocate output buffer: %s", strerror(errno));
        resp->status = -1;
        return;
    }

    // Get the realpath in case only given relative
    char full_path[PATH_MAX];
    if (realpath(path, full_path) == NULL) {
        DBGPRINT("realpath failed for %s: %s", path, strerror(errno));
        memcpy(resp->output, "Could not resolve path", sizeof("Could not resolve path"));
        resp->status = -1;
        return;
    }

    // Stat the resolved path
    struct stat parent_linfo;
    if (lstat(full_path, &parent_linfo) == -1) {
        DBGPRINT("lstat failed for %s: %s", full_path, strerror(errno));
        memcpy(resp->output, "Could not stat path", sizeof("Could not stat path"));
        resp->status = -1;
        return;
    }

    // Follow symlinks only for is_file/is_dir determination
    struct stat parent_sinfo;
    bool use_stat = S_ISLNK(parent_linfo.st_mode) && stat(full_path, &parent_sinfo) == 0;
    bool is_dir = S_ISDIR(use_stat ? parent_sinfo.st_mode : parent_linfo.st_mode);

    // Get basename and parent
    char tmp1[PATH_MAX], tmp2[PATH_MAX];
    strncpy(tmp1, full_path, PATH_MAX - 1);
    tmp1[PATH_MAX - 1] = '\0';
    strncpy(tmp2, full_path, PATH_MAX - 1);
    tmp2[PATH_MAX - 1] = '\0';

    char *parent = strdup(dirname(tmp1));
    if (parent == NULL) {
        DBGPRINT("strdup failed for parent: %s", strerror(errno));
        memcpy(resp->output, "Memory allocation failed", sizeof("Memory allocation failed"));
        resp->status = -1;
        return;
    }

    char *path_name = strdup(basename(tmp2));
    if (path_name == NULL) {
        DBGPRINT("strdup failed for path_name: %s", strerror(errno));
        memcpy(resp->output, "Memory allocation failed", sizeof("Memory allocation failed"));
        free(parent);
        resp->status = -1;
        return;
    }

    // Create perms object
    cJSON *permissions = create_PermsObject(parent_linfo, full_path);
    if (permissions == NULL) {
        DBGPRINT("create_PermsObject failed for %s", full_path);
        memcpy(resp->output, "Failed to create permissions object", sizeof("Failed to create permissions object"));
        free(parent);
        free(path_name);
        resp->status = -1;
        return;
    }

    // Build the response object
    resp->formatted_response = cJSON_CreateObject();
    if (resp->formatted_response == NULL) {
        DBGPRINT("cJSON_CreateObject failed for formatted_response: %s", strerror(errno));
        memcpy(resp->output, "Memory allocation failed", sizeof("Memory allocation failed"));
        cJSON_Delete(permissions);
        free(parent);
        free(path_name);
        resp->status = -1;
        return;
    }

    // Set formatted_response_key
    resp->formatted_response_key = "file_browser";

    // Setup json object
    cJSON_AddStringToObject(resp->formatted_response, "name", path_name);
    cJSON_AddStringToObject(resp->formatted_response, "parent_path", parent);
    cJSON_AddBoolToObject(resp->formatted_response, "success", true);
    cJSON_AddNumberToObject(resp->formatted_response, "access_time",
                            (double)parent_linfo.st_atim.tv_sec * 1000.0 + parent_linfo.st_atim.tv_nsec / 1000000.0);
    cJSON_AddNumberToObject(resp->formatted_response, "modify_time",
                            (double)parent_linfo.st_mtim.tv_sec * 1000.0 + parent_linfo.st_mtim.tv_nsec / 1000000.0);
    cJSON_AddNumberToObject(resp->formatted_response, "size", parent_linfo.st_size);
    cJSON_AddItemToObject(resp->formatted_response, "permissions", permissions);

    // If is directory try to open the directory and gather information on the children
    if (is_dir) {
        cJSON_AddBoolToObject(resp->formatted_response, "is_file", false);

        // Gather information on all files and add them to a files array
        DIR *dr = opendir(full_path);

        // can't open directory
        if (dr == NULL) {
            DBGPRINT("opendir failed for %s: %s", full_path, strerror(errno));
            memcpy(resp->output, "Could not open directory", sizeof("Could not open directory"));
            cJSON_Delete(resp->formatted_response);
            resp->formatted_response = NULL;
            free(parent);
            free(path_name);
            resp->status = -1;
            return;
        }

        cJSON *files = cJSON_CreateArray();
        if (files == NULL) {
            DBGPRINT("cJSON_CreateArray failed: %s", strerror(errno));
            memcpy(resp->output, "Memory allocation failed", sizeof("Memory allocation failed"));
            cJSON_Delete(resp->formatted_response);
            resp->formatted_response = NULL;
            closedir(dr);
            free(parent);
            free(path_name);
            resp->status = -1;
            return;
        }

        struct dirent *de;
        size_t full_path_len = strlen(full_path);

        while ((de = readdir(dr)) != NULL) {
            // Pass over . and ..
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                continue;

            // Create a file object
            char child_path[PATH_MAX];
            size_t name_len = strlen(de->d_name);
            if (full_path_len + 1 + name_len + 1 > PATH_MAX) {
                DBGPRINT("child path too long for %s, skipping", de->d_name);
                continue;
            }
            memcpy(child_path, full_path, full_path_len);
            child_path[full_path_len] = '/';
            memcpy(child_path + full_path_len + 1, de->d_name, name_len + 1);

            cJSON *file = create_FileObject(child_path, de->d_name);
            if (file == NULL) {
                // Skip entries we can't stat rather than failing the whole listing
                DBGPRINT("create_FileObject failed for %s, skipping", child_path);
                continue;
            }

            // Add object to the array
            cJSON_AddItemToArray(files, file);
        }

        // Add array to the file browser JSON
        cJSON_AddItemToObject(resp->formatted_response, "files", files);

        // Close dirent object
        closedir(dr);
    } else {
        // Only report information on the file
        cJSON_AddBoolToObject(resp->formatted_response, "is_file", true);
    }

    // Set this to populate the user_output
    cJSON_AddBoolToObject(resp->formatted_response, "set_as_user_output", true);

    // Cleanup
    free(parent);
    free(path_name);
    resp->status = 0;
}
