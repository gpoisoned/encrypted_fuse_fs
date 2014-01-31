/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/


#define FUSE_USE_VERSION 28
#define BUFSIZE 256
#define PAGESIZE 4096
#define CIPHER_BLOCKSIZE 128
#define AES_ENCRYPT 1
#define AES_DECRYPT 0
#define AES_PASSTHRU -1
#define HAVE_SETXATTR
#define ENCRYPTED_ATTR  "user.pa4-encfs.encrypted"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#define _GNU_SOURCE
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include <openssl/evp.h>
#include <openssl/aes.h>

#include "aes-crypt.h"

typedef struct {
    char *rootdir;
    char key[32];
    char iv[32];
} xmp_state;

static char *_xmp_fullpath(char *buf, const char *path, size_t bufsize){
    xmp_state *state = (xmp_state *)(fuse_get_context()->private_data);
    snprintf(buf, bufsize, "%s%s", state->rootdir, path);
    return buf;
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
    int res;
    char buf[BUFSIZE];

    res = lstat(_xmp_fullpath(buf, path, BUFSIZE), stbuf);

    if (res == -1)
        return -errno;

    return 0;
}
static int xmp_access(const char *path, int mask) {
    int res;
    char buf[BUFSIZE];

    res = access(_xmp_fullpath(buf, path, BUFSIZE), mask);

    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
    int res;
    char pathbuf[BUFSIZE];

    res = readlink(_xmp_fullpath(pathbuf, path, BUFSIZE), buf, size - 1);

    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
        off_t offset, struct fuse_file_info *fi)
{
    DIR *dp;
    struct dirent *de;
    char pathbuf[BUFSIZE];

    (void) offset;
    (void) fi;

    dp = opendir(_xmp_fullpath(pathbuf, path, BUFSIZE));

    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0))
            break;
    }

    closedir(dp);
    return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;
    char buf[BUFSIZE];

    _xmp_fullpath(buf, path, BUFSIZE);

    /* On Linux this could just be 'mknod(path, mode, rdev)' but this
       is more portable */

    if (S_ISREG(mode)) {
        res = open(buf, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
            res = close(res);
    } else if (S_ISFIFO(mode))
        res = mkfifo(buf, mode);
    else
        res = mknod(buf, mode, rdev);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
    int res;
    char buf[BUFSIZE];

    res = mkdir(_xmp_fullpath(buf, path, BUFSIZE), mode);

    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_unlink(const char *path)
{
    int res;
    char buf[BUFSIZE];

    res = unlink(_xmp_fullpath(buf, path, BUFSIZE));

    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rmdir(const char *path)
{
    int res;
    char buf[BUFSIZE];

    res = rmdir(_xmp_fullpath(buf, path, BUFSIZE));
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
    int res;
    char full_from[BUFSIZE];
    char full_to[BUFSIZE];

    res = symlink(_xmp_fullpath(full_from, from, BUFSIZE), 
            _xmp_fullpath(full_to, to, BUFSIZE));
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rename(const char *from, const char *to)
{
    int res;
    char full_from[BUFSIZE];
    char full_to[BUFSIZE];

    res = rename(_xmp_fullpath(full_from, from, BUFSIZE), 
            _xmp_fullpath(full_to, to, BUFSIZE));

    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_link(const char *from, const char *to)
{
    int res;
    char full_from[BUFSIZE];
    char full_to[BUFSIZE];

    res = link(_xmp_fullpath(full_from, from, BUFSIZE), 
            _xmp_fullpath(full_to, to, BUFSIZE));

    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
    int res;
    char buf[BUFSIZE];

    res = chmod(_xmp_fullpath(buf, path, BUFSIZE), mode);

    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;
    char buf[BUFSIZE];

    res = lchown(_xmp_fullpath(buf, path, BUFSIZE), uid, gid);

    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
    int res;
    char buf[BUFSIZE];

    res = truncate(_xmp_fullpath(buf, path, BUFSIZE), size);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
    int res;
    struct timeval tv[2];
    char buf[BUFSIZE];

    tv[0].tv_sec = ts[0].tv_sec;
    tv[0].tv_usec = ts[0].tv_nsec / 1000;
    tv[1].tv_sec = ts[1].tv_sec;
    tv[1].tv_usec = ts[1].tv_nsec / 1000;

    res = utimes(_xmp_fullpath(buf, path, BUFSIZE), tv);

    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
    int res;
    char buf[BUFSIZE];

    res = open(_xmp_fullpath(buf, path, BUFSIZE), fi->flags);
    if (res == -1)
        return -errno;

    close(res);
    return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
        struct fuse_file_info *fi)
{
    FILE *f, *memstream;
    int res;
    char pathbuf[BUFSIZE];
    char *membuf;
    size_t memsize;

    (void) fi;
    f = fopen(_xmp_fullpath(pathbuf, path, BUFSIZE), "r");
    memstream = open_memstream(&membuf, &memsize);
    if (f == NULL || memstream == NULL)
        return -errno;

    char attrbuf[8];
    ssize_t attr_len = getxattr(pathbuf, ENCRYPTED_ATTR, attrbuf, 8);
    int crypt_action = AES_PASSTHRU;
    if(attr_len != -1 && !memcmp(attrbuf, "true", 4)){
        crypt_action = AES_DECRYPT;
    }

    xmp_state *state = (xmp_state *)(fuse_get_context()->private_data);
    do_crypt(f, memstream, crypt_action, state->key);
    fflush(memstream);
    fseek(memstream, offset, SEEK_SET);
    res = fread(buf, 1, size, memstream);
    fclose(memstream);

    if (res == -1)
        res = -errno;

    fclose(f);
    return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
        off_t offset, struct fuse_file_info *fi)
{
    FILE *f, *memstream;
    int res;
    char pathbuf[BUFSIZE];
    char *membuf;
    size_t memsize;

    (void) fi;
    xmp_state *state = (xmp_state *)(fuse_get_context()->private_data);
    f = fopen(_xmp_fullpath(pathbuf, path, BUFSIZE), "r");
    memstream = open_memstream(&membuf, &memsize);

    if (memstream == NULL)
        return -errno;

    char attrbuf[8];
    ssize_t attr_len = getxattr(pathbuf, ENCRYPTED_ATTR, attrbuf, 8);
    int encrypted = 0;
    if(attr_len != -1 && !memcmp(attrbuf, "true", 4)){
        encrypted = 1;
    }

    if(f != NULL){
        do_crypt(f, memstream, (encrypted ? AES_DECRYPT : AES_PASSTHRU), state->key);
        fclose(f);
    }

    fseek(memstream, offset, SEEK_SET);
    res = fwrite(buf, 1, size, memstream);
    fflush(memstream);
    f = fopen(pathbuf, "w");

    fseek(memstream, 0, SEEK_SET);
    do_crypt(memstream, f, (encrypted ? AES_ENCRYPT : AES_PASSTHRU), state->key);
    fclose(memstream);

    if (res == -1)
        res = -errno;

    fclose(f);
    return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
    int res;
    char buf[BUFSIZE];

    res = statvfs(_xmp_fullpath(buf, path, BUFSIZE), stbuf);

    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

    (void) fi;
    (void) mode;
    char buf[BUFSIZE];

    FILE *res;
    res = fopen(_xmp_fullpath(buf, path, BUFSIZE), "w");
    if(res == NULL)
        return -errno;

    FILE *tmp = tmpfile();
    xmp_state *state = (xmp_state *)(fuse_get_context()->private_data);
    do_crypt(tmp, res, AES_ENCRYPT, state->key);
    fclose(tmp);

    if(fsetxattr(fileno(res), ENCRYPTED_ATTR, "true", 4, 0)){
        return -errno;
    }

    fclose(res);


    return 0;
}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{
    /* Just a stub.	 This method is optional and can safely be left
       unimplemented */

    (void) path;
    (void) fi;
    return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
        struct fuse_file_info *fi)
{
    /* Just a stub.	 This method is optional and can safely be left
       unimplemented */

    (void) path;
    (void) isdatasync;
    (void) fi;
    return 0;
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value,
        size_t size, int flags)
{
    char buf[BUFSIZE];
    int res = lsetxattr(_xmp_fullpath(buf, path, BUFSIZE), name, value, 
            size, flags);
    if (res == -1)
        return -errno;
    return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
        size_t size)
{
    char buf[BUFSIZE];
    int res = lgetxattr(_xmp_fullpath(buf, path, BUFSIZE), name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
    char buf[BUFSIZE];
    int res = llistxattr(_xmp_fullpath(buf, path, BUFSIZE), list, size);
    if (res == -1)
        return -errno;
    return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
    char buf[BUFSIZE];
    int res = lremovexattr(_xmp_fullpath(buf, path, BUFSIZE), name);
    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
    .getattr		= xmp_getattr,
    .access		= xmp_access,
    .readlink		= xmp_readlink,
    .readdir		= xmp_readdir,
    .mknod		= xmp_mknod,
    .mkdir		= xmp_mkdir,
    .symlink		= xmp_symlink,
    .unlink		= xmp_unlink,
    .rmdir		= xmp_rmdir,
    .rename		= xmp_rename,
    .link		= xmp_link,
    .chmod		= xmp_chmod,
    .chown		= xmp_chown,
    .truncate		= xmp_truncate,
    .utimens		= xmp_utimens,
    .open		= xmp_open,
    .read		= xmp_read,
    .write		= xmp_write,
    .statfs		= xmp_statfs,
    .create         	= xmp_create,
    .release		= xmp_release,
    .fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
    .setxattr		= xmp_setxattr,
    .getxattr		= xmp_getxattr,
    .listxattr		= xmp_listxattr,
    .removexattr	= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
    umask(0);
    xmp_state state;

    if(argc < 4){

        fprintf(stderr, "encfs usage: ./pa4-encfs %s %s %s\n",
                "<Key Phrase>", "<Mirror Directory>", "<Mount Point>");
        return 1;
    }

    state.rootdir = realpath(argv[2], NULL);
    strncpy(state.key, argv[1], 32);
    state.key[31] = '\0';
    
    return fuse_main(argc - 2, argv + 2, &xmp_oper, &state);
}
