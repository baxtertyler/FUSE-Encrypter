#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define MAX_PATH 1024
#define LOG_PATH "/home/tybaxter/453/prog4/log.txt"
#define AES_BLOCK_SIZE 16
#define PASSWORD "password"

unsigned char key[32];

struct f_state {
    char *rootdir;
};

#define F_DATA ((struct f_state *) fuse_get_context()->private_data)

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


// modified from OpenSSL wiki
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) 
        handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
        
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
        
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// modified from OpenSSL wiki
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            fprintf(stderr, "Error: Failed to create EVP_CIPHER_CTX\n");
            return -EIO;
    }

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
        fprintf(stderr, "Error: EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -EIO;
    }

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){
        fprintf(stderr, "Error: EVP_DecryptUpdate failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -EIO;
    }

    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)){
        fprintf(stderr, "Error: EVP_DecryptFinal_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

static void fullpath(char fpath[MAX_PATH], const char *path)
{
    strcpy(fpath, F_DATA->rootdir);
    strncat(fpath, path, MAX_PATH); 
}

// get path of iv directory or file depending on dir flag
char* getIVpath(const char *path, int dir) {
    if (path == NULL) return NULL;

    const char *lastSlash = strrchr(path, '/');
    
    if (lastSlash == NULL) {
        size_t len = strlen(path) + 5;
        char *newPath = calloc(len, 1);
        if (!newPath) return NULL;
        snprintf(newPath, len, "iv/%s", path);
        return newPath;
    }

    size_t prefixLen = lastSlash - path + 1; 
    size_t totalLen = strlen(path) + 3 + 1;

    char *newPath = calloc(totalLen, 1);
    if (!newPath) return NULL;

    strncpy(newPath, path, prefixLen);
    newPath[prefixLen] = '\0';
    strcat(newPath, ".iv/");
    if (dir == 0) {
        strcat(newPath, lastSlash + 1);
    }

    return newPath;
    free(newPath);
}

int directory_exists(const char *path) {
    struct stat sb;
    return (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode));
}

int iv_file_exists(const char *path) {
    struct stat sb;
    return (stat(path, &sb) == 0 && S_ISREG(sb.st_mode));
}

void generate_random_iv(unsigned char *iv) {
    if (RAND_bytes(iv, 16) != 1) {
        fprintf(stderr, "Error generating random IV\n");
        exit(1); 
    }
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
    int res;

    char fpath[MAX_PATH];
    fullpath(fpath, path);

    res = lstat(fpath, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_access(const char *path, int mask)
{
    int res;

    char fpath[MAX_PATH];
    fullpath(fpath, path);

    res = access(fpath, mask);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    DIR *dp;
    struct dirent *de;

    (void) offset;
    (void) fi;

    char fpath[MAX_PATH];
    fullpath(fpath, path);

    dp = opendir(fpath);
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

static int xmp_mkdir(const char *path, mode_t mode)
{
    int res;

    char fpath[MAX_PATH];
    fullpath(fpath, path);
    
    res = mkdir(fpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rmdir(const char *path)
{
    int res;

    char fpath[MAX_PATH];
    fullpath(fpath, path);

    res = rmdir(fpath);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
    int res;
    
    char fpath[MAX_PATH];
    fullpath(fpath, path);

    char ivFilePath[MAX_PATH];
    strcpy(ivFilePath, getIVpath(fpath, 0));
    
    // regular file
    if (!iv_file_exists(ivFilePath)) {
        res = truncate(fpath, size);
        if (res == -1)
            return -errno;
        return 0;
    }

    // get our IV
    unsigned char iv[16];
    int fd_iv;
    fd_iv = open(ivFilePath, O_RDONLY, 0644);
    pread(fd_iv, iv, 16, 0);
    close(fd_iv);

    // read from the file
    int fd = open(fpath, O_RDWR);

    int ciphertext_len;
    ciphertext_len = lseek(fd, 0, SEEK_END); //  get size of encrypted file
    if (ciphertext_len == 0) {
        close(fd);
        return 0;
    }
    unsigned char* ciphertext = calloc(ciphertext_len, sizeof(char));
    lseek(fd, 0, SEEK_SET); // set FD back to beginning of file;

    res = pread(fd, ciphertext, ciphertext_len, 0);
    if (res == -1) {
        close(fd);
        return -errno;
    }

    // decrypte the file
    unsigned char* plaintext = calloc(ciphertext_len, sizeof(char));
    int plaintext_len = decrypt(ciphertext, ciphertext_len, key, iv, plaintext);
    plaintext = realloc(plaintext, plaintext_len);

    // encrypt the file with size
    unsigned char* output = calloc(plaintext_len + AES_BLOCK_SIZE + size, sizeof(char));

    close(fd);

    // delete old file
    res = unlink(fpath);

    // create new file
    fd = open(fpath, O_CREAT | O_EXCL | O_WRONLY, 0777);

    // encrypt plaintext
    ciphertext_len = encrypt(plaintext, size, key, iv, output);
    output = realloc(output, ciphertext_len);

    int trunc_size = ftruncate(fd, ciphertext_len);
    if (trunc_size == -1) {
        close(fd);
        return -errno;
    }
    
    // write ciphertext to new file
    res = write(fd, output, ciphertext_len);

    close(fd);
    free(output);
    free(plaintext);
    free(ciphertext);

    return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{

    int res;

    char fpath[MAX_PATH];
    fullpath(fpath, path);

    res = open(fpath, fi->flags);
    if (res == -1)
        return -errno;

    close(res);
    return 0;
}

/**
 * path - path of file being read
 * buf - buffer that should store the data from from the file specified by path
 * size - the number of bytes we are reading
 * offset - location in the file where reading should began
 * fi - metadata about open directory
 */
static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    int fd;
    int res;

    // get full path from given path
    char fpath[MAX_PATH];
    fullpath(fpath, path);

    // get FD of open file
    fd = open(fpath, O_RDONLY);

    char ivFilePath[MAX_PATH];
    strcpy(ivFilePath, getIVpath(fpath, 0));

    // unencrypted file...
    // we need to delete from IV when we unlink!!
    if (!iv_file_exists(ivFilePath)) {
        res = pread(fd, buf, size, offset);
        close(fd);
        return res;
    }

    // get IV
    unsigned char iv[16];
    int fd_iv;
    fd_iv = open(ivFilePath, O_RDONLY, 0644);
    pread(fd_iv, iv, 16, 0);
    close(fd_iv);


    // read from file (encrypted text)
    int ciphertext_len;
    ciphertext_len = lseek(fd, 0, SEEK_END); //  get size of encrypted file
    if (ciphertext_len == 0) {
        close(fd);
        return 0;
    }
    unsigned char* ciphertext = calloc(ciphertext_len, sizeof(char));
    lseek(fd, 0, SEEK_SET); // set FD back to beginning of file;

    res = pread(fd, ciphertext, size, offset);
    if (res == -1) {
        close(fd);
        return -errno;
    }

    // Create a buffer for the decrypted data
    unsigned char* plaintext = calloc(size, sizeof(char));
    int plaintext_len = decrypt(ciphertext, res, key, iv, plaintext);

    // Copy the decrypted data into the buffer to return to the user
    memcpy(buf, plaintext, plaintext_len);
        
    close(fd);
    free(ciphertext);
    free(plaintext);
    return res;
}

/**
 * path - path of file being written to
 * buf - pointer to the data that will be written to file at path
 * size - number of bytes the user wants to write
 * offset - location in file where write operation should start
 * fi - metadata for open file (THIS MEANS FILE IS ALREADY OPEN)
 */
static int xmp_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    int fd;
    int res;


    char fpath[MAX_PATH];
    fullpath(fpath, path);


    fd = open(fpath, O_RDWR);

    
    char ivFilePath[MAX_PATH];
    strcpy(ivFilePath, getIVpath(fpath, 0));

    
    if (!iv_file_exists(ivFilePath)) {
        res = pwrite(fd, buf, size, offset);
        close(fd);
        return res;
    }

    
    // get our IV
    unsigned char iv[16];
    int fd_iv;
    fd_iv = open(ivFilePath, O_RDONLY, 0644);
    pread(fd_iv, iv, 16, 0);
    close(fd_iv);


    // read from file (encrypted text)
    int ciphertext_len;
    ciphertext_len = lseek(fd, 0, SEEK_END); //  get size of encrypted file
    unsigned char* ciphertext = calloc(ciphertext_len, sizeof(char));
    lseek(fd, 0, SEEK_SET); // set FD back to beginning of file;


    unsigned char* output;

    if (ciphertext_len > 0) { // non empty file -> must decrypt, append, encrypt
        
        // read current file contents and store in ciphertext
        res = read(fd, ciphertext, ciphertext_len);
        if (res == -1) {
            close(fd);
            return -errno;
        }

        // decrypt current file content and store in plaintext
        int plaintext_len;
        unsigned char* plaintext;
        plaintext = calloc(ciphertext_len + size, sizeof(char));

        plaintext_len = decrypt(ciphertext, res, key, iv, plaintext);
        plaintext[plaintext_len] = 0;

        // add space for output from encrypting
        output = calloc(plaintext_len + size + AES_BLOCK_SIZE, sizeof(char));
        memcpy(plaintext + plaintext_len, buf, size);
        ciphertext_len = encrypt((unsigned char *) plaintext, plaintext_len + size, key, iv, output);
        free(plaintext);

    } else if (ciphertext_len == 0) { // empty file -> 
        output = calloc(size, 1);
        ciphertext_len = encrypt((unsigned char *) buf, size, key, iv, output);
    } else { //error
        return -errno;
    }

    fd = open(fpath, O_WRONLY);
    if (fd == -1)
        return -errno;

    res = pwrite(fd, output, ciphertext_len, 0);
    if (res == -1)
        res = -errno;

    close(fd);
    free(output);
    free(ciphertext);
    return res;

}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
    int res;

    char fpath[MAX_PATH];
    fullpath(fpath, path);

    res = statvfs(fpath, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rename(const char *from, const char *to)
{
    int res;

    // get from full path
    char fpath[MAX_PATH];
    fullpath(fpath, from);

    // get to full path
    char tpath[MAX_PATH];
    fullpath(tpath, to);

    res = rename(fpath, tpath);
    if (res == -1)
        return -errno;

    return 0;
}

/*
static int xmp_rename(const char *from, const char *to)
{
    // get from full path
    char fpath[MAX_PATH];
    fullpath(fpath, from);

    // get to full path
    char tpath[MAX_PATH];
    fullpath(tpath, to);

    // get from IV path
    char fromIvFilePath[MAX_PATH];
    strcpy(fromIvFilePath, getIVpath(fpath, 0));

    // get to IV path
    char toIvFilePath[MAX_PATH];
    strcpy(toIvFilePath, getIVpath(tpath, 0));

    // Non encrypted file
    if (!iv_file_exists(fromIvFilePath)) {
        int res;

        res = rename(fpath, tpath);
        if (res == -1)
            return -errno;

        return 0;
    }

    int resPath;
    int resIv;

    // resIv = rename(fromIvFilePath, toIvFilePath);
    // resPath = rename(fpath, tpath);
    // if (resIv == -1 || resPath == -1) 
    //     return -errno;

    return 0;
    
}
*/


static int xmp_chmod(const char *path, mode_t mode)
{
    int res;

    char fpath[MAX_PATH];
    fullpath(fpath, path);

    res = chmod(path, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;

    char fpath[MAX_PATH];
    fullpath(fpath, path);

    res = lchown(fpath, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
    int res;

    char fpath[MAX_PATH];
    fullpath(fpath, path);

    char ivPath[MAX_PATH];
    strcpy(ivPath, getIVpath(fpath, 1));
    
    if (!directory_exists(ivPath)) {
        // create the iv directory
        mkdir(ivPath, 0777); 
    }
    
    // regardless if we just made it, the IV file wont exist yet
    char ivFilePath[MAX_PATH];
    strcpy(ivFilePath, getIVpath(fpath, 0));
    res = open(ivFilePath, O_CREAT | O_RDWR, 0777);
    
    // unsigned char* iv = malloc(16);
    unsigned char* iv = calloc(16, 1);

    generate_random_iv(iv);
    pwrite(res, iv, 16, 0); // should write actual IV!
    free(iv);

    /* On Linux this could just be 'mknod(path, mode, rdev)' but this
       is more portable */
    if (S_ISREG(mode)) {
        res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
            res = close(res);
    } else if (S_ISFIFO(mode))
        res = mkfifo(fpath, mode);
    else
        res = mknod(fpath, mode, rdev);
    if (res == -1) {
        return -errno;
    }
    return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
    
    char fpath[MAX_PATH];
    fullpath(fpath, path);

    int res;
    struct timeval tv[2];

    tv[0].tv_sec = ts[0].tv_sec;
    tv[0].tv_usec = ts[0].tv_nsec / 1000;
    tv[1].tv_sec = ts[1].tv_sec;
    tv[1].tv_usec = ts[1].tv_nsec / 1000;

    res = utimes(fpath, tv);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_unlink(const char *path)
{
    int res;

    char fpath[MAX_PATH];
    fullpath(fpath, path);
    res = unlink(fpath);
    if (res == -1)
        return -errno;

    return 0;
}

/*
static int xmp_unlink(const char *path)
{
    
    int res;
    
    char fpath[MAX_PATH];
    fullpath(fpath, path);

    char ivFilePath[MAX_PATH];
    strcpy(ivFilePath, getIVpath(fpath, 0));

    if (!iv_file_exists(ivFilePath)) {
        res = unlink(fpath);
        if (res == -1)
            return -errno;
    
        return 0;
    }

    // unlink the file path
    int resPath;
    resPath = unlink(fpath);

    // unline the IV file path
    int resIv;
    resIv = unlink(ivFilePath);

    if (resIv == -1 || resPath == -1) 
        return -errno;

    // return 0;  
}
*/

static struct fuse_operations xmp_oper = {
    .getattr    = xmp_getattr,
    .access = xmp_access,
    .readdir    = xmp_readdir,
    .mkdir  = xmp_mkdir,
    .rmdir  = xmp_rmdir,
    .open   = xmp_open,
    .read   = xmp_read,
    .write  = xmp_write,
    .statfs = xmp_statfs,
    .rename = xmp_rename,
    .truncate   = xmp_truncate,
    .unlink = xmp_unlink,
    .chmod  = xmp_chmod,
    .chown  = xmp_chown,
    .mknod  = xmp_mknod,
    .utimens    = xmp_utimens,

};

int main(int argc, char *argv[])
{
    struct f_state *f_data;

    unsigned char key[32];
    int nrounds = 5;
    int i;
    unsigned char iv[32];
    char passkey[256];

    printf("Enter passkey: ");
    fgets(passkey, sizeof(passkey), stdin);
    passkey[strcspn(passkey, "\n")] = 0;

    i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL, (unsigned char*)passkey, strlen(passkey), nrounds, key, iv);
    if (i != 32) {
        /* Error */
        fprintf(stderr, "Key size is %d bits - should be 256 bits\n", i*8);
        return 0;
    }


    //f_data = malloc(sizeof(struct f_state));
    f_data = calloc(sizeof(struct f_state), 1);
    
    if (f_data == NULL) {
        perror("main calloc");
        abort();
    }

    f_data->rootdir = realpath(argv[argc-1], NULL);
    argv[argc-1] = NULL;
    argc--;

    umask(0);
    return fuse_main(argc, argv, &xmp_oper, f_data);
    free(f_data);
}