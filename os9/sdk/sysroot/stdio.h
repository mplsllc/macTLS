#ifndef _STDIO_H
#define _STDIO_H

#include <stddef.h>

#define EOF (-1)
#define BUFSIZ 1024
#define FILENAME_MAX 1024

typedef struct __FILE FILE;

extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

extern int printf(const char *format, ...);
extern int fprintf(FILE *stream, const char *format, ...);
extern int sprintf(char *str, const char *format, ...);
extern int snprintf(char *str, size_t size, const char *format, ...);
extern int puts(const char *s);
extern int putchar(int c);
extern int puts(const char *s);
extern int fputc(int c, FILE *stream);
extern int fputs(const char *s, FILE *stream);
extern size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
extern size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
extern int fclose(FILE *stream);
extern FILE *fopen(const char *filename, const char *mode);
extern int fflush(FILE *stream);
extern int fseek(FILE *stream, long offset, int whence);
extern long ftell(FILE *stream);
extern int fgetc(FILE *stream);
extern int getc(FILE *stream);
extern int getchar(void);
extern int ungetc(int c, FILE *stream);

#endif
