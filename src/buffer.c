#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "buffer.h"

BUFFER newbuf(int initial_length) {
  BUFFER buf = malloc(sizeof(Buffer));

  buf->buflength = initial_length;
  buf->pos = 0;
  buf->buf = malloc(initial_length);
  memset(buf->buf, 0, initial_length);

  return buf;
}

BUFFER dupbuf(BUFFER buf) {
  BUFFER n = malloc(sizeof(Buffer));

  n->buflength = buf->buflength;
  n->pos = buf->pos;
  n->buf = malloc(buf->buflength);
  memcpy(n->buf, buf->buf, buf->buflength);

  return n;
}

void killbuf(BUFFER buf) {
  free(buf->buf);
  free(buf);
}

void buf_append(BUFFER buf, char ch) {
  if (buf->pos >= buf->buflength) {
    char *newbuf = realloc(buf->buf, buf->buflength + 128);

    if (newbuf == NULL) {
      fprintf(stderr, "buf_append: could not grow buffer\n");
      exit(1);
    }

    buf->buf = newbuf;
    buf->buflength += 128;
  }

  buf->buf[buf->pos++] = ch;
}

void buf_append_n(BUFFER buf, char *chs, int n) {
  if (buf->pos + n > buf->buflength) {
    char *newbuf = realloc(buf->buf, buf->buflength + n + 128);

    if (newbuf == NULL) {
      fprintf(stderr, "buf_append_n: could not grow buffer\n");
      exit(1);
    }

    buf->buf = newbuf;
    buf->buflength += n + 128;
  }

  memcpy(&buf->buf[buf->pos], chs, n);
  buf->pos += n;
}

void buf_insert(BUFFER buf, char ch, int pos) {
  int i;

  if (pos < 0)
    pos = 0;
  if (pos > buf->pos)
    pos = buf->pos;

  buf_append(buf, 0);
  for (i = buf->pos; i > pos; i--)
    buf->buf[i] = buf->buf[i-1];
  buf->buf[pos] = ch;
}

void buf_delete(BUFFER buf, int pos) {
  int i;

  if (pos < 0)
    pos = 0;
  if (pos >= buf->pos)
    pos = buf->pos - 1;

  for (i = pos; i < buf->pos; i++)
    buf->buf[i] = buf->buf[i+1];
  buf->buf[buf->pos - 1] = '\0';
  buf->pos--;
}
