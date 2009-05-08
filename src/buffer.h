#ifndef Buffer_H
#define Buffer_H

typedef struct Buffer {
    int buflength;
    int pos;
    char *buf;
} Buffer, *BUFFER;

extern BUFFER newbuf(int initial_length);
extern BUFFER dupbuf(BUFFER buf);
extern void killbuf(BUFFER buf);
extern void buf_append(BUFFER buf, char ch);
extern void buf_append_n(BUFFER buf, char *chs, int n);
extern void buf_insert(BUFFER buf, char ch, int pos);
extern void buf_delete(BUFFER buf, int pos);

#endif
