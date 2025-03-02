#ifndef LASH_HEX_H_
#define LASH_HEX_H_

void b2c(char in, char *out);
int c2b(const char in, char *out);
int h2b(const char *in, unsigned char *out);
void b2h(const unsigned char *in, int l, unsigned char *out);
char* c2h(char in, char *out);

#endif
