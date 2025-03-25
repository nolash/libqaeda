#ifndef LIBQAEDA_IO_H_
#define LIBQAEDA_IO_H_

#ifndef LQ_PATH_MAX
#define LQ_PATH_MAX 1024
#endif

/**
 * @brief Create temporary directory using template.
 *
 * @param[in] Directory path template
 * @return Pointer to valid path string. NULL if directory could not be created.
 */
char* mktempdir(char *s);
int lq_open(const char *pathname, int flags, int mode);
int lq_read(int f, char *buf, int c);
void lq_close(int fd);

#endif // LIBQAEDA_IO_H_
