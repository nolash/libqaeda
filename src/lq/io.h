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

#endif // LIBQAEDA_IO_H_
