#ifndef LIBQAEDA_IO_H_
#define LIBQAEDA_IO_H_

/**
 * @brief Create temporary directory using template.
 *
 * @param[in] Directory path template
 * @return Pointer to valid path string. NULL if directory could not be created.
 */
char* mktempdir(char *s);

#endif // LIBQAEDA_IO_H_
