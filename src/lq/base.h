#ifndef LQ_BASE_H_
#define LQ_BASE_H_

#ifndef LQ_BLOCKSIZE
/***
 * \brief The buffer unit size used by libqaeda.
 */
#define LQ_BLOCKSIZE 4096
#endif

/***
 * \brief Initialize libqaeda internals.
 *
 * \returns ERR_OK on successful initialization. On any other return value, library cannot be used.
 */
int lq_init();

/***
 * \brief Release resources used by libqaeda internals.
 */
void lq_finish();

#endif // LQ_BASE_H_
