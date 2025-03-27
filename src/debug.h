#ifndef MORGEL_H_
#define MORGEL_H_

/**
 * \brief Data type indicator for the structured log.
 *
 * \see debug_dbg_x
 */
enum debug_typ_e {
	MORGEL_TYP_BIN, ///< Binary content type.
	MORGEL_TYP_NUM, ///< Numeric content type.
	MORGEL_TYP_STR,
};

/**
 * \brief Log a literal message with the given namespace.
 *
 * \param[in] Namespace string. If NULL, will use the default namespace.
 * \param[in] Literal message to log.
 */
void debug_dbg(const char *ns, const char *msg);

/**
 * \brief Log a structured message with the given namespace.
 *
 * Each structured argument consist of three parameters:
 *	1. An enum debug_typ_e specifying the type of value (and thus how to format it)
 *	2. An int value specifying the length of the value behind the pointer, in bytes. Currently only used with MORGEL_TYPE_BIN
 *	3. Pointer to value.
 *
 * \param[in] Namespace string. If NULL, will use the default namespace.
 * \param[in] Main message to log.
 * \param[in] Number of structured key/value arguments.
 * \param[in] Key/value list (see above)
 */
void debug_dbg_x(const char *ns, const char *msg, int argc, ...);

/**
 * \brief Convenience function to log a single error, using rerr for error code to string resolution.
 *
 * \param[in] Log level to use for the log line.
 * \param[in] Error code to log.
 * \param[in] Supporting message to include in log line.
 * \return The error code.
 */
int debug_logerr(enum lloglvl_e lvl, int err, char *msg);

#endif // MORGEL_H_
