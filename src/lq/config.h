#ifndef LQ_CONFIG_H_
#define LQ_CONFIG_H_

#ifndef LQ_CONFIG_MEMCAP
#define LQ_CONFIG_MEMCAP 65536
#endif

#ifndef LQ_CONFIG_MAX
#define LQ_CONFIG_MAX 128
#endif

#include "lq/mem.h"

/**
 * Core configuration keys.
 */
enum lq_config_core_e {
	LQ_CFG_DIR_BASE, ///< Base working directory.
	LQ_CFG_DIR_CONFIG, ///< Configurations directory.
	LQ_CFG_DIR_DATA, ///< Data directory.
	LQ_CFG_DIR_CACHE, ///< Cache directory.
	LQ_CFG_LAST, ///< Start of subsystem defined configuration keys.
};


/**
 * \brief Initialize the instance-wide config singleton.
 *
 * @return ERR_OK on success.
 */
int lq_config_init();

/**
 * \brief Register a configuration key/value pair.
 *
 * \param[in] Type of value to be stored under key.
 * \param[in] Configuration key.
 * \return ERR_OK on success.
 */
int lq_config_register(enum lq_typ_e typ, const char *name);

/**
 * \brief Set value for a configuration key.
 *
 * \param[in] Configuration key.
 * \param[in] Value to set. Must correspond to the previously registered value type.
 * \return ERR_OK on success.
 *
 * \see lq_config_register
 */
int lq_config_set(int k, void *v); 

/**
 * \brief Retrieve a value stored under a configuration key.
 *
 * \param[in] Configuration key.
 * \param[out] Pointer to value write location. Must be sufficient to hold the registered value type.
 * \return ERR_OK on success.
 *
 * \see lq_config_register
 */
int lq_config_get(int k, void **r);

/**
 * \brief Release configuration resources.
 */
void lq_config_free();

#endif
