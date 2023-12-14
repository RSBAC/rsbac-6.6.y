/************************************ */
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2021: Amon Ott */
/* API:                               */
/* Functions for Access               */
/* Control Information / UDF          */
/* Last modified: 03/Dec/2021         */
/************************************ */

#ifndef __RSBAC_UDF_H
#define __RSBAC_UDF_H

#include <rsbac/types.h>

/* Get ttl for new cache items in seconds */
/* This function returns 0, if no cache is available, and the ttl value
   otherwise */
rsbac_time_t rsbac_udf_get_ttl(void);

/* Set ttl for new cache items in seconds */
/* ttl must be positive, values bigger than 10 years in seconds
   (RSBAC_LIST_MAX_AGE_LIMIT in lists.h) are reduced to this limit */
void rsbac_udf_set_ttl(rsbac_time_t ttl);

/* Get ttl for in-progress cache items in seconds */
/* This function returns 0, if no cache is available, and the ttl value
   otherwise */
rsbac_time_t rsbac_udf_get_progress_ttl(void);

/* Set ttl for in-progress cache items in seconds */
/* ttl must be positive, values bigger than 10 years in seconds
   (RSBAC_LIST_MAX_AGE_LIMIT in lists.h) are reduced to this limit */
void rsbac_udf_set_progress_ttl(rsbac_time_t ttl);

/* Flush UDF cache lists */
int rsbac_udf_flush_cache(void);
#endif
