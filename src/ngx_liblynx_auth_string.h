/*
 * Copyright (C) 2020 LibLynx LLC
 * Copyright (C) 2018 Tesla Government
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * https://github.com/liblynx-llc/ngx-liblynx-auth-module
 */

#ifndef _NGX_LIBLYNX_AUTH_STRING_H
#define _NGX_LIBLYNX_AUTH_STRING_H

#include <ngx_core.h>

char *ngx_str_t_to_char_ptr(ngx_pool_t *pool, ngx_str_t str);
ngx_str_t ngx_char_ptr_to_str_t(ngx_pool_t *pool, char *char_ptr);
char *ngx_substr_t_to_char_ptr(ngx_pool_t *pool, ngx_str_t src, size_t offset, size_t len);

#endif /* _NGX_LIBLYNX_AUTH_STRING_H */
