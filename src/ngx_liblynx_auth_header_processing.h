/*
 * Copyright (C) 2020 LibLynx LLC
 * Copyright (C) 2018 Tesla Government
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * https://github.com/liblynx-llc/ngx-liblynx-auth-module
 */

#ifndef _NGX_LIBLYNX_AUTH_HEADER_PROCESSING_H
#define _NGX_LIBLYNX_AUTH_HEADER_PROCESSING_H

ngx_table_elt_t *search_headers_in(ngx_http_request_t *r, u_char *name, size_t len);
ngx_int_t set_custom_header_in_headers_out(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *value);

#endif /* _NGX_LIBLYNX_AUTH_HEADER_PROCESSING_H */
