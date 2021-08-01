/*
 * Copyright (C) 2020 LibLynx LLC
 * Copyright (C) 2018 Tesla Government
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * https://github.com/liblynx-llc/ngx-liblynx-auth-module
 */

#include <jansson.h>
#include <jwt.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_liblynx_auth_header_processing.h"
#include "ngx_liblynx_auth_string.h"

typedef struct {
    ngx_str_t auth_liblynx_loginurl;
    ngx_str_t auth_liblynx_key;
    ngx_flag_t auth_liblynx_enabled;
    ngx_flag_t auth_liblynx_redirector;
    ngx_flag_t auth_liblynx_logout;
    ngx_str_t auth_liblynx_algorithm;
    ngx_flag_t auth_liblynx_validate_ip;
    ngx_str_t auth_liblynx_content_code;
    ngx_str_t auth_liblynx_denial;
    ngx_str_t auth_liblynx_cookie_name;
    ngx_str_t auth_liblynx_cookie_attrs;
} ngx_liblynx_auth_loc_conf_t;

static ngx_int_t ngx_liblynx_auth_init(ngx_conf_t *cf);
static ngx_int_t ngx_liblynx_auth_handler(ngx_http_request_t *r);
static void *ngx_liblynx_auth_create_loc_conf(ngx_conf_t *cf);
static char *ngx_liblynx_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *get_jwt_from_url(ngx_http_request_t *r);
static char *get_jwt_from_cookie(ngx_http_request_t *r, ngx_str_t auth_liblynx_cookie_name);
static char *ngx_get_fully_qualified_url(ngx_http_request_t *r);
static int redirect_to_login(ngx_http_request_t *r, ngx_liblynx_auth_loc_conf_t *config,
                             jwt_t *jwt);
static int redirect_denial(ngx_http_request_t *r, ngx_liblynx_auth_loc_conf_t *config);
static int redirect_with_cookie(ngx_http_request_t *r, ngx_liblynx_auth_loc_conf_t *config,
                                char *jwtCookieValChrPtr, jwt_t *jwt);
static int add_cookie(ngx_http_request_t *r, ngx_liblynx_auth_loc_conf_t *config,
                      char *jwtCookieValChrPtr, jwt_t *jwt);
static int server_error(ngx_http_request_t *r, char *msg);
static char *get_target_from_url(ngx_http_request_t *r);
static int redirect_target(ngx_http_request_t *r, char *target);
static int clear_cookie(ngx_http_request_t *r, ngx_liblynx_auth_loc_conf_t *config);

static ngx_command_t ngx_liblynx_auth_commands[] = {

    {ngx_string("auth_liblynx_loginurl"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_liblynx_auth_loc_conf_t, auth_liblynx_loginurl), NULL},

    {ngx_string("auth_liblynx_key"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_liblynx_auth_loc_conf_t, auth_liblynx_key), NULL},

    {ngx_string("auth_liblynx_enabled"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_liblynx_auth_loc_conf_t, auth_liblynx_enabled), NULL},

    {ngx_string("auth_liblynx_redirector"), NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_liblynx_auth_loc_conf_t, auth_liblynx_redirector), NULL},

    {ngx_string("auth_liblynx_logout"), NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_liblynx_auth_loc_conf_t, auth_liblynx_logout), NULL},

    {ngx_string("auth_liblynx_algorithm"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_liblynx_auth_loc_conf_t, auth_liblynx_algorithm), NULL},

    {ngx_string("auth_liblynx_validate_ip"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_liblynx_auth_loc_conf_t, auth_liblynx_validate_ip), NULL},

    {ngx_string("auth_liblynx_content_code"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_liblynx_auth_loc_conf_t, auth_liblynx_content_code), NULL},

    {ngx_string("auth_liblynx_denial"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_liblynx_auth_loc_conf_t, auth_liblynx_denial), NULL},

    {ngx_string("auth_liblynx_cookie_name"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_liblynx_auth_loc_conf_t, auth_liblynx_cookie_name), NULL},

    {ngx_string("auth_liblynx_cookie_attrs"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_liblynx_auth_loc_conf_t, auth_liblynx_cookie_attrs), NULL},

    ngx_null_command};

static ngx_http_module_t ngx_liblynx_auth_module_ctx = {
    NULL,                  /* preconfiguration */
    ngx_liblynx_auth_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_liblynx_auth_create_loc_conf, /* create location configuration */
    ngx_liblynx_auth_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_liblynx_auth_module = {NGX_MODULE_V1,
                                        &ngx_liblynx_auth_module_ctx, /* module context */
                                        ngx_liblynx_auth_commands,    /* module directives */
                                        NGX_HTTP_MODULE,              /* module type */
                                        NULL,                         /* init master */
                                        NULL,                         /* init module */
                                        NULL,                         /* init process */
                                        NULL,                         /* init thread */
                                        NULL,                         /* exit thread */
                                        NULL,                         /* exit process */
                                        NULL,                         /* exit master */
                                        NGX_MODULE_V1_PADDING};

static ngx_int_t ngx_liblynx_auth_handler(ngx_http_request_t *r) {
    ngx_str_t subjectHeaderName = ngx_string("x-subject");
    char *jwtCookieValChrPtr;
    ngx_liblynx_auth_loc_conf_t *config;
    jwt_t *jwt = NULL;
    int jwtParseReturnCode;
    jwt_alg_t alg;
    const char *ip;
    const char *sub;
    ngx_str_t sub_t;
    time_t exp;
    time_t now;
    ngx_str_t auth_liblynx_algorithm;
    size_t iplen;
    int returnedFromTransfer;

    config = ngx_http_get_module_loc_conf(r, ngx_liblynx_auth_module);

    if (!config->auth_liblynx_enabled) {
        return NGX_DECLINED;
    }

    // pass through options requests without token authentication
    if (r->method == NGX_HTTP_OPTIONS) {
        return NGX_DECLINED;
    }

    // first try url
    returnedFromTransfer = 0;
    jwtCookieValChrPtr = get_jwt_from_url(r);
    if (jwtCookieValChrPtr) {
        // we've returned from the login URL with a jwt payload
        returnedFromTransfer = 1;
    } else {
        // otherwise try cookie
        jwtCookieValChrPtr = get_jwt_from_cookie(r, config->auth_liblynx_cookie_name);
    }

    if (jwtCookieValChrPtr == NULL) {
        return redirect_to_login(r, config, jwt);
    }

    auth_liblynx_algorithm = config->auth_liblynx_algorithm;
    if (auth_liblynx_algorithm.len == 0 ||
        (auth_liblynx_algorithm.len == sizeof("HS256") - 1 &&
         ngx_strncmp(auth_liblynx_algorithm.data, "HS256", sizeof("HS256") - 1) == 0)) {
        // supported algorithm has been specified, we're good to go
    } else {
        // this is bad
        return server_error(r, "Unsupported auth_liblynx_algorithm value");
    }

    // validate the jwt
    jwtParseReturnCode = jwt_decode(&jwt, jwtCookieValChrPtr, config->auth_liblynx_key.data,
                                    config->auth_liblynx_key.len);
    if (jwtParseReturnCode != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to parse jwt %s",
                      jwtCookieValChrPtr);
        return redirect_to_login(r, config, jwt);
    }

    // after this point, any path which returns must free the jwt

    // validate the algorithm
    alg = jwt_get_alg(jwt);
    if (alg != JWT_ALG_HS256) {
        jwt_free(jwt);
        return server_error(r, "Invalid algorithm in jwt");
    }

    // validate the exp date of the JWT
    exp = (time_t)jwt_get_grant_int(jwt, "exp");
    now = ngx_time();

    if (exp < now) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "jwt has expired");
        return redirect_to_login(r, config, jwt);
    }

    if (returnedFromTransfer) {
        // we've returned from the login url, and we've got a good jwt
        // we're going to drop a cookie and return the same URL without the
        // payload
        // this function will free the jwt memory
        return redirect_with_cookie(r, config, jwtCookieValChrPtr, jwt);
    }

    // ip checks can be turned off in config
    if (config->auth_liblynx_validate_ip == 1) {
        // the JWT issue can decide to not insist on IP checks by not including an
        // ip
        ip = jwt_get_grant(jwt, "ip");
        if (ip) {
            // but if we reach here, the IP grant MUST match client IP
            iplen = strlen(ip);
            if ((iplen != r->connection->addr_text.len) ||
                (ngx_strncmp(r->connection->addr_text.data, ip, r->connection->addr_text.len) !=
                 0)) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "Inbound IP %V mismatched jwt IP %s - will reauthenticate",
                              &r->connection->addr_text, ip);
                return redirect_to_login(r, config, jwt);
            }
        }
    }

    // do a content code check
    if (config->auth_liblynx_content_code.len) {
        // a content code has been configured, it must appear in the jwt as a grant
        // with a boolean value

        // ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Checking required content code %V",
        //              &config->auth_liblynx_content_code);

        // we need a null terminated string
        char *strCode;
        int hasCode;

        strCode = ngx_str_t_to_char_ptr(r->pool, config->auth_liblynx_content_code);

        // jwt_get_grant_bool only in libjwt 1.9.0
        // hasCode = jwt_get_grant_bool(jwt, strCode) == 1;
        // jwt must have int value 1 to indicate code is authorized
        hasCode = jwt_get_grant_int(jwt, strCode) == 1;

        if (!hasCode) {
            jwt_free(jwt);

            // the code is required, but not present in the jwt, so we go to the
            // denial page
            return redirect_denial(r, config);
        }
    }

    if (config->auth_liblynx_redirector) {
        // this location is configured as a redirector - if we reach this far, we're
        // authenticated, and so we look for a target query string and redirect to it
        char *target;
        target = get_target_from_url(r);
        if (target) {
            return redirect_target(r, target);
        }
    }

    if (config->auth_liblynx_logout) {
        // this location is configured as a logout - so we clear our cookie
        // authenticated, and so we look for a target query string and redirect to it
        char *target;
        target = get_target_from_url(r);
        if (target) {
            clear_cookie(r, config);
            return redirect_target(r, target);
        }
    }

    // add subject as header
    sub = jwt_get_grant(jwt, "sub");
    if (sub == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "the jwt does not contain a subject");
    } else {
        sub_t = ngx_char_ptr_to_str_t(r->pool, (char *)sub);
        set_custom_header_in_headers_out(r, &subjectHeaderName, &sub_t);
    }

    jwt_free(jwt);

    return NGX_OK;
}

static int server_error(ngx_http_request_t *r, char *msg) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, msg);
    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}

static int redirect_to_login(ngx_http_request_t *r, ngx_liblynx_auth_loc_conf_t *config,
                             jwt_t *jwt) {

    jwt_t *jwtTransfer;
    char *strTransfer;

    if (jwt) {
        jwt_free(jwt);
    }

    r->headers_out.location = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.location == NULL) {
        return server_error(r, "failed to redirect_to_login");
    }

    r->headers_out.location->hash = 1;
    r->headers_out.location->key.len = sizeof("Location") - 1;
    r->headers_out.location->key.data = (u_char *)"Location";

    // we send our args as a jwt to be tamper proof
    if (jwt_new(&jwtTransfer) != 0) {
        return server_error(r, "failed to create login request jwt");
    }

    jwt_set_alg(jwtTransfer, JWT_ALG_HS256, config->auth_liblynx_key.data,
                config->auth_liblynx_key.len);

    // we include our apparent ip - the remote auth may observe a different ip if
    // the site is accessed via ezproxy - this allows the initial request to be proxied
    // but its fine if we break out during login - we'll come back to the unnproxied site
    jwt_add_grant(jwtTransfer, "ip", ngx_str_t_to_char_ptr(r->pool, r->connection->addr_text));

    // for a GET request, we add the URL - if its anything else, we omit it and
    // will return to the default entry point
    if (r->method == NGX_HTTP_GET) {
        jwt_add_grant(jwtTransfer, "url", ngx_get_fully_qualified_url(r));
    } else {
        // if a default url is configured, use it, otherwise, stick with
        // url as it stands
    }

    // add referrer if available
    if (r->headers_in.referer) {
        jwt_add_grant(jwtTransfer, "ref",
                      ngx_str_t_to_char_ptr(r->pool, r->headers_in.referer->value));
    }

    strTransfer = jwt_encode_str(jwtTransfer);

    int lenTransfer;
    lenTransfer = strlen(strTransfer);

    // now we can construct the return url
    int redirectLen;
    u_char *redirectUrl;
    int redirectIdx;

    redirectLen = config->auth_liblynx_loginurl.len + sizeof("?req=") - 1 + lenTransfer;
    redirectUrl = ngx_palloc(r->pool, redirectLen);
    redirectIdx = 0;

    ngx_memcpy(redirectUrl, config->auth_liblynx_loginurl.data, config->auth_liblynx_loginurl.len);
    redirectIdx += config->auth_liblynx_loginurl.len;

    ngx_memcpy(redirectUrl + redirectIdx, "?req=", sizeof("?req=") - 1);
    redirectIdx += sizeof("?req=") - 1;

    ngx_memcpy(redirectUrl + redirectIdx, strTransfer, lenTransfer);
    redirectIdx += lenTransfer;

    r->headers_out.location->value.len = redirectLen;
    r->headers_out.location->value.data = redirectUrl;

    // later versions of libjwt library use jwt_free_str
    free(strTransfer);
    jwt_free(jwtTransfer);

    return NGX_HTTP_MOVED_TEMPORARILY;
}

static int redirect_with_cookie(ngx_http_request_t *r, ngx_liblynx_auth_loc_conf_t *config,
                                char *jwtCookieValChrPtr, jwt_t *jwt) {
    char *url;
    char *tokenArg;
    char *additionalArgs;

    // strip _lljwt from query string
    url = ngx_get_fully_qualified_url(r);

    tokenArg = ngx_strstr(url, "_lljwt=");
    if (!tokenArg) {
        return server_error(r, "redirect_with_cookie called from invalid url");
    }

    additionalArgs = ngx_strchr(tokenArg, '&');
    if (additionalArgs) {
        int lenAdditionalArgs;
        // we're going to copy everything after the first &
        // over the top of our token including terminating null
        additionalArgs++;
        lenAdditionalArgs = ngx_strlen(additionalArgs);
        ngx_memcpy(tokenArg, additionalArgs, lenAdditionalArgs + 1);
    } else {
        // no args, we can null terminate our URL on the ? char
        tokenArg--;
        *tokenArg = '\0';
    }

    // url is now clean and does not contain the _lljwt query string

    // drop cookie
    if (add_cookie(r, config, jwtCookieValChrPtr, jwt) != NGX_OK) {
        return server_error(r, "redirect_with_cookie failed to add cookie");
    }

    // redirect
    r->headers_out.location = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.location == NULL) {
        return server_error(r, "redirect_with_cookie failed to add location header");
    }

    r->headers_out.location->hash = 1;
    r->headers_out.location->key.len = sizeof("Location") - 1;
    r->headers_out.location->key.data = (u_char *)"Location";
    r->headers_out.location->value.len = ngx_strlen(url);
    r->headers_out.location->value.data = (u_char *)url;

    // free the jwt
    jwt_free(jwt);

    return NGX_HTTP_MOVED_TEMPORARILY;
}

static int add_cookie(ngx_http_request_t *r, ngx_liblynx_auth_loc_conf_t *config,
                      char *jwtCookieValChrPtr, jwt_t *jwt) {
    time_t expires;
    int len;
    int valueLen;
    u_char *cookie;
    ngx_table_elt_t *set_cookie;
    u_char *p;

    // cookie will expire when the token does
    expires = (time_t)jwt_get_grant_int(jwt, "exp");

    valueLen = strlen(jwtCookieValChrPtr);
    len = config->auth_liblynx_cookie_name.len + 1 + valueLen;

    len += sizeof("; expires=") - 1 + sizeof("Mon, 01 Sep 1970 00:00:00 GMT") - 1;

    if (config->auth_liblynx_cookie_attrs.len) {
        len += 2 + config->auth_liblynx_cookie_attrs.len;
    }

    cookie = ngx_pnalloc(r->pool, len);
    if (cookie == NULL) {
        return NGX_ERROR;
    }

    p = ngx_copy(cookie, config->auth_liblynx_cookie_name.data,
                 config->auth_liblynx_cookie_name.len);
    *p++ = '=';
    p = ngx_copy(p, jwtCookieValChrPtr, valueLen);

    // add expires
    p = ngx_cpymem(p, "; expires=", sizeof("; expires=") - 1);
    p = ngx_http_cookie_time(p, expires);

    // add custom attrs
    if (config->auth_liblynx_cookie_attrs.len) {
        *p++ = ';';
        *p++ = ' ';
        p = ngx_cpymem(p, config->auth_liblynx_cookie_attrs.data,
                       config->auth_liblynx_cookie_attrs.len);
    }

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;

    // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "set cookie: \"%V\"", &set_cookie->value);
    return NGX_OK;
}

static int clear_cookie(ngx_http_request_t *r, ngx_liblynx_auth_loc_conf_t *config) {
    time_t expires;
    int len;
    int valueLen;
    u_char *cookie;
    ngx_table_elt_t *set_cookie;
    u_char *p;

    // set expiry to 2000-01-01
    expires = 946684800;

    valueLen = 0;
    len = config->auth_liblynx_cookie_name.len + 1 + valueLen;

    len += sizeof("; expires=") - 1 + sizeof("Mon, 01 Sep 1970 00:00:00 GMT") - 1;

    if (config->auth_liblynx_cookie_attrs.len) {
        len += 2 + config->auth_liblynx_cookie_attrs.len;
    }

    cookie = ngx_pnalloc(r->pool, len);
    if (cookie == NULL) {
        return NGX_ERROR;
    }

    p = ngx_copy(cookie, config->auth_liblynx_cookie_name.data,
                 config->auth_liblynx_cookie_name.len);
    *p++ = '=';
    // no value

    // add expires
    p = ngx_cpymem(p, "; expires=", sizeof("; expires=") - 1);
    p = ngx_http_cookie_time(p, expires);

    // add custom attrs
    if (config->auth_liblynx_cookie_attrs.len) {
        *p++ = ';';
        *p++ = ' ';
        p = ngx_cpymem(p, config->auth_liblynx_cookie_attrs.data,
                       config->auth_liblynx_cookie_attrs.len);
    }

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;

    // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "set cookie: \"%V\"", &set_cookie->value);
    return NGX_OK;
}

static int redirect_target(ngx_http_request_t *r, char *target) {
    r->headers_out.location = ngx_list_push(&r->headers_out.headers);

    if (r->headers_out.location == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.location->hash = 1;
    r->headers_out.location->key.len = sizeof("Location") - 1;
    r->headers_out.location->key.data = (u_char *)"Location";

    int redirectLen;
    u_char *redirectUrl;

    redirectLen = strlen(target);
    redirectUrl = ngx_palloc(r->pool, redirectLen);

    ngx_memcpy(redirectUrl, target, redirectLen);
    r->headers_out.location->value.len = redirectLen;
    r->headers_out.location->value.data = redirectUrl;

    return NGX_HTTP_MOVED_TEMPORARILY;
}

static int redirect_denial(ngx_http_request_t *r, ngx_liblynx_auth_loc_conf_t *config) {
    r->headers_out.location = ngx_list_push(&r->headers_out.headers);

    if (r->headers_out.location == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.location->hash = 1;
    r->headers_out.location->key.len = sizeof("Location") - 1;
    r->headers_out.location->key.data = (u_char *)"Location";

    // construct denial url adding code we could not authorize
    int redirectLen;
    u_char *redirectUrl;
    int redirectIdx;

    redirectLen = config->auth_liblynx_denial.len + sizeof("?code=") - 1 +
                  config->auth_liblynx_content_code.len;
    redirectUrl = ngx_palloc(r->pool, redirectLen);
    redirectIdx = 0;

    ngx_memcpy(redirectUrl, config->auth_liblynx_denial.data, config->auth_liblynx_denial.len);
    redirectIdx += config->auth_liblynx_denial.len;

    ngx_memcpy(redirectUrl + redirectIdx, "?code=", sizeof("?code=") - 1);
    redirectIdx += sizeof("?code=") - 1;

    ngx_memcpy(redirectUrl + redirectIdx, config->auth_liblynx_content_code.data,
               config->auth_liblynx_content_code.len);

    r->headers_out.location->value.len = redirectLen;
    r->headers_out.location->value.data = redirectUrl;

    return NGX_HTTP_MOVED_TEMPORARILY;
}

static char *ngx_get_fully_qualified_url(ngx_http_request_t *r) {
    char *scheme;
    ngx_str_t server;
    ngx_str_t uri_variable_name = ngx_string("request_uri");
    ngx_int_t uri_variable_hash;
    ngx_http_variable_value_t *request_uri_var;
    ngx_str_t uri;

    scheme = (r->connection->ssl) ? "https" : "http";
    server = r->headers_in.server;

    // get the URI
    uri_variable_hash = ngx_hash_key(uri_variable_name.data, uri_variable_name.len);
    request_uri_var = ngx_http_get_variable(r, &uri_variable_name, uri_variable_hash);

    // get the URI
    if (request_uri_var && !request_uri_var->not_found && request_uri_var->valid) {
        // ideally we would like the uri with the querystring parameters
        uri.data = ngx_palloc(r->pool, request_uri_var->len);
        uri.len = request_uri_var->len;
        ngx_memcpy(uri.data, request_uri_var->data, request_uri_var->len);
    } else {
        // fallback to the querystring without params
        uri = r->uri;
    }

    int targetlen;
    int targetidx;
    char *targeturl;

    targetlen = strlen(scheme) + sizeof("://") - 1 + server.len + uri.len + 1;
    targeturl = ngx_palloc(r->pool, targetlen);
    targetidx = 0;

    ngx_memcpy(targeturl, scheme, strlen(scheme));
    targetidx += strlen(scheme);
    ngx_memcpy(targeturl + targetidx, "://", sizeof("://") - 1);
    targetidx += sizeof("://") - 1;
    ngx_memcpy(targeturl + targetidx, server.data, server.len);
    targetidx += server.len;
    ngx_memcpy(targeturl + targetidx, uri.data, uri.len);
    targetidx += uri.len;
    targeturl[targetidx] = '\0';

    return targeturl;
}

static ngx_int_t ngx_liblynx_auth_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_liblynx_auth_handler;

    return NGX_OK;
}

static void *ngx_liblynx_auth_create_loc_conf(ngx_conf_t *cf) {
    ngx_liblynx_auth_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_liblynx_auth_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    // set the flag to unset
    conf->auth_liblynx_enabled = (ngx_flag_t)-1;
    conf->auth_liblynx_validate_ip = (ngx_flag_t)-1;
    conf->auth_liblynx_redirector = (ngx_flag_t)-1;
    conf->auth_liblynx_logout = (ngx_flag_t)-1;

    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "Created Location Configuration");

    return conf;
}

static char *ngx_liblynx_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_liblynx_auth_loc_conf_t *prev = parent;
    ngx_liblynx_auth_loc_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->auth_liblynx_loginurl, prev->auth_liblynx_loginurl, "");
    ngx_conf_merge_str_value(conf->auth_liblynx_key, prev->auth_liblynx_key, "");
    ngx_conf_merge_str_value(conf->auth_liblynx_algorithm, prev->auth_liblynx_algorithm, "HS256");
    ngx_conf_merge_off_value(conf->auth_liblynx_validate_ip, prev->auth_liblynx_validate_ip, 1);
    ngx_conf_merge_str_value(conf->auth_liblynx_content_code, prev->auth_liblynx_content_code, "");
    ngx_conf_merge_str_value(conf->auth_liblynx_denial, prev->auth_liblynx_denial, "");
    ngx_conf_merge_str_value(conf->auth_liblynx_cookie_name, prev->auth_liblynx_cookie_name,
                             "lljwt");

    ngx_conf_merge_str_value(conf->auth_liblynx_cookie_attrs, prev->auth_liblynx_cookie_attrs,
                             "Path=/; HttpOnly");

    if (conf->auth_liblynx_enabled == ((ngx_flag_t)-1)) {
        conf->auth_liblynx_enabled =
            (prev->auth_liblynx_enabled == ((ngx_flag_t)-1)) ? 0 : prev->auth_liblynx_enabled;
    }

    if (conf->auth_liblynx_redirector == ((ngx_flag_t)-1)) {
        conf->auth_liblynx_redirector =
            (prev->auth_liblynx_redirector == ((ngx_flag_t)-1)) ? 0 : prev->auth_liblynx_redirector;
    }

    if (conf->auth_liblynx_logout == ((ngx_flag_t)-1)) {
        conf->auth_liblynx_logout =
            (prev->auth_liblynx_logout == ((ngx_flag_t)-1)) ? 0 : prev->auth_liblynx_logout;
    }

    if (conf->auth_liblynx_validate_ip == ((ngx_flag_t)-1)) {
        conf->auth_liblynx_validate_ip = (prev->auth_liblynx_validate_ip == ((ngx_flag_t)-1))
                                             ? 0
                                             : prev->auth_liblynx_validate_ip;
    }

    return NGX_CONF_OK;
}

static char *get_jwt_from_url(ngx_http_request_t *r) {
    char *jwtValChrPtr = NULL;
    u_char *ampersand;
    size_t jwtlen;

    // we expect to be the first query string var, and the name is _lljwt so
    // we can do a very rapid rejection for most requests
    if ((r->args.len == 0) || (r->args.data[0] != '_')) {
        return NULL;
    }

    // we don't expect large query strings, so huge ones could be an attempt
    // to exploit flaws
    if (r->args.len > 4096) {
        return NULL;
    }

    // if we reach here we MUST have a query string and it MUST start with _
    // so now we can take the time to check it properly and extract it
    if ((r->args.len > sizeof("_lljwt=")) &&
        (ngx_strncmp(r->args.data, "_lljwt=", sizeof("_lljwt=") - 1) == 0)) {
        jwtlen = r->args.len;
        // shouldn't be other args, but we check anyway
        ampersand = (u_char *)ngx_strchr(r->args.data, '&');
        if (ampersand) {
            jwtlen = ampersand - r->args.data;
        }
        jwtlen -= sizeof("_lljwt=") - 1;

        jwtValChrPtr = ngx_substr_t_to_char_ptr(r->pool, r->args, sizeof("_lljwt=") - 1, jwtlen);
    }

    return jwtValChrPtr;
}

static char *get_target_from_url(ngx_http_request_t *r) {
    char *ampersand;
    size_t arglen;
    char *pos;
    int fqdn = 0;

    // find target= in the query string
    pos = (char *)ngx_strstr(r->args.data, "target=");
    if (!pos) {
        return NULL;
    }
    pos += sizeof("target=") - 1;

    int offset = pos - (char *)r->args.data;
    arglen = r->args.len - offset;

    // check if there's anything after it...
    ampersand = (char *)ngx_strlchr((u_char *)pos, (u_char *)pos + arglen, '&');
    if (ampersand) {
        arglen = ampersand - pos;
    }

    // now we can decode it
    u_char *decoded = ngx_palloc(r->pool, arglen + 1);
    u_char *ptr = decoded;
    ngx_unescape_uri(&ptr, (u_char **)&pos, arglen, NGX_UNESCAPE_URI);
    ptr[0] = '\0';

    // the target must be relative - we redirect to the *proxied* target
    if (ngx_strncasecmp(decoded, (u_char *)"http://", sizeof("http://") - 1) == 0) {
        decoded += sizeof("http://") - 1;
        fqdn = 1;
    }
    if (ngx_strncasecmp(decoded, (u_char *)"https://", sizeof("https://") - 1) == 0) {
        decoded += sizeof("https://") - 1;
        fqdn = 1;
    }

    if (fqdn) {
        // skip domain part to slash
        decoded = (u_char *)ngx_strstr(decoded, (u_char *)"/");
        if (!decoded) {
            // we really expect at least a slash
            return NULL;
        }
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get_target_from_url(2) decoded=%s", decoded);

    return (char *)decoded;
}

static char *get_jwt_from_cookie(ngx_http_request_t *r, ngx_str_t auth_liblynx_cookie_name) {

    char *jwtCookieValChrPtr = NULL;
    ngx_int_t location;
    ngx_str_t cookie_value;
    location = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &auth_liblynx_cookie_name,
                                                 &cookie_value);
    if (location != NGX_DECLINED) {
        jwtCookieValChrPtr = ngx_str_t_to_char_ptr(r->pool, cookie_value);
    }
    return jwtCookieValChrPtr;
}
