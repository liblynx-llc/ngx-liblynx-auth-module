# Intro
This is an NGINX module which can use the [LibLynx](http://www.liblynx.com) Access Management API to protect access to content, typically proxied from upstream servers.

This allows content to be easily protected by IP address, username/password, Shibboleth/SAML,
OpenID Connect, SIP2/library cards, and many other authentication mechanisms.

> To use this module, you require a LibLynx API key - contact [support@liblynx.com](mailto:support@liblynx.com) for assistance.

## Building and testing

The build and test environments are Dockerized to allow easy targetting of
specific build environments.

To build the module and docker containers to test it with, and run all tests,
simply execute
```
make all
```

When you make a change to the module, run `make module`.

When you make a change to `test.sh`, run `make test-runner`.

| Command                    | Description                                 |
| -------------------------- |:-------------------------------------------:|
| `make module`              | Builds the NGINX image for recent nginx version. The module and dependencies are stored in the `build/` subdirectory |
| `make test-runner`         | Builds the image that will run `test.sh`    |
| `make start-nginx`         | Starts the NGINX container                  |
| `make stop-nginx`          | Stops the NGINX container                   |
| `make test`                | Runs `test.sh` against the NGINX container  |

You can re-run tests as many times as you like while NGINX is up.
When you're done running tests, make sure to stop the NGINX container.

The Dockerfile builds all of the dependencies as well as the module,
downloads a binary version of NGINX, and runs the module as a dynamic module.

# Targeting specific version of NGINX

`make module` by default will target the most recent version of nginx the module
has been tested with. You can target other versions with an `NGINX="x.x.x"` setting, e.g.

```
make module NGINX="1.10.1"
```

The makefile will select a suitable Dockerfile for building the targetted
version, but this can be overridden. For example, `BASE="centos6"` will force
the build process to use `Dockerfile-module-centos6` for the build.


## Dependencies
This module depends on the [JWT C Library](https://github.com/benmcollins/libjwt)

Transitively, that library depends on a JSON Parser called
[Jansson](https://github.com/akheron/jansson) as well as the OpenSSL library.

## NGINX Directives
This module requires several new `nginx.conf` directives,
which can be specified in on the `main` `server` or `location` level.

### auth_liblynx_key

This is a secret key used to verify the tokens used by authenticated visitors have not been tampered with.

This value is created in the LibLynx admin portal.

```
auth_liblynx_key "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
```

Typically this directive is specified at the `main` level.

### auth_liblynx_algorithm

This is the algorithm used to verify the tokens. The default is `HS256` and should not be changed.

### auth_liblynx_loginurl

The login URL is the URL the module will redirect to when a
visitor does not have a valid authorization token.

```
auth_liblynx_loginurl "https://example.com/authorize";

```

This URL is obtained from the LibLynx admin portal.

Typically this directive is specified at the `main` level.

### auth_liblynx_enabled

This controls whether the module is activated. This would typically be used at a `location` level to only force
authentication for protected content areas you want to secure.

```
auth_liblynx_enabled on;
```

### auth_liblynx_redirector

Can only be used at a `location` level and specifies the location is a redirector and will include a 'target' query string.

A redirector can be used when the origin site has pages which can be viewed without authentication, but
show full content when authenticated. The page can detect a visitor is not authenticated, and offer a login link
which goes via the redirector. This link should include a `target` query string argument which gives the URL of the
page to return to after authentication.

```
auth_liblynx_redirector on;
```

### auth_liblynx_logout

Can only be used at a `location` level, and indicates a location is a logout location - requesting a path in this location will clear any authentication cookies and redirect to a `target` query string

```
auth_liblynx_logout on;
```


### auth_liblynx_cookie_name

This is the name of the cookie used to store the access token. By default this is `lljwt`

```
auth_liblynx_cookie_name "lljwt";
```

This need only be changed for advanced use-cases, e.g. having separate cookies for different
server locations.

### auth_liblynx_cookie_attrs

These are [additional cookie attributes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) added to the cookie. The default ensures the cookie
applies to the entire domain, and prevents Javascript for seeing the cookie.

```
auth_liblynx_cookie_attrs "Path=/; HttpOnly";
```
These defaults are good starting point, but it is recommended the following attributes are
included if possible

* `Secure` - set this if the site is only accessed via `https`
* `SameSite=Lax` The cookie is withheld on cross-site subrequests, such as calls to load images or frames, but is sent when a user navigates to the URL from an external site, such as by following a link.


### auth_liblynx_content_code

This directive is useful where content is provided as
separate collections that a customer may, or may not, be
granted access to.

>In the LibLynx admin portal, customers can have
subscriptions which link them with "content codes". By
using a `auth_liblynx_content_code` directive, you
can control access to particular collections.

For example:
```
auth_liblynx_content_code "ABCD";
```
This would ensure only visitors granted access to `ABCD` are permitted.

If a user does not have access, they will receive a `403 Forbidden` response. For a friendlier response, consider adding a `auth_liblynx_denial` directive to redirect them to a denial page where you can offer support options.

This optional configuration directive can be applied at `main` and `server` level, but is more useful at `location`
level as it allows access to different URL paths to be
controlled.

### auth_liblynx_denial

This is the fully qualified URL of the page a visitor
should be directed to if their token does not permit access to the content code specified by a `auth_liblynx_content_code` directive.

On redirecting, the URL will have a `?code=XXX` query string appended to it, indicating the code which was not authorized. A publisher should provide a page which tells the user access was denied and informs them how they may obtain access.




### auth_liblynx_validate_ip

After authorization, a visitor is given a token which contains their IP address. By default each request will be checked to ensure the request IP matches the token IP.

This behaviour can be turned off at `main` `server` or `location` level with
```
auth_liblynx_validate_ip off;
```

We recommend this is left in its default `on` setting unless troubleshooting specific access problems.
