# Branches

We use the 'git-flow' model https://nvie.com/posts/a-successful-git-branching-model/

* master -  most recent release
* develop - next release - features and hotfixes merged here
* nnnn-feature-name - feature branch - branches from develop and merges back there
* release-maj.min.patch - a release branch is named using semantic versioning - branches from develop,
  merges back to master and develop
* hotfix-xxx - branch from master and merged into master and develop   

Each release is tagged with the version number

# Versioning

Version numbers follow Semantic Versioning conventions:

* major releases require nginx upgrades, configuration changes to the module,
  or changes in the external API and are thus not backwards compatible
* minor releases are backwards compatible - they may introduce new configuration
  directives, but these will have backwards compatible defaults
* patch releases are bug fixes that do not introduce new functionality  

# Targetting particular NGINX versions and configurations

The module is built within a docker container, and the desired NGINX version is passed as an
argument. Customized builds can be made by creating a new Dockerfile. There are presently 2
build Dockerfiles

* Dockerfile-module-centos6 - uses Centos 6 to build for earlier version of nginx, 1.10.1 by default
* Dockerfile-module-centos7 - uses Centos 7 to build for more recent versions of nginx

The desired version and base image can be passed to make, e.g.

```
make module NGINX="1.10.1" BASE="centos6"
```
docker run -v build:/build --rm liblynx/liblynx-nginx:1.10.1   \
  /bin/bash -c "cp /usr/lib64/nginx/modules/ngx_liblynx_auth_module.so /build/ ; cp /usr/local/lib/libjansson.* /build/ ; cp /usr/local/lib/libjwt.* /build/ ; cp /usr/local/lib/*.pc /build/"

  docker run -v build:/build --rm liblynx/liblynx-nginx:1.10.1 /bin/bash -c "cp /root/build/* /build/" ; \


# Internals

Here's an overview of the the module internals

## Module flow
* ignore request if `auth_liblynx_enabled` is `no`
* ignore request if method is `OPTIONS`
* try to get a jwt from `_lljwt` query string, and then from cookie named by the `auth_liblynx_cookie_name` directive
* if the jwt was found but unparseable, fail the request
* if the jwt was not found, expired or invalid, redirect to login url (see Authorization Request below)
* if the jwt is valid and contains an ip, check the ip matches the request. Redirect to login if not found
* if the location has a `auth_liblynx_content_code` directive, ensure the jwt contains the code as a grant - if not redirect to denial page
* otherwise, we're good to go!

## JWT structure

This module expects a JWT with the following grants

| grant          | description | required? |
| -------------- | ----------- | --------- |
| `ip`           | IP address which originally requested the token | no - if omitted no IP checks will be made |
| *content-code* | A content codename can be used as a grant with a boolean value of `true` to grant access to that content code | no |
| `exp`          | expiry timestamp | yes |
| `sub`          | subject - this will be added to upstream requests as an `x-subject` header |

## Authorization request

When the module finds it has no token, or the token it has given is
invalid or has expired, it will redirect to the `auth_liblynx_loginurl`
appending a `req` query string containing a JWT with the following elements

| grant | description |
| ----- | ----------- |
| `ip`  | IP address of client |
| `url` | URL of requested page - this is omitted if the page was not a GET request |
| `ref` | If request contained a `Referer` header, it will be included here |

## Authorization response

The  `auth_liblynx_loginurl` will redirect back to the url given in the `req` JWT, but including an `_lljwt` query string which contains the JWT for the user. The module will spot this, drop the JWT as a cookie, and redirect the request into the
original URL without the extra query string argument.

(idea - the transfer could be a JWT with a very narrow time window. If the req contains the server time, we
can calculate a diff for the server clock, then on redirecting, built a transfer jwt which has a very narrow window
of time to be be redeemed)
