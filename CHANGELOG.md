# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [1.1.0] - 2021-08-01


### Added
- Added `auth_liblynx_redirector` configuration setting to create automatic
  login URLs which redirect to a target page when authenticated
- Added `auth_liblynx_logout` configuration setting to create automatic
  logout URLs which clear the authentication cookie and redirect to a target
- Added `auth_liblynx_soft` configuration setting to set up paths with will
  attempt authentication but still allow anonymous access 
- Added a build environment for Ubuntu 20.04 using Nginx 1.18.0

## [1.0.0] - 2021-01-20

First release
