#!/usr/bin/env bash

RED='\033[01;31m\u274c '
GREEN='\033[01;32m\u2714 '
NONE='\033[00m'

test_response () {
  local name=$1
  local path=$2
  local expect=$3
  local extra=$4

  local cmd="curl -X GET -o /dev/null --silent --head --write-out '%{http_code}' http://${NGINX_PORT_8000_TCP_ADDR}:8000$path -H 'cache-control: no-cache' $extra"

  local test=$( eval ${cmd} )
  if [ "$test" -eq "$expect" ];then
    echo -e "${GREEN}${name}: passed (good response code ${test})${NONE}";
  else
    echo -e "${RED}${name}: failed (bad response code ${test})${NONE}";
    echo -e "${RED}${cmd}${NONE}";
  fi
}

test_redirect() {
  local name=$1
  local path=$2
  local pattern=$3
  local extra=$4

  local cmd="curl -X GET -o /dev/null --silent --head --write-out '%{redirect_url}' 'http://${NGINX_PORT_8000_TCP_ADDR}:8000$path' -H 'cache-control: no-cache' $extra"

  local test=$( eval ${cmd} )

  if [[ $test =~ $pattern ]];then
    echo -e "${GREEN}${name}: passed (good redirect) to ${test}${NONE}";
  else
    echo -e "${RED}${name}:${path} redirect failed (unexpected redirect to ${test})${NONE}";
    echo -e "${RED}${cmd}${NONE}";
  fi
}

test_cookie() {

  local name=$1
  local path=$2
  local pattern=$3

  local cmd="curl -D - -X GET -o /dev/null --silent http://${NGINX_PORT_8000_TCP_ADDR}:8000$path -H 'cache-control: no-cache' $extra | grep Set-Cookie"

  local test=$( eval ${cmd} )

  if [[ $test =~ $pattern ]];then
    echo -e "${GREEN}${name}: passed (good cookie response)${NONE}";
  else
    echo -e "${RED}${name}:${path} cookie check failed (${test})${NONE}";
  fi

  #Set-Cookie: lljwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpcCI6IjEuMS4xLjEiLCJleHAiOjE5MTU5NTMxNDYsIkFCQ0QiOnRydWV9.z7x8Yaq8touzVA3k3aK27gD2uMAgybMCp_4v7Mj1fqo; expires=Wed, 18-Sep-30 09:12:26 GMT; Path=/; HttpOnly
  #echo "cookie = $test"
}

get_body_from_jwt() {
  local jwt=$1
  body=$(echo $jwt | awk -F'.' '{print $2}')
  base64=$(echo $body | sed 's/-/+/g; s/_/\//g')
  json=$(echo $base64 | base64 -d)

  echo $json
}

test_referrer() {
  local name=$1
  local path=$2

  local cmd="curl -D - -X GET -o /dev/null --silent --referer http://example.com/foo http://${NGINX_PORT_8000_TCP_ADDR}:8000$path -H 'cache-control: no-cache' $extra | grep Location | sed 's/.*req=//'"
  local jwt=$( eval ${cmd} )
  local body=$(get_body_from_jwt $jwt)

  if [[ $body =~ "example.com" ]];then
    echo -e "${GREEN}${name}: passed (referrer picked up)${NONE}";
  else
    echo -e "${RED}${name}:${path} referrer check failed (${test})${NONE}";
  fi
}

main() {
  # load generated JWT values
  source test.env

  test_response "Insecure test" "/" "200"

  # ensure secured area redirects to login
  test_response "Secure test without jwt cookie" "/secure/" "302"
  test_redirect "Secure test without jwt cookie" "/secure/" '^https://example\.com\?req='

  #entering redirector with no cookie should go to authentication auth_liblynx_loginurl
  test_redirect "Redirector test without jwt cookie" "/login?target=http://foo.com" '^https://example.com\?req'
  #with a jwt in the URL, we're simulating a redirect back, so we expect to redirect to same URL without the jwt
  test_redirect "Redirector test with jwt in url" "/login?_lljwt=${VALID_JWT}&target=http://foo.com" '^http://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/login\?target=http://foo.com'
  #with a jwt cookie, we expect to go to the target
  test_redirect "Redirector test with jwt cookie" "/login?target=http://foo.com/banjo" '^http://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:8000/banjo' "--cookie \"lljwt=${VALID_JWT}\""


  # if valid JWT cookie given, all is well
  test_response "Secure test with jwt cookie" "/secure/" "200" "--cookie \"lljwt=${VALID_JWT}\""

  # if we've stolen a JWT which doesn't have our IP...
  #temporarily disabled, see TODO.md. Feature works, it's the test environment which makes it hard to test
  #test_response "Secure test with bad ip in cookie" "/secure/" "302" "--cookie \"lljwt=${BAD_IP_JWT}\""

  # same for an expired token
  test_response "Secure test with expired jwt" "/secure/" "302" "--cookie \"lljwt=${EXPIRED_JWT}\""

  # check handling of jwt in url
  test_response "Secure test with JWT in URL" "/secure/?_lljwt=${VALID_JWT}" "302"
  test_redirect "Check redirect with JWT in URL" "/secure/?_lljwt=${VALID_JWT}" '^http://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/secure/$'
  test_cookie "Check cookie drop" "/secure/?_lljwt=${VALID_JWT}" '^Set-Cookie: lljwt='

  # /secure-abcd/ requires a JWT with a content code
  test_response "Secure test with valid content code" "/secure-abcd/" "200" "--cookie \"lljwt=${ABCD_JWT}\""
  test_response "Secure test with missing content code" "/secure-abcd/" "302" "--cookie \"lljwt=${VALID_JWT}\""
  test_redirect "Check denial redirect pattern" "/secure-abcd/" '^https://example\.com/denied' "--cookie \"lljwt=${VALID_JWT}\""

  test_referrer "Check referrer included in login request" "/secure/"

  # ensure soft area redirects to login
  test_response "Soft test without jwt cookie" "/soft/" "302"
  test_redirect "Soft test without jwt cookie" "/soft/" '^https://example\.com\?req='

  #anon cookie is allowed
  test_response "Soft test with anon jwt" "/soft/" "200" "--cookie \"lljwt=${ANON_JWT}\""

  #anon cookie not allowed in secure area
  test_response "Secure test with anon jwt" "/secure/" "302" "--cookie \"lljwt=${ANON_JWT}\""
}

main "$@"
