#!/usr/bin/env python

"""Implementation of CAS (central authentication service) authentication.

This is a simple wrapper for automated login to a CAS service.  It can be used
to implement a CAS client (e.g. the 3rd party service that wants to validate
credentials).  It also implements the browser logic, so it is possible to use
this script to test a CAS server or automate login to test credentials when no
better mechanism is available.

Credits:
  The initial version of this code was inspired by "Django CAS"[1].

Features:
  CAS versions 1.0 and 2.0 are supported.

Requirements:
  This project requires installation of "Beautilful Soup"[2] for scraping HTML
  pages in the browser logic.  This is not necessary in the CAS service logic.

References:
  [1]: http://code.google.com/p/django-cas/
  [2]: http://www.crummy.com/software/BeautifulSoup/
"""

import BeautifulSoup
import cookielib
import optparse
import urllib
import urllib2
import urlparse
import re
import sys

try:
    from xml.etree import ElementTree
except ImportError:
    from elementtree import ElementTree

SERVICE_URL = ''
CAS_EXTRA_LOGIN_PARAMS = {}
CAS_SERVER_URL = ''
CAS_RETRY_LOGIN = True

class Session:
    """HTTP session with support for cookies."""

    def __init__ ( self ):
        """Build an HTTP session with a fresh cookie jar."""
          # we need cookies for accepting the terms and conditions.
        self.cookies = cookielib.CookieJar()
        self.factory = urllib2.build_opener(
            urllib2.HTTPCookieProcessor(self.cookies))

    @staticmethod
    def _process_response ( response ):
        try:
            head = response.info()
            body = response.read()
            code = response.code
            return (code, body)
        finally:
            response.close()

    def get ( self, url ):
        """Perform an HTTP GET request at the given URL.
        
        Returns the numeric status code and the response body.
        """
        headers = {
            'Accept': 'text/html',
            }
        request = urllib2.Request(url, None, headers)
        return Session._process_response(self.factory.open(request))

    def post ( self, url, **data ):
        """Perform an HTTP POST request at the given URL.

        Returns the numeric status code and the response body.
        """
        headers = {
            'Content-type': 'application/x-www-form-urlencoded',
            'Accept': 'text/html',
            }
        request = urllib2.Request(url, urllib.urlencode(data), headers)
        return Session._process_response(self.factory.open(request))

class Service:
    """CAS service wrapper.  Implements all logic, save for HTTP."""

    def __init__ ( self, base, name, version ):
        """Build a CAS service wrapper for a given CAS server."""
        self.base = base
        self.name = name
        (self.validate_url, self.validate) = {
            1: (self._validate_url_1, self._validate_1),
            2: (self._validate_url_2, self._validate_2),
            }[version]

    def login_url ( self, extra={} ):
        """Get the URL to the CAS server's HTML login form."""
        query = {'service': self.name}
        query.update(extra)
        query = '?' + urllib.urlencode(query)
        return urlparse.urljoin(self.base, 'login') + query

    def logout_url ( self ):
        """Get the URL to the CAS server's logout page."""
        return urlparse.urljoin(self.base, 'logout')

    def _validate_url_1 ( self, ticket ):
        """Get service ticket validation URL for CAS 1.0."""
        query = {'ticket': ticket, 'service': self.name}
        query = '?' + urllib.urlencode(query)
        return urlparse.urljoin(self.base, 'validate') + query

    def _validate_url_2 ( self, ticket ):
        """Get service ticket validation URL for CAS 2.0."""
        query = {'ticket': ticket, 'service': self.name}
        query = '?' + urllib.urlencode(query)
        return urlparse.urljoin(self.base, 'proxyValidate') + query

    def _validate_1 ( self, body ):
        """Perform service ticket validation for CAS 1.0."""
        body = body.split('\n')[:2]
        if (len(body) >= 1) and (body[0] == 'yes'):
            if len(body) > 1:
                return body[1]
            return ''
        return None

    def _validate_2 ( self, body ):
        """Perform service ticket validation for CAS 2.0."""
        response = ElementTree.fromstring(body)
        if tree[0].tag.endswith('authenticationSuccess'):
            return tree[0][0].text
        else:
            return None

def cas_login ( session, service, username, password, validate=True ):
    """Perform login to CAS server through HTTP.
    
    First, automate the HTML login form submission and get a service ticket.
    Then, validate the ticket against the CAS server (just to be sure).  Stricly
    speaking, the second step is not required for two-factor authentication,
    but do it anyways out of paranoia.
    """
    # get HTML login form and scrape fields.
    (code, body) = session.get(service.login_url())
    if code != 200:
        raise Exception("HTTP error %s: '%s'", str(code), str(body))
    soup = BeautifulSoup.BeautifulSoup(body)
    fields = {}
    for form in soup.body('form'):
        for field in form('input'):
            key = field.get('id',field.get('name',''))
            fields[key] = field.get('value','')
    # submit login HTML form to CAS server.
    fields['username'] = username
    fields['password'] = password
    (code, body) = session.post(service.login_url(), **fields)
    if code != 200:
        raise Exception("HTTP error %s: '%s'", str(code), str(body))
    # scrape returned page for service ticket.
    pattern = re.compile('"'+re.escape(service.name+'?')+'ticket=(.*)"')
    match = pattern.search(body)
    if not match:
        return False
    ticket = match.group(1)
    # validate service ticket agains the CAS server.
    if validate:
        (code, body) = session.get(service.validate_url(ticket))
        if code != 200:
            raise Exception("Could not validate service ticket.")
        return not service.validate(body) is None
    else:
        return (not ticket is None) and (ticket[:3] == 'ST-')

def parse ( pam, flags, arguments ):
    """Parse module arguments given in PAM configuration."""
    arguments = dict(map(lambda a: a.split('=',1), arguments))
      # parse list of users.
    users = arguments.get('users','')
    if users:
        users = users.split(',')
    else:
        users = []
      # store context passed to other pam callbacks.
    context = {
          # core settings.
        'verbose': ((flags & pam.PAM_SILENT) == 0) \
            and (arguments.get('verbose','no')=='yes'),
        'service': Service(
            arguments['hostname'],
            arguments['service'], 1),
          # additional context.
        'session': Session(),
        'users': users,
        }
    return context

def pam_sm_authenticate ( pam, flags, arguments ):
    """Prompt for and check credentials."""
    status = pam.PAM_AUTH_ERR
    stream = open('/tmp/pam_cas_fucker.txt','w')
    print >>stream, "In 'pam_sm_authenticate()'."
    stream.close()
    try:
          # prepare to handle the request.
        context = parse(pam, flags, arguments[1:])
          # request username.
        username = pam.user
        if not username:
            conversation = pam.conversation(
                pam.Message(pam.PAM_PROMPT_ECHO_OFF, 'Username:'))
            username = conversation.resp
          # request password.
        password = pam.authtok
        if not password:
            conversation = pam.conversation(
                pam.Message(pam.PAM_PROMPT_ECHO_OFF, 'Password:'))
            password = conversation.resp
          # if limiting to a subset of users, validate that the
          # user is allowed to authenticate with the system.
        users = context['users']
        if (len(users) == 0) or (username in users):
              # proceed with the authentication.
            success = cas_login(
                context['session'],
                context['service'],
                username, password, False)
              # check authentication success.
            if success:
                status = pam.PAM_SUCCESS
     # diagnose whatever went wrong.
    except Exception, error:
        if context['verbose']:
            print >>sys.stderr, "pam_cas: FAIL. ("+str(error)+")"
    return status

def pam_sm_open_session ( pam, flags, arguments ):
    return pam.PAM_SUCCESS

def pam_sm_close_session ( pam, flags, arguments ):
    return pam.PAM_SUCCESS

def pam_sm_setcred ( pam, flags, arguments ):
    return pam.PAM_SUCCESS

def pam_sm_acct_mgmt ( pam, flags, arguments ):
    return pam.PAM_SUCCESS

def pam_sm_chauthtok ( pam, flags, arguments ):
    return pam.PAM_SERVICE_ERR

if __name__ == '__main__':
      # Define command-line interface.
    parser = optparse.OptionParser()
    parser.add_option('-H', '--host', dest='hostname',
                      help="CAS server host name or IP adress.")
    parser.add_option('-u', '--username', dest='username',
                      help="Username to use for CAS authentification.")
    parser.add_option('-p', '--password', dest='password',
                      help="Password to use for CAS authentification.")
    parser.add_option('-s', '--service', dest='service',
                      help="Service name used for authentication..")
      # Parse command line arguments.
    (options, arguments) = parser.parse_args()
    errors = 0
    if not options.username:
        print >>sys.stderr, "Missing username."
        errors = errors + 1
    if not options.password:
        print >>sys.stderr, "Missing password."
        errors = errors + 1
    if not options.service:
        print >>sys.stderr, "Missing service."
        errors = errors + 1
    if not options.hostname:
        print >>sys.stderr, "Missing server hostname."
        errors = errors + 1
    if errors > 0:
        sys.exit(1)
      # Build service context.
    session = Session()
    service = Service(options.hostname, options.service, 1)
      # Attempt authentication.
    success = cas_login(session, service,
                        options.username, options.password, False)
    if not success:
        print "Failed authentication.  Check hostname, username and password."
        sys.exit(1)
