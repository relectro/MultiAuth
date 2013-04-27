#!/usr/bin/env python
"""Summary
Validate a Yubikey against Yubico's web-service
Author: kaleissin
License: MIT
Script and library to validate yubikeys using a web service.
When used as a library, default_api_* should probably be set once and
for all:

>>> yubikey.py.default_api_id = <some integer>
>>> yubikey.py.default_api_key = <some base64-encoded api key>

Get your api key and api id at https://api.yubico.com/get-api-key/
"""

import sys, os
import urllib2
import hmac
import base64
import hashlib

# XXX: Should be easily configurable
default_api_id = 
default_api_key = ''

class YubikeyError(Exception):
    pass

class YubikeyBadKeyError(YubikeyError):
    pass

class YubikeyConfigError(YubikeyError):
    pass

class YubikeyOtherError(YubikeyError):
    pass

class YubikeyReturnCodes(object):
    """The return codes of the web service as defined in
    http://www.yubico.com/developers/api/"""

    codes = {
            'OK': 'The OTP is valid.',
            'BAD_OTP': 'The OTP is invalid format.',
            'REPLAYED_OTP': 'The OTP has already been seen by the service.',
            'BAD_SIGNATURE': 'The HMAC signature verification failed.',
            'MISSING_PARAMETER': 'The request lacks parameter given by key info.',
            'NO_SUCH_CLIENT': '',
            'OPERATION_NOT_ALLOWED': '',
            'BACKEND_ERROR': '',
    }

    ok = ('OK',)
    bad = ('BAD_OTP', 'REPLAYED_OTP', 'BAD_SIGNATURE')
    config = ('MISSING_PARAMETER', 'NO_SUCH_CLIENT')
    other = ('OPERATION_NOT_ALLOWED', 'BACKEND_ERROR')

class YubikeyResponse(object):
    """Parses a response from the web service"""

    valid_sections = ('h', 't', 'status', 'info')
    return_codes = YubikeyReturnCodes()

    def __init__(self, response_lines, api_key=''):
        self.api_key = api_key or default_api_key
        for line in response_lines:
            line = line.strip()
            if not line: continue
            section, response = line.split('=', 1)
            if section in self.valid_sections:
                self.__dict__[section] = response

    def _make_block(self):
        return '&'.join(['%s=%s' % (section, self.__dict__[section])
                for section in ('info', 'status', 't')
                if self.__dict__.get(section, False)])

    def is_valid(self):
        """Returns True if the key is valid, False otherwise"""
        if not self.status in self.return_codes.codes:
            raise YubikeyOtherError, 'Non-existing status code!'
        if self.status in self.return_codes.ok:
            return True
        if self.status in self.return_codes.other:
            raise YubikeyOtherError, self.return_codes.codes.get(self.status, 'Impossible OtherError')
        if self.status in self.return_codes.config:
            error_msg = self.return_codes.codes.get(self.status, 'Impossible ConfigError')
            if self.status == 'MISSING_PARAMETER':
                error_msg = '%s: "%s"' % (error_msg, self.info)
            raise YubikeyConfigError, error_msg
        return False

    def is_paranoid_valid(self, api_key=default_api_key):
        """Returns True if the key is valid, False if not, raises an
        exception if the response-signature is bad."""
        #assert False, 'Not finished'
        api_key = api_key or self.api_key
        if not api_key:
            raise YubikeyConfigError, 'No API Key given, cannot check response for validity'
        is_ok = self.is_valid()
        block = self._make_block()
        hash = hmac.new(base64.b64decode(api_key), block, hashlib.sha1)
        if hash.digest() == base64.b64decode(self.h):
            return is_ok
        raise YubikeyBadKeyError, self.return_codes.codes.get('BAD_SIGNATURE', 'Bad signature')

def dump(otp, api_id=default_api_id, authserver_prefix='http://api.yubico.com/wsapi/verify?id='):
    """Dump the response from the web service"""
    url = '%s%s&otp=%s' % (authserver_prefix, api_id, otp)

    assert api_id

    print urllib2.urlopen(url).read()

def verify(otp, api_id=default_api_id, authserver_prefix='http://api.yubico.com/wsapi/verify?id='):
    """Ask the server using the Yubico Web Services API at
    authserver_prefix if the otp is valid."""

    assert api_id

    url = '%s%s&otp=%s' % (authserver_prefix, api_id, otp)

    LINK = urllib2.urlopen(url)
    yubiresp = YubikeyResponse(LINK)
    return yubiresp.is_valid()

def verify_paranoid(otp, api_id=default_api_id, authserver_prefix='http://api.yubico.com/wsapi/verify?id=',
api_key=default_api_key):
    """Ask the server using the Yubico Web Services API at
    authserver_prefix if the otp is valid. Raises an exception if the
    response-signature is bad."""

    assert api_id

    url = '%s%s&otp=%s' % (authserver_prefix, api_id, otp)

    LINK = urllib2.urlopen(url)
    yubiresp = YubikeyResponse(LINK)
    return yubiresp.is_paranoid_valid(api_key=api_key)

if __name__ == '__main__':

    usage = """
Usage: %s api_id [api_key] otp
    api_id:  numeric id of API Key
    api_key: API Key belonging to api_id, base64 (optional)
    otp:     one time password from Yubikey
""" % (os.path.basename(sys.argv[0]))

    if len(sys.argv) == 3:
        sys.exit(not(verify(sys.argv[-1], sys.argv[1])))
    elif len(sys.argv) == 4:
        sys.exit(not(verify_paranoid(sys.argv[-1], sys.argv[1], api_key=sys.argv[2])))
    else:
        print >>sys.stderr, usage
