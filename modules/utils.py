import sys
import utils

if sys.version[0] == "3":
    from urllib.parse import urlencode
    from urllib.request import Request
    from urllib.request import urlopen
    from urllib.parse import urljoin
else:
    from urllib import urlencode
    from urllib2 import Request
    from urllib2 import urlopen
    from urlparse import urljoin


def to_bytes(s):
    if sys.version[0] == "3":
        return bytes(s, "utf-8")
    else:
        return s


def to_string(s):
    if sys.version[0] == "3":
        return s.decode("utf-8")
    else:
        return s


def do_HTTP_request(url, params={}, httpheaders={}):
    '''
    Send a GET or POST HTTP Request.
    @return: HTTP Response
    '''

    data = {}
    request = None

    # If there is parameters, they are been encoded
    if params:
        data = utils.to_bytes(urlencode(params))

        request = Request(url, data, headers=httpheaders)
    else:
        request = Request(url, headers=httpheaders)

    # Send the request
    try:
        response = urlopen(request, timeout=2)
    except:
        return ""

    return response


def join_url(p1, p2):
    return urljoin(p1, p2)
