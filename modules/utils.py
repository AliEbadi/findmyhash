import urllib
import urllib2


def do_HTTP_request(url, params={}, httpheaders={}):
    '''
    Send a GET or POST HTTP Request.
    @return: HTTP Response
    '''

    data = {}
    request = None

    # If there is parameters, they are been encoded
    if params:
        data = urllib.urlencode(params)

        request = urllib2.Request(url, data, headers=httpheaders)
    else:
        request = urllib2.Request(url, headers=httpheaders)

    # Send the request
    try:
        response = urllib2.urlopen(request, timeout=2)
    except:
        return ""

    return response
