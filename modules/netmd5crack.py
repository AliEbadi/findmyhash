from algos import *
import model
import utils
import re


class NetMD5Crack(model.Cracker):
    NAME = "netmd5crack"
    URL = "http://www.netmd5crack.com"
    ALGORITHMS = [MD5]

    @classmethod
    def algo_supported(cls, alg):
        """Return True if HASHCRACK can crack this type of algorithm and
        False if it cannot."""

        return alg in cls.ALGORITHMS

    @classmethod
    def crack(cls, hashvalue, alg):
        """Try to crack the hash.
        @param hashvalue Hash to crack.
        @param alg Algorithm to crack."""

        # Check if the cracker can crack this kind of algorithm
        if not cls.algo_supported(alg):
            return None

        # Build the URL
        url = utils.join_url(
            cls.URL,
            "/cgi-bin/Crack.py?InputHash=%s" % (hashvalue)
        )

        # Make the request
        response = utils.do_HTTP_request(url)

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        regexp = r'<tr><td class="border">%s</td>\
<td class="border">[^<]*</td></tr></table>' % (hashvalue)
        match = re.search(utils.to_bytes(regexp), html)

        if match:
            match2 = re.search("Sorry, we don't have \
that hash in our database", match.group())
            if match2:
                return None
            else:
                return match.group().split('border')[2].split('<')[0][2:]
