from algos import *
import model
import utils
import re
import urlparse


class Noisette(model.Cracker):
    NAME = "noisette.ch"
    URL = "http://md5.noisette.ch"
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
        url = urlparse.urljoin(cls.URL, "/index.php")

        # Build the parameters
        params = {
            "hash": hashvalue
        }

        # Make the request
        response = utils.do_HTTP_request(url, params)

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = re.search(r'<p>String to hash : \
<input name="text" value="[^"]+"/>', html)

        if match:
            return match.group().split('"')[3]
        else:
            return None
