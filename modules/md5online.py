from algos import *
import model
import utils
import re


class MD5Online(model.Cracker):
    NAME = "md5online"
    URL = "http://md5online.net"
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

        # Build the parameters
        params = {
            "pass": hashvalue,
            "option": "hash2text",
            "send": "Submit"
        }

        # Make the request
        response = utils.do_HTTP_request(cls.URL, params)

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = re.search(
            utils.to_bytes(
                r'<center><p>md5 :<b>\w*</b> \
<br>pass : <b>[^<]*</b></p></table>'
            ),
            html
        )

        if match:
            return match.group().split('b>')[3][:-2]
        else:
            return None
