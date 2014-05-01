from algos import *
import model
import utils
import re


class MyAddr(model.Cracker):
    NAME = "my-addr"
    URL = "http://md5.my-addr.com"
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
        url = utils.join_url(cls.URL, "/md5_decrypt-md5_cracker_online\
/md5_decoder_tool.php")

        # Build the parameters
        params = {
            "md5": hashvalue,
            "x": 21,
            "y": 8
        }

        # Make the request
        response = utils.do_HTTP_request(url, params)

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = re.search(
            utils.to_bytes("<span class='middle_title'>Hashed string</span>: \
[^<]*</div>"),
            html
        )

        if match:
            return utils.to_string(
                match.group()
            ).split('span')[2][3:-6]
        else:
            return None
