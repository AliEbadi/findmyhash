from algos import *
import model
import utils
import re


class LeakDB(model.Cracker):
    NAME = "LeakDB"
    URL = "https://api.leakdb.net/"
    ALGORITHMS = [
        MD4,
        MD5,
        MYSQL,
        RIPEMD,
        NTLM,
        GOST,
        SHA1,
        SHA224,
        SHA256,
        SHA384,
        SHA512,
        WHIRLPOOL
    ]

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

        hash2 = hashvalue
        if alg in [NTLM] and ':' in hashvalue:
            hash2 = hashvalue.split(':')[1]

        # Confirm the initial '*' character
        if alg == MYSQL and hash2[0] != '*':
            hash2 = '*' + hash2

        # Build the URL
        url = utils.join_url(cls.URL, "/?t=%s" % (hash2))

        # Make the request
        response = utils.do_HTTP_request(url)

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = re.search(
            utils.to_bytes("\nplaintext=(.*?)\n"),
            html
        )

        if match:
            return utils.to_string(match.group(1))
        else:
            return None
