from algos import *
import model
import utils
import re


class MD5Decryption(model.Cracker):
    NAME = "md5decryption"
    URL = "http://md5decryption.com"
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

        # Build the parameters
        params = {
            "hash": hashvalue,
            "submit": "Decrypt It!"
        }

        # Make the request
        response = utils.do_HTTP_request(cls.URL, params)

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        match = re.search(r"Decrypted Text: </b>[^<]*</font>", html)

        if match:
            return match.group().split('b>')[1][:-7]
        else:
            return None
