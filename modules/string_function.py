from algos import *
import model
import utils
import re


class StringFunction(model.Cracker):
    NAME = "stringfunction"
    URL = "http://www.stringfunction.com"
    ALGORITHMS = [MD5, SHA1]

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
        url = ""
        if alg == MD5:
            url = utils.join_url(cls.URL, "/md5-decrypter.html")
        else:
            url = utils.join_url(cls.URL, "/sha1-decrypter.html")

        # Build the parameters
        params = {
            "string": hashvalue,
            "submit": "Decrypt",
            "result": ""
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
            utils.to_bytes(
                r'<textarea class="textarea-input-tool-b" \
rows="10" cols="50" name="result"[^>]*>[^<]+</textarea>'
            ),
            html
        )

        if match:
            return match.group().split('>')[1][:-10]
        else:
            return None
