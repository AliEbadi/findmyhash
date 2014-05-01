from algos import *
import model
import utils
import re


#Useless for now, mut recaliber leakdb
#class GooglLi(model.Cracker):
class GooglLi():
    NAME = "goog.li"
    URL = "http://goog.li"
    ALGORITHMS = [
        MD5,
        MYSQL,
        SHA1,
        SHA224,
        SHA384,
        SHA256,
        SHA512,
        RIPEMD,
        NTLM,
        GOST,
        WHIRLPOOL,
        LDAP_MD5,
        LDAP_SHA1
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

        hash2 = None
        if alg in [NTLM] and ':' in hashvalue:
            hash2 = hashvalue.split(':')[1]
        else:
            hash2 = hashvalue

        # Confirm the initial '*' character
        if alg == MYSQL and hash2[0] != '*':
            hash2 = '*' + hash2

        # Build the URL
        url = utils.join_url(cls.URL, "/?q=%s" % (hash2))

        # Make the request
        response = utils.do_HTTP_request(url)

        # Analyze the response
        html = None
        if response:
            html = response.read()
        else:
            return None

        print(html)

        match = re.search(r'<br />plaintext[^:]*: [^<]*<br />', html)

        if match:
            return match.group().split(':')[1].strip()[:-6]
        else:
            return None
