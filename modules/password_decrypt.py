from algos import *
import model
import utils
import re
import urlparse


class PasswordDecrypt(model.Cracker):
    NAME = "password-decrypt"
    URL = "http://password-decrypt.com"
    ALGORITHMS = [CISCO7, JUNIPER]

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

        # Build the URL and the parameters
        url = ""
        params = None
        if alg == CISCO7:
            url = urlparse.urljoin(cls.URL, "/cisco.cgi")
            params = {
                "submit": "Submit",
                "cisco_password": hashvalue,
                "submit": "Submit"
            }
        else:
            url = "http://password-decrypt.com/juniper.cgi"
            params = {
                "submit": "Submit",
                "juniper_password": hashvalue,
                "submit": "Submit"
            }

        response = utils.do_HTTP_request(url, params)

        html = None
        if response:
            html = response.read()
        else:
            return None

        match = re.search(r'Decrypted Password:&nbsp;<B>[^<]*</B> </p>', html)

        if match:
            return match.group().split('B>')[1][:-2]
        else:
            return None
