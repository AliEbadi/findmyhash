# -*- coding: iso-8859-1 -*-

###############################################################################
### LICENSE
###############################################################################
#
# findmyhash.py - v 1.1.3
#
# This script is under GPL v3 License
# (http://www.gnu.org/licenses/gpl-3.0.html).
#
# Only this source code is under GPL v3 License. Web services used in this
# script are under different licenses.
#
# If you know some clause in one of these web services which forbids to use
# it inside this script,
# please contact me to remove the web service as soon as possible.
#
# Developed by JulGor ( http://laxmarcaellugar.blogspot.com/ )
# Mail: bloglaxmarcaellugar AT gmail DOT com
# twitter: @laXmarcaellugar
#
# Maintained by Talanor (https://github.com/Talanor/findmyhash)
# Mail: adroneus AT gmail DOT com
#

import sys
import hashlib
import random
import argparse
import re
import base64
import traceback
import string
import collections
from modules import *

if sys.version[0] == "3":
    hashlib_algorithms = hashlib.algorithms_available
else:
    hashlib_algorithms = hashlib.algorithms


#Can find some more there :
#http://www.useragentstring.com/pages/useragentstring.php
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36",
    "Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/36.0.1985.67 Safari/537.36"
]


def isHex(s):
    return all(map(lambda x: x in string.hexdigits, s))


#Obviously this function is not generic and contains errors, please report
#them if you find any
def guess_hash_type(hash):
    if len(hash) == 12:
        return ["juniper"]
    elif len(hash) == 32:
        return ["md5", "md4", "ntlm"]
    elif len(hash) == 40:
        return ["sha1", 'ripemd']
    elif len(hash) == 56:
        return ["sha224"]
    elif len(hash) == 64:
        return ["sha256", 'gost']
    elif len(hash) == 96:
        return ["sha384"]
    elif len(hash) == 128:
        return ["whirlpool", "sha512"]
    return None


def crack_hash(cracker, algorithm, hashvalue):
    if algorithm not in cracker.ALGORITHMS:
        return None

    # Crack the hash
    result = None
    try:
        result = cracker.crack(hashvalue, algorithm)
    # If it was some trouble, exit
    except:
        info = sys.exc_info()
        print("\nSomething was wrong. Please, contact us \
to report the bug:\n%s %s\n\n\
https://github.com/Talanor/findmyhash\n" % (str(info[0]), str(info[1])))
        traceback.print_exc()
        return None

    # If there is any result...
    if result:
        # If it is a hashlib supported algorithm...
        if algorithm.upper() in map(str.upper, hashlib_algorithms):
            # Hash value is calculated to compare with cracker result
            h = hashlib.new(algorithm)
            h.update(utils.to_bytes(result))

            if h.hexdigest() == hashvalue:
                result = (result, True)
            else:
                result = None

        # If it is a half-supported hashlib algorithm
        elif algorithm in [LDAP_MD5, LDAP_SHA1]:
            alg = algorithm.split('_')[1]
            ahash = base64.decodestring(hashvalue.split('}')[1])

            # Hash value is calculated to compare with cracker result
            h = hashlib.new(alg)
            h.update(result)

            if h.digest() == ahash:
                result = (result, True)
            else:
                result = None

        elif algorithm == NTLM or \
                (algorithm == LM and ':' in hashvalue):
            # NTLM Hash value is calculated to compare
            # with cracker result
            candidate = hashlib.new(
                'md4',
                result.split()[-1].encode('utf-16le')
            ).hexdigest()

            # It's a LM:NTLM combination or a single NTLM hash
            if (':' in hashvalue and
                candidate == hashvalue.split(':')[1]) \
                    or (':' not in hashvalue
                        and candidate == hashvalue):
                result = (result, True)
        else:
            result = (result, False)
    else:
        result = None

    return result


def crackloop_hash(hashvalues):
    """Crack a hash or all the hashes of a file.

    @param hashvalue Hash value to be cracked.
    @return If the hash has been cracked or not."""

    # Cracked hashes will be stored here
    hashes_results = collections.OrderedDict()

    # hashestocrack depends on the input value

    for activehash in hashvalues:
        hash_state = {
            "hash": activehash,
            "cracked": False,
            "value": None,
            "type": None,
            "verified" : False
        }
        algorithms = guess_hash_type(activehash)
        if algorithms is None:
            print("hash type could not be guessed")
        else:
            for algorithm in algorithms:
                print("Trying to find %s hash : '%s'" % (algorithm, activehash))
                hashresults = []

                # Standarize the hash
                activehash = activehash.strip()
                if algorithm not in [JUNIPER, LDAP_MD5, LDAP_SHA1]:
                    activehash = activehash.lower()

                cracker_list = Cracker.__subclasses__()
                random.shuffle(cracker_list)

                result = None

                for cr in cracker_list:
                    if not cr.algo_supported(algorithm):
                        continue

                    print(" Cracker : %s" % (cr.NAME))

                    result = crack_hash(cr, algorithm, activehash)

                    # Had the hash been cracked?
                    if result is not None:
                        hashresults.append(result[0])
                        hash_state["value"] = result[0]
                        hash_state["type"] = algorithm
                        hash_state["cracked"] = True
                        # If result was verified, break
                        if result[1] is True:
                            hash_state["verified"] = True
                            break

                if result is not None and result[1] is True:
                    break

        hashes_results[activehash] = hash_state

    return hashes_results


def google_hash(hashvalue):
    '''Google the hash value looking for any result which
    could give some clue...

    @param hashvalue The hash is been looking for.'''

    results = []

    # Build the URL
    url = "http://www.google.com/search?hl=en&q=%s&filter=0" % (hashvalue)

    # Build the Headers with a random User-Agent
    headers = {
        "User-Agent": random.choice(USER_AGENTS)
    }

    # Send the request
    response = utils.do_HTTP_request(url, httpheaders=headers)

    # Extract the results ...
    html = None
    if response:
        html = response.read()

        resultlist = re.findall(
            utils.to_bytes(r'<h3.*?>.*?<a.*?href="(.*?)".*?>.*?</a>.*?</h3>'),
            html,
            re.DOTALL
        )

        results = []

        # ... saving only new ones
        for r in resultlist:
            results.append(utils.to_string(r))
    else:
        results = []

    if results:
        results.sort()

    return results


def getLinesLocalFile(url):
    lines = []
    with open(url, 'r') as f:
        lines = [line.rstrip("\n") for line in f.readlines()]
    return lines


def getLinesHTTP(url):
    if sys.version[0] == "3":
        from urllib.request import urlopen
    else:
        from urllib import urlopen

    response = urlopen(url)

    if response.getcode() == 404:
        raise Exception

    return [line.rstrip("\n") for line in response.readlines()]


def getLinesFiles(urls):
    if sys.version[0] == "3":
        from urllib.parse import urlparse
    else:
        from urlparse import urlparse

    fileslines = collections.OrderedDict()

    for url in urls:
        urlinfos = urlparse(url)
        fileslines[url] = {
            "succes": True,
            "lines": []
        }
        try:
            if urlinfos.scheme == '' and urlinfos.netloc == '':
                fileslines[url]["lines"] = getLinesLocalFile(url)
            elif urlinfos.scheme == 'http':
                fileslines[url]["lines"] = getLinesHTTP(url)
            else:
                fileslines[url]["succes"] = False
                print(urlinfos)
        except:
            print(sys.exc_info())
            fileslines[url]["succes"] = False

    return fileslines


def main(args):
    """Main method."""

    parser = argparse.ArgumentParser(
        prog="findmyhash",
        description="""Cracks a hash from remote webservices

Accepted algorithms are:
------------------------

""" + "\n".join(SUPPORTED_ALGORITHMS),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
---------

  -> Try to crack only one hash.
     python %s --hash 098f6bcd4621d373cade4e832627b4f6

  -> Try to crack a JUNIPER encrypted password escaping special characters.
     python %s --hash "\$9\$LbHX-wg4Z"

  -> If the hash cannot be cracked, it will be searched in Google.
     python %s --hash "{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA=" -g

  -> Try to crack multiple hashes using a file (one hash per line).
     python %s --file mysqlhashesfile.txt


Contact:
--------

[Github]: https://github.com/Talanor/findmyhash
""" % ((args[0],) * 4)
    )
    parser.add_argument(
        "--hash", "-s",
        nargs=1, metavar="HASH",
        action='store', default=None,
        help="Hash value"
    )
    parser.add_argument(
        "--file", "-f",
        nargs=1, metavar="FILE",
        action='store', default=None,
        help="Path to a file containing hashes"
    )
    parser.add_argument(
        "--version", "-V",
        action="version", version="%(prog)s 1.1.3a",
        help="findmyhash's version"
    )
    parser.add_argument(
        "--google", "-g",
        action='store_const', const=True, default=False,
        help="Indicates that findmyhash should search hashes on google \
            if the lookup on the webservices failed to identify the hash"
    )

    ns = parser.parse_args(args[1:])
    # Retrieve arg dict
    ns = dict(ns._get_kwargs())

    if ("help" in ns and ns["help"] is True) \
            or any((ns["file"], ns["hash"])) is False:
        parser.print_help()
        sys.exit(1)

    hashvalues = [] if ns["hash"] is None else ns["hash"]
    googlesearch = ns["google"]

    if ns["file"] is not None and len(ns["file"]) > 0:
        for key, val in getLinesFiles(ns["file"]).items():
            if val["succes"] is True:
                hashvalues.extend(val["lines"])
            else:
                print("Failure to open %s" % key)

    random.seed()

    cracked_hashes = crackloop_hash(hashvalues)

    if len(cracked_hashes) > 0:
        print("Hashes:")
        for original, cracked_hash in cracked_hashes.items():
            if cracked_hash["cracked"] is True:
                print("%s: %s (%s) " % (original, cracked_hash["value"], cracked_hash["type"]))
            else:
                print("%s: Not Found" % (original))
    elif googlesearch:
        links = google_hash(hashvalue)
        print("Google:")
        for link in links:
            print(link)


if __name__ == "__main__":
    main(sys.argv)
