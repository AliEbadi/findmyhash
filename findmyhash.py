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
from modules import *

if sys.version[0] == "3":
    hashlib_algorithms = hashlib.algorithms_available
else:
    hashlib_algorithms = hashlib.algorithms


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36"
]


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
            ahash = base64.decodestring(activehash.split('}')[1])

            # Hash value is calculated to compare with cracker result
            h = hashlib.new(alg)
            h.update(result)

            if h.digest() == ahash:
                result = (result, True)
            else:
                result = None

        elif algorithm == NTLM or \
                (algorithm == LM and ':' in activehash):
            # NTLM Hash value is calculated to compare
            # with cracker result
            candidate = hashlib.new(
                'md4',
                result.split()[-1].encode('utf-16le')
            ).hexdigest()

            # It's a LM:NTLM combination or a single NTLM hash
            if (':' in activehash and
                candidate == activehash.split(':')[1]) \
                    or (':' not in activehash
                        and candidate == activehash):
                result = (result, True)
        else:
            result = (result, False)
    else:
        result = None

    return result


def crackloop_hash(algorithm, hashvalues):
    """Crack a hash or all the hashes of a file.

    @param alg Algorithm of the hash (MD5, SHA1...).
    @param hashvalue Hash value to be cracked.
    @return If the hash has been cracked or not."""

    # Cracked hashes will be stored here
    crackedhashes = []

    # Is the hash cracked?
    cracked = False

    # hashestocrack depends on the input value

    for activehash in hashvalues:
        hashresults = []

        # Standarize the hash
        activehash = activehash.strip()
        if algorithm not in [JUNIPER, LDAP_MD5, LDAP_SHA1]:
            activehash = activehash.lower()

        cracker_list = Cracker.__subclasses__()
        random.shuffle(cracker_list)

        for cr in cracker_list:
            if not cr.algo_supported(algorithm):
                continue

            result = crack_hash(cr, algorithm, activehash)

            # Had the hash been cracked?
            if result is not None:
                hashresults.append(result[0])
                # If result was verified, break
                if result[1] is True:
                    break

        if hashresults:
            resultlist = []
            for r in hashresults:
                if r not in resultlist:
                    resultlist.append(r)

            finalresult = ""
            if len(resultlist) > 1:
                finalresult = ', '.join(resultlist)
            else:
                finalresult = resultlist[0]

            # Valid results are stored
            crackedhashes.append((activehash, finalresult))

    return crackedhashes
    # Show a resume of all the cracked hashes
#     print("\nThe following hashes were cracked:\n\
# ----------------------------------\n")
#     print(crackedhashes and "\n".join(
#         "%s -> %s" % (hashvalue, result.strip())
#         for hashvalue, result in crackedhashes
#     ) or "NO HASH WAS CRACKED.")
#     print("")

#     return (cracked)


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
     python %s --type MD5 --hash 098f6bcd4621d373cade4e832627b4f6

  -> Try to crack a JUNIPER encrypted password escaping special characters.
     python %s --type JUNIPER --hash "\$9\$LbHX-wg4Z"

  -> If the hash cannot be cracked, it will be searched in Google.
     python %s --type LDAP_SHA1 --hash "{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA=" -g

  -> Try to crack multiple hashes using a file (one hash per line).
     python %s MYSQL --file mysqlhashesfile.txt


Contact:
--------

[Github]: https://github.com/Talanor/findmyhash
""" % ((args[0],) * 4)
    )
    parser.add_argument(
        "--type", "-t",
        nargs=1, metavar='TYPE',
        action='store', default=None,
        help="Hash type (MD5, SHA1, ...)"
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
            or any((ns["file"], ns["hash"])) is False \
            or ns["type"] is None:
        parser.print_help()
        sys.exit(1)

    algorithm = ns["type"][0].lower()
    hashvalue = None if ns["hash"] is None else ns["hash"][0]
    hashfile = None if ns["file"] is None else ns["file"][0]
    googlesearch = ns["google"]

    random.seed()

    cracked_hashes = crackloop_hash(algorithm, [hashvalue])

    if len(cracked_hashes) > 0:
        print("Hashes:")
        for cracked_hash, original in cracked_hashes:
            print("%s: %s" % (cracked_hash, original))
    elif googlesearch:
        links = google_hash(hashvalue)
        print("Google:")
        for link in links:
            print(link)


if __name__ == "__main__":
    main(sys.argv)
