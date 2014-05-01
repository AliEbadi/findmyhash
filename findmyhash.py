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

try:
    import sys
    import hashlib
    import urllib2
    import argparse
    import random
    from modules import Cracker
    from os import path
    from re import search, findall
    from random import seed, randint
    from base64 import decodestring
    from cookielib import LWPCookieJar
except:
    print """
Execution error:

  You required some basic Python libraries.

  This application uses:
    sys, hashlib, urllib, urllib2, os, re, random, base64 and cookielib.

  Please, check if you have all of them installed in your system.

"""
    print(sys.exc_info())
    sys.exit(1)


MD4 = "md4"
MD5 = "md5"
SHA1 = "sha1"
SHA224 = "sha224"
SHA256 = "sha256"
SHA384 = "sha384"
SHA512 = "sha512"
RIPEMD = "rmd160"
LM = "lm"
NTLM = "ntlm"
MYSQL = "mysql"
CISCO7 = "cisco7"
JUNIPER = "juniper"
GOST = "gost"
WHIRLPOOL = "whirlpool"
LDAP_MD5 = "ldap_md5"
LDAP_SHA1 = "ldap_sha1"


USER_AGENTS = [
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; \
        SV1; Crazy Browser 1.0.5)",
    "curl/7.7.2 (powerpc-apple-darwin6.0) libcurl 7.7.2 (OpenSSL 0.9.6b)",
    "Mozilla/5.0 (X11; U; Linux amd64; en-US; rv:5.0) Gecko/20110619 \
        Firefox/5.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b8pre) Gecko/20101213 \
        Firefox/4.0b8pre",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) \
        chromeframe/10.0.648.205",
    "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; \
        InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; \
        .NET CLR 2.0.50727)",
    "Opera/9.80 (Windows NT 6.1; U; sv) Presto/2.7.62 Version/11.01",
    "Opera/9.80 (Windows NT 6.1; U; pl) Presto/2.7.62 Version/11.00",
    "Opera/9.80 (X11; Linux i686; U; pl) Presto/2.6.30 Version/10.61",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) AppleWebKit/535.2 \
        (KHTML, like Gecko) Chrome/15.0.861.0 Safari/535.2",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.2 (KHTML, like Gecko) \
        Chrome/15.0.872.0 Safari/535.2",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.1 (KHTML, like Gecko) \
        Chrome/14.0.812.0 Safari/535.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
]


def configureCookieProcessor(cookiefile='/tmp/searchmyhash.cookie'):
    '''Set a Cookie Handler to accept cookies from the different Web sites.

    @param cookiefile Path of the cookie store.'''

    cookieHandler = LWPCookieJar()
    if cookieHandler is not None:
        if path.isfile(cookiefile):
            cookieHandler.load(cookiefile)

        opener = urllib2.build_opener(
            urllib2.HTTPCookieProcessor(cookieHandler)
        )
        urllib2.install_opener(opener)


def crackHash(algorithm, hashvalue=None, hashfile=None):
    """Crack a hash or all the hashes of a file.

    @param alg Algorithm of the hash (MD5, SHA1...).
    @param hashvalue Hash value to be cracked.
    @param hashfile Path of the hash file.
    @return If the hash has been cracked or not."""

    # Cracked hashes will be stored here
    crackedhashes = []

    # Is the hash cracked?
    cracked = False

    # Only one of the two possible inputs can be setted.
    if (not hashvalue and not hashfile) or (hashvalue and hashfile):
        return False

    # hashestocrack depends on the input value
    hashestocrack = None
    if hashvalue:
        hashestocrack = [hashvalue]
    else:
        try:
            hashestocrack = open(hashfile, "r")
        except:
            print "\nIt is not possible to read input file (%s)\n" % (hashfile)
            return cracked

    for activehash in hashestocrack:
        hashresults = []

        # Standarize the hash
        activehash = activehash.strip()
        if algorithm not in [JUNIPER, LDAP_MD5, LDAP_SHA1]:
            activehash = activehash.lower()

        print "\nCracking hash: %s\n" % (activehash)

        cracker_list = Cracker.__subclasses__()
        random.shuffle(cracker_list)

        for cr in cracker_list:

            if not cr.algo_supported(algorithm):
                continue

            # Analyze the hash
            print "Analyzing with %s (%s)..." % (cr.NAME, cr.URL)

            # Crack the hash
            result = None
            try:
                result = cr.crack(activehash, algorithm)
            # If it was some trouble, exit
            except:
                info = sys.exc_info()
                print "\nSomething was wrong. Please, contact us \
to report the bug:\n%s %s\n\n\
https://github.com/Talanor/findmyhash\n" % (str(info[0]), str(info[1]))
                if hashfile:
                    try:
                        hashestocrack.close()
                    except:
                        pass
                return False

            # If there is any result...
            cracked = 0
            if result:

                # If it is a hashlib supported algorithm...
                if algorithm in [
                        MD4,
                        MD5,
                        SHA1,
                        SHA224,
                        SHA384,
                        SHA256,
                        SHA512,
                        RIPEMD
                        ]:
                    # Hash value is calculated to compare with cracker result
                    h = hashlib.new(algorithm)
                    h.update(result)

                    if h.hexdigest() == activehash:
                        hashresults.append(result)
                        cracked = 2

                # If it is a half-supported hashlib algorithm
                elif algorithm in [LDAP_MD5, LDAP_SHA1]:
                    alg = algorithm.split('_')[1]
                    ahash = decodestring(activehash.split('}')[1])

                    # Hash value is calculated to compare with cracker result
                    h = hashlib.new(alg)
                    h.update(result)

                    if h.digest() == ahash:
                        hashresults.append(result)
                        cracked = 2

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
                        hashresults.append(result)
                        cracked = 2

                # If it is another algorithm, we search in all the crackers
                else:
                    hashresults.append(result)
                    cracked = 1

            # Had the hash cracked?
            if cracked:
                print "\n***** HASH CRACKED!! *****\n\
The original string is: %s\n" % (result)
                # If result was verified, break
                if cracked == 2:
                    break
            else:
                print "... hash not found in %s\n" % (cr.NAME)

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

    if hashfile:
        try:
            hashestocrack.close()
        except:
            pass

    # Show a resume of all the cracked hashes
    print "\nThe following hashes were cracked:\n----------------------------------\n"
    print crackedhashes and "\n".join("%s -> %s" % (hashvalue, result.strip()) for hashvalue, result in crackedhashes) or "NO HASH WAS CRACKED."
    print

    return cracked


def searchHash(hashvalue):
    '''Google the hash value looking for any result which could give some clue...

    @param hashvalue The hash is been looking for.'''

    start = 0
    finished = False
    results = []

    sys.stdout.write("\nThe hash wasn't found in any database. Maybe Google has any idea...\nLooking for results...")
    sys.stdout.flush()

    while not finished:

        sys.stdout.write('.')
        sys.stdout.flush()

        # Build the URL
        url = "http://www.google.com/search?hl=en&q=%s&filter=0" % (hashvalue)
        if start:
            url += "&start=%d" % (start)

        # Build the Headers with a random User-Agent
        headers = {"User-Agent": USER_AGENTS[randint(0, len(USER_AGENTS)) - 1]}

        # Send the request
        response = do_HTTP_request(url, httpheaders=headers)

        # Extract the results ...
        html = None
        if response:
            html = response.read()
        else:
            continue

        resultlist = findall(r'<a href="[^"]*?" class=l', html)

        # ... saving only new ones
        new = False
        for r in resultlist:
            url_r = r.split('"')[1]

            if not url_r in results:
                results.append(url_r)
                new = True

        start += len(resultlist)

        # If there is no a new result, finish
        if not new:
            finished = True

    if results:
        print "\n\nGoogle has some results. Maybe you would like \
to check them manually:\n"

        results.sort()
        for r in results:
            print "  *> %s" % (r)
        print

    else:
        print "\n\nGoogle doesn't have any result. Sorry!\n"


def main(args):
    """Main method."""

    parser = argparse.ArgumentParser(
        prog="findmyhash",
        description="""Cracks a hash from remote webservices

Accepted algorithms are:
------------------------

  MD4       - RFC 1320
  MD5       - RFC 1321
  SHA1      - RFC 3174 (FIPS 180-3)
  SHA224    - RFC 3874 (FIPS 180-3)
  SHA256    - FIPS 180-3
  SHA384    - FIPS 180-3
  SHA512    - FIPS 180-3
  RMD160    - RFC 2857
  GOST      - RFC 5831
  WHIRLPOOL - ISO/IEC 10118-3:2004
  LM        - Microsoft Windows hash
  NTLM      - Microsoft Windows hash
  MYSQL     - MySQL 3, 4, 5 hash
  CISCO7    - Cisco IOS type 7 encrypted passwords
  JUNIPER   - Juniper Networks $9$ encrypted passwords
  LDAP_MD5  - MD5 Base64 encoded
  LDAP_SHA1 - SHA1 Base64 encoded

  NOTE: for LM / NTLM it is recommended to introduce both values with this format:
         python %s --type LM --hash 9a5760252b7455deaad3b435b51404ee:0d7f1f2bdeac6e574d6e18ca85fb58a7
         python %s --type NTLM --hash 9a5760252b7455deaad3b435b51404ee:0d7f1f2bdeac6e574d6e18ca85fb58a7
        """ % ((args[0],) * 2),
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

    configureCookieProcessor()

    seed()

    cracked = 0

    cracked = crackHash(algorithm, hashvalue, hashfile)

    if not cracked and googlesearch and not hashfile:
        searchHash(hashvalue)


if __name__ == "__main__":
    main(sys.argv)
