  # MD4       - RFC 1320
  # MD5       - RFC 1321
  # SHA1      - RFC 3174 (FIPS 180-3)
  # SHA224    - RFC 3874 (FIPS 180-3)
  # SHA256    - FIPS 180-3
  # SHA384    - FIPS 180-3
  # SHA512    - FIPS 180-3
  # RMD160    - RFC 2857
  # GOST      - RFC 5831
  # WHIRLPOOL - ISO/IEC 10118-3:2004
  # LM        - Microsoft Windows hash
  # NTLM      - Microsoft Windows hash
  # MYSQL     - MySQL 3, 4, 5 hash
  # CISCO7    - Cisco IOS type 7 encrypted passwords
  # JUNIPER   - Juniper Networks $9$ encrypted passwords
  # LDAP_MD5  - MD5 Base64 encoded
  # LDAP_SHA1 - SHA1 Base64 encoded

algos = [
    "MD4",
    "MD5",
    "SHA1",
    "SHA224",
    "SHA256",
    "SHA384",
    "SHA512",
    "RIPEMD",
    "LM",
    "NTLM",
    "MYSQL",
    "CISCO7",
    "JUNIPER",
    "GOST",
    "WHIRLPOOL",
    "LDAP_MD5",
    "LDAP_SHA1",
]

for algo in algos:
    locals()[algo] = algo.lower()
