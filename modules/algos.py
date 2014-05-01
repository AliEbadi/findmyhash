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
    globals()[algo] = algo.lower()
