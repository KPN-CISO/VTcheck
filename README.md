# Description  

(c) Arnim Eijkhoudt \<arnime _squiggly_ kpn-cert.nl\>, 2017-2019, KPN-CERT, GPLv3 license
  
VTcheck lets you run an online-check of md5/sha1/sha256 hashes against VirusTotal. This tool is particularly useful for automatically checking leaked/dumped hashes in structured or unstructured files for potential maliciousness.
  
VTcheck will automatically parse the entirety of any text file (unstructured or not) for anything resembling an md5, sha1 or sha256 hash and tell you:

1) which hashes are potentially malicious or unknown
2) the amount of unique and total hashes found

# Requirements  
  
1) Python 3.x
  
# Installation  
  
1) git clone https://github.com/KPN-CISO/VTcheck/
2) Log in to your VirusTotal account and grab your API key

# Usage  
  
```1) ./vtcheck.py -f <file containing hashes> -k <VT_API_key>```

or

```2) ./vtcheck.py -k <VT_API_key> <hash1> <hash2> ... <hashN>```

Usage notes:

1) Unless you have a paid VirusTotal subscription, do not decrease the time interval to lower than 15 seconds!
1) You can combine a file containing hashes, and at the same time specify additional hashes on the command line.
