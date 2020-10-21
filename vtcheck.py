#!/usr/bin/env python


import optparse
import re
import time
import requests


API_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
HASHMD5 = re.compile(r"\b([a-fA-F\d]{32})\b")
HASHSHA1 = re.compile(r"\b([a-fA-F\d]{40})\b")
HASHSHA256 = re.compile(r"\b([a-fA-F\d]{64})\b")
HTTPHEADERS = {'Accept-Encoding': 'gzip, deflate',
               'User-Agent': 'gzip, vtcheck'}
EMPTYMD5 = "d41d8cd98f00b204e9800998ecf8427e"
EMPTYSHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
EMPTYSHA256 = "e3b0c44298fc1c149afbf4c8996fb924"\
              "27ae41e4649b934ca495991b7852b855"


def checkHash(hash, apikey):
    params = {'apikey': apikey}
    params['resource'] = hash
    try:
        response = requests.get(API_URL, params=params, headers=HTTPHEADERS)
    except IOError:
        print("E) An error occurred connecting to the VirusTotal API URL: " +
              API_URL + " - please check for connectivity issues!")
    if response:
        try:
            json_response = response.json()
            if 'positives' in json_response.keys():
                positives = int(json_response['positives'])
                total = int(json_response['total'])
                result = "Verdict: "
                if positives > 30:
                    result += "highly likely"
                elif positives > 20:
                    result += "very likely"
                elif positives > 10:
                    result += "likely"
                elif positives > 0:
                    result += "potentially"
                else:
                    result += "not"
                result += " malicious"
                result += " [" + str(positives) + "/" + str(total) + "]"
                if options.verbose:
                    result += "\nVirusTotal JSON output:\n"
                    result += str(json_response)
                return result, positives
            else:
                return "Verdict: unknown hash", 0
        except ValueError:
            print("An error occurred: ")
            print(response)


if __name__ == "__main__":
    cli = optparse.OptionParser(usage="usage: %prog -f <hashfile> "
                                      "-t <interval> <hashes>")
    cli.add_option('-f', '--file', dest='filename', action='store',
                   help='[required] File containing hashes to check',
                   metavar='IPFILE', default=None)
    cli.add_option('-k', '--key', dest='apikey', action='store',
                   default=None, help='[required] VT API key to use')
    cli.add_option('-t', '--interval', dest='interval', action='store',
                   default=15, help='[optional] Specify time interval between'
                   ' each VirusTotal request (default: 15 seconds)')
    cli.add_option('-c', '--csv', dest='csv', action='store_true',
                   default=False, help='[optional] Do not print progress, '
                   'errors (quiet operation), CSV output format')
    cli.add_option('-v', '--verbose', dest='verbose', action='store_true',
                   default=False, help='[optional] Print verbose errors')
    (options, hashes) = cli.parse_args()
    if (options.filename or hashes) and options.apikey:
        total = 0
        count = 1
        hashlist = set()
        if options.filename:
            if not options.csv:
                print("I) Parsing " + options.filename +
                      " for md5/sha1/sha256 " +
                      "hashes...")
            try:
                hashfile = open(options.filename, 'r')
            except IOError:
                print("E) An error occurred opening the file: " +
                      options.filename)
            for line in hashfile.readlines():
                resultmd5 = HASHMD5.finditer(line)
                resultsha1 = HASHSHA1.finditer(line)
                resultsha256 = HASHSHA256.finditer(line)
                for hash in [line.group(0) for line in resultmd5]:
                    if hash != EMPTYMD5:
                        hashlist.add((hash, 'md5'))
                        total += 1
                for hash in [line.group(0) for line in resultsha1]:
                    if hash != EMPTYSHA1:
                        hashlist.add((hash, 'sha1'))
                        total += 1
                for hash in [line.group(0) for line in resultsha256]:
                    if hash != EMPTYSHA256:
                        hashlist.add((hash, 'sha256'))
                        total += 1
        if hashes:
            for hash in hashes:
                resultmd5 = HASHMD5.finditer(line)
                resultsha1 = HASHSHA1.finditer(line)
                resultsha256 = HASHSHA256.finditer(line)
                for hash in [line.group(0) for line in resultmd5]:
                    if hash != EMPTYMD5:
                        hashlist.add((hash, 'md5'))
                        total += 1
                for hash in [line.group(0) for line in resultsha1]:
                    if hash != EMPTYSHA1:
                        hashlist.add((hash, 'sha1'))
                        total += 1
                for hash in [line.group(0) for line in resultsha256]:
                    if hash != EMPTYSHA256:
                        hashlist.add((hash, 'sha256'))
                        total += 1
        if options.csv:
            print("\"hash\",\"hashtype\",\"result\"")
        else:
            print("I) VTCheck found " + str(len(hashlist)) +
                  " unique hashes out of " + str(total) +
                  " in total. Now checking against "
                  "VirusTotal (this may take a while) ...")
        count = 1
        for hash, hashtype in hashlist:
            try:
                result, report = checkHash(hash, options.apikey)
                if options.csv:
                    print("\"" + hash + "\",\"" + hashtype + "\",\"" +
                          result + "\"")
                else:
                    print("[" + str(count) + "/" +
                          str(len(hashlist)) + "] " +
                          "Result for " + hashtype +
                          " hash: " + hash +
                          " -> " + result)
                count += 1
            except Exception as e:
                print("E) An error occurred checking " + hashtype +
                      " hash: " + hash)
                print("E) " + e.msg)
            time.sleep(float(options.interval))
        if not options.csv:
            print("I) Checks successfully completed for " + str(len(hashlist)) +
                  " out of " + str(len(hashlist)) + " hashes.")
    else:
        if not options.filename and not hashes:
            print("E) You must specify a file and/or hash(es) to check.")
        if not options.apikey:
            print("E) You must specify a VirusTotal API key to use.")
        cli.print_help()
