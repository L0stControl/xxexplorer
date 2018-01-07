# xxexplorer

Usage: xxexplorer.rb [options]
    -f, --file /path/to/file         *Mandatory* File with XXE request (from burp), use [PLACEHOLDER]
    -w, --wordlist /path/to/wordlist To attempt to retrieve the contents of the files (Fuzzying)
        --phprce                     XXE PHP Module
    -p, --port 8080                  Different port
    -e, --phpencode                  Encode using php://filter/convert.base64-encode/resource=
    -u, --urlencode                  Encode placeholder payloads
    -s, --https                      enable HTTPS
    -b, --oob http://site.com/       XXE Out-of-band exploitation module(xxeserve)
    -d, --delay n                    Requests delay in seconds
        --ssrf /path/to/hosts        SSRF Exploitation using payload file
        --payloads /path/to/payloads.list
                                     Payloads file to SSRF Exploitation
    -h, --help                       Displays Help
