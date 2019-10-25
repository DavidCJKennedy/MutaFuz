
fuzzer.py arguments:

1 - App root URL
2 - Display successful payloads, -s to display payloads, -n to not display payloads
3 - Name of .txt containing XSS payloads. 
NOTE: XSS payloads file must be in same directory as fuzzer.py

~~ eg. To execute and display successful payloads
python3 fuzzer.py "http://somedomaintofuzz" -s payloads.txt

~~ eg. To execute and hide successful payloads
python3 fuzzer.py "http://somedomaintofuzz" -n payloads.txt

XSS payload file supplied is named XSS_payloads.txt.
python3 fuzzer.py "http://somedomaintofuzz" -n XSS_payloads.txt