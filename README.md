web_search.py: Short script to run nikto and dirb against a list of hosts and open ports from an nmap file.
  Supply the path to the nmap file. The directory path is all it needs, not the file itself. It will look for it in the path you give it. I've run the script with simple directing to a txt file: ./web_search.py ./path/to/nmap > outfile.txt

web_search_nmap.py: Take an nmap file to check for 200 codes, using Find-Fruit type dictionary.
