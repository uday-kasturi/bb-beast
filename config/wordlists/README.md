# Wordlists

Place wordlists here. The following are expected by the tool wrappers:

## Required
- common.txt                     — ~4,000 common dirs/files (SecLists: Discovery/Web-Content/common.txt)
- raft-medium-directories.txt    — ~30,000 dirs (SecLists: Discovery/Web-Content/raft-medium-directories.txt)
- raft-large-directories.txt     — ~60,000 dirs (SecLists: Discovery/Web-Content/raft-large-directories.txt)
- subdomains-top1million-5000.txt — top 5000 subdomains (SecLists: Discovery/DNS/)

## Optional but recommended
- raft-medium-words.txt          — for parameter fuzzing
- burp-parameter-names.txt       — common parameter names
- web-extensions.txt             — file extensions

## Download (SecLists)
git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/SecLists
ln -s /opt/SecLists/Discovery/Web-Content/common.txt common.txt
ln -s /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt raft-medium-directories.txt
ln -s /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt raft-large-directories.txt
ln -s /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt subdomains-top1million-5000.txt
