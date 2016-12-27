# bro_zipfilenames
Bro Script to extract the filenames from a zipfile

## About

This script parses through a zip file (.zip) and extracts the list of filenames.
It then generates a Bro Notice if any of the file extensions are on the hardcoded blacklist. The script does not perform any decompression or analysis of the zip's contents.
