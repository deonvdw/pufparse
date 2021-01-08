# pufparse
pufparse is a small utility to display the contents of Paradox .puf firmware update files. These files contain a lot of header information (device name, family, version numbers) and various image files written to the device. The processor firmware images themselves are encrypted, this utility will not decrypt them. Other resources are in plain text.

## Usage
    pufparse.py <puf-filename>

The pufparse script will write out all the images files embedded in the .puf file using the following naming convention:

{productname}\_{devicenum}\_{familyid}\_{productid}\_{deviceid}\_{versionstr}\_{partnum}\_{enctype}\_{parttype}\_{imagename}.bin

pufparse requires Python 3 to run - developed and tested on version 3.8.

## Notes            
There are still a few unknown elements in the .puf files which pufparse does not properly handle. 
