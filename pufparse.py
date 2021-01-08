import sys

def dword_at(srcbytes,offset):
    return int.from_bytes(srcbytes[offset:offset+4],byteorder='little')

def word_at(srcbytes,offset):
    return int.from_bytes(srcbytes[offset:offset+2],byteorder='little')

## Parse initial headers of PUF file
def parse_puf_header(buf):
    magic= buf[0:0x30]
    if magic != b"Paradox File: Paradox Update File (PUF Format)\r\n":
        print (f"Invalid PUF file signature data {magic} found")
        sys.exit()
    print (f"Found PUF header {magic}")

    pufversion= buf[0x30]
    print (f" Version: {pufversion:d}")

    print (f" pf_Unknown31: {buf[0x31]:02X} {buf[0x32]:02X} {buf[0x33]:02X}")
    print (f" pf_Unknown34: {dword_at(buf,0x34):08x}")
    print (f" pf_Unknown38: {dword_at(buf,0x38):08x}")
    print (f" pf_Unknown3C: {dword_at(buf,0x3C):08x}")
    print (f" pf_Unknown40: {dword_at(buf,0x40):08x}")

    print (f" Hardware version?: {buf[0x44]:02X}, revision: {buf[0x45]:02X}")
    print (f" Product ID: {buf[0x46]:02X}, Family ID: {buf[0x47]:02X}, Group ID: {buf[0x48]:02X}")
    print (f" Version number: {buf[0x49]:X}.{buf[0x4A]:02X}.{buf[0x4B]:03d}")
    print (f" Minimum version: {buf[0x4C]:X}.{buf[0x4D]:02X}.{buf[0x4E]:03d}")
    print (f" Maximum version: {buf[0x4F]:X}.{buf[0x50]:02X}.{buf[0x51]:03d}")

    if pufversion==1:
        ## Fixed length of 0x52 bytes for PUF file v1 header
        namesoffset= 0x52
        devicedatalen= []        ## Not defined for V1?

    elif pufversion==2:
        ## Fixed length of 0x60 bytes for PUF file v2 header [true?]
        namesoffset= 0x60
        devicedatalen= []        ## Not defined for V2?
        print (f" v2 pf_Unknown52: {dword_at(buf,0x52):08x}")
        print (f" v2 pf_Unknown56: {dword_at(buf,0x56):08x}")
        print (f" v2 Product ID: {buf[0x5A]:02X}, Family ID: {buf[0x5B]:02X}")
        print (f" v2 pf_Unknown5C: {dword_at(buf,0x5C):08x}")

    else:
        print (f" v4 Minimum DLL version?: {buf[0x52]:X}.{buf[0x53]:02X}.{buf[0x54]:03d}")
        print (f" v4 pf_Unknown55: {dword_at(buf,0x55):08x}")
        print (f" v4 pf_Unknown59: {dword_at(buf,0x59):08x}")
        devoffset= dword_at(buf,0x5D)
        namesoffset= word_at(buf,0x61)

        print (f" v4 Device Count offset: {devoffset:08x}")
        print (f" v4 PUF header len / product names offset: {namesoffset:04x}")

        print (f" v4 pf_Unknown63: {word_at(buf,0x63):08x}")
        print (f" v4 pf_Unknown65: {dword_at(buf,0x65):08x}")
        print (f" v4 pf_Unknown69: {buf[0x69]:02X} ")

        print (f" v4 Product ID: {buf[0x6A]:02X}, Family ID: {buf[0x6B]:02X}")
        print (f" v4 Hardware version?: {buf[0x6C]:02X}, revision: {buf[0x6D]:02X}")
        print (" v4 pf_Unknown6E: "+" ".join("{:02x}".format(c) for c in buf[0x6E:devoffset]))        
        
        numdevices= buf[devoffset]
        print (f" v4 Number of chip devices: {numdevices}")

        ## loop through all the device info records, print info and keep track of header offset
        devoffset+= 1
        devicedatalen= []
        for devnum in range(numdevices):
            dilength= buf[devoffset+1]
            print (f"  v4 device info {devnum+1} - length {dilength}")
        
            print (f"   di_Unknown0: {buf[devoffset]:02X}")
            print (f"   di_Unknown2: {buf[devoffset+2]:02X}")    ## high byte for record length?
            print (f"   Device ID: {buf[devoffset+3]:02X}")
            numparts= buf[devoffset+4]
            print (f"   Number of parts: {numparts}")
            partoffset= devoffset+5
            partdatalen= []
            for partno in range(numparts):
                partdatalen.append(dword_at(buf,partoffset+0x09))
                print (f"    Part {partno+1}:")
                print (f"     Part number?: {buf[partoffset]}")
                print (f"     Part type/format: {buf[partoffset+1]:02X}")
                print (f"     Image version number: {buf[partoffset+2]:X}.{buf[partoffset+3]:02X}.{buf[partoffset+4]:03d}")
                print (f"     pi_Unknown5: {dword_at(buf,partoffset+0x05):08x}")
                print (f"     Image data length: {dword_at(buf,partoffset+0x09):08x}")
                print (f"     Image start address?: {dword_at(buf,partoffset+0x0D):08x}")
                print (f"     Image end address?: {dword_at(buf,partoffset+0x11):08x}")
                partoffset+= 0x15
            devoffset+= dilength
            devicedatalen.append(partdatalen)
            ## verify we understand the structure correctly...
            if devoffset!=partoffset:
                print (f"Hmmm,  !!! unknown structure - devoffset ({devoffset:04x}) <> ending partoffset ({partoffset:04x})")

        ## verify we understand the structure correctly...
        if namesoffset!=devoffset:
            print (f"Hmmm, !!! unknown structure - product names start ({namesoffset}) <> end of device info ({devoffset})")
    return (namesoffset, pufversion, devicedatalen)

## Parse product name header in PUF file
def parse_product_name(buf,offset,pufversion):
    print (f"Product name header at offset {offset:04X}")
    startoffset= offset

    if pufversion>2:
        ## Extra byte in produce names header for version>2
        print (f" pnv4_Unknown0 count: {buf[offset]:02X}")
        reclen= buf[offset]
        offset+= 1
        print (" pnv4_Unknown1: "+" ".join("{:02x}".format(c) for c in buf[offset:offset+reclen]))        
        offset+= reclen

    print (f" Datafile(??) version?: {buf[offset]:X}.{buf[offset+1]:02X}.{buf[offset+2]:03d}")
    print (f" Minimum DLL version?: {buf[offset+3]:X}.{buf[offset+4]:02X}.{buf[offset+5]:03d}")
    offset+= 6

    term= offset+buf[offset:].find(b'\x0d\x0a')
    productname= buf[offset+1:term].decode()
    print (f" Product ID {buf[offset]:02X}, name: {buf[offset+1:term]} ")
    offset= term+2

    term= offset+buf[offset:].find(b'\x0d\x0a')
    print (f" Product desc: {buf[offset:term]}")
    offset= term+2

    term= offset+buf[offset:].find(b'\x0d\x0a')
    print (f" Family ID {buf[offset]:02X}, name: {buf[offset+1:term]}")
    offset= term+2

    print (f" pn_Unknown1: {buf[offset]:02X} {buf[offset+1]:02X} {buf[offset+2]:02X}")
    offset+= 3

    term= offset+buf[offset:].find(b'\x0d\x0a')
    print (f" Group ID {buf[offset]:02X}, name: {buf[offset+1:term]}")
    offset= term+2

    print (f" pn_Unknown2: {dword_at(buf,offset):08x}")

    numdevices= buf[offset+4]
    print (f" Number of chip devices: {numdevices}")
    print (f" pn Unknown3: {buf[offset+5]:02X} {buf[offset+6]:02X} {buf[offset+7]:02X}")
    offset+= 8

    print (f" pn header length = {offset-startoffset:d} / {offset-startoffset:02x}")
    return (offset, productname, numdevices)

##########################################################################
##########################################################################
def print_headers():
  ## This method prints the headers at the top of our hex dump ##
  print ("Offset 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F")

def is_character_printable(s):
  ## This method returns true if a byte is a printable ascii character ##
  return (s< 127) and (s >= 32)

def validate_byte_as_printable(byte):
  ## Check if byte is a printable ascii character. If not replace with a '.' character ##
  if is_character_printable(byte):
    return chr(byte)
  else:
    return '.'
  
def hexdump(buf):
    memory_address = 0
    ascii_string = ""
    print_headers()

    ## Loop through the given file while printing the address, hex and ascii output ##
    for byte in buf:
        ascii_string = ascii_string + validate_byte_as_printable(byte)
        if memory_address%16 == 0:
            print(f"{memory_address:06X} {byte:02X} ", end ="")
        elif memory_address%16 == 15:
            print(f"{byte:02X}  {ascii_string}")
            ascii_string = ""
        else:
            print(f"{byte:02X} ", end ="")
        memory_address = memory_address + 1
    print ("")
##########################################################################
##########################################################################

def parse_image_type(buf,offset,parttype,datalen):
    startoffset= offset
    if parttype==1 or parttype==8 or parttype==9:
        ## type 1= firmware/binary, 8= PSK, 9= general binary? [for PCS265]
        return datalen

    elif parttype==2:
        print (f"   dp2_Unknown0 [count?] {dword_at(buf,offset):08x}")
        print (f"   PT2 Symbol set?: {dword_at(buf,offset+4):08x}")
        print (f"   dp2_Unknown8 [count?] {dword_at(buf,offset+8):08x}")
        offset+= 0x0C
        if (dword_at(buf,offset-12)!=0 or dword_at(buf,offset-8)!=0 or dword_at(buf,offset-4)!=0):
            print (f"   PT2 LanguageCode {buf[offset]:02x}")
            print (f"   PT2 start address (erase)? {dword_at(buf,offset+0x1):08x}")
            print (f"   PT2 start address (erase)? {dword_at(buf,offset+0x5):08x}")
            print (f"   dp2_Unknown15  {dword_at(buf,offset+0x9):08x}")
            print (f"   dp2_Unknown19  {dword_at(buf,offset+0xD):08x}")
            print (f"   PT2 Number of blocks: {dword_at(buf,offset+0x11):08x}")
            totalblocks= dword_at(buf,offset+0x11)
            offset+= 0x15
            for blocknum in range(totalblocks):
                print (f"    Block {blocknum+1}: start addr {dword_at(buf,offset):08x} count {dword_at(buf,offset+4):08x} (end= {dword_at(buf,offset)+dword_at(buf,offset+4):08x})")
                offset= offset+8+dword_at(buf,offset+4)
        return offset-startoffset

    elif parttype==3:
        print ("   dp3_Unknown0 "+" ".join("{:02x}".format(c) for c in buf[offset:offset+0xC]))
        print (f"   PT3 Number of version groups {dword_at(buf,offset+0xC):08x} [dp_unknownD= {dword_at(buf,offset-4):08x}]")
        totalvergroups= dword_at(buf,offset+0xC)
        offset+= 0x10

        for vergroupno in range(totalvergroups):
            totalblocks= dword_at(buf,offset+6)
            print (f"    PT3 Version group {vergroupno+1} - {totalblocks:08x} blocks")
            print (f"     PT3 Apply from version {buf[offset]:X}.{buf[offset+1]:02X}.{buf[offset+2]:03d} to version {buf[offset+3]:X}.{buf[offset+4]:02X}.{buf[offset+5]:03d}")
            offset+= 0xA

            for blocknum in range(totalblocks):
                print (f"     PT3 Block {blocknum+1} base? {dword_at(buf,offset):08x}, count {dword_at(buf,offset+4):08x}")
                offset= offset+8+dword_at(buf,offset+4)*6
        return offset-startoffset

    elif parttype==5:   ## k07 type fw.
        print (f"Hmmm, dont know how to handle partition type 5. Using fixed size")
        return 590087 ## at least for a few files examined. - todo fix me! 

    elif parttype==7:   ## mg6250 type fw.
        print (f"Hmmm, unknown partition type {parttype}... just assuming using declared data len bytes")
        return datalen ## todo fix me!.

    print (f"Hmmm, unknown partition type {parttype}... just assuming using declared data len bytes")
    return datalen

## Parse all the images parts for a device
def parse_device_images(buf,offset,pufversion,productname,devicenum,partlengths):
    devheaderstart= offset
    deviceid= buf[offset]
    familyid= buf[offset+5]
    productid= buf[offset+6]
    enctype= buf[offset+2]
    versionstr= f"{buf[offset+7]:X}.{buf[offset+8]:02X}.{buf[offset+9]:03d}"
    print (f" Device ID: {buf[offset]:02X}")
    print (f" dh_Unknown1: {buf[offset+1]:02X}")
    print (f" DH encryption type: {buf[offset+2]:02X}  A6=NONE, 3B=Original, 57=Extended")
    print (f" dh_Unknown3 -- contains data???: {buf[offset+3]:02X} [more devs to come?]")
    print (f" Image Device ID (again?): {buf[offset+4]:02X}")
    print (f" Image Family ID: {buf[offset+5]:02X}")
    print (f" Image Product ID: {buf[offset+6]:02X}")
    print (f" Image Version number: {buf[offset+7]:X}.{buf[offset+8]:02X}.{buf[offset+9]:03d}")
    print (f" Image Application Start Address?: {dword_at(buf,offset+0x0A):08x}")
    print (f" Image Application End Address?: {dword_at(buf,offset+0x0E):08x}")
    print (f" Image Structure base address?: {dword_at(buf,offset+0X12):08x}")
    print (" dh_Unknown22 "+" ".join("{:02x}".format(c) for c in buf[offset+0x16:offset+0x18]))
    offset+= 0x18

    partnum= 0
    ## Iterate through everthing that looks like a partition using heuristic. (2nd byte>='0' is probably a filename in a partition)
    ## Check we are not at the end of the file and offset 1 looks like a filename (or just 0D 0A empty name)
    while offset<(len(buf)-20) and (buf[offset+1]>=0x30 or (buf[offset+1]>=0xD and buf[offset+2]>=0xA)):
        partnum+= 1
        ## Check against partition info from v4/v5 if we have it
        if pufversion>2 and partnum>len(partlengths):
            print (f"Hmmm, more partitions in file than specified in device info structures. Partition {partnum} of {len(partlengths)}!!")

        print (f"  Device partition {partnum} -- offset {offset:04X} ")
        print (f"   Part type/format: {buf[offset]:02X}")

        parttype= buf[offset]
        term= offset+buf[offset:].find(b'\x0d\x0a')
        filename= buf[offset+1:term].decode()
        print (f"   Part Image name (use): {buf[offset+1:term]}")
        offset= term+2
        print (f"   Part Application Start Address?: {dword_at(buf,offset):08x}")
        print (f"   Part Application End Address?: {dword_at(buf,offset+4):08x}")
        print (f"   Part NoDataFlag: {buf[offset+8]:02X}")
        print (f"   Part Data length: {dword_at(buf,offset+9):08x}")
        nodataflag= buf[offset+8]
        datalen= dword_at(buf,offset+9)
        ## some sanity checking/verificction
        if partnum<=len(partlengths):
            didatalen= partlengths[partnum-1]
            print (f"   ..DI Data length: {didatalen:08x}")
            if didatalen>0 and nodataflag>0:
                print ("Hmmm, NoDataFlag set and device info has >0 bytes for this entry")
            if didatalen==0 and nodataflag==0 and datalen>0:
                print ("Hmmm, NoDataFlag clear and device info has zero bytes for this entry")
            if didatalen!=datalen:
                print (f"Hmmm, Device info ({didatalen:08x}) and partition entry ({datalen:08x}) lengths differ")

        print (f"   dp_unknownD [Number of version sets?]: {dword_at(buf,offset+0x0D):08x}")  ## same as data offset C into part type 3
        if nodataflag>0:
            datalen= 0
        offset+= 0x11
        ## Parse partition type and possibly data from file to determine the image size
        compsize= parse_image_type(buf,offset,parttype,datalen)
        print (f"   Computed file data size {compsize:08x}")
        ## Possibly write out file here...
        if (parttype!=2 and compsize>0) or compsize>12:
            outname= f"{productname}_{devicenum}_{familyid:02X}_{productid:02X}_{deviceid:02X}_{versionstr}_{partnum:02X}_{enctype:02X}_{parttype:02X}_{filename}.bin"
            print (f"... Writing {compsize} bytes to filename {outname}")
            with open(outname,"wb") as f:
                f.write(buf[offset:offset+compsize])
        offset+= compsize
    return offset

## Main program...
if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <puf-filename>")
    sys.exit()
pufname= sys.argv[1]
print(f"Parsing PUF file {pufname}")

with open(pufname,"rb") as f:
    ## read entire file at once. maybe change to read 64k chunks or whatever at a later stage
    pufdata=f.read()
    if len(pufdata)<0x52:
        print (f"File {pufname} is too short ({len(pufdata)} bytes) to be a PUF file.")
        sys.exit()
    ## process initial pf header, get offset to next data section
    offset, pufversion, devicedatalen= parse_puf_header(pufdata)
    ## now process the product name header
    offset, productname, numdevices= parse_product_name(pufdata,offset,pufversion)
    ## check if number of devices from v4/v5 device info structure matches number of devices from product names header
    if pufversion>2:
        print (f"Device data len {devicedatalen}")
        if numdevices!=len(devicedatalen):
            print (f"Hmmm, number of devices mismatch between device info records ({len(devicedatalen)} devices) and product names record ({numdevices} devices)")
   
    for devicenum in range(numdevices):
        print (f"Device Header entry #{devicenum+1} at offset {offset:04X}")
        ## Dump some file data to help with debuging
        hexdump(pufdata[offset:offset+0x40])
        ## Check against partition info from v4/v5 if we have it
        partlengths= []
        if pufversion>2:
            if devicenum<len(devicedatalen):
                partlengths= devicedatalen[devicenum]
            else:
                print (f"Hmmm, this device is not in the device info structures. Device {devicenum+1} of {len(devicedatalen)}!!")
        ## Parse data for this device (header and all partitions)
        offset= parse_device_images (pufdata,offset,pufversion,productname,devicenum+1,partlengths)

    if len(pufdata)-offset != 4:
        print ("Hmmm,  --- decoding error --- incorrect number of tail bytes: {len(pufdata)-offset}")
        hexdump(pufdata[offset:])
    else:
        print (f"CRC/Checksum? value: {dword_at(pufdata,offset):08x}") 
