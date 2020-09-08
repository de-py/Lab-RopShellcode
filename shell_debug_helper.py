import os
import sys
import re
import time
def replace_c(new_shell):
    f = open("shellcode_stub.c", "r")
    the_file = f.read()
    f.close()

    new_file = re.compile('char shellcode\[[\S\s]+\";')
    try_it = new_file.sub(new_shell,the_file)
    
    f = open("shellcode_stub.c", "w")
    f.write(try_it)
    f.close()


# function borrowed, does pveReadbin.pl
def convert(new_name):
    f = open(new_name, 'rb')
    bytes = f.read()
    num = len(bytes)

    array = 'char shellcode[%d] = \n\t"' % (num)
    for b in range(len(bytes)):
      if b > num: break 
      if b % 16 == 0 and b > 0:
        array += '"\n\t"'
      array += '\\x%02x' % ord(bytes[b])

    array += '";\n'

    return array


file_name = sys.argv[1]

try:
    suffix = int(sys.argv[2])

except:
    print("You need two arguments and you need an integer")
    exit()

#os.system("wget --no-check-certificate -O shellcode_stub.c <yourwebsite or github>/shellcode_stub.c ") 
#os.system("wget --no-check-certificate -O shellcode.asm <yourwebsite or github>/shellcode.asm")
#os.system("wget --no-check-certificate <yourwebsite or github>/shell_debug_helper.py")

while True:
    new_name = ("shellv%d" % suffix)
    os.system("nasm %s -o %s.bin" % (file_name, new_name))
    new_shell = convert(new_name+".bin")
    replace_c(new_shell)
    os.system("cl %s -o %s.exe" % ("shellcode_stub.c", new_name))
    os.system('windbg %s.exe -c "g" '% new_name)
    old = os.stat("shellcode.asm").st_mtime

