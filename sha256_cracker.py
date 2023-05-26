import sys
from pwn import *

if(len(sys.argv) != 2):
    print("invalid argument")
    print("./{} <sha256sum>".format(sys.argv[0]))
    exit()
input_hash = sys.argv[1]
password_file = "rockyou.txt"
attempts = 0
with log.progress("Attempting to back: {} ! \n".format(input_hash)) as p :
    with open(password_file, "r", encoding="latin-1") as password_list:
        for password in password_list:
            password = password.strip("\n").encode("latin-1")  
            password_hash = sha256sumhex(password)
            p.status("[{}] {} == {}".format(attempts, password.decode("latin-1"), password_hash))
            if password_hash == input_hash:
                print("Password find after {} attempts! {} heshes to {}".format(attempts, password.decode("latin-1"), password_hash))
                exit()
            attempts += 1
        p.failure("Password hash not found")
