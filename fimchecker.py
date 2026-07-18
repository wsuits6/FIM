#importing modules  
import os
import hashlib
import time

#File integrity  checker

#take the directory path
dir_path = str(input("Input dir Path"))

#calculate the SHA256 for that path
dir_hash = sha256(dir_path)

#return the path and store  it in a text file 

# lock the text file soo ti cant be modifed 

# then chekc for changes int he direcoty path  by runnigthe tool  again 