#!/usr/bin/python

__version__ = '0.1.1.5'

# -------------------------------------------------------------------------------
# Encryption / Decryption algorithm using, CBC with triple key and double AES.
# Under GNU License - Feel free to modify it :)
# -------------------------------------------------------------------------------
# Anastasios Stasinopoulos - <stasinopoulos[at]unipi[dot]gr>
# -------------------------------------------------------------------------------
# [>] Stupid bugs fixed.
# [>] Added some exceptions.
# [>] Added functionality for "n" blocks encryption / decryption
# ------------------------------------------------------------------------------

import sys
from Crypto.Cipher import AES, XOR

# ------------------------------------------
# Function to encrypt message with XOR.
# ------------------------------------------

def xor(message, key):
  message_to_xor = message
  key_for_xor = XOR.new(key)
  xor = key_for_xor.encrypt(message_to_xor)
  return xor

# ------------------------------------------

# ------------------------------------------
# Function to encrypt message with AES.
# ------------------------------------------

def EncryptAES(x,y):
  return x.encrypt(y)

# ------------------------------------------

# ------------------------------------------
# Function to decrypt message with AES.
# ------------------------------------------

def DecryptAES(x, y):
  return x.decrypt(y).rstrip(PadChar)

# ------------------------------------------

# Padding (with NullByte) character
PadChar = "\x00" 	# <~ Change this if need!

# Default number of (minimum) blocks.
Num_of_Blocks = 2	# <~ Change this if need!

print("\n+-----------------------------------------------------------------------------+")
print("  Encryption / Decryption algorithm using, CBC with triple key and double AES.")
print("  Anastasios Stasinopoulos - <stasinopoulos[at]unipi[dot]gr>")
print("+-----------------------------------------------------------------------------+")
print("\n --> 1.Encrypt.\n --> 2.Decrypt.\n --> 3.Quit.")

while True:
  try:
    try:
      choice = int(raw_input("\n[*] Enter your choice: "))
      
      # ---------------------------------+  
      # Option 1: Encrypt                |
      # Encryption method (E) using AES  |
      # ---------------------------------+-------------------------------------------------------
      #												|
      #      +----------+                +----------+                    +----------+  		|
      #      |    m1    |                |    m2    |                    |    mn    |		|
      #      +----------+                +----------+                    +----------+		|
      #           |                            |                               |		|
      #           |                            |                               |		|
      # k -->    (+)          |-------------> (+)             |-------------> (+)		|
      #           |           |                |              |                |		|
      #        +-----+        |             +-----+           |             +-----+		|
      # k1 --> |  E  |        |      k1 --> |  E  |           |      k1 --> |  E  |		|         
      #        +-----+        |             +-----+           |             +-----+		|
      #           |------------                |---------------                |		|
      #        +-----+                      +-----+                         +-----+		|
      # k2 --> |  E  |               k2 --> |  E  |                  k2 --> |  E  |  		|
      #        +-----+                      +-----+                         +-----+		|
      #           |                            |                               |		|
      #           |                            |                               |		|
      #      +----------+                 +----------+                   +----------+		|
      #      |    c1    |                 |    c2    |                   |    cn    |		|
      #      +----------+                 +----------+    (.......)      +----------+		|
      # -----------------------------------------------------------------------------------------
      
      if choice == 1:
		
	# The Key must be triple!
	# So, the key must be 48, 64 or 80 characters in length.
	
	Key = raw_input('[*] Please, enter your key (must be 48, 64 or 80 characters) : ')
	if len(Key) == 48 or len(Key) == (64) or len(Key) == (80):
	  
	  # Standard length -for AES- 128 bits
	  # Must be |k| == BLOCK_SIZE
	  
	  BLOCK_SIZE = 16
	  k  = Key[0 : BLOCK_SIZE]
	  	  
	  # Split the rest of "Key" in two keys
	  
	  REST_OF_KEY = (len(Key) - BLOCK_SIZE) / 2
	  k1 = Key[BLOCK_SIZE : BLOCK_SIZE + REST_OF_KEY]
	  k2 = Key[BLOCK_SIZE + REST_OF_KEY : BLOCK_SIZE +(REST_OF_KEY*2)]
	  
	else:
	  print "\n[-] Please check your key's length, is "+ str(len(Key)) +" characters!\n"
	  sys.exit()
	
	MAX_SIZE = BLOCK_SIZE * Num_of_Blocks
	
	# Two cipher Objects
	
	Cipher  = AES.new(k1)
	Cipher2 = AES.new(k2)
	
	# Create an empty array, 
	# For plain text -messages- storage.
	
	m = []
	
	message = raw_input('[*] Enter your message: ')

	if len(message) > MAX_SIZE:
	  	  
	  MAX_BLOCK = (len(message) / BLOCK_SIZE) + 1
	  MAX_SIZE = BLOCK_SIZE * MAX_BLOCK
	  
	  padding_required = MAX_SIZE - (len(message))
	  Padding = PadChar * padding_required
	  print Padding

	  if padding_required == 0:
	    for num in range(0,MAX_BLOCK):
	      n = message[int(BLOCK_SIZE * num) : (BLOCK_SIZE * (num + 1))]
	      m.append(n)
	    
	  else:
	    message = message + Padding
	    for num in range(0,MAX_BLOCK):
	      n = message[int(BLOCK_SIZE * num) : (BLOCK_SIZE * (num + 1))]
	      m.append(n)
	      
	  print "\n\033[1;31mThe cipher text:\033[1;m"
	  
	  flag = True
	  for i in m:
	    if flag == True:
	      E = EncryptAES(Cipher, xor(i,k))
	      C = EncryptAES(Cipher2,E).encode("hex") 
	      sys.stdout.write(C)
	      flag = False
	      
	    else:
		K  = E
		E  = EncryptAES(Cipher, xor(i,K))
		C1 = EncryptAES(Cipher2,E).encode("hex")
	        sys.stdout.write(C1)
	      	      
	  print "\n"       

	else:
	  MAX_BLOCK = Num_of_Blocks
	  MAX_SIZE = BLOCK_SIZE * MAX_BLOCK
	  
	  padding_required = MAX_SIZE - (len(message))
	  Padding = PadChar * padding_required

	  if padding_required == 0:
	    for num in range(0,MAX_BLOCK):
	      n = message[int(BLOCK_SIZE * num) : (BLOCK_SIZE * (num + 1))]
	      m.append(n)
	      
	  else:
	    message = message + Padding
	    for num in range(0,MAX_BLOCK):
	      n = message[int(BLOCK_SIZE * num) : (BLOCK_SIZE * (num + 1))]
	      m.append(n)
	  
	  print "\n\033[1;31mThe cipher text:\033[1;m"
	  
	  flag = True
	  for i in m:
	    if flag == True:
	      E = EncryptAES(Cipher, xor(i,k))
	      C = EncryptAES(Cipher2,E).encode("hex")			
	      sys.stdout.write(C)
	      flag = False
	      
	    else:
		K  = E
		E  = EncryptAES(Cipher, xor(i,K))
		C1 = EncryptAES(Cipher2,E).encode("hex")
	        sys.stdout.write(C1)
	      	      
	  print "\n"   	  

      # ---------------------------------+ 
      # Option 2: Decrypt                |
      # Decryption method (D) using AES  |
      # ---------------------------------+-------------------------------------------------------
      #												|
      #      +----------+                +----------+                    +----------+  		|
      #      |    c1    |                |    c2    |                    |    cn    |		|
      #      +----------+                +----------+                    +----------+		|
      #           |                            |                               |		|
      #           |                            |                               |		|
      #        +-----+                      +-----+                         +-----+		|
      # k2 --> |  D  |               k2 --> |  D  |                  k2 --> |  D  |         	|
      #        +-----+                      +-----+                         +-----+		|
      #           |------------                |---------------                |		|
      #        +-----+        |             +-----+           |             +-----+		|
      # k1 --> |  D  |        |      k1 --> |  D  |           |      k1 --> |  D  |  		|
      #        +-----+        |             +-----+           |             +-----+		|
      #           |           |                |              |                |		|
      # k -->    (+)          |-------------> (+)             |-------------> (+)		|
      #           |                            |                               |		|
      #           |                            |                               |		|
      #      +----------+                 +----------+                   +----------+		|
      #      |    m1    |                 |    m2    |                   |    mn    |		|
      #      +----------+                 +----------+    (.......)      +----------+		|
      #												|
      # -----------------------------------------------------------------------------------------
      
      elif choice == 2:
		
	# The Key must be triple!
	# So, the key must be 48, 64 or 80 characters in length.
	
	Key = raw_input('[*] Please, enter your key (must be 48, 64 or 80 characters) : ')

	if len(Key) == 48 or len(Key) == (64) or len(Key) == (80):
	  
	  # Standard length -for AES- 128 bits
	  # Must be |k| == BLOCK_SIZE
	  
	  BLOCK_SIZE = 16
	  k  = Key[0 : BLOCK_SIZE]
	  	  
	  # Split the rest of "Key" in two keys
	  
	  REST_OF_KEY = (len(Key) - BLOCK_SIZE) / 2
	  k1 = Key[BLOCK_SIZE : BLOCK_SIZE + REST_OF_KEY]
	  k2 = Key[BLOCK_SIZE + REST_OF_KEY : BLOCK_SIZE +(REST_OF_KEY*2)]
	  	  
	else:
	  print "\n[-] Please check your key's length, is "+ str(len(Key)) +" characters!\n"
	  sys.exit()
	  
	MAX_SIZE = BLOCK_SIZE * Num_of_Blocks
	
	# Create an empty array, 
	# For cipher text -messages- storage.
	
	c = []
	
	# Two cipher Objects
	Cipher  = AES.new(k1)
	Cipher2 = AES.new(k2)
	
	CipherText = raw_input('[*] Enter your cipher text: ')
	if len(CipherText) == (MAX_SIZE * 2):
	  
	  # Split the blocks
	  MAX_BLOCK  = ((len(CipherText) / BLOCK_SIZE) / 2)
	  
	  BLOCK_SIZE_2 = BLOCK_SIZE * 2
	  
	  for num in range(0,MAX_BLOCK):
	    n = CipherText[int(BLOCK_SIZE_2 * num) : (BLOCK_SIZE_2 * (num + 1))]
	    c.append(n)
	
	else:
	  MAX_BLOCK  = ((len(CipherText) / BLOCK_SIZE) / 2) + 1
	  BLOCK_SIZE_2 = BLOCK_SIZE * 2
	  
	  for num in range(0,MAX_BLOCK):
	    n = CipherText[int(BLOCK_SIZE_2 * num) : (BLOCK_SIZE_2 * (num + 1))]
	    c.append(n)

	print "\n\033[1;32mThe Original plain text:\033[1;m"
	
	flag = True
	for i in c:
	  unhex = i.decode("hex")
	  if flag == True:
	    DN  = DecryptAES(Cipher2,unhex)
	    D   = DecryptAES(Cipher,DN)
	    M   = xor(D,k)
	    sys.stdout.write(M)
	    flag = False
	    
	  else:
	    K   = DN
	    DN  = DecryptAES(Cipher2,unhex)
	    D   = DecryptAES(Cipher,DN)
	    M1  = xor(D,K)
	    sys.stdout.write(M1)
	    
	print "\n"

      # ------------------+ 
      # Option 3: Quit    |   
      # ------------------+
      
      elif choice == 3:
	print("\nBye..\n")
	sys.exit(1)
	
      else:
	print("\n[-] Wrong Option!\n[-] Check the menu again.")
	
    except ValueError:
      print("\n[-] Wrong Option!\n[-] Check the main menu again.")
      
  except KeyboardInterrupt:
    print("\n[-] Keyboard Interrupt detected.\n[-] To quit, press \"3\".")
    
# EOF
