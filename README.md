# Cryptography  
## picoCtf
substitution0 https://play.picoctf.org/practice/challenge/307?page=1&search=substitu
Cách giải: 
- Đây là mật mã thay thế.
- 26 kí tự đầu tiên sẽ là khóa.


- from string import *
- with open("message.txt") as file:
    content = file.read()

- upper_key = "QWITJSYHXCNDFERMUKGOPVALBZ"
- lower_key = upper_key.lower()


- for character in content:
-     if character.isupper():
-         print(ascii_uppercase[upper_key.index(character)],end = "")
-     elif character.islower():
-         print(ascii_lowercase[lower_key.index(character)],end = "")
-     else: 
-         print(character,end = "")