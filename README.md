# BÁO CÁO BÀI TẬP VỀ NHÀ: AN TOÀN VÀ BẢO MẬT THÔNG TIN
## Tên bài tập: Thuật toán DES, AES, RSA, Các mô hình ứng dụng & Hệ mật mã lai (Hybrid Cryptosystem)

---

- **Môn học:** An toàn và bảo mật thông tin
- **Hình thức thực hiện:** Làm trên máy cá nhân, quản lý phiên bản qua Git và đẩy lên GitHub công khai.
- Sinh viên thực hiện: Chu Trọng Tấn
- MSSV: K235480106063
- Lớp: K59KMT
- **Ngôn ngữ lập trình minh họa:** Python 3 / JavaScript (Web Crypto API)

---

## MỤC LỤC
1. [CÂU 1: THUẬT TOÁN MÃ HOÁ HIỆN ĐẠI DES VÀ AES](#2-câu-1-thuật-toán-mã-hoá-hiện-đại-des-và-aes)
   - 2.1 Tổng quan về mã hóa đối xứng (Symmetric Encryption)
   - 2.2 Thuật toán DES (Data Encryption Standard)
   - 2.3 Thuật toán AES (Advanced Encryption Standard - Rijndael)
   - 2.4 So sánh chi tiết DES và AES
   - 2.5 Cài đặt thuật toán AES bằng ngôn ngữ Python
3. [CÂU 2: THUẬT TOÁN MÃ HOÁ BẤT ĐỐI XỨNG RSA](#3-câu-2-thuật-toán-mã-hoá-bất-đối-xứng-rsa)
   - 3.1 Khái niệm mã hóa bất đối xứng (Asymmetric Encryption)
   - 3.2 Cơ sở toán học của RSA
   - 3.3 Nguyên lý sinh cặp khóa RSA (Public Key & Private Key)
   - 3.4 Quy trình mã hoá và giải mã RSA
   - 3.5 Ví dụ tính toán từng bước bằng số học cụ thể
4. [CÂU 3: CÁC MÔ HÌNH ỨNG DỤNG RSA, SO SÁNH HIỆU NĂNG VÀ HỆ MẬT LAI](#4-câu-3-các-mô-hình-ứng-dụng-rsa-so-sánh-hiệu-năng-và-hệ-mật-lai)
   - 4.1 Các mô hình áp dụng RSA (Xác thực người nhận, Xác thực người gửi, Cả hai)
   - 4.2 So sánh thời gian và hiệu năng giữa RSA và AES
   - 4.3 Ứng dụng kết hợp sức mạnh của RSA và AES: Hệ mật lai (Hybrid Cryptosystem)
5. [KẾT LUẬN VÀ TÀI LIỆU THAM KHẢO](#5-kết-luận-và-tài-liệu-tham-khảo)

---

# 2. CÂU 1: THUẬT TOÁN MÃ HOÁ HIỆN ĐẠI DES VÀ AES

## 2.1 Tổng quan về mã hóa đối xứng (Symmetric Encryption)
Mã hóa đối xứng (Symmetric Key Cryptography) là phương thức mật mã học trong đó **cùng một khóa bí mật (Secret Key K)** được sử dụng cho cả hai quy trình: **Mã hóa (Encryption)** và **Giải mã (Decryption)**.

- **Công thức:** Mã hóa $C = E_K(P)$, Giải mã $P = D_K(C)$
- **Ưu điểm:** Tốc độ cực nhanh, tiêu tốn ít tài nguyên CPU, tối ưu hóa phần cứng qua tập lệnh AES-NI. Thích hợp cho dữ liệu lớn.
- **Nhược điểm lớn nhất:** Vấn đề phân phối khóa bí mật an toàn và số lượng khóa bùng nổ theo công thức $N(N-1)/2$.

---

## 2.2 Thuật toán DES (Data Encryption Standard)

### a. Lịch sử hình thành
- Phát triển bởi IBM vào đầu những năm 1970 (dựa trên Lucifer), được NBS (nay là NIST) phê duyệt năm 1977 làm chuẩn liên bang FIPS PUB 46.

### b. Thông số kỹ thuật cơ bản
- **Kích thước khối (Block size):** 64 bits (8 bytes).
- **Độ dài khóa:** 64 bits danh nghĩa, trong đó 56 bits hiệu dụng (8 bits kiểm tra chẵn lẻ parity).
- **Kiến trúc:** Feistel Network.
- **Số vòng lặp:** 16 rounds.

### c. Quy trình mã hóa chi tiết
1. **Hoán vị ban đầu (Initial Permutation - IP):** Đổi chỗ 64 bits đầu vào, chia thành $L_0$ (32-bit) và $R_0$ (32-bit).
2. **16 Vòng lặp Feistel:**
   - $L_i = R_{i-1}$
   - $R_i = L_{i-1} \oplus f(R_{i-1}, K_i)$
   Trong đó hàm Feistel $f$ gồm 4 bước:
   - **Mở rộng (Expansion E):** 32-bit lên 48-bit.
   - **XOR với khóa con $K_i$ (48-bit).**
   - **Thay thế qua 8 hộp S-box:** 48-bit vào $\rightarrow$ 32-bit ra (cung cấp tính hỗn loạn Confusion).
   - **Hoán vị P-box:** 32-bit hoán vị vị trí (cung cấp tính khuếch tán Diffusion).
3. **Hoán vị nghịch đảo ($IP^{-1}$):** Đổi chỗ $(R_{16} || L_{16})$ rồi qua bảng $IP^{-1}$ cho ra bản mã 64-bit.

### d. Tình trạng an toàn của DES
- Không gian khóa quá bé ($2^{56} \approx 7.2 \times 10^{16}$), ngày nay GPU hoặc máy tính chuyên dụng có thể vét cạn (brute-force) trong vài giờ. DES đã chính thức bị NIST khai tử.

---

## 2.3 Thuật toán AES (Advanced Encryption Standard - Rijndael)

### a. Lịch sử hình thành
- Do hai nhà mật mã học Bỉ là Joan Daemen và Vincent Rijmen thiết kế (Rijndael), chiến thắng cuộc thi NIST năm 2000 và ban hành chuẩn FIPS 197 năm 2001.

### b. Thông số kỹ thuật cơ bản
- **Kích thước khối:** Cố định **128 bits** (16 bytes).
- **Độ dài khóa linh hoạt:**
  - AES-128: Khóa 128-bit $\rightarrow$ **10 vòng**
  - AES-192: Khóa 192-bit $\rightarrow$ **12 vòng**
  - AES-256: Khóa 256-bit $\rightarrow$ **14 vòng**
- **Kiến trúc:** Mạng thay thế - hoán vị **SPN (Substitution-Permutation Network)**. Toàn bộ 16 bytes được xử lý dưới dạng ma trận trạng thái State $4 \times 4$.

### c. Bốn phép biến đổi cốt lõi trong mỗi vòng AES
1. **SubBytes (Thay thế byte):** Tra bảng S-box phi tuyến tính trong trường hữu hạn Galois $GF(2^8)$ kết hợp affine mapping. Cung cấp tính hỗn loạn (**Confusion**).
2. **ShiftRows (Dịch chuyển hàng):** Hàng 0 giữ nguyên, hàng 1 dịch trái 1 byte, hàng 2 dịch 2 byte, hàng 3 dịch 3 byte. Cung cấp tính khuếch tán (**Diffusion**).
3. **MixColumns (Trộn cột):** Nhân ma trận với đa thức cố định trong trường $GF(2^8)$. Tạo hiệu ứng thác lũ (**Avalanche Effect**). *(Lưu ý: Vòng cuối cùng không có bước này)*.
4. **AddRoundKey (Cộng khóa vòng):** Phép XOR bit ma trận State với khóa con vòng $K_i$.

---

## 2.4 So sánh chi tiết DES và AES

| Tiêu chí | DES | AES |
| :--- | :--- | :--- |
| **Năm công bố** | 1977 | 2001 |
| **Cấu trúc** | Mạng Feistel | Mạng SPN (State Matrix 4x4) |
| **Kích thước khối** | 64 bits | **128 bits** |
| **Độ dài khóa** | 56 bits | **128, 192, 256 bits** |
| **Số vòng** | 16 vòng | 10, 12, 14 vòng |
| **Tính an toàn** | Đã bị bẻ khóa (Brute-Force) | **Tuyệt đối an toàn hiện nay** |
| **Tốc độ** | Chậm | Siêu nhanh (hỗ trợ AES-NI) |

---

## 2.5 Cài đặt thuật toán AES bằng ngôn ngữ Python

```python
import os, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class AESCipher:
    def __init__(self, key: bytes = None):
        self.key = key if key else os.urandom(32) # AES-256

    def encrypt(self, plaintext: str) -> dict:
        data_bytes = plaintext.encode('utf-8')
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data_bytes) + padder.finalize()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return {
            "key": base64.b64encode(self.key).decode(),
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

    def decrypt(self, ciphertext_b64: str, iv_b64: str) -> str:
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded) + unpadder.finalize()
        return data.decode('utf-8')
```

---

# 3. CÂU 2: THUẬT TOÁN MÃ HOÁ BẤT ĐỐI XỨNG RSA

## 3.1 Khái niệm mã hóa bất đối xứng
Mỗi thực thể sở hữu một cặp khóa:
- **Public Key (PK):** Công bố rộng rãi để ai cũng có thể mã hóa dữ liệu hoặc xác minh chữ ký.
- **Private Key (SK):** Giữ bí mật tuyệt đối dùng để giải mã hoặc tạo chữ ký số.

## 3.2 Cơ sở toán học của RSA
Độ an toàn của RSA dựa trên **Bài toán phân tích một số nguyên cực lớn thành thừa số nguyên tố (Integer Factorization)**.
- Hàm số Euler $\phi(n) = (p-1)(q-1)$.
- Định lý Euler: $a^{\phi(n)} \equiv 1 \pmod n$.
- Nghịch đảo Modulo $e \cdot d \equiv 1 \pmod{\phi(n)}$ tìm bằng thuật toán Euclid mở rộng.

## 3.3 Nguyên lý sinh cặp khóa RSA
1. Chọn 2 số nguyên tố lớn ngẫu nhiên $p, q$ ($p \neq q$).
2. Tính Modulus: $n = p \times q$.
3. Tính hàm Euler: $\phi(n) = (p-1)(q-1)$.
4. Chọn số mũ công khai $e$ sao cho $1 < e < \phi(n)$ và $\gcd(e, \phi(n)) = 1$ (thường chọn $e = 65537$).
5. Tính số mũ bí mật $d$ là nghịch đảo modulo: $d \equiv e^{-1} \pmod{\phi(n)}$.

- **Public Key:** $(e, n)$
- **Private Key:** $(d, n)$

## 3.4 Quy trình mã hoá và giải mã
- **Mã hóa:** $c = m^e \pmod n$
- **Giải mã:** $m = c^d \pmod n$

## 3.5 Ví dụ tính toán số học từng bước
- Chọn $p = 61, q = 53 \implies n = 61 \times 53 = 3233$.
- $\phi(n) = (61-1)(53-1) = 60 \times 52 = 3120$.
- Chọn $e = 17$ (thỏa mãn $\gcd(17, 3120) = 1$).
- Dùng Euclid mở rộng tính $d$: $17 \times d \equiv 1 \pmod{3120} \implies d = 2753$.
- Khóa công khai: $PK = (17, 3233)$, Khóa bí mật: $SK = (2753, 3233)$.
- **Mã hóa ký tự 'A' ($m = 65$):** $c = 65^{17} \pmod{3233} = 2790$.
- **Giải mã:** $m = 2790^{2753} \pmod{3233} = 65$ (Chính xác ký tự 'A'!).

---

# 4. CÂU 3: CÁC MÔ HÌNH ỨNG DỤNG RSA, SO SÁNH HIỆU NĂNG VÀ HỆ MẬT LAI

## 4.1 Ba mô hình áp dụng RSA
1. **Xác thực người nhận (Bảo mật thông tin - Confidentiality):**
   - Người gửi dùng Public Key người nhận để mã hóa: $C = M^{e_B} \pmod{n_B}$.
   - Chỉ người nhận có Private Key $d_B$ mới giải mã được.
   - *Nhược điểm:* Không xác thực được ai là người gửi.
2. **Xác thực người gửi (Chữ ký số - Digital Signature & Non-repudiation):**
   - Người gửi ký lên hàm băm thông điệp bằng Private Key của mình: $S = [\text{Hash}(M)]^{d_A} \pmod{n_A}$.
   - Người nhận dùng Public Key của người gửi $e_A$ để kiểm tra tính hợp lệ.
   - *Đạt được:* Xác thực danh tính người gửi, đảm bảo tính toàn vẹn dữ liệu, chống chối bỏ.
3. **Kết hợp cả hai (Mã hóa + Ký số):**
   - Alice ký thông điệp bằng $SK_A$, sau đó mã hóa toàn bộ bằng $PK_B$. Bob giải mã bằng $SK_B$ và kiểm tra chữ ký bằng $PK_A$.
   - Đạt trọn vẹn 4 trụ cột an toàn thông tin.

## 4.2 So sánh thời gian và hiệu năng giữa RSA và AES
- **Tốc độ:** AES nhanh hơn RSA từ **100 đến 1,000 lần** nhờ cấu trúc ma trận bit và tối ưu phần cứng.
- **Kích thước khóa:** AES-256 có độ an toàn tương đương RSA-15360!
- **Giới hạn kích thước:** RSA chỉ mã hóa được khối nhỏ hơn độ dài khóa (RSA-2048 tối đa ~190-245 bytes), trong khi AES mã hóa được tập tin vô hạn kích thước theo dòng/khối.

## 4.3 Hệ mật lai (Hybrid Cryptosystem / Digital Envelope)
- **Ý tưởng:** Kết hợp tốc độ siêu việt của AES và khả năng phân phối khóa của RSA.
- **Quy trình gửi (Alice):**
  1. Sinh khóa phiên đối xứng ngẫu nhiên $K_{session}$ (AES-256).
  2. Mã hóa dữ liệu lớn $M$ bằng AES: $C_{data} = \text{AES}(M, K_{session})$.
  3. Mã hóa khóa phiên $K_{session}$ bằng RSA Public Key của Bob: $C_{key} = \text{RSA}_{PK_B}(K_{session})$.
  4. Đóng gói thành Phong bì số $(C_{data}, C_{key}, IV)$ gửi cho Bob.
- **Quy trình nhận (Bob):**
  1. Dùng RSA Private Key $SK_B$ mở $C_{key}$ để lấy lại $K_{session}$.
  2. Dùng $K_{session}$ giải mã $C_{data}$ bằng AES để lấy lại $M$.
- **Ứng dụng thực tế:** Giao thức HTTPS (TLS/SSL), PGP/GPG trong mã hóa email, Signal, WhatsApp.