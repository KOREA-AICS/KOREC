import tkinter as tk
from tkinter import filedialog, messagebox
import os
import hashlib
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# --- 암호화 관련 상수 정의 ---
# FIPS-197, Appendix B. AES-128 Test Vector Key
NIST_KEY = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
IV_SIZE = 16    # IV 크기 (AES 블록 크기와 동일)
KEY_SIZE = 16   # 키 크기 (AES-128)

# --- 암호화 함수 ---
def encrypt_file(file_path):
    """지정된 파일을 하드코딩된 NIST 키와 AES-128-CBC 모드로 암호화합니다."""
    try:
        # 1. 원본 파일 데이터 및 파일명 읽기
        with open(file_path, 'rb') as f:
            image_data = f.read()
        
        original_filename = os.path.basename(file_path).encode('utf-8')

        # 2. 고정된 키 사용
        key = NIST_KEY

        # 3. 초기화 벡터(IV) 생성 및 암호화기 설정
        #iv = os.urandom(IV_SIZE)
        #fixed iv for practice
        iv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        
        # 4. 데이터 패딩 (PKCS7) - 이미지 데이터와 파일명 모두에 적용
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_image_data = padder.update(image_data) + padder.finalize()
        
        padder_fname = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_filename = padder_fname.update(original_filename) + padder_fname.finalize()

        # 5. 파일명과 이미지 데이터 암호화
        encryptor = cipher.encryptor()
        encrypted_image_data = encryptor.update(padded_image_data) + encryptor.finalize()
        
        # 새 암호화기 인스턴스 생성 (동일 IV 사용)
        encryptor_fname = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
        encrypted_filename = encryptor_fname.update(padded_filename) + encryptor_fname.finalize()
        
        # 6. 암호화된 출력 파일명 생성 (내용 기반 해시)
        output_hash = hashlib.sha256(iv + encrypted_image_data).hexdigest()
        output_filename = f"{output_hash}.enc"
        output_path = os.path.join(os.path.dirname(file_path), output_filename)

        # 7. 암호화된 파일 작성 (포맷: iv + 암호화된 파일명 길이 + 암호화된 파일명 + 암호화된 데이터)
        with open(output_path, 'wb') as f:
            f.write(iv)
            f.write(struct.pack('>H', len(encrypted_filename))) # 파일명 길이를 2바이트 정수로 저장
            f.write(encrypted_filename)
            f.write(encrypted_image_data)
            
        return f"성공: '{os.path.basename(file_path)}'이(가) '{output_filename}'(으)로 암호화되었습니다."

    except Exception as e:
        return f"암호화 오류: {e}"

# --- 복호화 함수 ---
def decrypt_file(file_path):
    """암호화된 파일을 복호화합니다."""
    try:
        # 1. 암호화된 파일 데이터 읽기
        with open(file_path, 'rb') as f:
            iv = f.read(IV_SIZE)
            encrypted_filename_len = struct.unpack('>H', f.read(2))[0]
            encrypted_filename = f.read(encrypted_filename_len)
            encrypted_image_data = f.read()

        # 2. 고정된 키 사용
        key = NIST_KEY

        # 3. 복호화기 설정
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        
        # 4. 파일명 복호화 및 언패딩
        decryptor_fname = cipher.decryptor()
        padded_filename = decryptor_fname.update(encrypted_filename) + decryptor_fname.finalize()
        unpadder_fname = padding.PKCS7(algorithms.AES.block_size).unpadder()
        original_filename = (unpadder_fname.update(padded_filename) + unpadder_fname.finalize()).decode('utf-8')

        # 5. 이미지 데이터 복호화 및 언패딩
        # 새 복호화기 인스턴스 생성 (동일 IV 사용)
        decryptor_img = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
        padded_data = decryptor_img.update(encrypted_image_data) + decryptor_img.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        image_data = unpadder.update(padded_data) + unpadder.finalize()
        
        # 6. 원본 파일명으로 복원
        output_path = os.path.join(os.path.dirname(file_path), original_filename)
        with open(output_path, 'wb') as f:
            f.write(image_data)
        
        return f"성공: '{os.path.basename(file_path)}'이(가) '{original_filename}'(으)로 복호화되었습니다."

    except Exception as e:
        return f"복호화 오류: 파일이 손상되었거나 암호화에 사용된 키와 다릅니다. ({e})"


# --- GUI 애플리케이션 클래스 ---
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("이미지 암호화/복호화 도구 (AES-128-CBC, 고정 키)")
        self.root.geometry("550x280")
        self.root.resizable(False, False)

        self.file_path = tk.StringVar()

        # UI 요소 생성
        main_frame = tk.Frame(root, padx=20, pady=20)
        main_frame.pack(fill="both", expand=True)

        # 파일 선택
        file_frame = tk.Frame(main_frame)
        file_frame.pack(fill="x", pady=10)
        
        file_label = tk.Label(file_frame, text="파일 경로:", anchor="w")
        file_label.pack(side="left")
        
        file_entry = tk.Entry(file_frame, textvariable=self.file_path, state="readonly", width=40)
        file_entry.pack(side="left", fill="x", expand=True, padx=5)

        browse_button = tk.Button(file_frame, text="파일 선택", command=self.browse_file)
        browse_button.pack(side="left")

        # 동작 버튼
        button_frame = tk.Frame(main_frame)
        button_frame.pack(pady=20)

        encrypt_button = tk.Button(button_frame, text="암호화", command=self.encrypt, width=15, height=2)
        encrypt_button.pack(side="left", padx=10)

        decrypt_button = tk.Button(button_frame, text="복호화", command=self.decrypt, width=15, height=2)
        decrypt_button.pack(side="left", padx=10)
        
        # 상태 표시줄
        self.status_label = tk.Label(main_frame, text="파일을 선택 후 버튼을 누르세요.", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, ipady=5)

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)
            self.status_label.config(text=f"선택된 파일: {os.path.basename(path)}")

    def execute_task(self, task_function):
        file = self.file_path.get()

        if not file:
            messagebox.showerror("오류", "파일을 선택해주세요.")
            return

        self.status_label.config(text="작업 중...")
        self.root.update_idletasks() # UI 업데이트 강제

        result = task_function(file)
        self.status_label.config(text=result)
        messagebox.showinfo("완료", result)

    def encrypt(self):
        self.execute_task(encrypt_file)

    def decrypt(self):
        self.execute_task(decrypt_file)

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()

