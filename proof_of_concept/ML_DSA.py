from dilithium_py.ml_dsa import ML_DSA_44
from docx import Document
import os # Dùng để kiểm tra file tồn tại và quản lý file
import json
import base64
# --- Hằng số cho định dạng PEM (đơn giản hóa cho PoC) ---
PUBLIC_KEY_PEM_HEADER = b"-----BEGIN PUBLIC KEY-----\n"
PUBLIC_KEY_PEM_FOOTER = b"-----END PUBLIC KEY-----\n"
PRIVATE_KEY_PEM_HEADER = b"-----BEGIN PRIVATE KEY-----\n"
PRIVATE_KEY_PEM_FOOTER = b"-----END PRIVATE KEY-----\n"

# Hàm đã có để đọc văn bản từ file .docx (không dùng cho ký số trực tiếp)
def read_docx_content(file_path):
    """Đọc toàn bộ văn bản từ một tệp .docx."""
    try:
        document = Document(file_path)
        full_text = []
        for para in document.paragraphs:
            full_text.append(para.text)
        return "\n".join(full_text)
    except Exception as e:
        print(f"Lỗi khi đọc nội dung văn bản DOCX: {e}")
        return None

# Hàm mới để lưu khóa dạng PEM
def save_keys_to_pem(public_key_bytes, secret_key_bytes, pub_filename="public.pem", priv_filename="private.pem"):
    """Lưu khóa công khai và bí mật vào các file .pem."""
    try:
        # Lưu Public Key
        with open(pub_filename, 'wb') as f_pub:
            f_pub.write(PUBLIC_KEY_PEM_HEADER)
            # Mã hóa base64 khóa bytes để an toàn trong PEM (Python 3.8+ dùng base64.b64encode)
            import base64
            f_pub.write(base64.b64encode(public_key_bytes))
            f_pub.write(b'\n') # Thêm xuống dòng sau base64 data
            f_pub.write(PUBLIC_KEY_PEM_FOOTER)
        print(f"  > Khóa công khai đã được lưu vào '{pub_filename}'")

        # Lưu Private Key
        with open(priv_filename, 'wb') as f_priv:
            f_priv.write(PRIVATE_KEY_PEM_HEADER)
            f_priv.write(base64.b64encode(secret_key_bytes))
            f_priv.write(b'\n') # Thêm xuống dòng sau base64 data
            f_priv.write(PRIVATE_KEY_PEM_FOOTER)
        print(f"  > Khóa bí mật đã được lưu vào '{priv_filename}'")
        return True
    except Exception as e:
        print(f"Lỗi khi lưu khóa ra file PEM: {e}")
        return False

# Hàm mới để tải khóa dạng PEM
def load_keys_from_pem(pub_filename="public.pem", priv_filename="private.pem"):
    """Tải khóa công khai và bí mật từ các file .pem."""
    public_key_bytes = None
    secret_key_bytes = None
    import base64

    try:
        # Tải Public Key
        if os.path.exists(pub_filename):
            with open(pub_filename, 'rb') as f_pub:
                content = f_pub.read().strip() # Đọc và bỏ khoảng trắng/newline thừa
                # Loại bỏ header và footer PEM
                if content.startswith(PUBLIC_KEY_PEM_HEADER) and content.endswith(PUBLIC_KEY_PEM_FOOTER):
                    encoded_key = content[len(PUBLIC_KEY_PEM_HEADER):-len(PUBLIC_KEY_PEM_FOOTER)].strip()
                    public_key_bytes = base64.b64decode(encoded_key)
                else:
                    print(f"Cảnh báo: Định dạng file '{pub_filename}' không chuẩn PEM.")
        else:
            print(f"Không tìm thấy file '{pub_filename}'.")

        # Tải Private Key
        if os.path.exists(priv_filename):
            with open(priv_filename, 'rb') as f_priv:
                content = f_priv.read().strip()
                if content.startswith(PRIVATE_KEY_PEM_HEADER) and content.endswith(PRIVATE_KEY_PEM_FOOTER):
                    encoded_key = content[len(PRIVATE_KEY_PEM_HEADER):-len(PRIVATE_KEY_PEM_FOOTER)].strip()
                    secret_key_bytes = base64.b64decode(encoded_key)
                else:
                    print(f"Cảnh báo: Định dạng file '{priv_filename}' không chuẩn PEM.")
        else:
            print(f"Không tìm thấy file '{priv_filename}'.")

    except Exception as e:
        print(f"Lỗi khi tải khóa từ file PEM: {e}")

    return public_key_bytes, secret_key_bytes

GLOBAL_PUBLIC_KEY_BYTES = None
GLOBAL_SECRET_KEY_BYTES = None
GLOBAL_SIGNER_NAME = None # Tên của người ký được liên kết với cặp khóa này

# Hàm chính
def main():
    global GLOBAL_PUBLIC_KEY_BYTES, GLOBAL_SECRET_KEY_BYTES, GLOBAL_SIGNER_NAME
    signature_output_file = "signature.sigdata" # Đổi tên file để chứa cả dữ liệu chữ ký và metadata

    while True:
        print("\n================ ML-DSA Signature with Signer Info PoC ================")
        print("1. Tạo khóa công khai và khóa bí mật (và lưu ra file .pem)")
        print("2. Tải khóa từ file .pem (nếu đã có)")
        print("3. Ký một file DOCX/PDF/JPG (kèm thông tin người ký)")
        print("4. Kiểm tra chữ ký và hiển thị thông tin người ký")
        print("5. Thoát")

        choice = input("Vui lòng chọn chức năng (1-5): ")

        if choice == '1':
            print("\n--- Tạo khóa công khai và khóa bí mật ---")
            signer_name = input("Nhập tên định danh của người ký (ví dụ: 'Nguyen Van A'): ")
            if not signer_name:
                print("Tên định danh không được để trống.")
                continue

            pub_key_bytes, sec_key_bytes = ML_DSA_44.keygen()
            GLOBAL_PUBLIC_KEY_BYTES = pub_key_bytes
            GLOBAL_SECRET_KEY_BYTES = sec_key_bytes
            GLOBAL_SIGNER_NAME = signer_name

            print("  > Khóa đã được tạo thành công.")
            if save_keys_to_pem(GLOBAL_PUBLIC_KEY_BYTES, GLOBAL_SECRET_KEY_BYTES, 
                                pub_filename=f"{signer_name}.pub.pem", 
                                priv_filename=f"{signer_name}.priv.pem"):
                print(f"  > Khóa đã được lưu vào '{signer_name}.pub.pem' và '{signer_name}.priv.pem'.")
            else:
                print("  > Lưu khóa thất bại.")

        elif choice == '2':
            signer_name_to_load = input("Nhập tên định danh của người ký để tải khóa (ví dụ: 'Nguyen Van A'): ")
            if not signer_name_to_load:
                print("Tên định danh không được để trống.")
                continue
            
            print(f"\n--- Tải khóa cho '{signer_name_to_load}' từ file .pem ---")
            loaded_pub_key, loaded_priv_key = load_keys_from_pem(
                pub_filename=f"{signer_name_to_load}.pub.pem",
                priv_filename=f"{signer_name_to_load}.priv.pem"
            )
            
            if loaded_pub_key and loaded_priv_key:
                GLOBAL_PUBLIC_KEY_BYTES = loaded_pub_key
                GLOBAL_SECRET_KEY_BYTES = loaded_priv_key
                GLOBAL_SIGNER_NAME = signer_name_to_load
                print(f"  > Đã tải khóa cho '{GLOBAL_SIGNER_NAME}' thành công.")
            else:
                print("  > Không thể tải khóa. Vui lòng kiểm tra tên định danh và sự tồn tại của file.")

        elif choice == '3':
            if GLOBAL_PUBLIC_KEY_BYTES is None or GLOBAL_SECRET_KEY_BYTES is None or GLOBAL_SIGNER_NAME is None:
                print("\n  Bạn chưa có khóa hoặc tên người ký! Vui lòng chọn 1 hoặc 2 để tạo/tải khóa trước.")
                continue

            file_to_sign_name = input(f"Nhập tên file DOCX/PDF/JPG bạn muốn ký bằng '{GLOBAL_SIGNER_NAME}': ")
            if not os.path.exists(file_to_sign_name):
                print(f"  LỖI: Không tìm thấy file '{file_to_sign_name}'.")
                continue

            print(f"\n--- Đang ký file '{file_to_sign_name}' bằng '{GLOBAL_SIGNER_NAME}' ---")
            try:
                with open(file_to_sign_name, 'rb') as f:
                    document_content_bytes = f.read()
                
                # Tính toán hash của tài liệu
                import hashlib
                document_hash = hashlib.sha256(document_content_bytes).digest()

                # Tạo cấu trúc dữ liệu để ký (bao gồm Public Key và tên người ký)
                # Dùng dict để dễ dàng chuyển đổi sang JSON
                signature_metadata = {
                    "signer_name": GLOBAL_SIGNER_NAME,
                    "signer_public_key": base64.b64encode(GLOBAL_PUBLIC_KEY_BYTES).decode('utf-8'), # Mã hóa Base64 cho JSON
                    "document_hash": base64.b64encode(document_hash).decode('utf-8'), # Hash tài liệu
                    "timestamp": os.path.getmtime(file_to_sign_name) # Lấy thời gian sửa đổi gần nhất của file
                }
                # Chuyển đổi metadata thành chuỗi JSON và mã hóa thành bytes để ký
                metadata_bytes = json.dumps(signature_metadata, sort_keys=True).encode('utf-8')
                
                # Ký lên metadata (bao gồm hash tài liệu)
                actual_signature = ML_DSA_44.sign(GLOBAL_SECRET_KEY_BYTES, metadata_bytes)

                # Kết hợp chữ ký và metadata thành một đối tượng duy nhất
                final_signed_data = {
                    "ml_dsa_signature": base64.b64encode(actual_signature).decode('utf-8'),
                    "signed_metadata": base64.b64encode(metadata_bytes).decode('utf-8')
                }

                # Lưu toàn bộ dữ liệu đã ký (signature + metadata) vào file
                with open(signature_output_file, 'w') as f_sig:
                    json.dump(final_signed_data, f_sig, indent=4) # Lưu dưới dạng JSON để dễ đọc
                
                print(f"  > Ký thành công. Dữ liệu chữ ký đã được lưu vào '{signature_output_file}'.")
            except Exception as e:
                print(f"  LỖI: Ký file thất bại: {e}")

        elif choice == '4':
            file_to_verify_name = input("Nhập tên file gốc bạn muốn kiểm tra (ví dụ: document.docx): ")
            if not os.path.exists(file_to_verify_name):
                print(f"  LỖI: Không tìm thấy file gốc '{file_to_verify_name}'.")
                continue
            if not os.path.exists(signature_output_file):
                print(f"  LỖI: Không tìm thấy file chữ ký '{signature_output_file}'. Bạn đã ký file chưa?")
                continue

            print(f"\n--- Đang kiểm tra chữ ký cho file '{file_to_verify_name}' ---")
            try:
                # 1. Đọc nội dung file gốc và tính toán hash của nó
                with open(file_to_verify_name, 'rb') as f:
                    document_content_for_verification = f.read()
                current_document_hash = hashlib.sha256(document_content_for_verification).digest()
                print(f"  > Đã đọc nội dung file gốc và tính hash.")

                # 2. Đọc dữ liệu chữ ký từ file
                with open(signature_output_file, 'r') as f_sig:
                    signed_data_json = json.load(f_sig)
                
                actual_signature_b64 = signed_data_json.get("ml_dsa_signature")
                signed_metadata_b64 = signed_data_json.get("signed_metadata")

                if not actual_signature_b64 or not signed_metadata_b64:
                    print("  LỖI: File chữ ký không đúng định dạng.")
                    continue

                actual_signature = base64.b64decode(actual_signature_b64)
                metadata_bytes = base64.b64decode(signed_metadata_b64)
                
                # 3. Giải mã metadata và lấy public key từ đó
                signature_metadata = json.loads(metadata_bytes.decode('utf-8'))
                
                signer_name = signature_metadata.get("signer_name", "Không rõ")
                signer_public_key_b64 = signature_metadata.get("signer_public_key")
                signed_document_hash_b64 = signature_metadata.get("document_hash")
                signed_timestamp = signature_metadata.get("timestamp", "Không rõ")

                if not signer_public_key_b64 or not signed_document_hash_b64:
                    print("  LỖI: Dữ liệu metadata trong chữ ký bị thiếu thông tin quan trọng.")
                    continue

                signer_public_key_bytes = base64.b64decode(signer_public_key_b64)
                signed_document_hash = base64.b64decode(signed_document_hash_b64)

                print(f"\n  --- Thông tin người ký từ chữ ký ---")
                print(f"  Người ký: {signer_name}")
                print(f"  Public Key của người ký (một phần): {signer_public_key_b64[:60]}...")
                print(f"  Hash tài liệu đã ký: {signed_document_hash_b64}")
                # print(f"  Thời gian ký (timestamp file): {signed_timestamp}") # Cẩn thận với timestamp, nó có thể dễ bị giả mạo nếu không có nguồn tin cậy
                print(f"  ------------------------------------")


                # 4. Xác minh chữ ký ML-DSA
                is_signature_valid = ML_DSA_44.verify(signer_public_key_bytes, metadata_bytes, actual_signature)

                if is_signature_valid:
                    print("  > Chữ ký ML-DSA HỢP LỆ (metadata không bị chỉnh sửa).")
                    # 5. So sánh hash của tài liệu hiện tại với hash đã ký
                    if current_document_hash == signed_document_hash:
                        print("  > Hash của tài liệu hiện tại KHỚP với hash trong chữ ký.")
                        print("\n  KẾT QUẢ CUỐI CÙNG: Chữ ký HỢP LỆ và tài liệu KHÔNG BỊ CHỈNH SỬA!")
                    else:
                        print("  > Hash của tài liệu hiện tại KHÔNG KHỚP với hash trong chữ ký.")
                        print("\n  KẾT QUẢ CUỐI CÙNG: Chữ ký HỢP LỆ, nhưng tài liệu CÓ THỂ ĐÃ BỊ CHỈNH SỬA SAU KHI KÝ!")
                else:
                    print("\n  KẾT QUẢ CUỐI CÙNG: Chữ ký ML-DSA KHÔNG HỢP LỆ. Dữ liệu chữ ký có thể đã bị giả mạo.")

            except json.JSONDecodeError:
                print("  LỖI: File chữ ký không phải là JSON hợp lệ.")
            except Exception as e:
                print(f"  LỖI: Quá trình kiểm tra chữ ký gặp lỗi: {e}")

        elif choice == '5':
            print("Thoát chương trình. Tạm biệt!")
            break
        else:
            print("Lựa chọn không hợp lệ. Vui lòng nhập số từ 1 đến 5.")

# Điều này đảm bảo rằng hàm main() chỉ chạy khi script được thực thi trực tiếp
if __name__ == "__main__":
    main()