from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from flask_cors import CORS
import os
import json
import datetime
import base64

from modules.crypto_utils import (
    ecdsa_keygen, rsa_keygen, mldsa_keygen, save_pem, load_pem, load_pem_pub, load_mldsa_priv,
    public_key_fingerprint, ecdsa_sign, ecdsa_verify, rsa_encrypt, rsa_decrypt,
    aes_encrypt, aes_decrypt
)
from dilithium_py.ml_dsa import ML_DSA_44

app = Flask(__name__)
CORS(app)

KEY_DIR = "user_keys"
TRANSACTION_DIR = "transactions"
if not os.path.exists(KEY_DIR): os.makedirs(KEY_DIR)
if not os.path.exists(TRANSACTION_DIR): os.makedirs(TRANSACTION_DIR)

# --- API sinh/lưu key ---
@app.route("/api/generate_key", methods=["POST"])
def api_generate_key():
    data = request.get_json()
    username = data.get("username")
    key_type = data.get("key_type")
    passphrase = data.get("passphrase", "")
    passphrase_bytes = passphrase.encode()

    try:
        if key_type == "ECDSA":
            pub_bytes, priv_bytes = ecdsa_keygen(passphrase_bytes)
            pub_file = f"{KEY_DIR}/{username}.ecdsa.pub.pem"
            priv_file = f"{KEY_DIR}/{username}.ecdsa.priv.pem"
        elif key_type == "RSA":
            pub_bytes, priv_bytes = rsa_keygen(passphrase_bytes)
            pub_file = f"{KEY_DIR}/{username}.rsa.pub.pem"
            priv_file = f"{KEY_DIR}/{username}.rsa.priv.pem"
        elif key_type == "ML-DSA":
            pub_bytes, priv_bytes = mldsa_keygen(passphrase_bytes)
            pub_file = f"{KEY_DIR}/{username}.mldsa.pub"
            priv_file = f"{KEY_DIR}/{username}.mldsa.priv"
        else:
            return jsonify({"success": False, "message": "Loại khóa không hợp lệ"}), 400

        save_pem(pub_file, pub_bytes)
        save_pem(priv_file, priv_bytes)

        return jsonify({
            "success": True,
            "message": f"Đã sinh và lưu {key_type} cho {username}",
            "public_key": base64.b64encode(pub_bytes).decode(),
            "fingerprint": public_key_fingerprint(pub_bytes),
            "pub_file": pub_file,
            "priv_file": priv_file
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Lỗi: {str(e)}"}), 500

# --- API tạo giao dịch ---
@app.route("/api/create_transaction", methods=["POST"])
def api_create_transaction():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "Không nhận được dữ liệu"}), 400
    order = {
        "order_id": data.get("order_id"),
        "buyer": data.get("buyer"),
        "seller": data.get("seller"),
        "amount": data.get("amount"),
        "currency": data.get("currency"),
        "items": [item.strip() for item in data.get("items", "").split(",")],
        "timestamp": datetime.datetime.now().isoformat()
    }
    filename = f'{TRANSACTION_DIR}/order_{order["order_id"]}_{int(datetime.datetime.now().timestamp())}.json'
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(order, f, ensure_ascii=False, indent=2)
        return jsonify({
            "success": True,
            "message": f"Đã lưu giao dịch vào {filename}",
            "filename": filename,
            "order": order
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Lỗi lưu file: {e}"}), 500

# --- API ký số & mã hóa giao dịch ---
@app.route("/api/sign_encrypt", methods=["POST"])
def api_sign_encrypt():
    order_file = request.files['order_file']
    signer_name = request.form.get("signer_name")
    ecdsa_passphrase = request.form.get("ecdsa_passphrase")
    mldsa_passphrase = request.form.get("mldsa_passphrase") 
    receiver_name = request.form.get("receiver_name")

    order = json.load(order_file)
    # Load khóa riêng ECDSA (người mua)
    ecdsa_priv_obj = load_pem(f"{KEY_DIR}/{signer_name}.ecdsa.priv.pem", passphrase=ecdsa_passphrase.encode())
    if not hasattr(ecdsa_priv_obj, 'sign'):
        return jsonify({"success": False, "message": "Không load được khóa ECDSA"}), 400
    ecdsa_pub_pem = ecdsa_priv_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # ML-DSA
    mldsa_priv = load_mldsa_priv(f"{KEY_DIR}/{signer_name}.mldsa.priv", mldsa_passphrase.encode())
    mldsa_pub = load_pem_pub(f"{KEY_DIR}/{signer_name}.mldsa.pub")
    data_bytes = json.dumps(order, ensure_ascii=False).encode()
    ecdsa_sig = ecdsa_sign(ecdsa_priv_obj, data_bytes)
    mldsa_sig = ML_DSA_44.sign(mldsa_priv, data_bytes)
    package = {
        "order": order,
        "signatures": [
            {
                "algo": "ECDSA",
                "signer_name": signer_name,
                "signature": base64.b64encode(ecdsa_sig).decode(),
                "public_key": base64.b64encode(ecdsa_pub_pem).decode(),
                "fingerprint": public_key_fingerprint(ecdsa_pub_pem),
            },
            {
                "algo": "ML-DSA",
                "signer_name": signer_name,
                "signature": base64.b64encode(mldsa_sig).decode(),
                "public_key": base64.b64encode(mldsa_pub).decode(),
                "fingerprint": public_key_fingerprint(mldsa_pub),
            }
        ]
    }
    json_bytes = json.dumps(package, ensure_ascii=False, indent=2).encode()
    # AES + RSA (bên người bán)
    rsa_rec_name = order["seller"]
    rsa_pub = load_pem_pub(f"{KEY_DIR}/{rsa_rec_name}.rsa.pub.pem")
    if not rsa_pub:
        return jsonify({"success": False, "message": "Không tìm thấy khóa công khai RSA của người bán!"}), 400
    aes_key = os.urandom(32)
    iv, aes_ciphertext = aes_encrypt(aes_key, json_bytes)
    rsa_key_cipher = rsa_encrypt(rsa_pub, aes_key)
    data_to_send = {
        "rsa_key_cipher": base64.b64encode(rsa_key_cipher).decode(),
        "iv": base64.b64encode(iv).decode(),
        "aes_ciphertext": base64.b64encode(aes_ciphertext).decode(),
    }
    output_file = f'{TRANSACTION_DIR}/transaction_{order["order_id"]}_{int(datetime.datetime.now().timestamp())}.encrypted'
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data_to_send, f, ensure_ascii=False, indent=2)
    return jsonify({
        "success": True,
        "message": f"Đã tạo file gửi giao dịch: {output_file}",
        "filename": output_file
    })

# --- API giải mã & xác thực giao dịch ---
@app.route("/api/decrypt_verify", methods=["POST"])
def api_decrypt_verify():
    encrypted_file = request.files['encrypted_file']
    rsa_rec_name = request.form.get("receiver_name")
    rsa_passphrase = request.form.get("rsa_passphrase")
    data_to_send = json.load(encrypted_file)
    rsa_priv_obj = load_pem(f"{KEY_DIR}/{rsa_rec_name}.rsa.priv.pem", passphrase=rsa_passphrase.encode())
    if not hasattr(rsa_priv_obj, 'decrypt'):
        return jsonify({"success": False, "message": "Không load được khóa RSA!"}), 400
    try:
        rsa_key_cipher = base64.b64decode(data_to_send["rsa_key_cipher"])
        iv = base64.b64decode(data_to_send["iv"])
        aes_ciphertext = base64.b64decode(data_to_send["aes_ciphertext"])
        aes_key = rsa_decrypt(rsa_priv_obj, rsa_key_cipher)
        json_bytes = aes_decrypt(aes_key, iv, aes_ciphertext)
        package = json.loads(json_bytes)
    except Exception as e:
        return jsonify({"success": False, "message": f"LỖI giải mã: {e}"}), 400

    # Xác minh chữ ký
    data_bytes = json.dumps(package["order"], ensure_ascii=False).encode()
    verify_results = []
    for sig in package["signatures"]:
        algo = sig["algo"]
        signer = sig.get("signer_name", "??")
        pubkey_b64 = sig["public_key"]
        fingerprint = sig.get("fingerprint", "")
        signature_b64 = sig["signature"]
        valid = False
        if algo == "ECDSA":
            try:
                valid = ecdsa_verify(
                    base64.b64decode(pubkey_b64), data_bytes, base64.b64decode(signature_b64))
            except Exception as e:
                valid = False
        elif algo == "ML-DSA":
            try:
                valid = ML_DSA_44.verify(
                    base64.b64decode(pubkey_b64), data_bytes, base64.b64decode(signature_b64))
            except Exception as e:
                valid = False
        verify_results.append({
            "algo": algo,
            "signer": signer,
            "fingerprint": fingerprint,
            "valid": valid
        })
    app.logger.info(package["order"])
    app.logger.info(verify_results)
    return jsonify({
        "success": True,
        "order": package["order"],
        "verify_results": verify_results
    })

# --- API lấy log hệ thống ---
@app.route("/api/get_log", methods=["GET"])
def api_get_log():
    log_file = "action.log"
    if not os.path.exists(log_file):
        return jsonify({"log": "Không có log."})
    with open(log_file, encoding="utf-8") as f:
        return jsonify({"log": f.read()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5560, debug=True)
