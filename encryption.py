import streamlit as st
import hashlib
from cryptography.fernet import Fernet, InvalidToken

# Persistent encryption key (DO NOT change between sessions)
KEY = b'kNg4EslMvqkReR8gvGMo3rK1-HStG4oajzPrm_lgTCQ='  # Replace with your generated key
cipher = Fernet(KEY)

# Initialize session state variables
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "login_required" not in st.session_state:
    st.session_state.login_required = False

# Hash passkey function (SHA-256)
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data (using Fernet)
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data (using Fernet)
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    for entry in st.session_state.stored_data.values():
        # Validate entry structure and check match
        if isinstance(entry, dict) and \
           "encrypted_text" in entry and \
           "passkey" in entry and \
           entry["encrypted_text"] == encrypted_text and \
           entry["passkey"] == hashed_passkey:
            try:
                st.session_state.failed_attempts = 0
                return cipher.decrypt(encrypted_text.encode()).decode()
            except InvalidToken:
                st.error("⚠️ Corrupted or invalid encrypted text.")
                return None

    # Increment failed attempts if incorrect passkey is used
    st.session_state.failed_attempts += 1
    return None

# --- UI Layout ---
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📁 Navigation", menu)

# --- Home Page ---
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.markdown("""
    Use this app to **securely store and retrieve data** using a secret passkey.

    - Encrypted with **Fernet** (symmetric encryption)
    - Passkey is **hashed with SHA-256**
    - 3 wrong attempts triggers reauthorization
    """)

# --- Store Data ---
elif choice == "Store Data":
    st.subheader("📦 Store New Data")
    user_data = st.text_area("Enter data to store:")
    passkey = st.text_input("Enter a passkey", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_passkey = hash_passkey(passkey)

            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }

            st.success("✅ Data encrypted and stored!")
            st.code(encrypted_text, language="text")
        else:
            st.error("❗ Both fields are required!")

# --- Retrieve Data ---
elif choice == "Retrieve Data":
    if st.session_state.login_required:
        st.warning("🔐 Too many failed attempts. Please log in again.")
        st.session_state.failed_attempts = 0
        st.session_state.login_required = False
        st.rerun()

    st.subheader("🔍 Retrieve Stored Data")
    encrypted_text = st.text_area("Enter the encrypted data:")
    passkey = st.text_input("Enter your passkey", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success("✅ Decrypted Data:")
                st.code(result)
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey. Attempts left: {remaining}")
                if remaining == 0:
                    st.warning("🔐 Too many failed attempts. Please log in again.")
                    st.session_state.failed_attempts = 0
                    st.session_state.login_required = True
        else:
            st.error("❗ Both fields are required!")

# --- Login Page ---
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    show_password = st.checkbox("Show Admin Password")

    if show_password:
        st.info("Admin Password: admin123")

    login_pass = st.text_input("Enter admin password", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.login_required = False
            st.success("✅ Reauthorized. You may now access Retrieve Data.")
        else:
            st.error("❌ Incorrect password!")
