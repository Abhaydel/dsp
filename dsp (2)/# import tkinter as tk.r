# import tkinter as tk
# from tkinter import scrolledtext, messagebox
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives import hashes

# # -----------------------------
# # Generate RSA Key Pair
# # -----------------------------
# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048
# )
# public_key = private_key.public_key()

# signature = None

# def sign_message():
#     global signature
#     msg = message_input.get("1.0", tk.END).strip().encode()
#     if not msg:
#         messagebox.showwarning("Warning", "Message cannot be empty")
#         return
    
#     signature = private_key.sign(
#         msg,
#         padding.PSS(
#             mgf=padding.MGF1(hashes.SHA256()),
#             salt_length=padding.PSS.MAX_LENGTH
#         ),
#         hashes.SHA256()
#     )
#     signature_output.delete("1.0", tk.END)
#     signature_output.insert(tk.END, signature.hex())
#     messagebox.showinfo("Success", "Digital Signature Generated ✅")

# def verify_signature():
#     global signature
#     msg = message_input.get("1.0", tk.END).strip().encode()
#     if not signature:
#         messagebox.showwarning("Warning", "Generate a signature first!")
#         return
    
#     try:
#         public_key.verify(
#             signature,
#             msg,
#             padding.PSS(
#                 mgf=padding.MGF1(hashes.SHA256()),
#                 salt_length=padding.PSS.MAX_LENGTH
#             ),
#             hashes.SHA256()
#         )
#         messagebox.showinfo("Success", "Signature Verified ✅")
#     except Exception:
#         messagebox.showerror("Error", "Verification Failed ❌")

# # -----------------------------
# # Tkinter UI Setup
# # -----------------------------
# root = tk.Tk()
# root.title("RSA Digital Signature Demo")
# root.geometry("600x400")

# # Message input
# tk.Label(root, text="Enter Message:", font=("Arial", 12, "bold")).pack()
# message_input = scrolledtext.ScrolledText(root, height=5, width=70)
# message_input.pack(pady=5)

# # Buttons
# btn_frame = tk.Frame(root)
# btn_frame.pack(pady=10)
# tk.Button(btn_frame, text="Sign Message", command=sign_message, bg="lightblue", width=20).grid(row=0, column=0, padx=10)
# tk.Button(btn_frame, text="Verify Signature", command=verify_signature, bg="lightgreen", width=20).grid(row=0, column=1, padx=10)

# # Signature Output
# tk.Label(root, text="Generated Signature (Hex):", font=("Arial", 12, "bold")).pack()
# signature_output = scrolledtext.ScrolledText(root, height=5, width=70)
# signature_output.pack(pady=5)

# root.mainloop()
import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# -----------------------------
# Generate RSA Keys
# -----------------------------
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# -----------------------------
# GUI Functions
# -----------------------------
def generate_signature():
    message = input_text.get("1.0", tk.END).strip().encode()
    if not message:
        messagebox.showwarning("Warning", "Enter a message to sign!")
        return

    global signature
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    output_text.config(state="normal")
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, f"Signature (hex):\n{signature.hex()}")
    output_text.config(state="disabled")
    messagebox.showinfo("Success", "Digital signature generated!")

def verify_signature():
    message = input_text.get("1.0", tk.END).strip().encode()
    if not message:
        messagebox.showwarning("Warning", "Enter a message to verify!")
        return
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        messagebox.showinfo("Verification", "Signature is VALID ✅")
    except Exception:
        messagebox.showerror("Verification", "Signature is INVALID ❌")

# -----------------------------
# Tkinter UI
# -----------------------------
root = tk.Tk()
root.title("RSA Digital Signature")
root.geometry("600x450")

tk.Label(root, text="Enter Message:", font=("Arial", 12, "bold")).pack(pady=5)
input_text = scrolledtext.ScrolledText(root, height=6, width=70)
input_text.pack(pady=5)

btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)
tk.Button(btn_frame, text="Generate Signature", command=generate_signature, bg="lightblue", width=20).grid(row=0, column=0, padx=10)
tk.Button(btn_frame, text="Verify Signature", command=verify_signature, bg="lightgreen", width=20).grid(row=0, column=1, padx=10)

tk.Label(root, text="Signature Output:", font=("Arial", 12, "bold")).pack()
output_text = scrolledtext.ScrolledText(root, height=8, width=70, state="disabled")
output_text.pack(pady=5)

root.mainloop()