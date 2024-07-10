
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
import csv
import random
import time
from lightphe import LightPHE
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import graph_display  # Import the new graph_display module

# Generate a random 256-bit (32-byte) key for AES encryption
AES_KEY = os.urandom(32)

def pad_data(data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad_data(data):
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

def aes_encrypt(plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad_data(plaintext.encode())
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def aes_decrypt(ciphertext):
    ciphertext = base64.b64decode(ciphertext.encode())
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return unpad_data(padded_plaintext).decode('utf-8')

def generate_and_write_transactions(filename, num_transactions):
    transactions = []
    for _ in range(num_transactions):
        amount_received = round(random.uniform(10, 500), 2)  
        transactions.append(("Deposit", amount_received))
    
    with open(filename, "w", newline="") as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["Transaction Type", "Amount"])
        csvwriter.writerows(transactions)

def compute_total_amount():
    try:
        start_time = time.time()
        filename = "transaction_history.csv"
        total_amount = 0
        
        with open(filename, 'r') as file:
            reader = csv.reader(file)
            next(reader)  # Skip header row
            for row in reader:
                if row[0] == 'Deposit':
                    total_amount += float(row[1])
        
        end_time = time.time()
        result_label.config(text=f"Total amount (traditional computation): ${total_amount:.2f}\nTime taken: {end_time - start_time:.10f} seconds")
       
    except Exception as e:
        result_label.config(text="Error: " + str(e))

def compute_total_amount_homomorphic():
    try:
        start_time = time.time()
        filename = "transaction_history.csv"

        cs = LightPHE(algorithm_name="Paillier")
        
        encrypted_values = []
        
        encryption_start = time.time()
        with open(filename, 'r') as file:
            reader = csv.reader(file)
            next(reader)  
            for row in reader:
                if row[0] == 'Deposit':
                    encrypted_amount = cs.encrypt(plaintext=[float(row[1])])  # Encrypt float as a tensor
                    encrypted_values.append(encrypted_amount)
        encryption_end = time.time()
        
        computation_start = time.time()
        total_encrypted_sum = encrypted_values[0]
        for encrypted_amount in encrypted_values[1:]:
            total_encrypted_sum += encrypted_amount
        computation_end = time.time()
        
        decryption_start = time.time()
        total_sum_decrypted = cs.decrypt(total_encrypted_sum)[0]  # Convert tensor back to float
        decryption_end = time.time()
        
        end_time = time.time()
        
        result_text = (
            f"Total amount (homomorphic encryption-Paillier): ${total_sum_decrypted:.2f}\n"
            f"Time taken: {end_time - start_time:.10f} seconds\n"
            f"Encryption time: {encryption_end - encryption_start:.10f} seconds\n"
            f"Computation time: {computation_end - computation_start:.10f} seconds\n"
            f"Decryption time: {decryption_end - decryption_start:.10f} seconds"
        )
        result_label.config(text=result_text)
        computation_times["Paillier"] = (end_time - start_time)*1000.0
    except Exception as e:
        result_label.config(text="Error: " + str(e))

def compute_total_amount_homomorphic2():
    try:
        start_time = time.time()
        filename = "transaction_history.csv"

        cs = LightPHE(algorithm_name="Damgard-Jurik")
        
        encrypted_values = []
        
        encryption_start = time.time()
        with open(filename, 'r') as file:
            reader = csv.reader(file)
            next(reader)  
            for row in reader:
                if row[0] == 'Deposit':
                    encrypted_amount = cs.encrypt(plaintext=[float(row[1])])  # Encrypt float as a tensor
                    encrypted_values.append(encrypted_amount)
        encryption_end = time.time()
        
        computation_start = time.time()
        total_encrypted_sum = encrypted_values[0]
        for encrypted_amount in encrypted_values[1:]:
            total_encrypted_sum += encrypted_amount
        computation_end = time.time()
        
        decryption_start = time.time()
        total_sum_decrypted = cs.decrypt(total_encrypted_sum)[0]  # Convert tensor back to float
        decryption_end = time.time()
        
        end_time = time.time()
        
        result_text = (
            f"Total amount (homomorphic encryption-Damgard-Jurik): ${total_sum_decrypted:.2f}\n"
            f"Time taken: {end_time - start_time:.10f} seconds\n"
            f"Encryption time: {encryption_end - encryption_start:.10f} seconds\n"
            f"Computation time: {computation_end - computation_start:.10f} seconds\n"
            f"Decryption time: {decryption_end - decryption_start:.10f} seconds"
        )
        result_label.config(text=result_text)
        computation_times["Damgard-Jurik"] = (end_time - start_time)*1000.0
    except Exception as e:
        result_label.config(text="Error: " + str(e))

def compute_total_amount_aes():
    try:
        start_time = time.time()
        filename = "transaction_history.csv"
        total_amount = 0
        
        encrypted_values = []
        
        encryption_start = time.time()
        with open(filename, 'r') as file:
            reader = csv.reader(file)
            next(reader)  # Skip header row
            for row in reader:
                if row[0] == 'Deposit':
                    encrypted_amount = aes_encrypt(row[1])
                    encrypted_values.append(encrypted_amount)
        encryption_end = time.time()
        
        decryption_start = time.time()
        for encrypted_amount in encrypted_values:
            decrypted_amount = float(aes_decrypt(encrypted_amount))
            total_amount += decrypted_amount
        decryption_end = time.time()
        
        final_encryption_start = time.time()
        total_amount_encrypted = aes_encrypt(str(total_amount))
        encrypted_transactions = []
        
        with open(filename, 'r') as file:
            reader = csv.reader(file)
            next(reader)  # Skip header row
            for row in reader:
                transaction_type = row[0]
                amount = row[1]
                encrypted_transaction = (transaction_type, aes_encrypt(amount))
                encrypted_transactions.append(encrypted_transaction)
        
        with open("encrypted_transaction_history.csv", "w", newline="") as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(["Transaction Type", "Amount"])
            csvwriter.writerows(encrypted_transactions)
        
        final_encryption_end = time.time()
        
        end_time = time.time()
        
        result_text = (
            f"Total amount (AES encryption): ${total_amount:.2f}\n"
            f"Time taken: {end_time - start_time:.10f} seconds\n"
            f"Encryption time: {encryption_end - encryption_start:.10f} seconds\n"
            f"Decryption time: {decryption_end - decryption_start:.10f} seconds\n"
            f"Final encryption time: {final_encryption_end - final_encryption_start:.10f} seconds"
        )
        result_label.config(text=result_text)
        computation_times["AES"] = (end_time - start_time)*1000.0
    except Exception as e:
        result_label.config(text="Error: " + str(e))

def update_transaction_count():
    try:
        global num_transactions
        num_transactions = int(transaction_entry.get())
        generate_and_write_transactions("transaction_history.csv", num_transactions)
        transaction_count_label.config(text=f"Transactions generated: {num_transactions}")
    except ValueError:
        transaction_count_label.config(text="Invalid input. Please enter a valid integer.")

def view_csv():
    try:
        with open("transaction_history.csv", 'r') as file:
            data = file.read()
            csv_display.delete(1.0, tk.END)
            csv_display.insert(tk.END, data)
    except FileNotFoundError:
        csv_display.delete(1.0, tk.END)
        csv_display.insert(tk.END, "CSV file not found.")

def delete_csv_file():
    try:
        os.remove("transaction_history.csv")
        os.remove("encrypted_transaction_history.csv")
        root.destroy()
    except FileNotFoundError:
        root.destroy()

def open_graph_window():
    graph_display.show_graph(computation_times)

computation_times = {}

root = tk.Tk()
root.title("Bank Account Testing")

root.geometry("700x800") 

root.configure(bg="#8f9c92")
style = ttk.Style()
style.configure('TButton', background='#3a32a8', foreground='#070807')

# Input for number of transactions
transaction_label = tk.Label(root, text="Enter number of transactions to generate:", bg="#f0f0f0")
transaction_label.pack(pady=(20, 0))

transaction_entry = tk.Entry(root, width=10)
transaction_entry.pack()

generate_button = ttk.Button(root, text="Generate Transactions", command=update_transaction_count)
generate_button.pack(pady=10)

transaction_count_label = tk.Label(root, text="", bg="#8f9c92")
transaction_count_label.pack()

# Display CSV data
csv_display = scrolledtext.ScrolledText(root, width=60, height=15, wrap=tk.WORD)
csv_display.pack(pady=10)

view_csv_button = ttk.Button(root, text="View CSV", command=view_csv)
view_csv_button.pack(pady=5)

# Buttons to compute total amount
compute_button = ttk.Button(root, text="Compute Total Amount (Traditional)", command=compute_total_amount)
compute_button.pack(pady=10)

compute_homomorphic_button = ttk.Button(root, text="Compute Total Amount (Homomorphic-Paillier)", command=compute_total_amount_homomorphic)
compute_homomorphic_button.pack(pady=5)

compute_homomorphic_button = ttk.Button(root, text="Compute Total Amount (Homomorphic-Damgard-Jurik)", command=compute_total_amount_homomorphic2)
compute_homomorphic_button.pack(pady=5)

compute_aes_button = ttk.Button(root, text="Compute Total Amount (AES)", command=compute_total_amount_aes)
compute_aes_button.pack(pady=5)

result_frame = tk.Frame(root, bg="#8f9c92", bd=2, relief=tk.GROOVE)
result_frame.pack(pady=10, fill=tk.BOTH, expand=True)

result_label = tk.Label(result_frame, text="", bg="#8f9c92", justify=tk.LEFT, anchor="w")
result_label.pack(fill=tk.BOTH, expand=True)

# Button to open graph window
graph_button = ttk.Button(root, text="Show Computation Time Graph", command=open_graph_window)
graph_button.pack(pady=10)

# Exit button to delete CSV file and close the application
exit_button = ttk.Button(root, text="Exit", command=delete_csv_file)
exit_button.pack(pady=10)

root.mainloop()
