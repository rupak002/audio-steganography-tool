import os
import base64
import hashlib
import wave
import numpy as np
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
from cryptography.fernet import Fernet, InvalidToken
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from tkinterdnd2 import TkinterDnD, DND_FILES

class StegoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("\U0001F50A Audio Steganography Tool")
        self.root.geometry("1050x800")
        self.set_theme()

        self.embed_audio_path = ""
        self.extract_audio_path = ""
        self.image_path = ""
        self.file_path = ""
        self.mode = tk.StringVar(value="text")

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_style()

        header_frame = ttk.Frame(root, style="Header.TFrame")
        header_frame.pack(pady=10, fill="x")
        header_style = ttk.Style()
        header_style.configure("Header.TFrame", background="#e6f2ff")

        try:
            logo_img = Image.open("wave.png").resize((120, 60))
            self.logo = ImageTk.PhotoImage(logo_img)
            logo_label = ttk.Label(header_frame, image=self.logo, background="#e6f2ff")
        except:
            logo_label = ttk.Label(header_frame, text="\U0001F3B5", font=("Arial", 24), background="#e6f2ff")
        logo_label.pack(side="left", padx=10)

        title_label = ttk.Label(header_frame, text="Audio Steganography Tool", font=("Segoe UI", 22, "bold"), background="#e6f2ff")
        title_label.pack(side="left", padx=10)

        main_frame = ttk.Frame(root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)

        self.embed_section(main_frame)
        self.extract_section(main_frame)

    def configure_style(self):
        sky_blue = "#87CEEB"
        section_font = ("Segoe UI", 12, "bold")
        self.style.configure("TButton", background=sky_blue, foreground="black", font=("Segoe UI", 10), padding=6)
        self.style.configure("TLabel", background="#f5f5f5", foreground="black", font=("Segoe UI", 10))
        self.style.configure("TEntry", fieldbackground="white", foreground="black")
        self.style.configure("TLabelframe", background="#f0f8ff", foreground="black", font=section_font, borderwidth=2)
        self.style.configure("TLabelframe.Label", background="#87CEEB", foreground="black", font=section_font, padding=6)

    def set_theme(self):
        self.root.configure(bg="#f5f5f5")

    def embed_section(self, parent):
        embed_frame = ttk.Labelframe(parent, text="\U0001F512 Embed Section", padding=15)
        embed_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        self.embed_audio_btn = ttk.Button(embed_frame, text="Select Audio for Embedding(.wav)", command=self.select_embed_audio)
        self.embed_audio_btn.grid(row=0, column=0, sticky="w")
        self.audio_label = ttk.Label(embed_frame, text="No file selected", relief="solid", padding=5, width=40)
        self.audio_label.grid(row=0, column=1, sticky="w", padx=10)
        self.audio_label.drop_target_register(DND_FILES)
        self.audio_label.dnd_bind("<<Drop>>", self.drop_embed_audio)

        self.waveform_frame = ttk.Frame(embed_frame)
        self.waveform_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=10)
        self.waveform_canvas = None

        # Hide Text
        ttk.Radiobutton(embed_frame, text="Hide Text", variable=self.mode, value="text").grid(row=2, column=0, sticky="w")
        self.text_entry = tk.Text(embed_frame, height=4, width=40, font=("Segoe UI", 10))
        self.text_entry.grid(row=2, column=1, columnspan=2, pady=5, sticky="w")

        # Hide Image
        ttk.Radiobutton(embed_frame, text="Hide Image", variable=self.mode, value="image").grid(row=3, column=0, sticky="w")
        ttk.Button(embed_frame, text="Select Image", command=self.select_image).grid(row=3, column=1, sticky="w")
        self.image_label = ttk.Label(embed_frame, text="No image selected", relief="solid", padding=5, width=30)
        self.image_label.grid(row=3, column=2, sticky="w", padx=5)
        self.image_label.drop_target_register(DND_FILES)
        self.image_label.dnd_bind("<<Drop>>", self.drop_image)

        # Hide File
        ttk.Radiobutton(embed_frame, text="Hide File", variable=self.mode, value="file").grid(row=4, column=0, sticky="w")
        ttk.Button(embed_frame, text="Select File (PDF/ZIP/Any)", command=self.select_file).grid(row=4, column=1, sticky="w")
        self.file_label = ttk.Label(embed_frame, text="No file selected", relief="solid", padding=5, width=30)
        self.file_label.grid(row=4, column=2, sticky="w", padx=5)

        # Secret Key
        ttk.Label(embed_frame, text="Secret Key (used for both embedding and extraction):").grid(row=5, column=0, columnspan=2, sticky="w", pady=5)
        self.secret_key_entry = ttk.Entry(embed_frame, show="*", width=40)
        self.secret_key_entry.grid(row=6, column=0, columnspan=2, pady=5, sticky="w")

        # Embed Button
        ttk.Button(embed_frame, text="Embed", command=self.embed).grid(row=7, column=0, columnspan=3, pady=10)

    def extract_section(self, parent):
        extract_frame = ttk.Labelframe(parent, text="\U0001F50D Extract Section", padding=15)
        extract_frame.grid(row=0, column=1, sticky="nsew")

        self.extract_audio_btn = ttk.Button(extract_frame, text="Select Audio for Extraction", command=self.select_extract_audio)
        self.extract_audio_btn.grid(row=0, column=0, sticky="w")
        self.extract_label = ttk.Label(extract_frame, text="No file selected", relief="solid", padding=5, width=40)
        self.extract_label.grid(row=0, column=1, sticky="w", padx=10)
        self.extract_label.drop_target_register(DND_FILES)
        self.extract_label.dnd_bind("<<Drop>>", self.drop_extract_audio)

        ttk.Label(extract_frame, text="Enter Secret Key:").grid(row=1, column=0, sticky="w", pady=5)
        self.secret_key_entry_extract = ttk.Entry(extract_frame, show="*", width=40)
        self.secret_key_entry_extract.grid(row=1, column=1, pady=5, sticky="w")

        ttk.Button(extract_frame, text="Extract", command=self.extract).grid(row=2, column=0, columnspan=2, pady=10)

    def drop_embed_audio(self, event):
        path = event.data.strip('{}')
        if os.path.isfile(path) and path.lower().endswith('.wav'):
            self.embed_audio_path = path
            self.audio_label.config(text=os.path.basename(path))
            self.plot_waveform(path)
        else:
            messagebox.showerror("Error", "Invalid WAV file")

    def drop_extract_audio(self, event):
        path = event.data.strip('{}')
        if os.path.isfile(path) and path.lower().endswith('.wav'):
            self.extract_audio_path = path
            self.extract_label.config(text=os.path.basename(path))
        else:
            messagebox.showerror("Error", "Invalid WAV file")

    def drop_image(self, event):
        path = event.data.strip('{}')
        if os.path.isfile(path) and path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
            self.image_path = path
            self.image_label.config(text=os.path.basename(path))
        else:
            messagebox.showerror("Error", "Invalid image file")

    def select_embed_audio(self):
        file_path = filedialog.askopenfilename(filetypes=[("WAV Files", "*.wav")])
        if file_path:
            self.embed_audio_path = file_path
            self.audio_label.config(text=os.path.basename(file_path))
            self.plot_waveform(file_path)

    def select_extract_audio(self):
        file_path = filedialog.askopenfilename(filetypes=[("WAV Files", "*.wav")])
        if file_path:
            self.extract_audio_path = file_path
            self.extract_label.config(text=os.path.basename(file_path))

    def select_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.bmp")])
        if file_path:
            self.image_path = file_path
            self.image_label.config(text=os.path.basename(file_path))

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path = file_path
            self.file_label.config(text=os.path.basename(file_path))

    def plot_waveform(self, file_path):
        if self.waveform_canvas:
            self.waveform_canvas.get_tk_widget().destroy()
        try:
            with wave.open(file_path, 'rb') as audio:
                frames = audio.readframes(audio.getnframes())
                dtype = np.int16 if audio.getsampwidth() == 2 else np.int8
                audio_signal = np.frombuffer(frames, dtype=dtype)
                time_axis = np.linspace(0, len(audio_signal) / audio.getframerate(), num=len(audio_signal))
            fig, ax = plt.subplots(figsize=(6, 2), dpi=80)
            ax.plot(time_axis, audio_signal, color="blue")
            ax.set_xlabel("Time (s)")
            ax.set_ylabel("Amplitude")
            fig.tight_layout()
            self.waveform_canvas = FigureCanvasTkAgg(fig, master=self.waveform_frame)
            self.waveform_canvas.draw()
            self.waveform_canvas.get_tk_widget().pack(fill="both", expand=True)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to plot waveform: {e}")

    def embed(self):
        if not self.embed_audio_path:
            messagebox.showerror("Error", "Select an audio file for embedding.")
            return
        secret_key = self.secret_key_entry.get()
        if not secret_key:
            messagebox.showerror("Error", "Enter a secret key.")
            return
        try:
            if self.mode.get() == "text":
                message = self.text_entry.get("1.0", tk.END).strip()
                if not message:
                    messagebox.showerror("Error", "Enter text to embed.")
                    return
                encrypted = encrypt_data(message, secret_key)
            elif self.mode.get() == "image":
                if not self.image_path:
                    messagebox.showerror("Error", "Select an image file.")
                    return
                with open(self.image_path, "rb") as img_file:
                    b64_data = base64.b64encode(img_file.read()).decode()
                encrypted = encrypt_data(f"data:image;base64,{b64_data}", secret_key)
            elif self.mode.get() == "file":
                if not self.file_path:
                    messagebox.showerror("Error", "Select a file to embed.")
                    return
                with open(self.file_path, "rb") as f:
                    b64_data = base64.b64encode(f.read()).decode()
                ext = os.path.splitext(self.file_path)[1]
                encrypted = encrypt_data(f"data:file;ext={ext};base64,{b64_data}", secret_key)
            embed_bytes_in_audio(self.embed_audio_path, encrypted)
            messagebox.showinfo("Success", "Data embedded successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def extract(self):
        if not self.extract_audio_path:
            messagebox.showerror("Error", "Select an audio file for extraction.")
            return
        secret_key = self.secret_key_entry_extract.get()
        if not secret_key:
            messagebox.showerror("Error", "Enter the secret key used for embedding.")
            return
        try:
            extracted = extract_data_from_audio(self.extract_audio_path)
            decrypted_bytes = decrypt_data(base64.b64decode(extracted), secret_key)
            if decrypted_bytes is None:
                raise ValueError("Invalid decryption key or corrupted audio.")
            decoded_str = decrypted_bytes.decode()
            if decoded_str.startswith("data:image"):
                b64_data = decoded_str.split(",")[1]
                save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Files", "*.png")])
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(base64.b64decode(b64_data))
                    messagebox.showinfo("Extracted", f"Image extracted and saved to:\n{save_path}")
            elif decoded_str.startswith("data:file"):
                ext = decoded_str.split("ext=")[1].split(";")[0]
                b64_data = decoded_str.split(",")[1]
                save_path = filedialog.asksaveasfilename(defaultextension=ext, filetypes=[("All files", "*.*")])
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(base64.b64decode(b64_data))
                    messagebox.showinfo("Extracted", f"File extracted and saved to:\n{save_path}")
            else:
                messagebox.showinfo("Extracted Text", decoded_str)
        except Exception as e:
            messagebox.showerror("Error", str(e))

# Utility Functions
def generate_fernet_key(user_key):
    digest = hashlib.sha256(user_key.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def encrypt_data(data, user_key):
    fernet_key = generate_fernet_key(user_key)
    return Fernet(fernet_key).encrypt(data.encode() if isinstance(data, str) else data)

def decrypt_data(token, user_key):
    try:
        fernet_key = generate_fernet_key(user_key)
        return Fernet(fernet_key).decrypt(token)
    except InvalidToken:
        return None

def embed_bytes_in_audio(audio_path, data_bytes):
    with wave.open(audio_path, 'rb') as audio:
        frame_bytes = bytearray(audio.readframes(audio.getnframes()))
        data = base64.b64encode(data_bytes).decode() + "###"
        bits = ''.join([format(ord(i), '08b') for i in data])
        if len(bits) > len(frame_bytes):
            raise ValueError("Data too large to embed in this audio file.")
        for i, bit in enumerate(bits):
            frame_bytes[i] = (frame_bytes[i] & 254) | int(bit)
        output_path = filedialog.asksaveasfilename(defaultextension=".wav", filetypes=[("WAV files", "*.wav")])
        if output_path:
            with wave.open(output_path, 'wb') as modified_audio:
                modified_audio.setparams(audio.getparams())
                modified_audio.writeframes(bytes(frame_bytes))

def extract_data_from_audio(audio_path):
    with wave.open(audio_path, 'rb') as audio:
        frame_bytes = bytearray(audio.readframes(audio.getnframes()))
    extracted_bits = [frame_bytes[i] & 1 for i in range(len(frame_bytes))]
    chars = []
    for i in range(0, len(extracted_bits), 8):
        byte = extracted_bits[i:i+8]
        if len(byte) < 8:
            break
        char = chr(int(''.join(map(str, byte)), 2))
        chars.append(char)
        if ''.join(chars[-3:]) == "###":
            break
    return ''.join(chars).replace("###", "")

# Launch App
if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = StegoApp(root)
    root.mainloop()
