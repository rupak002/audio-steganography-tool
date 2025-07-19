# audio-steganography-tool
This Python GUI tool hides text, images, or files inside audio using steganography techniques and encryption.

# 🔊 Audio Steganography Tool with Encryption and GUI

This is a professional audio steganography tool built in Python using Tkinter with drag & drop support and a beautiful user interface. It allows you to hide **text**, **images**, or **any file (e.g. PDF/ZIP)** inside `.wav` audio files with **AES-based encryption** using a secret key. The same key is required to extract the embedded data.

---

## 🚀 Features

- 🎵 Hide or extract **Text**, **Image**, or **Any file** (PDF/ZIP etc.) in WAV audio
- 🔐 Secret key-based AES encryption (via Fernet - SHA256)
- 📈 Real-time audio waveform preview
- 🖱️ Drag and Drop support for audio/image selection
- 🌗 Professional GUI using `ttk`, `matplotlib`, and `tkinterdnd2`
- 💼 File save dialogs and automatic file extension handling
- 📦 Supports embedding binary files using base64

---

## 🖥️ GUI Preview

> GUI includes:
- Embed Section (Text/Image/File + Key Input)
- Extract Section (Audio + Key Input)
- Audio waveform viewer
- Styled headers and sections

---

## 📦 Installation

1. **Clone the repo**
  
   git clone https://github.com/rupak002/audio-steganography-tool.git
   
   cd audio-steganography-tool

2.Install requirements:
  
   pip install -r requirements.txt

▶️ Running the Tool

    python audiosteg.py

✅ Use a Virtual Environment(optional but recommended):

   If you are facing error: externally-managed-environment.The error you're encountering is a PEP 668-compliant protection mechanism in Python which defines how distributions should mark Python as "externally managed" to prevent accidental system damage via pip .

To fix this issue:

i]Install python3-venv if not already installed : sudo apt install python3-venv

ii]Create a virtual environment : python3 -m venv venv

iii]Activate the virtual environment : source venv/bin/activate

iv]Now install your requirements safely : pip install -r requirements.txt

v]To run your app, stay in the activated environment : python audiosteg.py

vi]To exit the virtual environment later : deactivate


