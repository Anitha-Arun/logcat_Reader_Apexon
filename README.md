


```markdown
# 📱 Logcat_Reader_Apexon

**Logcat_Reader_Apexon** is a powerful Flask-based web tool that parses and analyzes Android `logcat` logs. It extracts structured insights such as device metadata, software versions, IP/MAC addresses, and sign-in activity — all presented in a clean, human-readable format.

---

## 🌟 Features

✅ Upload or paste raw `logcat` logs via web UI  
✅ Extracts detailed **device and software metadata**  
✅ Identifies **IP addresses**, **MAC addresses**, and **network logs**  
✅ Parses **sign-in activity** (emails, usernames, status, timestamps)  
✅ Outputs organized summaries grouped by category  
✅ Lightweight and fast — powered by Flask  
✅ 100% local processing — privacy-safe

---

## 📸 Screenshot Preview

> _Sample output after parsing a logcat file:_

| Category         | Extracted Info                                         |
|------------------|--------------------------------------------------------|
| Device Info      | Model: SM-G960F, Serial: 1234567890ABCDEF             |
| Build Details    | Android 9, Build Fingerprint: samsung/starltexx/...   |
| Network          | IP: 192.168.0.12, MAC: 02:00:00:00:00:00              |
| Login Activity   | Email: user@gmail.com, Status: Success, Timestamp: 🕒 |

---

## 🚀 Getting Started

Follow these steps to set up the project locally:

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/Logcat_Reader_Apexon.git
cd Logcat_Reader_Apexon
```

### 2. Set Up a Virtual Environment (Recommended)

```bash
python -m venv venv
# Activate it:
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Flask Server

```bash
python app.py
```

### 5. Access the Web App

Open your browser and navigate to:

```
http://127.0.0.1:5000/
```

> Paste or upload your `logcat` logs and instantly get structured analysis! 🔍

---

## 🧠 What It Detects

| Category         | Data Points Extracted                                   |
|------------------|----------------------------------------------------------|
| 📱 Device Info    | Model, Manufacturer, Serial Number, IMEI, Android ID    |
| 🛠️ Build Info     | OS Version, Build Fingerprint, Build Type, Kernel Info  |
| 🌐 Network        | IP addresses, MAC addresses, DNS logs                   |
| 🔐 Sign-in Logs   | Email/Usernames, Login Success/Failure, Timestamps      |
| 🗂️ Miscellaneous  | Custom tags, boot info, crash traces (optional)         |

---

## 📁 Project Structure

```
Logcat_Reader_Apexon/
├── app.py              # Flask web server
├── parser.py           # Core parsing logic
├── templates/
│   └── index.html      # Web interface
├── static/
│   └── style.css       # Optional styling (CSS)
├── requirements.txt    # Python dependencies
└── README.md           # You are here 🚀
```

---

## ⚙️ Example Log Snippet (Input)

```
04-05 12:34:56.789 1234 5678 I SystemInfo: Device Model: SM-G960F
04-05 12:34:56.790 1234 5678 I Build: Build Fingerprint: samsung/starltexx/starlte:9/PPR1...
04-05 12:34:56.791 1234 5678 I WifiService: Connected to IP 192.168.0.12 MAC 02:00:00:00:00:00
04-05 12:34:56.792 1234 5678 I LoginService: Login successful for user@gmail.com
```

### 🔍 Parsed Output

- **Device Model:** SM-G960F  
- **Build Fingerprint:** samsung/starltexx/starlte:9/PPR1...  
- **IP Address:** 192.168.0.12  
- **MAC Address:** 02:00:00:00:00:00  
- **Email:** user@gmail.com (Login ✅)

---

## 🧪 Development & Testing

- Test with sample log files or copy-paste logcat content
- Adjust parsing rules in `parser.py` to handle new patterns or custom tags

---

## 🗃️ To-Do / Improvements

- [ ] Drag-and-drop log file upload support  
- [ ] Export parsed results to CSV/JSON  
- [ ] Add log filtering and search  
- [ ] Enable dark mode UI  
- [ ] Mobile responsive design  

---

## 🤝 Contribution Guidelines

We welcome contributions! Here’s how to get started:

1. Fork the repo
2. Create a new branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Commit and push: `git commit -m "Add my feature"` then `git push`
5. Submit a pull request 🎉

---

## 📄 License

This project is licensed under the **MIT License** — feel free to use, modify, and share.

---

## 📬 Contact

Have feedback, questions, or ideas?  
Drop an email: (mailto:anithadamarla0313@gmail.com)  
Or connect on [LinkedIn](https://www.linkedin.com/in/anitha0313/)

---

> 🛡️ Built with ❤️ by [Anitha] at Apexon for parsing Android logs smartly.
```

---

Let me know if you want me to add a badge (e.g., Flask, MIT License, Made with Python), deploy to Render or Heroku instructions, or generate a live demo link + GIF preview!
