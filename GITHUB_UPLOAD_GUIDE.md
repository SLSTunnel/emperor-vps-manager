# GitHub Upload Guide - Drag & Drop Method

## 📁 File Structure for GitHub Upload

Simply drag and drop these files to your GitHub repository in this exact order:

### 1. Root Files (Upload First)
```
📄 README.md
📄 requirements.txt
📄 app.py
📄 manage.py
📄 install.sh
📄 setup.sh
📄 LICENSE
📄 DEPLOYMENT_GUIDE.md
📄 GITHUB_UPLOAD_GUIDE.md
```

### 2. Templates Folder
Create folder: `templates/`
Then upload:
```
📁 templates/
├── 📄 base.html
├── 📄 dashboard.html
├── 📄 login.html
├── 📄 users.html
└── 📄 services.html
```

### 3. Static Folder
Create folder: `static/`
Then create subfolder: `static/css/`
Upload:
```
📁 static/
├── 📁 css/
│   └── 📄 style.css
└── 📁 js/
    └── 📄 dashboard.js
```

### 4. Config Folder
Create folder: `config/`
Then upload:
```
📁 config/
├── 📄 admin.json
└── 📄 services.json
```

## 🚀 Quick Upload Steps

1. **Go to your GitHub repository**: https://github.com/SLSTunnel/emperor-vps-manager

2. **Click "Add file" → "Upload files"**

3. **Drag and drop files in this order:**
   - First: All root files (README.md, requirements.txt, etc.)
   - Second: Create `templates/` folder and upload HTML files
   - Third: Create `static/` folder and upload CSS/JS files
   - Fourth: Create `config/` folder and upload JSON files

4. **Add commit message**: "Initial commit: Emperor VPS Manager with Advanced Features"

5. **Click "Commit changes"**

## ✅ Final Repository Structure

Your repository should look exactly like this:
```
📁 emperor-vps-manager/
├── 📄 README.md
├── 📄 requirements.txt
├── 📄 app.py
├── 📄 manage.py
├── 📄 install.sh
├── 📄 setup.sh
├── 📄 LICENSE
├── 📄 DEPLOYMENT_GUIDE.md
├── 📄 GITHUB_UPLOAD_GUIDE.md
├── 📁 templates/
│   ├── 📄 base.html
│   ├── 📄 dashboard.html
│   ├── 📄 login.html
│   ├── 📄 users.html
│   └── 📄 services.html
├── 📁 static/
│   ├── 📁 css/
│   │   └── 📄 style.css
│   └── 📁 js/
│       └── 📄 dashboard.js
└── 📁 config/
    ├── 📄 admin.json
    └── 📄 services.json
```

## 🎯 After Upload

Once uploaded, you can install on your VPS with:

```bash
curl -sSL https://raw.githubusercontent.com/SLSTunnel/emperor-vps-manager/main/install.sh | bash
```

## 🔧 Advanced Features Included

✅ **Hacker Theme Dashboard** with neon animations  
✅ **Real-time Monitoring** (CPU, RAM, Disk, Users)  
✅ **Advanced VPN Services** (SSH, V2Ray, WireGuard, OpenVPN, Shadowsocks)  
✅ **Admin Panel** with user management  
✅ **Security Features** (SSL, Firewall, Fail2ban)  
✅ **Automated Backups** and monitoring  
✅ **Mobile Responsive** design  
✅ **Professional UI** with animations  

---

**Emperor DevSupport** - Professional VPS Management Solutions 