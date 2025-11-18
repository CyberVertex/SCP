# Security Copilot Skill Crawler (PowerShell)

A PowerShell script for exporting **Security Copilot plugins and skills**

🔧 **Script:**  
https://github.com/CyberVertex/SCP/blob/main/SkillCrawler/SkillCrawler1.0.ps1

The script automatically discovers skillsets, retrieves all related skills (with pagination), and saves structured output optimized for automation, cataloging, and version control.

---

## ✨ Features

- Authentication via copied token from the Security Copilot quick-start flow  
- Automatic discovery of **Plugins** and their **skills**  
- Generates:
  - `Security Copilot Plugins/skills-index.csv`
  - `Security Copilot Plugins/all-skills.json`
  - A JSON file per skill (ideal for diffing and Git history)
  - `Security Copilot Plugins/hashes.csv` (SHA-256 manifest)

Perfect for:
- Creating **agent catalogs**  
- Building **prompt books**  
- Tracking **drift** across environments or time  
- Feeding catalogs into CI/CD to **enforce consistency**  

---

## 🚀 Quick Start

1. Open browser Dev Tools (`F12`)  
2. Navigate to **securitycopilot.microsoft.com**  
3. Search for **"skillsets"**, then copy:  
   - **PodId**  
   - **Workspace**  
     <img width="2294" height="362" alt="image" src="https://github.com/user-attachments/assets/b4247122-7c64-432f-9837-a1a586fa3864" />
   - **Bearer token** (scroll down looking for a long string)

4. Update the script with your PodId and Workspace  
5. Run the script and paste the bearer token when prompted  

---
