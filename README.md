# SonarQube_report

這是一個用於 **自動化生成 SonarQube 掃描報告** 的工具，支援輸出 **HTML 與 PDF 格式**，並整合了 Quality Gate Badge，方便開發團隊檢視程式碼漏洞與品質狀態。

---

## 功能特色
- 透過 SonarQube API 抓取專案的 **漏洞 (VULNERABILITY)** 資料
- 自動整理與排序問題，依照嚴重性 (Severity) 分級
- 產生 **HTML 報告**（含統計摘要、詳細問題清單）
- 選配產生 **PDF 報告**（需安裝 Chrome / Chromium）
- 支援 **Quality Gate Badge**，顯示專案當前品質狀態
- 可指定 **分支 (branch)** 與輸出檔名

---

## 安裝需求
- Python 3.8+
- 已安裝套件：
  ```bash
  pip install requests pandas jinja2
  ```
- 選擇性（如需輸出 PDF）：
  - 安裝 **Google Chrome** 或 **Chromium**

---

## 設定檔範例 (`profile.json`)
請在專案根目錄建立 `profile.json`：

```json
{
  "project_name": "your_project_key",
  "project_branch": "main",
  "sonar_url": "http://your-sonarqube-server",
  "global_token": "your_global_token",
  "project_token": "",
  "user_token": "your_user_token",
  "report_name": "sonarqube_report.html",
  "export_pdf": true,
  "pdf_name": "sonarqube_report.pdf",
  "chrome_path": "/usr/bin/google-chrome"
}
```

### 欄位說明
- `project_name`: SonarQube 專案 Key
- `project_branch`: 分支名稱（可選）
- `sonar_url`: SonarQube 伺服器 URL
- `global_token`: 全域 Token（需具備 API 存取權限）
- `project_token`: 專案 Token（可替代 global_token）
- `user_token`: 使用者 Token（必填，用於 Badge API）
- `report_name`: 輸出 HTML 報告檔名
- `export_pdf`: 是否輸出 PDF
- `pdf_name`: 輸出 PDF 檔名
- `chrome_path`: Chrome/Chromium 路徑（可選，若系統 PATH 已有可略）

---

## 使用方式
1. 編輯好 `profile.json`
2. 執行程式：
   ```bash
   python main.py
   ```
3. 程式會在 `Output/` 資料夾內依時間戳建立子目錄，並輸出：
   - `xxx_report.html`
   - `xxx_report.pdf`（若 `export_pdf = true`）

---

## 範例輸出
- **統計數據**
  - Blocker / Critical / High 數量
  - Major / Medium 數量
  - Minor / Low / Info 數量
- **詳細列表**
  - 規則 (`Rule`)
  - 嚴重性 (`Severity`)
  - 訊息 (`Message`)
  - 檔案與行號 (`Component` / `Line`)
  - 建立日期 (`Creation Date`)
  - 狀態 (`Status`)

---

## 錯誤排除
- `[ERROR] 找不到可用的 Chrome/Chromium`  
  → 請安裝 Chrome 或指定 `chrome_path`
- `[ERROR] 無法解析 SonarQube 回應為 JSON`  
  → 確認 Token 是否正確，或權限是否足夠
- `⚠️ 沒有抓到漏洞資料`  
  → 代表專案目前無相關 VULNERABILITY 類型的 Issue

---
