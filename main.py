import requests
import pandas as pd
from datetime import datetime
import os,json,subprocess,base64
from jinja2 import Environment, FileSystemLoader

def get_argument():
    # 讀取設定
    with open("profile.json", "r", encoding="utf-8") as f:
        profile = json.load(f)

    project_key = profile.get("project_name") or ""
    branch = profile.get("project_branch") or ""
    sonar_url = (profile.get("sonar_url") or "").rstrip("/")
    token = profile.get("global_token") or profile.get("project_token") or ""
    user_token = profile.get("user_token") or ""
    report_name = profile.get("report_name") or f"{project_key}_report.html"

    # 驗證
    assert token, "global_token或project_token至少需要一個有值"
    assert user_token, "user_token不可為空值"
    assert project_key, "project_name不可為空值"
    assert report_name.lower().endswith(".html"), "report_name格式錯誤，副檔名需為 .html"

    # 輸出參數
    args = {
        "token": token,
        "user_token": user_token,
        "project_key": project_key,
        "sonar_url": sonar_url,
        "report_name": report_name,
        "export_pdf": bool(profile.get("export_pdf")),
        "pdf_name": profile.get("pdf_name") or f"{project_key}_report.pdf",
        "chrome_path": profile.get("chrome_path") or "",
        "branch": branch,
    }
    return args

def get_project_badge_token(argument):

    url = f"{argument['sonar_url'].rstrip('/')}/api/project_badges/token"
    params = {"project": argument["project_key"]}
    resp = requests.get(url, params=params, auth=(argument['user_token'], ""))
    if resp.status_code == 200:
        return resp.json().get("token")
    print(f"[WARN] 取得 badge token 失敗：HTTP {resp.status_code} {resp.text[:120]}")
    return None

def get_quality_gate_badge_data_uri(argument, badge_token=None):
    url = f"{argument['sonar_url'].rstrip('/')}/api/project_badges/quality_gate"
    params = {"project": argument["project_key"]}
    if argument.get("branch"):
        params["branch"] = argument["branch"]
    if badge_token:
        params["token"] = badge_token
    # 以使用者 token 認證，或在私有專案時使用 badge token
    resp = requests.get(url, params=params, auth=(argument["token"], ""))
    if resp.status_code == 200:
        svg_bytes = resp.content
        b64 = base64.b64encode(svg_bytes).decode("ascii")
        return f"data:image/svg+xml;base64,{b64}"
    print(f"[WARN] 讀取 quality_gate badge 失敗：HTTP {resp.status_code} {resp.text[:120]}")
    return None

def html_to_pdf(argument, html_path):
    output_dir = argument.get("output_dir", ".")
    pdf_path = os.path.join(output_dir, argument["pdf_name"])
    # Resolve absolute file URL
    abs_html = os.path.abspath(html_path)
    file_url = f"file://{abs_html}"

    # Candidate Chrome binaries (macOS first), or user provided
    candidates = []
    if argument.get("chrome_path"):
        candidates.append(argument["chrome_path"])
    candidates += [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "google-chrome",
        "chrome",
        "chromium",
        "chromium-browser",
    ]

    for chrome in candidates:
        try:
            cmd = [
                chrome,
                "--headless=new",
                "--disable-gpu",
                f"--print-to-pdf={pdf_path}",
                "--print-to-pdf-no-header",
                file_url,
            ]
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"[✅] PDF 已輸出：{pdf_path}")
            return pdf_path
        except Exception as e:
            # Try next candidate
            last_err = e
            continue

    print("[ERROR] 找不到可用的 Chrome/Chromium。請安裝 Chrome 或使用 --chrome_path 指定執行檔路徑。")
    return None

def connect_sonar_API(argument):
    # 抓取 SonarQube 資料
    print("[INFO] 正在抓取 SonarQube 資料...")
    url = f"{argument['sonar_url']}/api/issues/search"
    headers = {"Authorization": f"Bearer {argument['token']}"}
    params = {
        "componentKeys": argument["project_key"],
        "types": "VULNERABILITY",
        "ps": 500
    }

    response = requests.get(url, params=params, auth=(argument['token'], ''))
    # response = requests.get(url,params=params,headers=headers)

    if response.status_code != 200:
        print(f"[ERROR] HTTP {response.status_code} from SonarQube: {response.text[:200]}")
        return None
    try:
        data = response.json()
    except Exception as e:
        print(f"[ERROR] 無法解析 SonarQube 回應為 JSON: {e}. 可能是未授權或未登入 (token 錯誤/權限不足)。")
        return None
    issues = data.get("issues", [])
    print("[INFO] 完成 SonarQube 資料抓取")

    if not issues:
        print("⚠️ 沒有抓到漏洞資料")
        return None
    else:
        return issues
    
def create_report(argument,issues):
    # 轉成 DataFrame
    df = pd.DataFrame([{
        "Key": issue.get("key"),
        "Rule": issue.get("rule"),
        "Severity": (issue.get("severity") or (issue.get("impacts") or [{}])[0].get("severity")),
        "Message": issue.get("message"),
        "Component": issue.get("component"),
        "Line": issue.get("line", ""),
        "Status": issue.get("status"),
        "Type": issue.get("type"),
        "Creation Date": issue.get("creationDate")
    } for issue in issues])

    # 基本統計與顯示用欄位
    now_str = datetime.now().strftime('%Y%m%d-%H%M%S')
    output_dir = f"Output/{now_str}-{argument['project_key']}"
    os.makedirs(output_dir, exist_ok=True)
    argument["output_dir"] = output_dir

    df["Severity"] = df["Severity"].fillna("INFO").str.upper()
    sev_order = {"BLOCKER":5, "CRITICAL":4, "MAJOR":3, "MINOR":2, "INFO":1, "HIGH":4, "MEDIUM":3, "LOW":2}
    df["__rank"] = df["Severity"].map(lambda s: sev_order.get(str(s).upper(), 0))
    df_sorted = df.sort_values(["__rank", "Creation Date"], ascending=[False, True]).drop(columns=["__rank"])

    sev_counts = df_sorted["Severity"].value_counts().to_dict()
    def c(level):
        return sev_counts.get(level, 0)

    records = df_sorted.to_dict("records")

    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template('template.html')

    rendered_html = template.render(
        project_key=argument["project_key"],
        report_name=argument["report_name"],
        total_issues=len(df_sorted),
        critical_count=c("BLOCKER") + c("CRITICAL") + c("HIGH"),
        major_count=c("MAJOR") + c("MEDIUM"),
        minor_count=c("MINOR") + c("LOW") + c("INFO"),
        badge_data_uri=argument.get("badge_data_uri"),
        records=records
    )

    output_path = os.path.join(output_dir, argument["report_name"])
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)

    print(f"[✅] 報告已生成：{output_path}，共 {len(df_sorted)} 筆資料")
    return output_path

def main():
    argument = get_argument()
    # 取得 badge 並放入頁首右側
    badge_token = get_project_badge_token(argument)
    argument["badge_data_uri"] = get_quality_gate_badge_data_uri(argument, badge_token)
    issues = connect_sonar_API(argument)
    if issues:
        html_path = create_report(argument, issues)
        if argument.get("export_pdf"):
            html_to_pdf(argument, html_path)


if __name__ == "__main__":
    main()