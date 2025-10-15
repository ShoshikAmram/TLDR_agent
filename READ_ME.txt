# 📨 TLDR Gmail Agent

A Google Cloud Function that automatically **summarizes recent Gmail messages**, **extracts actionable todos**, and **emails you a daily HTML digest** — all powered by **LangGraph**, **Groq LLM**, and the **Gmail API**.

---

## 🚀 Project Overview

Inbox fatigue is real. This project automates the process of scanning your Gmail inbox, summarizing new messages, and sending a single clean summary email each day.

The agent:
1. Fetches recent emails (from a predefined list of senders).
2. Uses a Large Language Model (via Groq API) to summarize and extract todos, deadlines, and priorities.
3. Generates a polished HTML digest.
4. Sends it back to you via Gmail — so you can focus only on what matters.

The pipeline is orchestrated via **LangGraph**, deployed as a **Google Cloud Function**, and securely retrieves tokens through **Google Secret Manager**.

---

## 🧩 Tech Stack

- **Python 3.12+**
- **LangGraph** – to define and execute the agent workflow
- **Groq API (LLM)** – for summarization and task extraction
- **Google Cloud Secret Manager** – for token and credential management
- **Google Gmail API** – for reading and sending emails
- **Google Cloud Functions and scheduler** – for daily automation

---

## 📋 Prerequisites

- Google Cloud Project with billing enabled
- Gmail API enabled
- Secret Manager API enabled
- Cloud Functions API enabled
- Cloud Scheduler API enabled
- Groq API account and API key

---

## 🔧 Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/tldr-gmail-agent.git
cd tldr-gmail-agent
```

### 2. Enable Required APIs
```bash
gcloud services enable gmail.googleapis.com
gcloud services enable secretmanager.googleapis.com
gcloud services enable cloudfunctions.googleapis.com
gcloud services enable cloudscheduler.googleapis.com
```

### 3. Configure Gmail OAuth
1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Navigate to APIs & Services → Credentials
3. Create OAuth 2.0 credentials
4. Download credentials and run OAuth flow to get refresh token
5. Store the token JSON in Secret Manager as `TLDR_gmail_token`

### 4. Add Secrets to Secret Manager
```bash
# Add Gmail token
gcloud secrets create TLDR_gmail_token --data-file=gmail_token.json

# Add Groq API key
echo -n "your_groq_api_key" | gcloud secrets create TLDR_groq_api_key --data-file=-
```

### 5. Configure the Code
Edit `main.py` and update:
- `MONITORED_SENDERS` – list of email addresses to monitor
- `DEFAULT_RECIPIENTS` – where to send the digest

Example:
MONITORED_SENDERS = [
    "school@example.org",
    "notifications@company.com",
    "newsletter@service.com",
]

DEFAULT_RECIPIENTS = ["youremail@gmail.com"]
```

- `MONITORED_SENDERS` – Email addresses you want to track and summarize
- `DEFAULT_RECIPIENTS` – Where to send the daily digest (can be multiple addresses)

### 6. Deploy Cloud Function
```bash
gcloud functions deploy email-daily-digest \
  --runtime python312 \
  --trigger-http \
  --entry-point run_daily_summary \
  --region us-east1 \
  --allow-unauthenticated
```

### 7. Set up Cloud Scheduler
```bash
gcloud scheduler jobs create http daily-email-digest \
  --schedule="0 8 * * *" \
  --uri="https://YOUR_FUNCTION_URL" \
  --http-method=POST \
  --location=us-east1
```

---

## 🏗️ Architecture
```
Gmail Inbox → Cloud Function → LangGraph Agent
                                    ↓
                            Fetch Messages
                                    ↓
                            Summarize (Groq LLM)
                                    ↓
                            Generate HTML Report
                                    ↓
                            Send via Gmail API
```

---

## 📂 Project Structure
```
.
├── main.py              # Main Cloud Function code
├── requirements.txt     # Python dependencies
├── README.md           # This file
└── .gitignore          # Git ignore file
```

---

## 🔒 Security Notes

- **Never commit API keys or tokens**
- All secrets are stored in Google Secret Manager
- OAuth tokens have limited scopes (readonly + send)
- Service account has minimal IAM permissions

---

## 🛠️ Customization

### Change Summarization Prompt
Edit the `SYSTEM_PROMPT` in the `LLMService` class.

### Adjust Email Filters
Modify `MONITORED_SENDERS` list or change the Gmail query logic in `GmailService.build_query()`.

### Change Schedule
Update the cron expression in Cloud Scheduler (default: daily at 8 AM).

---

## 📊 Sample Output

The digest email includes:
- Email subject and sender
- AI-generated summary (1-2 sentences)
- Extracted todos and deadlines
- Priority level and confidence score
- Direct link to open in Gmail

---

## 🐛 Troubleshooting

**Permission Denied Error:**
```bash
gcloud secrets add-iam-policy-binding TLDR_groq_api_key \
  --member="serviceAccount:YOUR_SERVICE_ACCOUNT" \
  --role="roles/secretmanager.secretAccessor"
```

**Function Times Out:**
Increase timeout in deployment:
```bash
--timeout=300s
```

**Check Logs:**
```bash
gcloud functions logs read email-daily-digest --limit 50
```

---

## 🤝 Contributing

Contributions welcome! Please open an issue or submit a PR.