"""Cloud Function: summarize recent Gmail messages, generate HTML digest, and email it."""

#### imports ####
# stdlib
import base64
import json
import logging
import re
import traceback
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape
from typing import List, TypedDict, Optional

# third-party
from google.auth import default
from google.cloud import secretmanager
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from groq import Groq
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

#### Logging Configuration ####
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)
logger = logging.getLogger(__name__)

#### Constants ####
GMAIL_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
]

MONITORED_SENDERS = []
DEFAULT_RECIPIENTS = []
DEFAULT_SUBJECT = "Daily Email Summaries"
MAX_MESSAGES = 50
LLM_MODEL = "llama-3.3-70b-versatile"
LLM_TEMPERATURE = 0.2
LLM_MAX_TOKENS = 300


#### Types ####
class Email(TypedDict, total=False):
    id: str
    from_: str
    subject: str
    snippet: str
    thread_id: str


class EmailSummary(TypedDict, total=False):
    summary: str
    todos: List[str]
    deadline: Optional[str]
    priority: str
    confidence: float
    email_id: str
    thread_id: str
    subject: str
    from_: str


class AgentState(TypedDict, total=False):
    start_date: str
    senders: List[str]
    emails: List[Email]
    summaries: List[EmailSummary]
    report_email_to: List[str]
    report_subject: str
    email_report_status: str


#### Services ####
class SecretManager:
    """Handles secret retrieval from Google Cloud Secret Manager."""

    @staticmethod
    def _get_secret(secret_name: str) -> str:
        """Get secret from Secret Manager."""
        _, project_id = default()
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"

        response = client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")

    @staticmethod
    def get_gmail_token() -> dict:
        """Get Gmail token from Secret Manager."""
        token_data = SecretManager._get_secret("TLDR_gmail_token")
        return json.loads(token_data)

    @staticmethod
    def get_groq_api_key() -> str:
        """Get Groq API key from Secret Manager."""
        return SecretManager._get_secret("TLDR_groq_api_key")


class GmailService:
    """Handles Gmail API operations."""

    def __init__(self):
        token = SecretManager.get_gmail_token()
        creds = Credentials.from_authorized_user_info(token, GMAIL_SCOPES)
        self.service = build("gmail", "v1", credentials=creds)

    def build_query(self, start_date: str, senders: List[str]) -> str:
        """Build Gmail search query."""
        after = start_date.replace("-", "/")
        q = f"after:{after}"
        if senders:
            q += " " + " OR ".join([f"from:{s}" for s in senders])
        return q

    def list_message_ids(self, query: str, max_results: int = MAX_MESSAGES) -> List[str]:
        """List message IDs matching query."""
        try:
            resp = self.service.users().messages().list(
                userId="me", q=query, maxResults=max_results
            ).execute()
            return [m["id"] for m in resp.get("messages", [])]
        except Exception as e:
            logger.error(f"Error listing messages: {e}")
            return []

    def get_basic_email(self, msg_id: str) -> Email:
        """Fetch basic email metadata."""
        try:
            msg = self.service.users().messages().get(
                userId="me",
                id=msg_id,
                format="metadata",
                metadataHeaders=["From", "Subject", "Date"],
            ).execute()

            headers = {h["name"].lower(): h["value"] for h in msg["payload"].get("headers", [])}
            from_raw = headers.get("from", "")
            m = re.search(r"<([^>]+)>", from_raw)
            from_addr = m.group(1) if m else from_raw

            return {
                "id": msg["id"],
                "from_": from_addr,
                "subject": headers.get("subject", ""),
                "snippet": msg.get("snippet", ""),
                "thread_id": msg.get("threadId", msg["id"])
            }
        except Exception as e:
            logger.error(f"Error fetching email {msg_id}: {e}")
            return {
                "id": msg_id,
                "from_": "unknown",
                "subject": "Error fetching email",
                "snippet": "",
                "thread_id": msg_id
            }

    def send_email(self, to_emails: List[str], subject: str, html_body: str, text_body: str = None):
        """Send email via Gmail API."""
        message = self._build_mime_message(to_emails, subject, html_body, text_body)
        raw = base64.urlsafe_b64encode(message.as_bytes()).decode("utf-8")
        return self.service.users().messages().send(userId="me", body={"raw": raw}).execute()

    @staticmethod
    def _build_mime_message(to_emails: List[str], subject: str, html_body: str, text_body: str = None):
        """Build MIME message for email."""
        msg = MIMEMultipart("alternative")
        msg["To"] = ", ".join(to_emails) if isinstance(to_emails, list) else to_emails
        msg["Subject"] = subject

        if not text_body:
            text_body = "Your email summaries (HTML version available)."

        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))
        return msg


class LLMService:
    """Handles LLM API operations for email summarization."""

    SYSTEM_PROMPT = """You are a precise assistant that summarizes emails for a productivity agent.
Rules:
- Output STRICTLY valid, minified JSON. No Markdown, no extra text.
- Fields:
  {"summary": str,
   "todos": [str],
   "deadline": str|null,
   "priority": "low"|"med"|"high",
   "confidence": float}
- Keep "summary" to 1–2 sentences.
- If nothing to do, "todos": [] and "priority": "low".
- If there is a todo from the email, set the priority as "high".
- If the email mentions a required attendance at a location (e.g., school meetings, appointments), add it to the todos.
- Never include personally identifiable tokens beyond what's in the email.
- If the email is a newsletter/marketing, summarize and set priority="low".
- If the email is a reply chain, summarize only the NEWEST author's main points."""

    USER_TEMPLATE = """Summarize the following email strictly per the JSON schema above.
Use the text inside the triple fences as the only source of truth.
If there are quoted threads or signatures, ignore boilerplate.

```email
Subject: {subject}
From: {from_}
---
{content}
```"""

    def __init__(self, api_key: str):
        self.client = Groq(api_key=api_key)

    def summarize_email(self, email: Email) -> dict:
        """Summarize a single email using LLM."""
        content = self._extract_email_text(email)
        user_msg = self.USER_TEMPLATE.format(
            subject=email.get("subject", "(no subject)"),
            from_=email.get("from_", "(unknown sender)"),
            content=content
        )

        try:
            resp = self.client.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg}
                ],
                temperature=LLM_TEMPERATURE,
                max_tokens=LLM_MAX_TOKENS,
            )
            raw = resp.choices[0].message.content.strip()
            return json.loads(raw)
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse LLM response for email {email.get('id')}")
            return self._fallback_summary(raw if 'raw' in locals() else "")
        except Exception as e:
            logger.error(f"Error summarizing email {email.get('id')}: {e}")
            return self._fallback_summary("")

    @staticmethod
    def _extract_email_text(email: Email) -> str:
        """Extract text content from email."""
        return (email.get("body") or email.get("snippet") or "").strip()

    @staticmethod
    def _fallback_summary(raw_text: str) -> dict:
        """Create fallback summary when LLM fails."""
        return {
            "summary": raw_text[:240] if raw_text else "Unable to summarize",
            "todos": [],
            "deadline": None,
            "priority": "low",
            "confidence": 0.3
        }


class ReportGenerator:
    """Generates HTML email digest reports."""

    @staticmethod
    def generate_html_report(summaries: List[EmailSummary], title: str = "Email Digest") -> str:
        """Generate HTML report from summaries."""
        rows = [ReportGenerator._render_summary_row(i, s) for i, s in enumerate(summaries, 1)]
        now = datetime.now().strftime("%Y-%m-%d %H:%M")

        return f"""
        <div style="font-family:ui-sans-serif,system-ui,Arial;">
          <h2 style="margin:0 0 8px 0;">{escape(title)}</h2>
          <div style="color:#555;margin-bottom:14px;">Generated: {now}</div>
          <table style="border-collapse:collapse;width:100%;font-size:14px;">
            <thead>
              <tr style="text-align:left;background:#f7f7f7;">
                <th style="padding:8px 12px;">#</th>
                <th style="padding:8px 12px;">Email Details</th>
                <th style="padding:8px 12px;">Deadline</th>
                <th style="padding:8px 12px;">Priority</th>
                <th style="padding:8px 12px;">Confidence</th>
              </tr>
            </thead>
            <tbody>
              {''.join(rows) if rows else '<tr><td colspan="5" style="padding:12px;">No items.</td></tr>'}
            </tbody>
          </table>
        </div>"""

    @staticmethod
    def _render_summary_row(index: int, summary: EmailSummary) -> str:
        """Render a single summary as an HTML table row."""
        s = ReportGenerator._normalize_summary(summary)

        summary_text = escape(str(s.get("summary", "")))
        from_addr = escape(str(s.get("from_", "Unknown")))
        subject = escape(str(s.get("subject", "No Subject")))
        todos = s.get("todos") or []
        deadline = escape(str(s.get("deadline"))) if s.get("deadline") else "—"
        priority = escape(str(s.get("priority", "low")))
        conf_val = s.get("confidence")
        conf_txt = f"{conf_val:.2f}" if isinstance(conf_val, (float, int)) else "—"

        link_html = ReportGenerator._render_gmail_link(s.get("thread_id"))
        todo_html = ReportGenerator._render_todos(todos)

        return f"""
        <tr>
          <td style="vertical-align:top;padding:8px 12px;border-bottom:1px solid #eee;">{index}</td>
          <td style="vertical-align:top;padding:8px 12px;border-bottom:1px solid #eee;">
            <div style="margin-bottom:4px;"><strong>{subject}</strong></div>
            <div style="color:#666;font-size:12px;margin-bottom:6px;">From: {from_addr}</div>
            <div>{summary_text}</div>
            {('<div style="margin-top:6px;"><strong>TODOs:</strong>' + todo_html + '</div>') if todos else ''}
            {('<div style="margin-top:8px;">' + link_html + '</div>') if link_html else ''}
          </td>
          <td style="vertical-align:top;padding:8px 12px;border-bottom:1px solid #eee;">{deadline}</td>
          <td style="vertical-align:top;padding:8px 12px;border-bottom:1px solid #eee;">{priority}</td>
          <td style="vertical-align:top;padding:8px 12px;border-bottom:1px solid #eee;">{conf_txt}</td>
        </tr>"""

    @staticmethod
    def _normalize_summary(summary) -> dict:
        """Normalize summary to dict format."""
        if isinstance(summary, dict):
            return summary
        if isinstance(summary, str):
            try:
                return json.loads(summary)
            except json.JSONDecodeError:
                return {
                    "summary": summary[:240],
                    "todos": [],
                    "deadline": None,
                    "priority": "low",
                    "confidence": 0.3
                }
        return {
            "summary": str(summary)[:240],
            "todos": [],
            "deadline": None,
            "priority": "low",
            "confidence": 0.3
        }

    @staticmethod
    def _render_gmail_link(thread_id: Optional[str]) -> str:
        """Render Gmail link HTML."""
        if not thread_id:
            return ""
        url = f"https://mail.google.com/mail/u/0/#inbox/{thread_id}"
        return f'<a href="{url}" style="color:#1a73e8;text-decoration:none;">📧 Open in Gmail</a>'

    @staticmethod
    def _render_todos(todos: List[str]) -> str:
        """Render todos as HTML list."""
        if not todos:
            return ""
        items = "".join(f"<li>{escape(str(t))}</li>" for t in todos)
        return f"<ul style='margin:4px 0;padding-left:20px;'>{items}</ul>"


#### Graph Nodes ####
def fetch_messages(state: AgentState) -> AgentState:
    """Fetch messages from Gmail based on criteria."""
    logger.info(f"Fetching messages since {state['start_date']}")

    gmail = GmailService()
    query = gmail.build_query(state["start_date"], state.get("senders", []))
    logger.info(f"Gmail query: {query}")

    ids = gmail.list_message_ids(query)
    emails = [gmail.get_basic_email(mid) for mid in ids]

    logger.info(f"Fetched {len(emails)} emails")
    return {"emails": emails}


def summarize_emails(state: AgentState) -> AgentState:
    """Summarize all emails using LLM."""
    emails = state.get("emails", [])
    logger.info(f"Summarizing {len(emails)} emails")

    api_key = SecretManager.get_groq_api_key()
    llm = LLMService(api_key=api_key)
    summaries = []

    for email in emails:
        summary = llm.summarize_email(email)
        summary.update({
            "email_id": email.get("id"),
            "thread_id": email.get("thread_id"),
            "subject": email.get("subject"),
            "from_": email.get("from_")
        })
        summaries.append(summary)

    logger.info(f"Created {len(summaries)} summaries")
    return {"summaries": summaries}


def email_report(state: AgentState) -> AgentState:
    """Generate and send email report."""
    logger.info("Generating and sending report")

    summaries = state.get("summaries", [])
    to_emails = state.get("report_email_to") or DEFAULT_RECIPIENTS
    if isinstance(to_emails, str):
        to_emails = [to_emails]

    subject = state.get("report_subject") or DEFAULT_SUBJECT
    html_body = ReportGenerator.generate_html_report(summaries, title=subject)

    try:
        gmail = GmailService()
        gmail.send_email(to_emails, subject, html_body)
        status = f"sent to {len(to_emails)} recipient(s)"
        logger.info(f"✅ Email sent to: {', '.join(to_emails)}")
    except Exception as e:
        status = f"error: {e}"
        logger.error(f"❌ Error sending email: {e}")
        traceback.print_exc()

    return {"email_report_status": status}


def end_node(state: AgentState) -> AgentState:
    """Final node - log completion."""
    logger.info(f"Finished. Processed {len(state.get('emails', []))} emails.")
    return state


#### Graph Management ####
class GraphManager:
    """Manages LangGraph instance and execution."""

    _graph = None
    _memory = MemorySaver()

    @classmethod
    def get_graph(cls):
        """Get or create graph instance."""
        if cls._graph is None:
            builder = StateGraph(AgentState)
            builder.add_node("fetch_messages", fetch_messages)
            builder.add_node("summarize_emails", summarize_emails)
            builder.add_node("email_report", email_report)
            builder.add_node("end", end_node)
            builder.set_entry_point("fetch_messages")
            builder.add_edge("fetch_messages", "summarize_emails")
            builder.add_edge("summarize_emails", "email_report")
            builder.add_edge("email_report", "end")
            builder.add_edge("end", END)
            cls._graph = builder.compile(checkpointer=cls._memory)
        return cls._graph


#### Cloud Function Entry Point ####
def run_daily_summary(request):
    """Cloud Function entry point - runs daily email summary."""
    logger.info("Cloud Function triggered")

    yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    config = {"configurable": {"thread_id": f"daily-{datetime.now().strftime('%Y%m%d')}"}}

    logger.info(f"🚀 Starting daily email summary for {yesterday}")
    logger.info(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        graph = GraphManager.get_graph()
        graph.invoke({
            "start_date": yesterday,
            "senders": MONITORED_SENDERS
        }, config=config)

        logger.info("✅ Daily summary completed successfully!")
        return {"status": "success", "message": "Email digest sent"}, 200
    except Exception as e:
        logger.error(f"❌ Error running daily summary: {e}")
        traceback.print_exc()
        return {"status": "error", "message": str(e)}, 500