import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';

// Load environment variables from .env if available
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Default Gemini Flash model (easily configurable via GEMINI_MODEL env var)
// gemini-3.1-flash-lite is fast, free-tier friendly, and available to new users
const DEFAULT_MODEL = 'gemini-3.1-flash-lite';
const MODEL_NAME = process.env.GEMINI_MODEL || DEFAULT_MODEL;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Lazy initialization for Google Gen AI client
let aiClient = null;
function getGeminiClient() {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return null;
  }
  if (!aiClient) {
    aiClient = new GoogleGenAI({
      apiKey: apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return aiClient;
}

// Twitch Chatbot Personality (Saudi Arabic)
const SYSTEM_INSTRUCTION = `أنت شات بوت ومتابع في شات تويتش (Twitch Chat Bot).
المواصفات والأسلوب:
1. تحدث دائماً باللهجة السعودية العامية الطبيعية والعفوية، كأنك واحد من الشباب ومتابعي الشات.
2. لا تتكلم كأنك ذكاء اصطناعي رسمي أو روبوت، ولا تتفلسف.
3. اجعل الردود قصيرة جداً ومناسبة لشات تويتش السريع (جملة أو جملتين فقط، بحد أقصى 150 حرف).
4. استخدم العبارات والكلمات السعودية الدارجة بشكل عفوي (مثل: هلا والله، ياخي، وش السالفة، ههههه، أبشر، تسلم، يارجال، شدعوة، من جد).
5. المزاح أو الطقطقة الخفيفة تكون فقط إذا كان سياق رسالة المتابع مناسب ومستاهل، ولا تمزح في كل رد.
6. لا تخترع مواقف أو قصص خيالية عن المتابع.
7. لا تستخدم نكات عشوائية أو تشبيهات غريبة ما لها علاقة بالسياق.
8. تجنب تكرار نفس العبارات أو اللوازم (مثل تكرار 'وش وضعك' أو 'يا وحش' في كل رد). نوّع في أسلوبك دائماً.
9. إذا سأل المتابع سؤال عادي أو مفيد، جاوبه بشكل طبيعي وعفوي وبسيط.
10. لا تحول المحادثة لاختبار ولا تختم كل رد بسؤال للمتابع.
11. أرجع نصاً عادياً فقط بدون أي تنسيق Markdown أو رموز أو علامات تنصيص، ليكون متوافقاً تماماً مع Nightbot وتويتش.`;

// Clean up text for Twitch chat single-line output
function sanitizeForTwitch(text) {
  if (!text) return '';
  let clean = text.replace(/[*_`#~]/g, '');
  clean = clean.replace(/^["']|["']$/g, '');
  clean = clean.replace(/\r?\n+/g, ' ').trim();
  if (clean.length > 350) {
    clean = clean.slice(0, 347) + '...';
  }
  return clean;
}

/**
 * Health Check Endpoint for Render & Monitoring
 * GET /health -> returns OK
 */
app.get('/health', (req, res) => {
  res.type('text/plain; charset=utf-8').status(200).send('OK');
});

/**
 * Main Twitch Nightbot AI Endpoint
 * GET /api/ai?q=VIEWER_MESSAGE
 * Returns plain text ONLY
 */
app.get('/api/ai', async (req, res) => {
  try {
    const rawQuery = req.query.q;

    // Handle empty query parameter gracefully
    if (!rawQuery || typeof rawQuery !== 'string' || !rawQuery.trim()) {
      return res
        .type('text/plain; charset=utf-8')
        .status(200)
        .send('وش تبي تقول؟ اكتب رسالتك بعد الأمر يا غالي 👋');
    }

    const userMessage = rawQuery.trim();

    // Check Gemini API key
    const ai = getGeminiClient();
    if (!ai) {
      console.warn('[Twitch AI] GEMINI_API_KEY is not set in environment variables');
      return res
        .type('text/plain; charset=utf-8')
        .status(200)
        .send('الـAI مشغول شوي 😂');
    }

    // Call Gemini Flash model
    const response = await ai.models.generateContent({
      model: MODEL_NAME,
      contents: userMessage,
      config: {
        systemInstruction: SYSTEM_INSTRUCTION,
        temperature: 0.85,
        maxOutputTokens: 120,
      },
    });

    const reply = sanitizeForTwitch(response.text) || 'هلا والله 👋';

    return res
      .type('text/plain; charset=utf-8')
      .status(200)
      .send(reply);
  } catch (error) {
    console.error('[Twitch AI] Error generating response:', error?.message || error);
    // Never crash the server, return a friendly fallback in Saudi Arabic
    return res
      .type('text/plain; charset=utf-8')
      .status(200)
      .send('الـAI مشغول شوي 😂');
  }
});

/**
 * Root route: Provides interactive tester and Nightbot setup instructions
 */
app.get('/', (req, res) => {
  res.type('html').send(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Twitch AI Control Plane - Nightbot</title>
  <style>
    :root {
      --bg: #F9FAFB;
      --card: #FFFFFF;
      --card-border: #E5E7EB;
      --card-border-subtle: #F3F4F6;
      --text: #111827;
      --text-muted: #6B7280;
      --text-dim: #9CA3AF;
      --primary: #111827;
      --primary-hover: #1F2937;
      --accent: #2563EB;
      --accent-bg: #EFF6FF;
      --accent-border: #DBEAFE;
      --success: #10B981;
      --success-bg: #ECFDF5;
      --success-border: #D1FAE5;
      --success-text: #065F46;
      --code-bg: #111827;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 32px 20px;
      display: flex;
      justify-content: center;
      min-height: 100vh;
    }
    .container {
      width: 100%;
      max-width: 820px;
      display: flex;
      flex-direction: column;
      gap: 24px;
    }
    header {
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 24px 28px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
      box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.04);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 5px 14px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
      background: var(--success-bg);
      color: var(--success-text);
      border: 1px solid var(--success-border);
      letter-spacing: 0.02em;
    }
    .dot {
      width: 7px;
      height: 7px;
      background: var(--success);
      border-radius: 50%;
    }
    h1 { font-size: 20px; font-weight: 700; color: var(--text); letter-spacing: -0.02em; }
    p.subtitle { color: var(--text-muted); font-size: 13px; margin-top: 4px; }
    
    .status-strip {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
    }
    .status-card {
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 16px 20px;
      box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.02);
    }
    .status-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-dim);
      font-weight: 600;
      margin-bottom: 4px;
    }
    .status-value {
      font-size: 15px;
      font-weight: 600;
      color: var(--text);
    }

    .card {
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 24px 28px;
      box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.04);
    }
    .card h2 {
      font-size: 15px;
      font-weight: 600;
      margin-bottom: 12px;
      color: var(--text);
      letter-spacing: -0.01em;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .card-caption {
      font-size: 13px;
      color: var(--text-muted);
      margin-bottom: 14px;
    }
    .form-group { display: flex; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; }
    input[type="text"] {
      flex: 1;
      min-width: 240px;
      padding: 10px 16px;
      border-radius: 8px;
      background: #FFFFFF;
      border: 1px solid var(--card-border);
      color: var(--text);
      font-size: 14px;
      outline: none;
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    input[type="text"]:focus {
      border-color: #9CA3AF;
      box-shadow: 0 0 0 3px rgba(17, 24, 39, 0.05);
    }
    button.btn-primary {
      background: var(--primary);
      color: #FFFFFF;
      border: 1px solid var(--primary);
      border-radius: 8px;
      padding: 10px 20px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.15s ease;
      white-space: nowrap;
    }
    button.btn-primary:hover { background: var(--primary-hover); }
    button.btn-secondary {
      background: #FFFFFF;
      color: var(--text);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 8px 16px;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    button.btn-secondary:hover {
      background: #F9FAFB;
      border-color: #D1D5DB;
    }
    .chips { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
    .chip {
      background: #F3F4F6;
      border: 1px solid #E5E7EB;
      border-radius: 6px;
      padding: 6px 12px;
      font-size: 12px;
      font-weight: 500;
      cursor: pointer;
      color: #374151;
      transition: all 0.15s ease;
    }
    .chip:hover {
      background: #E5E7EB;
      color: var(--text);
    }
    .response-label {
      font-size: 12px;
      font-weight: 500;
      color: var(--text-muted);
      margin-bottom: 6px;
    }
    .response-box {
      background: #F9FAFB;
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 14px 18px;
      min-height: 50px;
      font-size: 14px;
      color: var(--text);
      word-break: break-word;
      line-height: 1.6;
    }
    .response-box.rtl {
      direction: rtl;
      text-align: right;
    }
    .code-block {
      background: var(--code-bg);
      border: 1px solid #1F2937;
      border-radius: 8px;
      padding: 14px 18px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 13px;
      color: #F9FAFB;
      direction: ltr;
      overflow-x: auto;
      margin: 10px 0 12px 0;
      line-height: 1.5;
    }
    .endpoint-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px 0;
      border-bottom: 1px solid var(--card-border-subtle);
      font-size: 13px;
    }
    .endpoint-item:last-child { border-bottom: none; }
    .method {
      background: var(--accent-bg);
      color: var(--accent);
      border: 1px solid var(--accent-border);
      padding: 3px 8px;
      border-radius: 4px;
      font-weight: 700;
      font-size: 11px;
      margin-left: 8px;
      font-family: monospace;
    }
    .status-ok {
      font-size: 12px;
      font-weight: 600;
      color: var(--success);
      font-family: monospace;
    }
    .copy-status {
      font-size: 12px;
      color: var(--success-text);
      margin-right: 8px;
      display: none;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>واجهة التحكم بالذكاء الاصطناعي (Nightbot API)</h1>
        <p class="subtitle">Twitch AI Control Plane • مشغل بنموذج Gemini Flash باللهجة السعودية</p>
      </div>
      <div class="badge"><span class="dot"></span> السيرفر يعمل بشكل ممتاز (Operational)</div>
    </header>

    <div class="status-strip">
      <div class="status-card">
        <div class="status-label">الحالة التشغيلية</div>
        <div class="status-value">جاهز للاستقبال • 200 OK</div>
      </div>
      <div class="status-card">
        <div class="status-label">نموذج الذكاء الاصطناعي</div>
        <div class="status-value" style="font-family: monospace; font-size: 13px;">gemini-3.1-flash-lite</div>
      </div>
      <div class="status-card">
        <div class="status-label">صيغة الرد لشات تويتش</div>
        <div class="status-value">نص عادي (Plain Text)</div>
      </div>
    </div>

    <div class="card">
      <h2>تجربة الـ API مباشرة</h2>
      <p class="card-caption">اكتب رسالة كأنك متابع بالشات لتجربة رد الذكاء الاصطناعي الفوري:</p>
      <div class="chips">
        <span class="chip" onclick="setQuery('مرحبا')">مرحبا</span>
        <span class="chip" onclick="setQuery('وش تسوي؟')">وش تسوي؟</span>
        <span class="chip" onclick="setQuery('هلا والله')">هلا والله</span>
        <span class="chip" onclick="setQuery('من فاز أمس؟')">من فاز أمس؟</span>
        <span class="chip" onclick="setQuery('مين أنت؟')">مين أنت؟</span>
      </div>
      <div class="form-group">
        <input type="text" id="queryInput" placeholder="اكتب رسالتك هنا..." value="وش تسوي؟" />
        <button class="btn-primary" onclick="sendQuery()">إرسال الرسالة</button>
      </div>
      <div class="response-label">الرد الفعلي كنص خام (Plain Text):</div>
      <div id="resultBox" class="response-box rtl">اضغط إرسال للتجربة...</div>
    </div>

    <div class="card">
      <h2>أمر Nightbot المباشر للشات</h2>
      <p class="card-caption">انسخ هذا الأمر وضعه مباشرة في شات تويتش لديك لتفعيل البوت:</p>
      <div class="code-block" id="nightbotCmd">!addcom !ai $(urlfetch <span id="appDomain"></span>/api/ai?q=$(querystring))</div>
      <div style="display: flex; align-items: center;">
        <button class="btn-secondary" onclick="copyNightbotCmd()">نسخ الأمر</button>
        <span id="copyFeedback" class="copy-status">تم النسخ إلى الحافظة ✓</span>
      </div>
    </div>

    <div class="card">
      <h2>نقاط الاتصال (Endpoints)</h2>
      <div class="endpoint-item">
        <div style="display: flex; align-items: center;">
          <span class="method">GET</span>
          <code style="color: #374151; font-weight: 500; margin-right: 8px;">/health</code>
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
          <span style="color: var(--text-muted); font-size: 13px;">فحص استجابة Render</span>
          <span class="status-ok">200 OK</span>
        </div>
      </div>
      <div class="endpoint-item">
        <div style="display: flex; align-items: center;">
          <span class="method">GET</span>
          <code style="color: #374151; font-weight: 500; margin-right: 8px;">/api/ai?q=نص_المتابع</code>
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
          <span style="color: var(--text-muted); font-size: 13px;">يرجع رد الذكاء الاصطناعي كنص عادي فقط</span>
          <span class="status-ok">200 OK</span>
        </div>
      </div>
    </div>
  </div>

  <script>
    const origin = window.location.origin;
    document.getElementById('appDomain').innerText = origin;

    function setQuery(text) {
      document.getElementById('queryInput').value = text;
      sendQuery();
    }

    async function sendQuery() {
      const q = document.getElementById('queryInput').value.trim();
      const box = document.getElementById('resultBox');
      box.innerText = 'جاري المعالجة من Gemini...';
      try {
        const res = await fetch('/api/ai?q=' + encodeURIComponent(q));
        const text = await res.text();
        box.innerText = text;
      } catch (err) {
        box.innerText = 'خطأ في الاتصال بالسيرفر';
      }
    }

    function copyNightbotCmd() {
      const cmd = '!addcom !ai $(urlfetch ' + origin + '/api/ai?q=$(querystring))';
      navigator.clipboard.writeText(cmd).then(() => {
        const fb = document.getElementById('copyFeedback');
        fb.style.display = 'inline';
        setTimeout(() => { fb.style.display = 'none'; }, 2500);
      });
    }
  </script>
</body>
</html>`);
});

// Start listening
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[Twitch AI Server] Running on http://0.0.0.0:${PORT}`);
  console.log(`[Twitch AI Server] Model: ${MODEL_NAME}`);
});
