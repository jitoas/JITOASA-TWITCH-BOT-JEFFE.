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

function resolveModelName(raw) {
  if (raw && typeof raw === 'string') {
    const trimmed = raw.trim();
    // Validate model format: starts with 'gemini-' or 'models/gemini-', contains only valid characters
    if (/^(models\/)?gemini-[a-zA-Z0-9.-]+$/.test(trimmed)) {
      return trimmed;
    }
  }
  return DEFAULT_MODEL;
}

const MODEL_NAME = resolveModelName(process.env.GEMINI_MODEL);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Lazy initialization for Google Gen AI client
let aiClient = null;
function getGeminiClient() {
  let apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || !apiKey.trim()) {
    // Fallback in case the user accidentally entered their API key in GEMINI_MODEL
    const candidate = process.env.GEMINI_MODEL;
    if (candidate && (candidate.startsWith('AIza') || candidate.startsWith('AQ.'))) {
      apiKey = candidate.trim();
    }
  }
  if (!apiKey || !apiKey.trim()) {
    return null;
  }
  if (!aiClient) {
    aiClient = new GoogleGenAI({
      apiKey: apiKey.trim(),
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return aiClient;
}

// Twitch Chatbot Personality & Instructions (Saudi Arabic)
const SYSTEM_INSTRUCTION = `أنت شات بوت ومتابع في شات تويتش (Twitch Chat Bot).
المواصفات والأسلوب والتعليمات:
1. اللهجة: تحدث دائماً باللهجة السعودية العامية الطبيعية والخفيفة جداً (مثل: هلا والله، ياخي، وش السالفة، ههههه، أبشر، تسلم، يارجال، من جد، كفو).
2. الشات السريع: الردود تكون قصيرة ومباشرة ومناسبة لسرعة شات تويتش (جملة أو جملتين فقط، بحد أقصى 150 حرف)، وتجنب الإطالة تماماً.
3. الروح والأسلوب: خلك ودود وعفوي، تمزح وتطقطق بخفة وبدون إزعاج أو ثقل دم، ولا تتكلم برسمية ولا كأنك روبوت أو نظام ذكاء اصطناعي.
4. عفوية الحديث: لا تحول كل محادثة لسؤال أو اختبار؛ سولف مع المتابعين بشكل طبيعي ولا تختم كل رد بسؤال موجه لهم.
5. التفاعل وتقييم الإجابات (قابل للتوسع لنظام الإجابات وأمر !a): إذا كان كلام المتابع إجابة على سؤال سابق طُرح في البث أو الشات، حاول تقييم إجابته بخفة ولطف ووضّح إذا كانت صحيحة أو خطأ إذا كان بالإمكان التحقق من صحتها.
6. المصداقية: لا تخترع معلومات أو تواريخ أو قصص على أنها حقائق مؤكدة؛ وإذا ما كنت متأكد من معلومة، قل بكل بساطة وعفوية إنك مو متأكد.
7. التنوع: تجنب تكرار نفس الكلمات أو العبارات في كل رد، ونوّع في أسلوبك دائماً.
8. الصيغة النهائية: أرجع نصاً عادياً فقط (Plain Text) بدون أي تنسيق Markdown (بدون نجوم *، بدون #، بدون شرطات أو علامات تنصيص)، ليكون متوافقاً تماماً مع Nightbot وتويتش.`;

// Answer evaluation system instruction for !a
const ANSWER_EVALUATION_INSTRUCTION = `أنت شات بوت ومتابع في شات تويتش (Twitch Chat Bot).
مهمتك: تقييم إجابة المتابع على السؤال الذي طُرح عليه سابقاً.
الأسلوب والتعليمات:
1. تحدث دائماً باللهجة السعودية العامية العفوية والخفيفة جداً (مثل: كفو، مالك لواء، يا وحش، ههههه، من جد).
2. اجعل الرد قصير جداً ومباشر (جملة أو جملتين فقط، بحد أقصى 150 حرف)، مناسب لشات تويتش وسرعته.
3. إذا كانت الإجابة صحيحة أو قريبة جداً من الصواب: شجعه بحماس وطقطقة خفيفة، مثل: "جوابك صححح 🔥" أو "كفو والله، إجابة صحيحة يا وحش! 🔥".
4. إذا كانت الإجابة خاطئة: امزح معه وطقطق بخفة واذكر له الجواب الصحيح باختصار، مثل: "غلططط 😂، الجواب الصح هو [...]" أو "مالك لواء، غلططط 😂".
5. تعامل مع الإجابات النصية والأرقام والكلمات المرادفة بذكاء ومرونة.
6. لا تخترع وجود سؤال إذا لم يذكر في سياق السؤال السابق.
7. الرد يجب أن يكون نصاً عادياً فقط (Plain Text) بدون Markdown أو علامات تنصيص أو نجوم نهائياً.`;

// In-Memory Conversation & Question Management (per user or global)
const userMemoryMap = new Map();
const MAX_TRACKED_USERS = 250;
const MAX_HISTORY_MESSAGES = 6; // up to 3 turns (user + assistant)
const QUESTION_EXPIRY_MS = 15 * 60 * 1000; // 15 minutes

function getUserState(userKey) {
  let state = userMemoryMap.get(userKey);
  if (!state) {
    // Evict oldest user if memory exceeds max limit
    if (userMemoryMap.size >= MAX_TRACKED_USERS) {
      const oldestKey = userMemoryMap.keys().next().value;
      userMemoryMap.delete(oldestKey);
    }
    state = {
      history: [],
      lastQuestion: null,
      lastActive: Date.now(),
    };
    userMemoryMap.set(userKey, state);
  }
  state.lastActive = Date.now();
  return state;
}

// Common rhetorical greetings that shouldn't be treated as trivia/quiz questions
const RHETORICAL_GREETINGS = [
  'وش مسوي',
  'كيفك',
  'شلونك',
  'شخبارك',
  'كيف حالك',
  'وش اخبارك',
  'وش أخبارك',
  'وش علومك',
  'عساك بخير',
  'عساك طيب',
  'وش وضعك',
  'وش رايك',
];

// Helper to check if text contains an explicit question directed at the chatter
function extractQuestion(text) {
  if (!text || (!text.includes('؟') && !text.includes('?'))) {
    return null;
  }
  // Split into sentences and find candidate question
  const sentences = text.split(/[\.\!\n\r]/);
  for (const s of sentences) {
    if (s.includes('؟') || s.includes('?')) {
      const cleaned = s.trim();
      if (cleaned.length >= 6) {
        const stripped = cleaned.replace(/[؟?!\.,]/g, '').trim();
        // Check if it's merely a casual greeting inquiry
        const isGreeting = RHETORICAL_GREETINGS.some(
          g => stripped === g || stripped.endsWith(g) || (stripped.startsWith(g) && stripped.length < g.length + 6)
        );
        if (!isGreeting) {
          return cleaned;
        }
      }
    }
  }
  return null;
}

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
 * GET /api/ai?q=VIEWER_MESSAGE&user=USERNAME
 * Returns plain text ONLY
 */
app.get('/api/ai', async (req, res) => {
  try {
    const rawQuery = req.query.q;
    const rawUser = req.query.user;
    const username = (rawUser && typeof rawUser === 'string' && rawUser.trim()) ? rawUser.trim() : 'global';
    const userKey = username.toLowerCase();

    // Handle empty query parameter gracefully
    if (!rawQuery || typeof rawQuery !== 'string' || !rawQuery.trim()) {
      return res
        .type('text/plain; charset=utf-8')
        .status(200)
        .send('وش تبي تقول؟ اكتب رسالتك بعد الأمر يا غالي 👋');
    }

    // Protect against excessively large inputs
    const userMessage = rawQuery.trim().slice(0, 400);

    // Check Gemini API key
    const ai = getGeminiClient();
    if (!ai) {
      console.warn('[Twitch AI] GEMINI_API_KEY is not set in environment variables');
      return res
        .type('text/plain; charset=utf-8')
        .status(200)
        .send('الـAI مشغول شوي 😂');
    }

    const userState = getUserState(userKey);

    // Prepare multi-turn contents with recent history for context
    const conversationContents = [
      ...userState.history.slice(-MAX_HISTORY_MESSAGES),
      { role: 'user', parts: [{ text: userMessage }] },
    ];

    // Standard generation configuration
    const generationConfig = {
      systemInstruction: SYSTEM_INSTRUCTION,
      temperature: 0.85,
      maxOutputTokens: 120,
    };

    // Call Gemini Flash model with automatic fallback
    let response;
    try {
      response = await ai.models.generateContent({
        model: MODEL_NAME,
        contents: conversationContents,
        config: generationConfig,
      });
    } catch (modelErr) {
      if (MODEL_NAME !== DEFAULT_MODEL) {
        console.warn(`[Twitch AI] Model ${MODEL_NAME} failed, falling back to ${DEFAULT_MODEL}:`, modelErr?.message || modelErr);
        response = await ai.models.generateContent({
          model: DEFAULT_MODEL,
          contents: conversationContents,
          config: generationConfig,
        });
      } else {
        throw modelErr;
      }
    }

    const reply = sanitizeForTwitch(response.text) || 'هلا والله 👋';

    // Update conversation history
    userState.history.push({ role: 'user', parts: [{ text: userMessage }] });
    userState.history.push({ role: 'model', parts: [{ text: reply }] });
    if (userState.history.length > MAX_HISTORY_MESSAGES) {
      userState.history = userState.history.slice(-MAX_HISTORY_MESSAGES);
    }

    // Check if the reply asks an explicit question to save as the last question
    const question = extractQuestion(reply);
    if (question) {
      userState.lastQuestion = {
        question: question,
        askedAt: Date.now(),
        userName: username,
      };
    }

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
 * Answer Evaluation Endpoint for Nightbot !a
 * GET /api/answer?q=ANSWER&user=USERNAME
 * Returns plain text ONLY
 */
app.get('/api/answer', async (req, res) => {
  try {
    const rawQuery = req.query.q;
    const rawUser = req.query.user;
    const username = (rawUser && typeof rawUser === 'string' && rawUser.trim()) ? rawUser.trim() : 'global';
    const userKey = username.toLowerCase();

    // Check if viewer provided an answer
    if (!rawQuery || typeof rawQuery !== 'string' || !rawQuery.trim()) {
      return res
        .type('text/plain; charset=utf-8')
        .status(200)
        .send('وش جوابك؟ اكتب إجابتك بعد الأمر يا غالي 👋');
    }

    // Protect against excessively large inputs
    const answerText = rawQuery.trim().slice(0, 300);
    const userState = getUserState(userKey);

    // Check if there is an active question for this user within validity window
    if (!userState.lastQuestion || (Date.now() - userState.lastQuestion.askedAt > QUESTION_EXPIRY_MS)) {
      return res
        .type('text/plain; charset=utf-8')
        .status(200)
        .send('ما عندي سؤال لك الحين 😂');
    }

    const previousQuestion = userState.lastQuestion.question;
    // Clear question once answered so it is not re-evaluated repeatedly
    userState.lastQuestion = null;

    // Check Gemini API key
    const ai = getGeminiClient();
    if (!ai) {
      console.warn('[Twitch AI] GEMINI_API_KEY is not set in environment variables');
      return res
        .type('text/plain; charset=utf-8')
        .status(200)
        .send('الـAI مشغول شوي 😂');
    }

    const evaluationPrompt = `السؤال السابق الذي طُرح على المتابع: "${previousQuestion}"\nإجابة المتابع: "${answerText}"\nقم بتقييم الإجابة هل هي صحيحة أم خاطئة، ورد بأسلوب شات تويتش السعودي القصير جداً.`;

    const evalConfig = {
      systemInstruction: ANSWER_EVALUATION_INSTRUCTION,
      temperature: 0.7,
      maxOutputTokens: 100,
    };

    let response;
    try {
      response = await ai.models.generateContent({
        model: MODEL_NAME,
        contents: evaluationPrompt,
        config: evalConfig,
      });
    } catch (modelErr) {
      if (MODEL_NAME !== DEFAULT_MODEL) {
        console.warn(`[Twitch AI] Model ${MODEL_NAME} failed in evaluation, falling back to ${DEFAULT_MODEL}:`, modelErr?.message || modelErr);
        response = await ai.models.generateContent({
          model: DEFAULT_MODEL,
          contents: evaluationPrompt,
          config: evalConfig,
        });
      } else {
        throw modelErr;
      }
    }

    const reply = sanitizeForTwitch(response.text) || 'مالك لواء، غلططط 😂';

    // Store in history for continuity
    userState.history.push({ role: 'user', parts: [{ text: `[إجابتي على سؤال: ${previousQuestion}]: ${answerText}` }] });
    userState.history.push({ role: 'model', parts: [{ text: reply }] });
    if (userState.history.length > MAX_HISTORY_MESSAGES) {
      userState.history = userState.history.slice(-MAX_HISTORY_MESSAGES);
    }

    return res
      .type('text/plain; charset=utf-8')
      .status(200)
      .send(reply);
  } catch (error) {
    console.error('[Twitch AI] Error evaluating answer:', error?.message || error);
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
        <div class="status-value" style="font-family: monospace; font-size: 13px;">${MODEL_NAME}</div>
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
      <h2>أوامر Nightbot المباشرة للشات</h2>
      <p class="card-caption">أضف هذه الأوامر مباشرة في شات تويتش لديك لتفعيل الرد الذكي ونظام الإجابات:</p>
      
      <div style="margin-bottom: 16px;">
        <div style="font-size: 13px; font-weight: 600; margin-bottom: 4px; color: var(--text);">1. أمر الذكاء الاصطناعي العام (!ai):</div>
        <div class="code-block" id="nightbotCmdAi">!commands add !ai $(urlfetch <span class="appDomainSpan"></span>/api/ai?q=$(querystring)&user=$(user))</div>
        <div style="display: flex; align-items: center;">
          <button class="btn-secondary" onclick="copyCmd('ai')">نسخ أمر !ai</button>
          <span id="copyFeedbackAi" class="copy-status">تم النسخ إلى الحافظة ✓</span>
        </div>
      </div>

      <div>
        <div style="font-size: 13px; font-weight: 600; margin-bottom: 4px; color: var(--text);">2. أمر تقييم الإجابات (!a):</div>
        <div class="code-block" id="nightbotCmdAns">!commands add !a $(urlfetch <span class="appDomainSpan"></span>/api/answer?q=$(querystring)&user=$(user))</div>
        <div style="display: flex; align-items: center;">
          <button class="btn-secondary" onclick="copyCmd('ans')">نسخ أمر !a</button>
          <span id="copyFeedbackAns" class="copy-status">تم النسخ إلى الحافظة ✓</span>
        </div>
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
          <code style="color: #374151; font-weight: 500; margin-right: 8px;">/api/ai?q=النص&user=المستخدم</code>
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
          <span style="color: var(--text-muted); font-size: 13px;">يرجع رد الذكاء الاصطناعي مع حفظ سياق المحادثة</span>
          <span class="status-ok">200 OK</span>
        </div>
      </div>
      <div class="endpoint-item">
        <div style="display: flex; align-items: center;">
          <span class="method">GET</span>
          <code style="color: #374151; font-weight: 500; margin-right: 8px;">/api/answer?q=الإجابة&user=المستخدم</code>
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
          <span style="color: var(--text-muted); font-size: 13px;">يقيم إجابة المشاهد على آخر سؤال طرحه البوت</span>
          <span class="status-ok">200 OK</span>
        </div>
      </div>
    </div>
  </div>

  <script>
    const origin = window.location.origin;
    document.querySelectorAll('.appDomainSpan').forEach(el => el.innerText = origin);

    function setQuery(text) {
      document.getElementById('queryInput').value = text;
      sendQuery();
    }

    async function sendQuery() {
      const q = document.getElementById('queryInput').value.trim();
      const box = document.getElementById('resultBox');
      box.innerText = 'جاري المعالجة من Gemini...';
      try {
        const res = await fetch('/api/ai?q=' + encodeURIComponent(q) + '&user=tester');
        const text = await res.text();
        box.innerText = text;
      } catch (err) {
        box.innerText = 'خطأ في الاتصال بالسيرفر';
      }
    }

    function copyCmd(type) {
      let cmd = '';
      let fbId = '';
      if (type === 'ai') {
        cmd = '!commands add !ai $(urlfetch ' + origin + '/api/ai?q=$(querystring)&user=$(user))';
        fbId = 'copyFeedbackAi';
      } else {
        cmd = '!commands add !a $(urlfetch ' + origin + '/api/answer?q=$(querystring)&user=$(user))';
        fbId = 'copyFeedbackAns';
      }
      navigator.clipboard.writeText(cmd).then(() => {
        const fb = document.getElementById(fbId);
        if (fb) {
          fb.style.display = 'inline';
          setTimeout(() => { fb.style.display = 'none'; }, 2500);
        }
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
