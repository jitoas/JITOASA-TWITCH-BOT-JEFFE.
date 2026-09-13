import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { GoogleGenAI } from '@google/genai';

// Load environment variables from .env if available
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Twitch OAuth Configuration for Bot Account (جعفر)
const TWITCH_CLIENT_ID = (process.env.TWITCH_CLIENT_ID || '').trim();
const TWITCH_CLIENT_SECRET = (process.env.TWITCH_CLIENT_SECRET || '').trim();
const TWITCH_REDIRECT_URI = (process.env.TWITCH_REDIRECT_URI || '').trim() || 'https://twitch-bot-jeffe.onrender.com/auth/twitch/callback';
const TWITCH_SCOPES = ['user:read:chat', 'user:write:chat', 'user:bot'];

// In-Memory OAuth state store to guard against CSRF attacks with TTL (10 minutes)
const oauthStateStore = new Map();
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;

function cleanupExpiredOAuthStates() {
  const now = Date.now();
  for (const [state, info] of oauthStateStore.entries()) {
    if (now - info.createdAt > OAUTH_STATE_TTL_MS) {
      oauthStateStore.delete(state);
    }
  }
}

// In-Memory Twitch authentication state for bot account "جعفر"
// Kept in server memory, ready for Phase 2 (EventSub, Chat reading/writing)
let twitchAuthState = {
  authorized: false,
  user: null, // { id, login, displayName, profileImageUrl }
  scopes: [],
  expiresAt: 0,
  accessToken: null,
  refreshToken: null,
  connectedAt: null,
};

/**
 * Safely refresh Twitch access token using refresh_token when needed
 * Ready for future phases (sending messages, EventSub, chat listening)
 */
async function refreshTwitchTokenIfNeeded() {
  if (!twitchAuthState.authorized || !twitchAuthState.refreshToken) {
    return null;
  }
  // Refresh 2 minutes before expiry
  if (Date.now() < (twitchAuthState.expiresAt - 2 * 60 * 1000)) {
    return twitchAuthState.accessToken;
  }
  if (!TWITCH_CLIENT_ID || !TWITCH_CLIENT_SECRET) {
    console.warn('[Twitch OAuth] Cannot refresh token: credentials missing in environment');
    return null;
  }

  try {
    const params = new URLSearchParams({
      client_id: TWITCH_CLIENT_ID,
      client_secret: TWITCH_CLIENT_SECRET,
      grant_type: 'refresh_token',
      refresh_token: twitchAuthState.refreshToken,
    });

    const response = await fetch('https://id.twitch.tv/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    if (!response.ok) {
      console.error(`[Twitch OAuth] Token refresh failed with status: ${response.status}`);
      return null;
    }

    const data = await response.json();
    twitchAuthState.accessToken = data.access_token;
    if (data.refresh_token) {
      twitchAuthState.refreshToken = data.refresh_token;
    }
    twitchAuthState.expiresAt = Date.now() + (data.expires_in * 1000);
    twitchAuthState.scopes = data.scope || twitchAuthState.scopes;
    console.log('[Twitch OAuth] Token refreshed successfully for user:', twitchAuthState.user?.login || 'bot');
    return twitchAuthState.accessToken;
  } catch (err) {
    console.error('[Twitch OAuth] Error refreshing token:', err?.message || err);
    return null;
  }
}

// Default Gemini Flash model (easily configurable via GEMINI_MODEL env var)
// gemini-3.1-flash-lite is fast, free-tier friendly, and verified available
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

// Single, verified active fallback model (different from primary model)
// Prioritizes low request pressure and fast recovery without multi-model loops
const FALLBACK_MODEL = (MODEL_NAME === 'gemini-3.5-flash-lite')
  ? 'gemini-3.1-flash-lite'
  : 'gemini-3.5-flash-lite';

// Delay helper
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Short randomized jitter (250–450ms) to avoid synchronized retry storms and ensure fast recovery
const randomJitter = (min = 250, max = 450) =>
  Math.floor(Math.random() * (max - min + 1)) + min;

// Only retry transient availability and connection/idle errors:
// HTTP 503, 502, 504, UNAVAILABLE, high demand, socket hang up, ECONNRESET, fetch failed after idle
// Do NOT retry permanent errors: auth, bad request, missing model, quota/rate limits
function isTemporaryAvailabilityError(err) {
  if (!err) return false;
  const status = err.status || err.code || err.statusCode || (err.cause && (err.cause.code || err.cause.status));
  const statusStr = String(status || '').toUpperCase();

  // Direct 503 / 502 / 504 / UNAVAILABLE / Socket & connection reset codes
  if (
    status === 503 ||
    status === 502 ||
    status === 504 ||
    statusStr === '503' ||
    statusStr === '502' ||
    statusStr === '504' ||
    statusStr === 'UNAVAILABLE' ||
    statusStr === 'ECONNRESET' ||
    statusStr === 'ETIMEDOUT' ||
    statusStr === 'UND_ERR_SOCKET' ||
    statusStr === 'ECONNREFUSED' ||
    statusStr === 'EPIPE'
  ) {
    return true;
  }

  // Explicit non-retryable status codes (client/auth/bad request/quota)
  if (
    status === 400 ||
    status === 401 ||
    status === 403 ||
    status === 404 ||
    status === 429 ||
    statusStr === 'INVALID_ARGUMENT' ||
    statusStr === 'PERMISSION_DENIED' ||
    statusStr === 'NOT_FOUND' ||
    statusStr === 'UNAUTHENTICATED' ||
    statusStr === 'RESOURCE_EXHAUSTED'
  ) {
    return false;
  }

  const msg = (
    (err.message || '') +
    ' ' +
    String(err) +
    ' ' +
    (err.cause?.message || '') +
    ' ' +
    (err.cause?.code || '')
  ).toLowerCase();

  // Exclude permanent client/auth/quota issues
  if (
    msg.includes('api_key') ||
    msg.includes('permission') ||
    msg.includes('not found') ||
    msg.includes('quota') ||
    msg.includes('resource_exhausted') ||
    msg.includes('rate limit')
  ) {
    return false;
  }

  // Detect genuine temporary 503 / unavailable / high demand / connection reset / socket hang up strings
  return (
    msg.includes('503') ||
    msg.includes('502') ||
    msg.includes('504') ||
    msg.includes('unavailable') ||
    msg.includes('high demand') ||
    msg.includes('temporarily') ||
    msg.includes('overloaded') ||
    msg.includes('service unavailable') ||
    msg.includes('fetch failed') ||
    msg.includes('socket hang up') ||
    msg.includes('econnreset') ||
    msg.includes('etimedout') ||
    msg.includes('network error') ||
    msg.includes('premature close') ||
    msg.includes('connection reset') ||
    msg.includes('other side closed')
  );
}

// Lazy initialization and connection freshness manager for Google Gen AI
let aiClient = null;
let lastRequestTimestamp = 0;
// Keep connection fresh: if idle for more than 45 seconds, refresh client to prevent dead socket reuse
const IDLE_CONNECTION_REFRESH_MS = 45 * 1000;

function resetGeminiClient() {
  aiClient = null;
}

function getGeminiClient(forceFresh = false) {
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

  const isIdle = (lastRequestTimestamp > 0 && (Date.now() - lastRequestTimestamp > IDLE_CONNECTION_REFRESH_MS));
  if (!aiClient || forceFresh || isIdle) {
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

/**
 * Execute Gemini generateContent prioritizing LOW REQUEST PRESSURE and FAST RECOVERY:
 * - Ensures connection is fresh before sending, avoiding idle socket failures.
 * - Maximum 2 Gemini attempts per incoming request.
 * - Attempt 1: primary model.
 * - If temporary 503/UNAVAILABLE/high-demand/socket error: wait short randomized delay (250–450ms).
 * - Attempt 2: ONE fallback model with refreshed client.
 * - Never retries the same model twice. Never tries 3, 4, or more models.
 * - NEVER logs or exposes GEMINI_API_KEY.
 */
async function generateWithRetryAndFallback(ai, { contents, config }) {
  // Ensure we have a fresh, ready client especially after idle periods
  let client = ai || getGeminiClient();
  if (!client) {
    client = getGeminiClient(true);
  }
  if (!client) {
    throw new Error('GEMINI_API_KEY is not set');
  }

  // Attempt 1: Primary Model
  try {
    const res = await client.models.generateContent({
      model: MODEL_NAME,
      contents,
      config,
    });
    lastRequestTimestamp = Date.now();
    return res;
  } catch (primaryErr) {
    const errStatus = primaryErr?.status || primaryErr?.code || 'ERROR';
    console.warn(`[Twitch AI] Primary model ${MODEL_NAME} failed (Status: ${errStatus})`);

    // Only retry transient availability, 503, high-demand, or idle socket connection errors
    if (!isTemporaryAvailabilityError(primaryErr)) {
      throw primaryErr;
    }

    // Immediately discard any stale socket / dead connection state
    resetGeminiClient();
    client = getGeminiClient(true);

    // Short randomized delay (250-450ms) before the single fallback attempt
    const jitterMs = randomJitter(250, 450);
    console.log(`[Twitch AI] Temporary error on ${MODEL_NAME}. Trying single fallback model ${FALLBACK_MODEL} in ${jitterMs}ms...`);
    await delay(jitterMs);

    // Attempt 2: ONE fallback model (never retry primary, never try a 3rd model)
    try {
      const res = await client.models.generateContent({
        model: FALLBACK_MODEL,
        contents,
        config,
      });
      lastRequestTimestamp = Date.now();
      return res;
    } catch (fallbackErr) {
      const fbStatus = fallbackErr?.status || fallbackErr?.code || 'ERROR';
      console.warn(`[Twitch AI] Fallback model ${FALLBACK_MODEL} failed (Status: ${fbStatus})`);
      resetGeminiClient();
      throw fallbackErr;
    }
  }
}

// Lightweight in-memory concurrency guards (no Redis or external dependencies)
const activeUserRequests = new Set();
let activeGlobalRequests = 0;
const MAX_GLOBAL_CONCURRENT = 4;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Twitch Chatbot Personality & Instructions (Saudi Arabic)
const SYSTEM_INSTRUCTION = `أنت شات بوت ومتابع في شات تويتش (Twitch Chat Bot). اسمك الاختياري هو 'جعفر'.
المواصفات والأسلوب والتعليمات:
1. الاسم والهوية: اسمك 'جعفر'. تنبيه وقاعدة حاسمة ومهمة جداً: لا تقدم نفسك نهائياً ولا تقل 'أنا جعفر' أو 'معك جعفر' أبداً. في الرسائل العادية تصرّف كشات بوت تويتش العادي بدون حشر اسمك. إذا ناداك المتابع أو خاطبك صراحة بقوله 'جعفر'، 'يا جعفر'، أو ذكر 'جعفر' في رسالته، افهم مباشرة أنه يخاطبك أنت شخصياً وتجاوب معه بعفوية وسلاسة وبأسلوبك المعتاد. لا تجعل الحديث متمحوراً حول اسمك.
2. سياق الأشخاص وتمييز الأدوار (People Context & Role Distinction):
   - "جيف" / "Jef" (جيف، جِيف، jef، Jef): هو الستريمر وصاحب قناة تويتش (Streamer/Owner). إذا سألك أحد عن رأيك في جيف (مثل "وش رايك في جيف؟" أو سأل عنه)، تحدث عنه بإيجابية وامدحه بصدق وحماس وبشكل عفوي كصاحب البث. لا تخترع إنجازات أو قصص شخصية أو وقائع غير معروفة عنه. لا تمدحه عشوائياً إذا لم يكن أحد يتكلم عنه، وإذا ذكر اسمه في سياق عادي بدون سؤال عن الرأي، لا تبدأ بمديح طويل غير مطلوب وتجاوب حسب السياق الفعلي فقط.
   - "جيتو" / "Jito" (جيتو، Jito، jito): هو المود/المشرف في مجتمع تويتش (Moderator/Helper) وهو أيضاً الشخص الذي قام بصنع وبرمجة وتطوير وبناء جعفر. إذا سألك أحد "وش رايك في جيتو؟"، امدح جيتو بشكل خاص وأقوى واعتبره أفضل وأفخم مود، واذكر بشكل طبيعي وعفوي في سياق الحديث أنه هو اللي صنعك/طورك (مثال: "جيتو؟ هذا رجال كفو وأفضل مود شفته في حياتي 🔥 وهو اللي صممني وضبطني"). نوّع في كلمات المدح دائماً ولا تكرر نفس العبارة بالحرف. لا تخترع أي تفاصيل تقنية حول ما بناه. ولا تمدحه عشوائياً إلا إذا سأل أحد عنه أو كان سياق الحديث يتعلق به بشكل طبيعي. وإذا ذكر اسمه فقط في سياق عادي، تفاعل حسب السياق ولا تبدأ بمديح طويل غير مطلوب.
   - "عفيفي" / "Afifi" (عفيفي، Afifi، afifi): هو أقوى داعم (Top / Strongest Supporter) للستريمر وللشات، ولقبه وسياقه هو "أقوى داعم" (تفصيلة سياقية للشخصية وليست معلومة تحتاج تحققاً من سجلات تبرعات أو اشتراكات). إذا سألك أحد "وش رايك في عفيفي؟" أو "من عفيفي؟" أو تحدث عنه المتابعون بشكل طبيعي، تجاوب بإيجابية واعترف به كأقوى داعم (مثال: "عفيفي؟ هذا الداعم الثقيل، وجوده لحاله يرفع المعنويات"، "عفيفي معروف، أقوى داعم عندنا"، "عفيفي؟ هذا ما يحتاج تعريف، داعم من الطراز الثقيل"). نوّع في صياغة الردود بشكل طبيعي. تنبيه مهم جداً بخصوص عفيفي: لا تستخدم إيموجيات أو تعبيرات الضحك (بدون 😂 وبدون ههههه) عند الحديث عن عفيفي احتراماً وتقديراً له. لا تذكره باستمرار ولا تذكره عشوائياً إذا لم يكن أحد يتكلم عنه. لا تخترع أرقام أو مبالغ تبرعات أو عدد اشتراكات أو ترتيبات مالية، ولا تدّعي أنه حرفياً الأول عالمياً أو على مستوى تويتش ككل. اجعل الرد قصيراً وطبيعياً ومناسباً لشات تويتش.
   - "ليان" / "Layan" (ليان، Layan، layan): ستريمر (أنثى/Streamer). جعفر يعرف الاسم ويفهم من المقصود عند ذكرها. تنبيه وقواعد حاسمة: لا تمدح ليان لمجرد ذكر الاسم، لا تطبل لها ولا تعطيها معاملة خاصة. كونها ستريمر هو فقط لفهم سياق الحديث. لا تخترع أي معلومات أو صفات أو ألعاب أو إنجازات عنها. إذا سأل أحد عنها أو عن رأيك فيها، رد بشكل طبيعي وعفوي ومحايد حسب السؤال فقط بدون تطبيل أو مديح زائد.
   - "سولي" / "Soly" (سولي، Soly، soly): متابعة عادية بالشات (أنثى/Viewer). جعفر يعرف الاسم ويفهم من المقصود عند ذكرها. تنبيه وقواعد حاسمة: لا تمدح سولي لمجرد ذكر الاسم، لا تطبل لها ولا تعطيها معاملة خاصة. كونها متابعة هو فقط لفهم السياق. لا تخترع أي معلومات أو صفات أو إنجازات عنها. إذا سأل أحد عنها، رد بشكل طبيعي وعفوي ومحايد حسب السؤال المطروح فقط بدون مديح مصطنع.
   - المتابعون الآخرون: متابعون عاديون في الشات، عاملهم باحترام وخوة وعفوية وسلاسة.
   - تجنب التكلف أو أن تبدو كإعلان ترويجي أو رسالة ملقنة؛ خلك طبيعي، عفوي، وبلهجة سعودية حقيقية.
3. اللهجة: تحدث دائماً باللهجة السعودية العامية الطبيعية والخفيفة جداً (مثل: هلا والله، ياخي، وش السالفة، ههههه، أبشر، تسلم، يارجال، من جد، كفو، يا وحش).
4. الشات السريع: الردود تكون قصيرة ومباشرة ومناسبة لسرعة شات تويتش (جملة أو جملتين فقط، بحد أقصى 150 حرف)، وتجنب الإطالة تماماً.
5. الروح والأسلوب: خلك ودود وعفوي، تمزح وتطقطق بخفة وبدون إزعاج أو ثقل دم، ولا تتكلم برسمية ولا كأنك روبوت أو نظام ذكاء اصطناعي.
6. عفوية الحديث: لا تحول كل محادثة لسؤال أو اختبار؛ سولف مع المتابعين بشكل طبيعي ولا تختم كل رد بسؤال موجه لهم.
7. التفاعل وتقييم الإجابات (قابل للتوسع لنظام الإجابات وأمر !a): إذا كان كلام المتابع إجابة على سؤال سابق طُرح في البث أو الشات، حاول تقييم إجابته بخفة ولطف ووضّح إذا كانت صحيحة أو خطأ إذا كان بالإمكان التحقق من صحتها.
8. المصداقية: لا تخترع معلومات أو تواريخ أو قصص خاصة على أنها حقائق مؤكدة؛ وإذا ما كنت متأكد من معلومة، قل بكل بساطة وعفوية إنك مو متأكد.
9. التنوع: تجنب تكرار نفس الكلمات أو العبارات في كل رد، ونوّع في أسلوبك دائماً.
10. الصيغة النهائية: أرجع نصاً عادياً فقط (Plain Text) بدون أي تنسيق Markdown (بدون نجوم *، بدون #، بدون شرطات أو علامات تنصيص)، ليكون متوافقاً تماماً مع Nightbot وتويتش.`;

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

  // 1. Lightweight per-user concurrency guard: prevent spamming multiple requests simultaneously
  if (userKey !== 'global' && activeUserRequests.has(userKey)) {
    return res
      .type('text/plain; charset=utf-8')
      .status(200)
      .send('اصبر شوي يا وحش، باقي أرد على رسالتك الأولى! 😂');
  }

  // 2. Lightweight global concurrency limit: avoid overloading Gemini with concurrent bursts
  if (activeGlobalRequests >= MAX_GLOBAL_CONCURRENT) {
    return res
      .type('text/plain; charset=utf-8')
      .status(200)
      .send('الشات زحمة والضغط عالي شوي، ثواني وراجع لكم! 😂');
  }

  if (userKey !== 'global') {
    activeUserRequests.add(userKey);
  }
  activeGlobalRequests++;

  try {
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

    // Call Gemini Flash model with smart retry and fallback handling
    const response = await generateWithRetryAndFallback(ai, {
      contents: conversationContents,
      config: generationConfig,
    });

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
  } finally {
    if (userKey !== 'global') {
      activeUserRequests.delete(userKey);
    }
    activeGlobalRequests = Math.max(0, activeGlobalRequests - 1);
  }
});

/**
 * Answer Evaluation Endpoint for Nightbot !a
 * GET /api/answer?q=ANSWER&user=USERNAME
 * Returns plain text ONLY
 */
app.get('/api/answer', async (req, res) => {
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

  const userState = getUserState(userKey);

  // Check if there is an active question for this user within validity window
  if (!userState.lastQuestion || (Date.now() - userState.lastQuestion.askedAt > QUESTION_EXPIRY_MS)) {
    return res
      .type('text/plain; charset=utf-8')
      .status(200)
      .send('ما عندي سؤال لك الحين 😂');
  }

  // 1. Lightweight per-user concurrency guard: prevent spamming multiple answers simultaneously
  if (userKey !== 'global' && activeUserRequests.has(userKey)) {
    return res
      .type('text/plain; charset=utf-8')
      .status(200)
      .send('اصبر شوي يا وحش، باقي أقيم إجابتك السابقة! 😂');
  }

  // 2. Lightweight global concurrency limit
  if (activeGlobalRequests >= MAX_GLOBAL_CONCURRENT) {
    return res
      .type('text/plain; charset=utf-8')
      .status(200)
      .send('الشات زحمة والضغط عالي شوي، ثواني وراجع لكم! 😂');
  }

  if (userKey !== 'global') {
    activeUserRequests.add(userKey);
  }
  activeGlobalRequests++;

  try {
    // Protect against excessively large inputs
    const answerText = rawQuery.trim().slice(0, 300);

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

    const response = await generateWithRetryAndFallback(ai, {
      contents: evaluationPrompt,
      config: evalConfig,
    });

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
  } finally {
    if (userKey !== 'global') {
      activeUserRequests.delete(userKey);
    }
    activeGlobalRequests = Math.max(0, activeGlobalRequests - 1);
  }
});

/**
 * ============================================================================
 * Twitch OAuth Endpoints for Bot Account (جعفر)
 * Modern Scopes: user:read:chat user:write:chat user:bot
 * ============================================================================
 */

/**
 * GET /auth/twitch
 * Initiates the Twitch OAuth authorization flow with a cryptographically
 * secure random state (CSRF protection) and temporary TTL storage.
 */
app.get('/auth/twitch', (req, res) => {
  if (!TWITCH_CLIENT_ID) {
    return res.status(500).type('html').send(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <title>إعدادات Twitch Client ID مفقودة</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #F9FAFB; padding: 40px 20px; display: flex; justify-content: center; color: #111827; }
    .card { background: white; border: 1px solid #E5E7EB; border-radius: 12px; padding: 28px; max-width: 540px; width: 100%; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
    h2 { color: #DC2626; margin-bottom: 12px; font-size: 18px; }
    p { color: #4B5563; font-size: 14px; line-height: 1.6; margin-bottom: 14px; }
    code { background: #F3F4F6; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 13px; color: #111827; }
    a { display: inline-block; background: #111827; color: white; text-decoration: none; padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 500; margin-top: 8px; }
  </style>
</head>
<body>
  <div class="card">
    <h2>⚠️ إعدادات Twitch مفقودة</h2>
    <p>لم يتم تعيين <code>TWITCH_CLIENT_ID</code> في متغيرات البيئة (Environment Variables) في Render.</p>
    <p>يرجى إضافة <code>TWITCH_CLIENT_ID</code> و <code>TWITCH_CLIENT_SECRET</code> و <code>TWITCH_REDIRECT_URI</code> ثم إعادة تشغيل السيرفر.</p>
    <a href="/">العودة إلى لوحة التحكم</a>
  </div>
</body>
</html>`);
  }

  // Clean up any stale states before generating a new one
  cleanupExpiredOAuthStates();

  // Generate cryptographically secure state
  const state = crypto.randomBytes(24).toString('hex');
  oauthStateStore.set(state, { createdAt: Date.now() });

  const authParams = new URLSearchParams({
    client_id: TWITCH_CLIENT_ID,
    redirect_uri: TWITCH_REDIRECT_URI,
    response_type: 'code',
    scope: TWITCH_SCOPES.join(' '),
    state: state,
    force_verify: 'true',
  });

  const authorizeUrl = `https://id.twitch.tv/oauth2/authorize?${authParams.toString()}`;
  return res.redirect(authorizeUrl);
});

/**
 * GET /auth/twitch/callback
 * Receives the authorization code, validates the state to prevent CSRF,
 * exchanges code for tokens, retrieves user account details, and renders
 * a success view without ever leaking tokens to logs or the browser.
 */
app.get('/auth/twitch/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  // 1. Handle error returned by Twitch (e.g. user canceled/denied)
  if (error) {
    console.warn(`[Twitch OAuth] Authorization denied by user: ${error} - ${error_description || ''}`);
    return res.status(400).type('html').send(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <title>تم إلغاء التفويض</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #F9FAFB; padding: 40px 20px; display: flex; justify-content: center; color: #111827; }
    .card { background: white; border: 1px solid #E5E7EB; border-radius: 12px; padding: 28px; max-width: 520px; width: 100%; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
    h2 { color: #DC2626; margin-bottom: 12px; font-size: 18px; }
    p { color: #4B5563; font-size: 14px; line-height: 1.6; margin-bottom: 16px; }
    a { display: inline-block; background: #111827; color: white; text-decoration: none; padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 500; }
  </style>
</head>
<body>
  <div class="card">
    <h2>تم إلغاء عملية التفويض من Twitch</h2>
    <p>تم رفض أو إلغاء التفويض: ${error_description || error || 'لم يكتمل التفويض'}. يمكنك المحاولة مجدداً في أي وقت.</p>
    <a href="/">العودة إلى لوحة التحكم</a>
  </div>
</body>
</html>`);
  }

  // 2. Validate state to prevent CSRF attacks
  if (!state || typeof state !== 'string' || !oauthStateStore.has(state)) {
    console.warn('[Twitch OAuth] Invalid or expired state received in callback');
    return res.status(400).type('html').send(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <title>حالة الأمان غير صالحة</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #F9FAFB; padding: 40px 20px; display: flex; justify-content: center; color: #111827; }
    .card { background: white; border: 1px solid #E5E7EB; border-radius: 12px; padding: 28px; max-width: 520px; width: 100%; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
    h2 { color: #DC2626; margin-bottom: 12px; font-size: 18px; }
    p { color: #4B5563; font-size: 14px; line-height: 1.6; margin-bottom: 16px; }
    a { display: inline-block; background: #111827; color: white; text-decoration: none; padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 500; }
  </style>
</head>
<body>
  <div class="card">
    <h2>⚠️ فشل التحقق من حالة الأمان (Invalid OAuth State)</h2>
    <p>جلسة التفويض غير صالحة أو انتهت مدتها للحماية من هجمات تزوير الطلبات (CSRF). يرجى بدء عملية الربط من جديد.</p>
    <a href="/auth/twitch">إعادة محاولة الربط</a>
  </div>
</body>
</html>`);
  }

  // Consume state immediately so it cannot be reused
  oauthStateStore.delete(state);

  // 3. Verify authorization code is present
  if (!code || typeof code !== 'string') {
    return res.status(400).type('text/plain; charset=utf-8').send('كود التفويض مفقود');
  }

  if (!TWITCH_CLIENT_SECRET) {
    console.error('[Twitch OAuth] TWITCH_CLIENT_SECRET is missing in environment variables');
    return res.status(500).type('text/plain; charset=utf-8').send('TWITCH_CLIENT_SECRET is not configured on the server');
  }

  try {
    // 4. Exchange authorization code for access_token and refresh_token
    const tokenParams = new URLSearchParams({
      client_id: TWITCH_CLIENT_ID,
      client_secret: TWITCH_CLIENT_SECRET,
      code: code,
      grant_type: 'authorization_code',
      redirect_uri: TWITCH_REDIRECT_URI,
    });

    const tokenResponse = await fetch('https://id.twitch.tv/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: tokenParams.toString(),
    });

    if (!tokenResponse.ok) {
      console.error(`[Twitch OAuth] Token exchange failed with HTTP ${tokenResponse.status}`);
      return res.status(500).type('html').send(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <title>خطأ في استبدال الرمز</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #F9FAFB; padding: 40px 20px; display: flex; justify-content: center; color: #111827; }
    .card { background: white; border: 1px solid #E5E7EB; border-radius: 12px; padding: 28px; max-width: 520px; width: 100%; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
    h2 { color: #DC2626; margin-bottom: 12px; font-size: 18px; }
    p { color: #4B5563; font-size: 14px; line-height: 1.6; margin-bottom: 16px; }
    a { display: inline-block; background: #111827; color: white; text-decoration: none; padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 500; }
  </style>
</head>
<body>
  <div class="card">
    <h2>فشل استبدال رمز التفويض مع Twitch</h2>
    <p>حدث خطأ أثناء الاتصال بسيرفرات Twitch (HTTP ${tokenResponse.status}). يرجى التأكد من تطابق الـ Redirect URI وصحة الـ Client Secret.</p>
    <a href="/">العودة إلى لوحة التحكم</a>
  </div>
</body>
</html>`);
    }

    const tokenData = await tokenResponse.json();

    // 5. Fetch Twitch user profile for the authorized account
    const userResponse = await fetch('https://api.twitch.tv/helix/users', {
      method: 'GET',
      headers: {
        'Client-Id': TWITCH_CLIENT_ID,
        'Authorization': `Bearer ${tokenData.access_token}`,
      },
    });

    let userData = null;
    if (userResponse.ok) {
      const userPayload = await userResponse.json();
      if (userPayload.data && userPayload.data.length > 0) {
        userData = userPayload.data[0];
      }
    }

    const accountLogin = userData ? userData.login : 'jaafar';
    const accountDisplayName = userData ? userData.display_name : 'جعفر';
    const accountId = userData ? userData.id : '';
    const profileImage = userData ? userData.profile_image_url : '';

    // 6. Save authentication state securely in server memory
    // NEVER expose accessToken or refreshToken to logs or client HTML
    twitchAuthState = {
      authorized: true,
      user: {
        id: accountId,
        login: accountLogin,
        displayName: accountDisplayName,
        profileImageUrl: profileImage,
      },
      scopes: tokenData.scope || TWITCH_SCOPES,
      expiresAt: Date.now() + (tokenData.expires_in * 1000),
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      connectedAt: new Date().toISOString(),
    };

    console.log(`[Twitch OAuth] Successfully authorized Twitch account: @${accountLogin} (${accountDisplayName})`);

    // 7. Render simple, polished success view
    return res.type('html').send(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>تم ربط حساب تويتش بنجاح</title>
  <style>
    :root {
      --bg: #F9FAFB;
      --card: #FFFFFF;
      --border: #E5E7EB;
      --text: #111827;
      --text-muted: #6B7280;
      --success: #10B981;
      --success-bg: #ECFDF5;
      --success-border: #D1FAE5;
      --primary: #111827;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 40px 20px;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 36px 32px;
      max-width: 500px;
      width: 100%;
      box-shadow: 0 2px 8px rgba(0,0,0,0.04);
      text-align: center;
    }
    .avatar {
      width: 80px;
      height: 80px;
      border-radius: 50%;
      margin: 0 auto 16px auto;
      border: 3px solid #9146FF;
      display: block;
      object-fit: cover;
    }
    .avatar-fallback {
      width: 80px;
      height: 80px;
      border-radius: 50%;
      margin: 0 auto 16px auto;
      background: #9146FF;
      color: white;
      font-size: 32px;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--success-bg);
      color: #065F46;
      border: 1px solid var(--success-border);
      padding: 4px 12px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
      margin-bottom: 12px;
    }
    .dot {
      width: 8px;
      height: 8px;
      background: var(--success);
      border-radius: 50%;
    }
    h1 {
      font-size: 20px;
      font-weight: 700;
      margin-bottom: 6px;
      color: var(--text);
    }
    p.desc {
      color: var(--text-muted);
      font-size: 14px;
      line-height: 1.6;
      margin-bottom: 24px;
    }
    .info-list {
      background: #F9FAFB;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px 18px;
      margin-bottom: 24px;
      text-align: right;
      font-size: 13px;
    }
    .info-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 7px 0;
      border-bottom: 1px solid #F3F4F6;
    }
    .info-row:last-child { border-bottom: none; }
    .info-label { color: var(--text-muted); font-size: 12px; }
    .info-val { font-weight: 600; color: var(--text); }
    .actions {
      display: flex;
      gap: 10px;
      justify-content: center;
      flex-wrap: wrap;
    }
    a.btn {
      display: inline-block;
      background: var(--primary);
      color: white;
      text-decoration: none;
      padding: 10px 20px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
    }
    a.btn-secondary {
      background: white;
      color: var(--text);
      border: 1px solid var(--border);
    }
  </style>
</head>
<body>
  <div class="card">
    ${profileImage ? `<img src="${profileImage}" alt="${accountDisplayName}" class="avatar" />` : `<div class="avatar-fallback">${accountDisplayName.charAt(0)}</div>`}
    <div class="badge"><span class="dot"></span> تم الربط بنجاح</div>
    <h1>حساب ${accountDisplayName} جاهز</h1>
    <p class="desc">تم تفويض وتوثيق حساب تويتش بنجاح عبر OAuth. السيرفر الآن يمتلك صلاحيات الشات اللازمة لبوت جعفر.</p>
    
    <div class="info-list">
      <div class="info-row">
        <span class="info-label">اسم الحساب:</span>
        <span class="info-val">${accountDisplayName} (@${accountLogin})</span>
      </div>
      <div class="info-row">
        <span class="info-label">معرف المستخدم (ID):</span>
        <span class="info-val" style="font-family: monospace;">${accountId || 'غير متوفر'}</span>
      </div>
      <div class="info-row">
        <span class="info-label">الصلاحيات:</span>
        <span class="info-val" style="font-family: monospace; font-size: 11px;">user:read:chat user:write:chat user:bot</span>
      </div>
      <div class="info-row">
        <span class="info-label">تخزين التوكن:</span>
        <span class="info-val" style="color: #065F46;">محفوظ بأمان في الذاكرة ✓</span>
      </div>
    </div>

    <div class="actions">
      <a href="/" class="btn">لوحة التحكم الرئيسية</a>
      <a href="/auth/twitch/status" class="btn btn-secondary" target="_blank">فحص حالة JSON</a>
    </div>
  </div>
</body>
</html>`);
  } catch (err) {
    console.error('[Twitch OAuth] Unexpected error in callback:', err?.message || err);
    return res.status(500).type('text/plain; charset=utf-8').send('حدث خطأ غير متوقع أثناء معالجة تفويض تويتش.');
  }
});

/**
 * GET /auth/twitch/status
 * Returns JSON showing whether Twitch is currently authorized or not,
 * with account identity details. Never exposes access or refresh tokens.
 */
app.get('/auth/twitch/status', (req, res) => {
  if (twitchAuthState.authorized && twitchAuthState.user) {
    const expiresInSeconds = Math.max(0, Math.round((twitchAuthState.expiresAt - Date.now()) / 1000));
    return res.status(200).json({
      authorized: true,
      account: {
        id: twitchAuthState.user.id,
        login: twitchAuthState.user.login,
        displayName: twitchAuthState.user.displayName,
        profileImageUrl: twitchAuthState.user.profileImageUrl || null,
      },
      scopes: twitchAuthState.scopes,
      connectedAt: twitchAuthState.connectedAt,
      tokenExpiresInSeconds: expiresInSeconds,
    });
  }

  return res.status(200).json({
    authorized: false,
    message: 'حساب تويتش غير مفوض حالياً. توجه إلى /auth/twitch لربط الحساب.',
    configuredClientId: Boolean(TWITCH_CLIENT_ID),
    configuredClientSecret: Boolean(TWITCH_CLIENT_SECRET),
    redirectUri: TWITCH_REDIRECT_URI,
  });
});

/**
 * Root route: Provides interactive tester, Twitch OAuth status, and Nightbot setup instructions
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
      --twitch: #9146FF;
      --twitch-bg: #F5F3FF;
      --twitch-border: #DDD6FE;
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
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
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
      font-size: 14px;
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
    .btn-twitch {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: #9146FF;
      color: white;
      text-decoration: none;
      border-radius: 8px;
      padding: 9px 18px;
      font-size: 13px;
      font-weight: 600;
      transition: background 0.15s ease;
    }
    .btn-twitch:hover { background: #772CE8; }
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
      flex-wrap: wrap;
      gap: 8px;
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
    .method-purple {
      background: var(--twitch-bg);
      color: var(--twitch);
      border: 1px solid var(--twitch-border);
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
        <h1>واجهة التحكم بالذكاء الاصطناعي (Nightbot & Twitch API)</h1>
        <p class="subtitle">Twitch AI Control Plane • مشغل بنموذج Gemini Flash ومجهّز بربط تويتش المستقل (جعفر)</p>
      </div>
      <div class="badge"><span class="dot"></span> السيرفر يعمل بشكل ممتاز (Operational)</div>
    </header>

    <div class="status-strip">
      <div class="status-card">
        <div class="status-label">الحالة التشغيلية</div>
        <div class="status-value">جاهز للاستقبال • 200 OK</div>
      </div>
      <div class="status-card">
        <div class="status-label">نموذج Gemini الأساسي</div>
        <div class="status-value" style="font-family: monospace; font-size: 13px;">${MODEL_NAME}</div>
      </div>
      <div class="status-card">
        <div class="status-label">حساب تويتش (جعفر)</div>
        <div class="status-value" id="twitchCardStatus" style="font-size: 13px;">جاري الفحص...</div>
      </div>
      <div class="status-card">
        <div class="status-label">نظام الحماية والتعافي</div>
        <div class="status-value" style="font-size: 12px; color: var(--success-text);">محاولتان كحد أقصى • تعافي سريع</div>
      </div>
    </div>

    <!-- Twitch OAuth Card -->
    <div class="card" style="border: 1px solid var(--twitch-border);">
      <h2>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="#9146FF"><path d="M11.571 4.714h1.715v5.143H11.57zm4.715 0H18v5.143h-1.714zM6 0L1.714 4.286v15.428h5.143V24l4.286-4.286h3.428L22.286 12V0zm14.571 11.143l-3.428 3.428h-3.429l-3 3v-3H6.857V1.714h13.714z"/></svg>
        ربط حساب تويتش المستقل (حساب جعفر • Twitch OAuth)
      </h2>
      <p class="card-caption">
        يتيح ربط حساب تويتش مستقل للبوت "جعفر" بصلاحيات قراءة وكتابة الشات الحديثة (<code style="background: #F3F4F6; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">user:read:chat user:write:chat user:bot</code>) تمهيداً للتفاعل المباشر في الشات:
      </p>

      <div id="twitchAuthDisplay" style="background: #F9FAFB; border: 1px solid var(--card-border); border-radius: 8px; padding: 16px 20px; margin-bottom: 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
          <div>
            <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 2px;">حالة التفويض الحالية:</div>
            <div id="twitchStatusText" style="font-weight: 600; font-size: 14px;">جاري التحقق من السيرفر...</div>
          </div>
          <div style="display: flex; gap: 10px; align-items: center;">
            <a href="/auth/twitch" id="authBtn" class="btn-twitch">ربط حساب تويتش عبر OAuth</a>
            <a href="/auth/twitch/status" target="_blank" class="btn-secondary" style="font-size: 12px; text-decoration: none;">عرض JSON الحالة</a>
          </div>
        </div>
      </div>
      <div style="font-size: 12px; color: var(--text-muted); line-height: 1.6;">
        🔒 <strong>أمان عالي:</strong> يتم استخدام تشفير عشوائي آمن (OAuth State مع TTL) لمنع هجمات CSRF، ولا يتم تسريب أو إظهار الـ Access Token أو الـ Refresh Token في الواجهة نهائياً.
      </div>
    </div>

    <div class="card">
      <h2>تجربة الـ API مباشرة</h2>
      <p class="card-caption">اكتب رسالة كأنك متابع بالشات لتجربة رد الذكاء الاصطناعي الفوري:</p>
      <div class="chips">
        <span class="chip" onclick="setQuery('مرحبا')">مرحبا</span>
        <span class="chip" onclick="setQuery('وش رايك في جيف؟')">وش رايك في جيف؟</span>
        <span class="chip" onclick="setQuery('وش رايك في جيتو؟')">وش رايك في جيتو؟</span>
        <span class="chip" onclick="setQuery('وش رايك في عفيفي؟')">وش رايك في عفيفي؟</span>
        <span class="chip" onclick="setQuery('من ليان؟')">من ليان؟</span>
        <span class="chip" onclick="setQuery('من سولي؟')">من سولي؟</span>
        <span class="chip" onclick="setQuery('جعفر وش رايك بأوفر واتش؟')">جعفر وش رايك بأوفر واتش؟</span>
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
      <div class="endpoint-item">
        <div style="display: flex; align-items: center;">
          <span class="method method-purple">GET</span>
          <code style="color: #374151; font-weight: 500; margin-right: 8px;">/auth/twitch</code>
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
          <span style="color: var(--text-muted); font-size: 13px;">بدء تفويض حساب تويتش بحماية State</span>
          <span style="font-family: monospace; font-size: 12px; color: var(--twitch);">302 Redirect</span>
        </div>
      </div>
      <div class="endpoint-item">
        <div style="display: flex; align-items: center;">
          <span class="method method-purple">GET</span>
          <code style="color: #374151; font-weight: 500; margin-right: 8px;">/auth/twitch/callback</code>
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
          <span style="color: var(--text-muted); font-size: 13px;">معالجة كود التفويض وتخزين التوكنات بأمان</span>
          <span class="status-ok">200 HTML</span>
        </div>
      </div>
      <div class="endpoint-item">
        <div style="display: flex; align-items: center;">
          <span class="method method-purple">GET</span>
          <code style="color: #374151; font-weight: 500; margin-right: 8px;">/auth/twitch/status</code>
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
          <span style="color: var(--text-muted); font-size: 13px;">فحص حالة تفويض الحساب وهوية البوت</span>
          <span class="status-ok">200 JSON</span>
        </div>
      </div>
    </div>
  </div>

  <script>
    const origin = window.location.origin;
    document.querySelectorAll('.appDomainSpan').forEach(el => el.innerText = origin);

    // Check Twitch status dynamically
    fetch('/auth/twitch/status')
      .then(res => res.json())
      .then(data => {
        const statusText = document.getElementById('twitchStatusText');
        const cardStatus = document.getElementById('twitchCardStatus');
        const authBtn = document.getElementById('authBtn');
        if (data.authorized && data.account) {
          statusText.innerHTML = '<span style="color: #065F46;">✓ مفوض ومتصل: ' + data.account.displayName + ' (@' + data.account.login + ')</span>';
          cardStatus.innerHTML = '<span style="color: #065F46;">متصل (' + data.account.login + ')</span>';
          authBtn.innerText = 'إعادة الربط أو التبديل';
        } else {
          statusText.innerHTML = '<span style="color: #B45309;">⚠️ غير متصل حتى الآن</span>';
          cardStatus.innerHTML = '<span style="color: #B45309;">غير متصل</span>';
        }
      })
      .catch(() => {
        document.getElementById('twitchStatusText').innerText = 'غير متصل';
        document.getElementById('twitchCardStatus').innerText = 'غير متصل';
      });

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
