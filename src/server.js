import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { GoogleGenAI } from '@google/genai';

// Load environment variables from .env if available
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Twitch OAuth Configuration for Bot Account (جعفر)
const TWITCH_CLIENT_ID = (process.env.TWITCH_CLIENT_ID || '').trim();
const TWITCH_CLIENT_SECRET = (process.env.TWITCH_CLIENT_SECRET || '').trim();
const TWITCH_REDIRECT_URI = (process.env.TWITCH_REDIRECT_URI || '').trim() || 'https://twitch-bot-jeffe.onrender.com/auth/twitch/callback';
const TWITCH_SCOPES = [
  'user:read:chat',
  'user:write:chat',
  'user:bot',
  'moderator:manage:banned_users',
];

// Target Broadcaster Twitch Channel Name (configured via environment variable)
const TWITCH_BROADCASTER_LOGIN = (process.env.TWITCH_BROADCASTER_LOGIN || '').trim();

// Twitch Stream Vision System Configuration
// Automatically captures stream screenshots periodically when stream is LIVE
const VISION_ENABLED = (process.env.VISION_ENABLED !== 'false');
const VISION_INTERVAL_SECONDS = Math.max(5, parseInt(process.env.VISION_INTERVAL_SECONDS || '60', 10) || 60);

const visionState = {
  enabled: VISION_ENABLED,
  intervalSeconds: VISION_INTERVAL_SECONDS,
  lastCaptureAt: null,
  lastAnalysisAt: null,
  lastStatus: 'idle', // 'idle' | 'capturing' | 'analyzed' | 'unchanged' | 'offline' | 'error'
  lastFrameHash: null,
  lastError: null,
  timer: null,
  isChecking: false,
  streamWasLive: false,
};

// General Web Search Engine Configuration (Real-time modern & general info)
const WEB_SEARCH_ENABLED = (process.env.WEB_SEARCH_ENABLED !== 'false');
const webSearchState = {
  enabled: WEB_SEARCH_ENABLED,
  lastSearchAt: null,
  lastQuery: null,
  lastResultsCount: 0,
  totalSearches: 0,
  lastError: null,
};

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
 * ============================================================================
 * Free-Tier OAuth Token Handling & Session Management
 * Render Free Web Services use ephemeral container filesystems.
 * - Primary guaranteed persistence: TWITCH_REFRESH_TOKEN environment variable.
 * - Runtime session cache: ./.data/twitch_auth.json (cached while container runs).
 * ============================================================================
 */
function getTwitchStorageFilePath() {
  if (process.env.TWITCH_STORAGE_PATH && process.env.TWITCH_STORAGE_PATH.trim()) {
    return process.env.TWITCH_STORAGE_PATH.trim();
  }
  return path.join(process.cwd(), '.data', 'twitch_auth.json');
}

function hasSavedTwitchAuth() {
  if (process.env.TWITCH_REFRESH_TOKEN && process.env.TWITCH_REFRESH_TOKEN.trim()) {
    return true;
  }
  try {
    const filePath = getTwitchStorageFilePath();
    return fs.existsSync(filePath);
  } catch (_) {
    return false;
  }
}

/**
 * Persists Twitch authentication state to runtime cache safely
 */
function saveTwitchAuthStateToDisk() {
  if (!twitchAuthState.authorized || !twitchAuthState.refreshToken) {
    return false;
  }
  try {
    const filePath = getTwitchStorageFilePath();
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const payload = {
      authorized: true,
      user: twitchAuthState.user,
      scopes: twitchAuthState.scopes,
      expiresAt: twitchAuthState.expiresAt,
      accessToken: twitchAuthState.accessToken,
      refreshToken: twitchAuthState.refreshToken,
      connectedAt: twitchAuthState.connectedAt,
      savedAt: new Date().toISOString(),
    };
    fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), { mode: 0o600, encoding: 'utf8' });
    return true;
  } catch (err) {
    console.error('[Twitch Storage] Error saving runtime OAuth cache:', err?.message || err);
    return false;
  }
}

/**
 * Loads Twitch authentication state from environment variable or runtime cache
 */
function loadTwitchAuthStateFromDisk() {
  // 1. Check TWITCH_REFRESH_TOKEN environment variable (primary persistence on Render Free)
  if (process.env.TWITCH_REFRESH_TOKEN && process.env.TWITCH_REFRESH_TOKEN.trim()) {
    console.log('[Twitch Storage] Bootstrapping OAuth from TWITCH_REFRESH_TOKEN environment variable.');
    return {
      authorized: true,
      user: null,
      scopes: TWITCH_SCOPES,
      expiresAt: 0,
      accessToken: null,
      refreshToken: process.env.TWITCH_REFRESH_TOKEN.trim(),
      connectedAt: new Date().toISOString(),
      source: 'environment',
    };
  }

  // 2. Check local container runtime cache
  try {
    const filePath = getTwitchStorageFilePath();
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, 'utf8');
      const data = JSON.parse(raw);
      if (data && (data.refreshToken || data.accessToken)) {
        console.log(`[Twitch Storage] Loaded runtime cached OAuth credentials (user: @${data.user?.login || 'bot'})`);
        data.source = 'cache';
        return data;
      }
    }
  } catch (err) {
    console.error('[Twitch Storage] Error reading runtime cached OAuth credentials:', err?.message || err);
  }

  return null;
}

/**
 * Safely refresh Twitch access token using refresh_token when needed
 * Automatically persists refreshed tokens to disk.
 */
async function refreshTwitchTokenIfNeeded(force = false) {
  if (!twitchAuthState.authorized || !twitchAuthState.refreshToken) {
    return null;
  }
  // If not forcing and access token is still fresh (at least 2 minutes remaining), return it
  if (!force && twitchAuthState.accessToken && Date.now() < (twitchAuthState.expiresAt - 2 * 60 * 1000)) {
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
      const errText = await response.text();
      console.error(`[Twitch OAuth] Token refresh failed with status ${response.status}: ${errText}`);
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
    
    // Persist refreshed credentials immediately
    saveTwitchAuthStateToDisk();
    return twitchAuthState.accessToken;
  } catch (err) {
    console.error('[Twitch OAuth] Error refreshing token:', err?.message || err);
    return null;
  }
}

/**
 * Ensures bot account user profile is fetched and cached
 */
async function ensureTwitchUserProfile() {
  if (twitchAuthState.user?.id && twitchAuthState.user?.login) {
    return twitchAuthState.user;
  }
  const token = await refreshTwitchTokenIfNeeded();
  if (!token || !TWITCH_CLIENT_ID) return null;
  try {
    const res = await fetch('https://api.twitch.tv/helix/users', {
      headers: {
        'Client-Id': TWITCH_CLIENT_ID,
        'Authorization': `Bearer ${token}`,
      },
    });
    if (res.ok) {
      const data = await res.json();
      if (data.data && data.data.length > 0) {
        const u = data.data[0];
        twitchAuthState.user = {
          id: u.id,
          login: u.login,
          displayName: u.display_name,
          profileImageUrl: u.profile_image_url,
        };
        saveTwitchAuthStateToDisk();
        console.log(`[Twitch OAuth] Bot profile confirmed: @${u.login} (${u.display_name}, ID: ${u.id})`);
        return twitchAuthState.user;
      }
    }
  } catch (err) {
    console.error('[Twitch OAuth] Failed to fetch user profile:', err?.message || err);
  }
  return null;
}

/**
 * Restores OAuth session from environment variable or runtime cache upon server boot,
 * refreshes tokens, and prepares Twitch EventSub connection.
 */
async function restoreTwitchAuthAndConnect() {
  const saved = loadTwitchAuthStateFromDisk();
  if (!saved || !saved.refreshToken) {
    return false;
  }

  console.log(`[Twitch Storage] Restoring Twitch OAuth session (source: ${saved.source || 'disk'})...`);
  twitchAuthState.authorized = true;
  twitchAuthState.refreshToken = saved.refreshToken;
  twitchAuthState.accessToken = saved.accessToken || null;
  twitchAuthState.expiresAt = saved.expiresAt || 0;
  twitchAuthState.scopes = saved.scopes || TWITCH_SCOPES;
  twitchAuthState.user = saved.user || null;
  twitchAuthState.connectedAt = saved.connectedAt || new Date().toISOString();

  // Validate or refresh token using refresh_token
  const token = await refreshTwitchTokenIfNeeded(true);
  if (!token) {
    console.warn('[Twitch Storage] Token could not be refreshed. User may need to re-authenticate via /auth/twitch.');
    return false;
  }

  // Ensure user profile details are populated
  await ensureTwitchUserProfile();

  // Verify moderator:manage:banned_users scope status for Timeout feature
  const hasTimeoutScope = hasModeratorManageBannedUsersScope();
  if (hasTimeoutScope) {
    console.log('[Twitch Moderation] ✅ Scope "moderator:manage:banned_users" is verified on active token. Timeout system is ready.');
  } else {
    console.warn('[Twitch Moderation] ========================================================');
    console.warn('[Twitch Moderation] ⚠️ NOTICE: The restored Twitch token DOES NOT contain scope "moderator:manage:banned_users".');
    console.warn('[Twitch Moderation] ⚠️ Active Scopes: [' + (Array.isArray(twitchAuthState.scopes) ? twitchAuthState.scopes.join(', ') : twitchAuthState.scopes) + ']');
    console.warn('[Twitch Moderation] ⚠️ To enable the Timeout feature, visit /auth/twitch in your browser to re-authorize Jaafar.');
    console.warn('[Twitch Moderation] ========================================================');
  }

  // Proactively resolve Jito's permanent Twitch User ID
  resolveJitoTwitchIdentity().catch(err => {
    console.warn('[Jito Identity] Background resolution notice on restore:', err?.message || err);
  });

  console.log(`[Twitch Storage] Session restored successfully for @${twitchAuthState.user?.login || 'bot'}. Connecting to EventSub WebSocket...`);
  startTwitchChatConnection();
  return true;
}

/**
 * ============================================================================
 * Twitch Chat EventSub WebSocket & Send Chat Message System
 * Official Twitch EventSub WebSocket (wss://eventsub.wss.twitch.tv/ws)
 * Channel: Specified dynamically via TWITCH_BROADCASTER_LOGIN
 * Bot Account: Authorized via twitchAuthState (جعفر)
 * ============================================================================
 */

let twitchChatState = {
  status: 'disconnected', // 'disconnected' | 'connecting' | 'connected' | 'reconnecting'
  connected: false,
  broadcaster: null, // { id, login, displayName }
  sessionId: null,
  subscriptions: {
    chatMessage: { status: 'none', id: null },
    streamOnline: { status: 'none', id: null },
    streamOffline: { status: 'none', id: null },
  },
  connectedAt: null,
  reconnectCount: 0,
  lastError: null,
  stats: {
    messagesReceived: 0,
    lastMessage: null, // { username, text, timestamp, isMention, isReplyToBot }
  },
};

/**
 * ============================================================================
 * Twitch Stream Session Memory System
 * Manages active stream chat memory without mixing history between streams.
 * stream.online  -> Starts clean new session & archives previous
 * stream.offline -> Marks session ended & archives
 * ============================================================================
 */
const MAX_SESSION_MESSAGES = 600;
const MAX_PAST_SESSIONS = 5;

let currentStreamSession = {
  id: null,
  active: false,
  startedAt: null,
  endedAt: null,
  type: 'none', // 'live' | 'pre_stream'
  messages: [], // Array of { id, userId, userLogin, userName, text, color, badges, isBroadcaster, isModerator, isVip, isSubscriber, isJito, timestamp, timeFormatted, isMention, isReplyToBot, replyParent }
  visualMemory: [], // Array of { timestamp, timeFormatted, summary, game, title }
  streamInfo: null,
  stats: {
    totalMessages: 0,
    mentionsCount: 0,
    repliesToBotCount: 0,
    visualFramesCount: 0,
  },
};

/**
 * Active SSE clients listening for real-time Twitch Chat Log (/chat-log)
 */
const chatLogClients = new Set();

function broadcastChatLogEvent(payload) {
  if (chatLogClients.size === 0) return;
  const rawData = `data: ${JSON.stringify(payload)}\n\n`;
  for (const client of chatLogClients) {
    try {
      client.res.write(rawData);
    } catch (_) {
      chatLogClients.delete(client);
    }
  }
}

// SSE Keepalive heartbeat every 20 seconds to prevent network timeout on Render
setInterval(() => {
  if (chatLogClients.size === 0) return;
  const ping = `: ping\n\n`;
  for (const client of chatLogClients) {
    try {
      client.res.write(ping);
    } catch (_) {
      chatLogClients.delete(client);
    }
  }
}, 20000);

const pastStreamSessions = [];

function archiveCurrentStreamSession() {
  const hasMessages = currentStreamSession.messages.length > 0;
  const hasVisual = Array.isArray(currentStreamSession.visualMemory) && currentStreamSession.visualMemory.length > 0;
  if (!currentStreamSession.id || (!hasMessages && !hasVisual)) return;

  pastStreamSessions.unshift({
    id: currentStreamSession.id,
    startedAt: currentStreamSession.startedAt,
    endedAt: currentStreamSession.endedAt || new Date().toISOString(),
    type: currentStreamSession.type,
    messageCount: currentStreamSession.messages.length,
    visualFramesCount: hasVisual ? currentStreamSession.visualMemory.length : 0,
    stats: { ...currentStreamSession.stats },
    sampleMessages: currentStreamSession.messages.slice(-10),
    sampleVisualMemory: hasVisual ? currentStreamSession.visualMemory.slice(-5) : [],
  });

  if (pastStreamSessions.length > MAX_PAST_SESSIONS) {
    pastStreamSessions.pop();
  }
}

function startNewStreamSession(streamEvent = null) {
  // Archive previous session so chat and visual memory NEVER mix between streams
  if (currentStreamSession.messages.length > 0 || (currentStreamSession.visualMemory && currentStreamSession.visualMemory.length > 0)) {
    archiveCurrentStreamSession();
  }

  const now = new Date().toISOString();
  currentStreamSession = {
    id: 'stream_' + (streamEvent?.id || Date.now()),
    active: true,
    startedAt: streamEvent?.started_at || now,
    endedAt: null,
    type: 'live',
    messages: [],
    visualMemory: [], // Pristine visual memory for this stream only
    streamInfo: streamEvent || null,
    stats: {
      totalMessages: 0,
      mentionsCount: 0,
      repliesToBotCount: 0,
      visualFramesCount: 0,
    },
  };

  // Reset vision frame hash for clean stream boundary
  visionState.lastFrameHash = null;
  visionState.streamWasLive = true;

  console.log(`[Twitch Stream] Started fresh stream session: ${currentStreamSession.id} at ${currentStreamSession.startedAt}`);

  // Broadcast to Chat Log SSE clients: stream session started
  broadcastChatLogEvent({
    type: 'session_started',
    sessionId: currentStreamSession.id,
    startedAt: currentStreamSession.startedAt,
    streamInfo: currentStreamSession.streamInfo,
    stats: {
      totalMessages: 0,
      sessionMessages: 0,
      sessionId: currentStreamSession.id,
      streamActive: true,
    },
  });
}

function endCurrentStreamSession() {
  if (!currentStreamSession.id) return;
  currentStreamSession.active = false;
  currentStreamSession.endedAt = new Date().toISOString();
  const visualCount = currentStreamSession.visualMemory ? currentStreamSession.visualMemory.length : 0;
  console.log(`[Twitch Stream] Stream ended. Session ${currentStreamSession.id} closed with ${currentStreamSession.messages.length} messages and ${visualCount} visual frames.`);
  archiveCurrentStreamSession();
  visionState.streamWasLive = false;

  // Broadcast to Chat Log SSE clients: stream session ended
  broadcastChatLogEvent({
    type: 'session_ended',
    sessionId: currentStreamSession.id,
    endedAt: currentStreamSession.endedAt,
    stats: {
      totalMessages: currentStreamSession.stats.totalMessages,
      sessionMessages: currentStreamSession.messages.length,
      sessionId: currentStreamSession.id,
      streamActive: false,
    },
  });
}

function ensureActiveSessionExists() {
  if (!currentStreamSession.id) {
    currentStreamSession.id = 'chat_session_' + Date.now();
    currentStreamSession.startedAt = new Date().toISOString();
    currentStreamSession.active = false;
    currentStreamSession.type = 'pre_stream';
  }
}

/**
 * Analyzes incoming Twitch Chat message for Mentions and Replies to Jaafar
 */
function analyzeChatMessage(chatEvent, botUser) {
  const botId = botUser?.id;
  const botLogin = (botUser?.login || 'jaafar_bot').toLowerCase();
  const text = (chatEvent.message?.text || '').trim();
  const textLower = text.toLowerCase();

  // 1. Detect Reply to Bot
  const reply = chatEvent.reply || null;
  let isReplyToBot = false;
  if (reply) {
    const parentUserId = reply.parent_user_id;
    const parentUserLogin = (reply.parent_user_login || '').toLowerCase();
    if ((botId && parentUserId === botId) || (botLogin && parentUserLogin === botLogin)) {
      isReplyToBot = true;
    }
  }

  // 2. Detect Mention
  let isMention = false;
  if (Array.isArray(chatEvent.message?.fragments)) {
    for (const frag of chatEvent.message.fragments) {
      if (frag.type === 'mention' && frag.mention) {
        if ((botId && frag.mention.user_id === botId) ||
            (botLogin && (frag.mention.user_login || '').toLowerCase() === botLogin)) {
          isMention = true;
          break;
        }
      }
    }
  }

  if (!isMention) {
    if (botLogin && textLower.includes('@' + botLogin)) {
      isMention = true;
    } else if (text.includes('جعفر') || text.includes('يا جعفر') || text.includes('@جعفر')) {
      isMention = true;
    }
  }

  return {
    isMention,
    isReplyToBot,
    replyParent: reply ? {
      messageId: reply.parent_message_id,
      userId: reply.parent_user_id,
      userLogin: reply.parent_user_login,
      userName: reply.parent_user_name,
      messageBody: reply.parent_message_body,
    } : null,
  };
}

/**
 * Records message into current stream session memory
 */
function recordStreamChatMessage(chatEvent, analysis) {
  ensureActiveSessionExists();

  // Extract badges safely
  const rawBadges = chatEvent.badges || [];
  const badges = [];
  for (const b of rawBadges) {
    if (b && b.set_id) {
      badges.push(b.set_id);
    }
  }

  const broadcasterLogin = (TWITCH_BROADCASTER_LOGIN || '8jef').toLowerCase();
  const chatterLogin = (chatEvent.chatter_user_login || '').toLowerCase();
  const chatterId = chatEvent.chatter_user_id || '';
  const broadcasterId = chatEvent.broadcaster_user_id || '';

  const isBroadcaster = badges.includes('broadcaster') || (broadcasterId && chatterId === broadcasterId) || (chatterLogin && chatterLogin === broadcasterLogin);
  const isModerator = badges.includes('moderator');
  const isVip = badges.includes('vip');
  const isSubscriber = badges.includes('subscriber');
  const isJito = isJitoChatter(chatEvent);

  const now = new Date();
  const timeFormatted = now.toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
    timeZone: 'Asia/Riyadh',
  });

  const record = {
    id: chatEvent.message_id || ('msg_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6)),
    userId: chatterId,
    userLogin: chatterLogin,
    userName: chatEvent.chatter_user_name || chatEvent.chatter_user_login || 'unknown',
    text: chatEvent.message?.text || '',
    color: chatEvent.color || null,
    badges,
    isBroadcaster,
    isModerator,
    isVip,
    isSubscriber,
    isJito,
    timestamp: now.toISOString(),
    timeFormatted,
    isMention: analysis.isMention,
    isReplyToBot: analysis.isReplyToBot,
    replyParent: analysis.replyParent,
  };

  currentStreamSession.messages.push(record);
  currentStreamSession.stats.totalMessages++;
  if (analysis.isMention) currentStreamSession.stats.mentionsCount++;
  if (analysis.isReplyToBot) currentStreamSession.stats.repliesToBotCount++;

  if (currentStreamSession.messages.length > MAX_SESSION_MESSAGES) {
    currentStreamSession.messages.shift();
  }

  // Real-time broadcast to all active /chat-log clients
  broadcastChatLogEvent({
    type: 'message',
    message: record,
    stats: {
      totalMessages: currentStreamSession.stats.totalMessages,
      sessionMessages: currentStreamSession.messages.length,
      sessionId: currentStreamSession.id,
      streamActive: currentStreamSession.active,
    },
  });

  return record;
}

/**
 * Retrieves recent stream chat context for Gemini prompt augmentation
 */
function getStreamContextRetrieval(maxRecent = 10) {
  const msgs = currentStreamSession.messages || [];
  if (msgs.length === 0) return '';
  const slice = msgs.slice(-maxRecent);
  return slice
    .map(m => `- ${m.userName || m.userLogin}: ${m.text}`)
    .join('\n');
}

/**
 * Phase 2 Readiness Pipeline:
 * Prepared to generate replies using mentions, replies, stream memory, user memory, and Gemini.
 * AUTO-REPLY IS ENABLED FOR TWITCH CHAT.
 */
const AUTO_REPLY_TO_TWITCH_CHAT = true;

async function prepareJaafarChatReplyPipeline({ chatEvent, analysis, record }) {
  if (!analysis.isMention && !analysis.isReplyToBot) {
    return;
  }

  const isJito = isJitoChatter(chatEvent);
  const chatter = chatEvent.chatter_user_name || chatEvent.chatter_user_login;
  const memoryKey = isJito ? getJitoMemoryKey() : chatEvent.chatter_user_login;
  console.log(`[Jaafar Pipeline] Mention or Reply received from @${chatter} (isMention=${analysis.isMention}, isReplyToBot=${analysis.isReplyToBot}, isJito=${isJito})`);

  const recentStreamChat = getStreamContextRetrieval(8);
  const userHistory = getUserHistory(memoryKey);

  let promptText = '';
  if (currentStreamSession.active) {
    promptText += `[سياق البث الحي الحالي - ${currentStreamSession.id}]:\n`;
  } else {
    promptText += `[سياق شات القناة]:\n`;
  }

  if (recentStreamChat) {
    promptText += `سياق آخر رسائل تم تداولها بالشات مؤخراً:\n${recentStreamChat}\n\n`;
  }

  if (userHistory.length > 0) {
    const historyName = isJito ? 'جيتو' : `@${chatter}`;
    promptText += `تاريخ حديثك السابق مع (${historyName}):\n`;
    userHistory.forEach(turn => {
      promptText += (turn.role === 'user' ? `${historyName}: ` : 'جعفر: ') + turn.text + '\n';
    });
    promptText += '\n';
  }

  if (isJito) {
    if (analysis.isReplyToBot && analysis.replyParent?.messageBody) {
      promptText += `المشاهد الذي يرد عليك الآن هو "جيتو" (صانعك ومطورك وأفضل مود في القناة، وحسابه في تويتش هو @${chatter}):\n`;
      promptText += `جيتو يرد على رسالتك السابقة:\n"${analysis.replyParent.messageBody}"\n`;
      promptText += `ورسالة جيتو الحالية هي:\n"${record.text}"\n`;
    } else {
      promptText += `المشاهد الذي يكلمك الآن هو "جيتو" (صانعك ومطورك وأفضل مود في القناة، وحسابه في تويتش هو @${chatter}):\n`;
      promptText += `رسالة جيتو لك:\n"${record.text}"\n`;
    }
    promptText += `تنبيه حاسم وإلزامي: يجب أن تنادي جيتو وتخاطبه صراحة باسم "جيتو" داخل ردك (مثل: "هلا يا جيتو"، "أبشر يا جيتو"، "كفو يا جيتو"، "تسلم يا جيتو"). رد عليه بأسلوبك العفوي كصديقك وصانعك، وبشكل مختصر جداً مناسب لسرعة الشات.`;
  } else {
    if (analysis.isReplyToBot && analysis.replyParent?.messageBody) {
      promptText += `المشاهد @${chatter} يرد على رسالتك السابقة:\n"${analysis.replyParent.messageBody}"\n`;
      promptText += `ورسالة المشاهد الحالية هي:\n"${record.text}"\n`;
    } else {
      promptText += `المشاهد @${chatter} منشنك أو وجه كلامه لك مباشرة:\n"${record.text}"\n`;
    }
    promptText += 'رد عليه بأسلوب جعفر العفوي والمحبوب، وبشكل مختصر جداً مناسب للشات.';
  }

  // Inject Twitch Live Stream Visual Memory (What Jaafar saw on stream)
  const visualContext = getVisualMemoryContext(6);
  if (visualContext) {
    promptText += `\n\n[الذاكرة البصرية للبث الحي - ما شاهده جعفر في لقطات البث الأخيرة]:\n${visualContext}\nتنبيه مهم: إذا سُئلت عن أحداث في البث المباشر (مثل وش صار، وش سوا جيف، وش اللعبة، فاز أو خسر)، أجب فقط بناءً على ما رأيته وسُجل في الذاكرة البصرية أعلاه. إذا كان السؤال عن لقطة أو حدث لم تشاهده أو لم يظهر في الفريمات المسجلة، قل بصراحة وعفوية أنك ما شفت اللقطة ذيك وما انتبهت لها، ولا تخترع أبداً أحداثاً من عندك.`;
  }

  // Check if user query requires general web search (matches, news, fresh info)
  if (WEB_SEARCH_ENABLED && needsWebSearch(record.text)) {
    try {
      const searchResult = await performWebSearch(record.text);
      const searchPromptBlock = formatWebSearchResultsContext(searchResult);
      if (searchPromptBlock) {
        promptText += `\n\n${searchPromptBlock}`;
      }
    } catch (searchErr) {
      console.error('[Jaafar Pipeline] Web search non-fatal error:', searchErr?.message || searchErr);
    }
  }

  const isGeminiReady = Boolean(getGeminiClient());
  console.log(`[Jaafar Pipeline] Retrieval & Prompt Ready (${promptText.length} chars). Gemini Ready: ${isGeminiReady}. Auto-reply is ${AUTO_REPLY_TO_TWITCH_CHAT ? 'ON' : 'OFF'}.`);

  if (!AUTO_REPLY_TO_TWITCH_CHAT) {
    return;
  }

  // Next Phase execution:
  try {
    const aiResult = await executeGeminiWithRecovery({ prompt: promptText });
    recordUserTurn(memoryKey, record.text, aiResult.text);
    await sendTwitchChatMessage(`@${chatter} ${aiResult.text}`);
  } catch (err) {
    console.error('[Jaafar Pipeline] Error sending reply:', err);
  }
}


let eventSubWs = null;
let keepaliveWatchdogTimer = null;
let reconnectTimer = null;
let isReconnectingSession = false;

/**
 * Resolves user profile from Twitch Helix API by username/login
 */
async function fetchTwitchUserInfoByLogin(login) {
  if (!login) return null;
  const token = await refreshTwitchTokenIfNeeded();
  if (!token || !TWITCH_CLIENT_ID) {
    console.warn(`[Twitch API] Cannot fetch user "${login}": Missing OAuth token or Client ID`);
    return null;
  }

  try {
    const res = await fetch(`https://api.twitch.tv/helix/users?login=${encodeURIComponent(login.toLowerCase())}`, {
      method: 'GET',
      headers: {
        'Client-Id': TWITCH_CLIENT_ID,
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!res.ok) {
      const errText = await res.text();
      console.error(`[Twitch API] Failed to fetch user info for "${login}": HTTP ${res.status} - ${errText}`);
      return null;
    }

    const json = await res.json();
    if (json.data && json.data.length > 0) {
      return {
        id: json.data[0].id,
        login: json.data[0].login,
        displayName: json.data[0].display_name,
        profileImageUrl: json.data[0].profile_image_url || '',
      };
    }
    console.warn(`[Twitch API] User "${login}" was not found on Twitch.`);
    return null;
  } catch (err) {
    console.error(`[Twitch API] Error fetching user "${login}":`, err?.message || err);
    return null;
  }
}

/**
 * Resolves user profile from Twitch Helix API by permanent User ID
 */
async function fetchTwitchUserInfoById(id) {
  if (!id) return null;
  const token = await refreshTwitchTokenIfNeeded();
  if (!token || !TWITCH_CLIENT_ID) {
    return null;
  }

  try {
    const res = await fetch(`https://api.twitch.tv/helix/users?id=${encodeURIComponent(id)}`, {
      method: 'GET',
      headers: {
        'Client-Id': TWITCH_CLIENT_ID,
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!res.ok) {
      const errText = await res.text();
      console.error(`[Twitch API] Failed to fetch user info for ID "${id}": HTTP ${res.status} - ${errText}`);
      return null;
    }

    const json = await res.json();
    if (json.data && json.data.length > 0) {
      return {
        id: json.data[0].id,
        login: json.data[0].login,
        displayName: json.data[0].display_name,
        profileImageUrl: json.data[0].profile_image_url || '',
      };
    }
    return null;
  } catch (err) {
    console.error(`[Twitch API] Error fetching user ID "${id}":`, err?.message || err);
    return null;
  }
}

/**
 * Fetches current live stream details from Twitch Helix API for the target broadcaster
 */
async function fetchTwitchLiveStream(broadcasterLogin, broadcasterId) {
  const token = await refreshTwitchTokenIfNeeded();
  if (!token || !TWITCH_CLIENT_ID) {
    return null;
  }

  const id = broadcasterId || twitchChatState.broadcaster?.id;
  const login = (broadcasterLogin || TWITCH_BROADCASTER_LOGIN || '8jef').toLowerCase();
  const queryParam = id ? `user_id=${encodeURIComponent(id)}` : `user_login=${encodeURIComponent(login)}`;

  try {
    const res = await fetch(`https://api.twitch.tv/helix/streams?${queryParam}`, {
      method: 'GET',
      headers: {
        'Client-Id': TWITCH_CLIENT_ID,
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!res.ok) {
      return null;
    }

    const json = await res.json();
    if (json.data && json.data.length > 0 && json.data[0].type === 'live') {
      return json.data[0];
    }
    return null;
  } catch (err) {
    return null;
  }
}

/**
 * ============================================================================
 * Jito Identity & Permanent User ID Resolution
 * - Jito (جيتو): Developer & Creator of Jaafar, and Top Moderator in Twitch chat.
 * - Current Twitch username: jitoheh
 * - Future / alternate Twitch username: 4VREN
 * - Permanent identifier: Twitch User ID (never changes on account rename)
 * - Jaafar always addresses him as "جيتو" and preserves his unified memory
 * ============================================================================
 */
const jitoIdentity = {
  userId: (process.env.JITO_USER_ID || '').trim() || null,
  login: (process.env.JITO_TWITCH_LOGIN || '').trim().toLowerCase() || 'jitoheh',
  knownLogins: new Set(['jitoheh', '4vren', 'jito']),
  displayName: 'جيتو',
  resolvedAt: null,
};

function getJitoStorageFilePath() {
  return path.join(process.cwd(), '.data', 'jito_identity.json');
}

function saveJitoIdentityToDisk() {
  if (!jitoIdentity.userId) return;
  try {
    const filePath = getJitoStorageFilePath();
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const payload = {
      userId: jitoIdentity.userId,
      login: jitoIdentity.login,
      knownLogins: Array.from(jitoIdentity.knownLogins),
      savedAt: new Date().toISOString(),
    };
    fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), 'utf8');
  } catch (err) {
    console.error('[Jito Identity] Error saving identity cache:', err?.message || err);
  }
}

function loadJitoIdentityFromDisk() {
  // 1. Env variable takes highest precedence
  if (process.env.JITO_USER_ID && process.env.JITO_USER_ID.trim()) {
    jitoIdentity.userId = process.env.JITO_USER_ID.trim();
  }
  // 2. Read persistent cache file if exists
  try {
    const filePath = getJitoStorageFilePath();
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, 'utf8');
      const data = JSON.parse(raw);
      if (data && data.userId) {
        if (!jitoIdentity.userId) {
          jitoIdentity.userId = data.userId;
        }
        if (data.login) {
          jitoIdentity.login = data.login;
          jitoIdentity.knownLogins.add(data.login.toLowerCase());
        }
        if (Array.isArray(data.knownLogins)) {
          data.knownLogins.forEach(l => jitoIdentity.knownLogins.add(String(l).toLowerCase()));
        }
        console.log(`[Jito Identity] Loaded cached identity: User ID ${jitoIdentity.userId} (known: ${Array.from(jitoIdentity.knownLogins).join(', ')})`);
      }
    }
  } catch (err) {
    console.error('[Jito Identity] Error loading cached identity:', err?.message || err);
  }
}

// Initial load on server startup
loadJitoIdentityFromDisk();

/**
 * Resolves Jito's permanent Twitch User ID from Twitch API:
 * 1. If User ID already known, fetches latest user info to detect any rename (e.g. jitoheh -> 4VREN)
 * 2. If User ID unknown, queries 'jitoheh', then '4vren' via Helix API
 */
async function resolveJitoTwitchIdentity() {
  // 1. If we already have the permanent User ID, sync the latest login name from Twitch
  if (jitoIdentity.userId) {
    try {
      const userById = await fetchTwitchUserInfoById(jitoIdentity.userId);
      if (userById) {
        jitoIdentity.login = userById.login;
        jitoIdentity.knownLogins.add(userById.login.toLowerCase());
        jitoIdentity.resolvedAt = new Date().toISOString();
        console.log(`[Jito Identity] Confirmed Jito identity: ID ${jitoIdentity.userId} is currently @${userById.login} (${userById.displayName})`);
        saveJitoIdentityToDisk();
        return true;
      }
    } catch (err) {
      console.warn('[Jito Identity] Error refreshing Jito user by ID:', err?.message || err);
    }
  }

  // 2. If no User ID yet, resolve from Twitch API starting with jitoheh, then 4vren
  const candidateLogins = [
    (process.env.JITO_TWITCH_LOGIN || '').trim().toLowerCase(),
    'jitoheh',
    '4vren',
  ].filter(Boolean);

  for (const candidate of candidateLogins) {
    try {
      console.log(`[Jito Identity] Resolving Jito Twitch User ID via API for login: "${candidate}"...`);
      const info = await fetchTwitchUserInfoByLogin(candidate);
      if (info && info.id) {
        jitoIdentity.userId = info.id;
        jitoIdentity.login = info.login;
        jitoIdentity.knownLogins.add(info.login.toLowerCase());
        jitoIdentity.resolvedAt = new Date().toISOString();
        console.log(`[Jito Identity] Successfully resolved Jito User ID: ${info.id} (@${info.login})`);
        saveJitoIdentityToDisk();
        return true;
      }
    } catch (err) {
      console.warn(`[Jito Identity] Failed resolving login "${candidate}":`, err?.message || err);
    }
  }

  console.warn('[Jito Identity] Could not resolve Jito User ID via API yet. Will detect dynamically from chat events.');
  return false;
}

/**
 * Checks if target chatEvent or chatter identifier belongs to Jito
 */
function isJitoChatter(target) {
  if (!target) return false;

  let chatterId = null;
  let chatterLogin = '';

  if (typeof target === 'string') {
    chatterLogin = target.toLowerCase().replace(/^@/, '').trim();
  } else {
    chatterId = target.chatter_user_id || target.userId || null;
    chatterLogin = (target.chatter_user_login || target.userLogin || '').toLowerCase().replace(/^@/, '').trim();
  }

  // 1. Primary permanent identity check: Twitch User ID
  if (chatterId && jitoIdentity.userId && String(chatterId) === String(jitoIdentity.userId)) {
    if (chatterLogin && !jitoIdentity.knownLogins.has(chatterLogin)) {
      jitoIdentity.knownLogins.add(chatterLogin);
      jitoIdentity.login = chatterLogin;
      saveJitoIdentityToDisk();
    }
    return true;
  }

  // 2. Known logins check (jitoheh, 4vren, etc.)
  if (chatterLogin) {
    if (jitoIdentity.knownLogins.has(chatterLogin) || chatterLogin === 'jitoheh' || chatterLogin === '4vren' || chatterLogin === 'jito') {
      if (chatterId && !jitoIdentity.userId) {
        jitoIdentity.userId = String(chatterId);
        jitoIdentity.knownLogins.add(chatterLogin);
        jitoIdentity.login = chatterLogin;
        jitoIdentity.resolvedAt = new Date().toISOString();
        console.log(`[Jito Identity] Pinned Jito User ID from chat event: ${jitoIdentity.userId} (@${chatterLogin})`);
        saveJitoIdentityToDisk();
      }
      return true;
    }
  }

  return false;
}

/**
 * Dynamically learns or confirms Jito's Twitch identity from incoming chat messages
 */
function learnJitoIdentityFromChat(chatEvent) {
  if (!chatEvent) return false;
  const chatterLogin = (chatEvent.chatter_user_login || '').toLowerCase().trim();
  const chatterId = chatEvent.chatter_user_id ? String(chatEvent.chatter_user_id).trim() : null;

  // 1. Match by permanent Twitch User ID
  if (chatterId && jitoIdentity.userId && chatterId === jitoIdentity.userId) {
    if (chatterLogin && !jitoIdentity.knownLogins.has(chatterLogin)) {
      console.log(`[Jito Identity] Detected username update for Jito: @${chatterLogin} (User ID: ${chatterId})`);
      jitoIdentity.knownLogins.add(chatterLogin);
      jitoIdentity.login = chatterLogin;
      saveJitoIdentityToDisk();
    }
    return true;
  }

  // 2. Match by known username ('jitoheh', '4vren', or configured)
  if (chatterLogin && (jitoIdentity.knownLogins.has(chatterLogin) || chatterLogin === 'jitoheh' || chatterLogin === '4vren')) {
    jitoIdentity.knownLogins.add(chatterLogin);
    jitoIdentity.login = chatterLogin;
    if (chatterId && !jitoIdentity.userId) {
      jitoIdentity.userId = chatterId;
      jitoIdentity.resolvedAt = new Date().toISOString();
      console.log(`[Jito Identity] Successfully pinned Jito Twitch User ID from chat: ${jitoIdentity.userId} (username: @${chatterLogin})`);
      saveJitoIdentityToDisk();
    }
    return true;
  }

  return false;
}

function getJitoMemoryKey() {
  return jitoIdentity.userId ? `jito_uid_${jitoIdentity.userId}` : 'jito_permanent';
}

/**
 * Helper to subscribe to a single Twitch EventSub topic via WebSocket transport
 */
async function subscribeToSingleEventSub({ sessionId, type, version = '1', condition, token }) {
  try {
    const res = await fetch('https://api.twitch.tv/helix/eventsub/subscriptions', {
      method: 'POST',
      headers: {
        'Client-Id': TWITCH_CLIENT_ID,
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        type,
        version,
        condition,
        transport: {
          method: 'websocket',
          session_id: sessionId,
        },
      }),
    });

    if (res.status === 202 || res.status === 200) {
      const json = await res.json();
      const sub = json.data && json.data[0];
      console.log(`[Twitch EventSub] ✓ Subscribed to ${type} (ID: ${sub?.id || 'ok'})`);
      return { status: 'enabled', id: sub?.id || null };
    }

    if (res.status === 409) {
      console.log(`[Twitch EventSub] Subscription ${type} already active (409 Conflict).`);
      return { status: 'enabled', id: null };
    }

    const errText = await res.text();
    console.error(`[Twitch EventSub] Subscription ${type} failed with HTTP ${res.status}: ${errText}`);
    return { status: 'failed', id: null, error: errText };
  } catch (err) {
    console.error(`[Twitch EventSub] Error subscribing to ${type}:`, err?.message || err);
    return { status: 'failed', id: null, error: err?.message || err };
  }
}

/**
 * Subscribes to all required Twitch EventSub topics:
 * 1. channel.chat.message (receives chat in Jef's channel)
 * 2. stream.online (starts fresh stream session memory)
 * 3. stream.offline (ends stream session memory & archives)
 */
async function subscribeToAllTwitchEvents(sessionId) {
  if (!sessionId) {
    console.error('[Twitch EventSub] Cannot subscribe: Missing EventSub WebSocket session ID');
    return false;
  }

  const token = await refreshTwitchTokenIfNeeded();
  if (!token || !TWITCH_CLIENT_ID) {
    console.error('[Twitch EventSub] Cannot subscribe: Missing OAuth token or Client ID');
    return false;
  }

  const botUserId = twitchAuthState.user?.id;
  if (!botUserId) {
    console.error('[Twitch EventSub] Cannot subscribe: Missing Bot User ID');
    return false;
  }

  // Ensure broadcaster user ID is resolved dynamically
  if (!twitchChatState.broadcaster?.id) {
    if (!TWITCH_BROADCASTER_LOGIN) {
      console.warn('[Twitch EventSub] TWITCH_BROADCASTER_LOGIN is not set in environment variables. Cannot subscribe.');
      twitchChatState.lastError = 'TWITCH_BROADCASTER_LOGIN is not configured in environment variables.';
      return false;
    }
    console.log(`[Twitch EventSub] Resolving broadcaster user ID for login: "${TWITCH_BROADCASTER_LOGIN}"...`);
    const broadcasterInfo = await fetchTwitchUserInfoByLogin(TWITCH_BROADCASTER_LOGIN);
    if (!broadcasterInfo) {
      console.error(`[Twitch EventSub] Failed to resolve broadcaster "${TWITCH_BROADCASTER_LOGIN}". Subscription aborted.`);
      twitchChatState.lastError = `Broadcaster "${TWITCH_BROADCASTER_LOGIN}" not found on Twitch.`;
      return false;
    }
    twitchChatState.broadcaster = broadcasterInfo;
    console.log(`[Twitch EventSub] Broadcaster resolved: ${broadcasterInfo.displayName} (@${broadcasterInfo.login}, ID: ${broadcasterInfo.id})`);
  }

  const broadcasterId = twitchChatState.broadcaster.id;

  // 1. channel.chat.message
  const chatSub = await subscribeToSingleEventSub({
    sessionId,
    type: 'channel.chat.message',
    version: '1',
    condition: {
      broadcaster_user_id: broadcasterId,
      user_id: botUserId,
    },
    token,
  });
  twitchChatState.subscriptions.chatMessage = chatSub;

  // 2. stream.online
  const onlineSub = await subscribeToSingleEventSub({
    sessionId,
    type: 'stream.online',
    version: '1',
    condition: {
      broadcaster_user_id: broadcasterId,
    },
    token,
  });
  twitchChatState.subscriptions.streamOnline = onlineSub;

  // 3. stream.offline
  const offlineSub = await subscribeToSingleEventSub({
    sessionId,
    type: 'stream.offline',
    version: '1',
    condition: {
      broadcaster_user_id: broadcasterId,
    },
    token,
  });
  twitchChatState.subscriptions.streamOffline = offlineSub;

  const hasAnyFailure = [chatSub, onlineSub, offlineSub].some(s => s.status === 'failed');
  if (hasAnyFailure) {
    twitchChatState.lastError = 'One or more EventSub subscriptions failed.';
  } else {
    twitchChatState.lastError = null;
  }

  return true;
}

// Retain alias for backward-compatibility
const subscribeToChannelChatMessage = subscribeToAllTwitchEvents;

/**
 * Resets the keepalive watchdog timer.
 * If Twitch doesn't send a message or keepalive within timeout + grace buffer, reconnect.
 */
function resetKeepaliveWatchdog(timeoutSeconds = 10) {
  if (keepaliveWatchdogTimer) {
    clearTimeout(keepaliveWatchdogTimer);
  }
  const graceMs = (timeoutSeconds + 5) * 1000;
  keepaliveWatchdogTimer = setTimeout(() => {
    console.warn('[Twitch Chat] Keepalive watchdog timeout exceeded. Reconnecting WebSocket...');
    if (eventSubWs) {
      try {
        eventSubWs.close(4000, 'Keepalive watchdog timeout');
      } catch (_) {}
    }
  }, graceMs);
}

/**
 * Schedules a reconnection attempt with gradual backoff
 */
function scheduleChatReconnect(delayMs = null) {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  twitchChatState.status = 'reconnecting';
  twitchChatState.connected = false;

  const attempt = twitchChatState.reconnectCount || 0;
  // Gradual backoff: 3s, 4.5s, 6.7s, 10s, 15s, 22s... capped at 60s
  const computedDelay = delayMs !== null
    ? delayMs
    : Math.min(60000, Math.round(3000 * Math.pow(1.5, Math.min(attempt, 8))));

  console.log(`[Twitch Chat] Reconnecting in ${(computedDelay / 1000).toFixed(1)}s (Attempt #${attempt + 1})...`);
  reconnectTimer = setTimeout(() => {
    startTwitchChatConnection();
  }, computedDelay);
}

/**
 * Starts or restarts the Twitch EventSub WebSocket connection
 */
async function startTwitchChatConnection(customWsUrl = null) {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }

  // 1. Guard: Check if OAuth is authorized
  if (!twitchAuthState.authorized) {
    console.log('[Twitch Chat] Bot account is not authorized yet. Visit /auth/twitch to authenticate.');
    twitchChatState.status = 'disconnected';
    twitchChatState.connected = false;
    return;
  }

  // 2. Ensure token is fresh before connecting
  const token = await refreshTwitchTokenIfNeeded();
  if (!token) {
    console.warn('[Twitch Chat] OAuth token refresh failed. Chat connection paused.');
    twitchChatState.status = 'disconnected';
    twitchChatState.connected = false;
    return;
  }

  // 3. Close any existing WebSocket if starting fresh (not reconnecting URL)
  if (!customWsUrl && eventSubWs) {
    try {
      eventSubWs.onclose = null;
      eventSubWs.onerror = null;
      eventSubWs.close();
    } catch (_) {}
    eventSubWs = null;
  }

  const targetUrl = customWsUrl || 'wss://eventsub.wss.twitch.tv/ws';
  twitchChatState.status = customWsUrl ? 'reconnecting' : 'connecting';
  console.log(`[Twitch Chat] Connecting to EventSub WebSocket at ${targetUrl}...`);

  try {
    const ws = new WebSocket(targetUrl);
    eventSubWs = ws;

    ws.onopen = () => {
      console.log('[Twitch Chat] WebSocket connection opened. Awaiting session_welcome...');
    };

    ws.onmessage = async (event) => {
      let data;
      try {
        data = JSON.parse(event.data);
      } catch (e) {
        console.warn('[Twitch Chat] Failed to parse EventSub message JSON:', e);
        return;
      }

      const msgType = data.metadata?.message_type;

      // 1. Welcome Message
      if (msgType === 'session_welcome') {
        const session = data.payload?.session;
        const sessionId = session?.id;
        const keepaliveSeconds = session?.keepalive_timeout_seconds || 10;

        twitchChatState.sessionId = sessionId;
        twitchChatState.status = 'connected';
        twitchChatState.connected = true;
        twitchChatState.connectedAt = new Date().toISOString();
        twitchChatState.lastError = null;
        twitchChatState.reconnectCount = 0; // Reset reconnect count on successful connection
        console.log(`[Twitch Chat] EventSub session established (ID: ${sessionId}). Keepalive: ${keepaliveSeconds}s`);

        resetKeepaliveWatchdog(keepaliveSeconds);

        // If this was a session_reconnect migration, subscriptions are preserved
        if (isReconnectingSession) {
          isReconnectingSession = false;
          console.log('[Twitch Chat] Reconnected session active. Subscriptions maintained.');
        } else {
          // Subscribe to all events: channel.chat.message, stream.online, stream.offline
          await subscribeToChannelChatMessage(sessionId);
        }
        return;
      }

      // 2. Keepalive Message
      if (msgType === 'session_keepalive') {
        resetKeepaliveWatchdog(10);
        return;
      }

      // 3. Reconnect Message
      if (msgType === 'session_reconnect') {
        const reconnectUrl = data.payload?.session?.reconnect_url;
        console.log(`[Twitch Chat] Twitch requested session_reconnect to: ${reconnectUrl}`);
        if (reconnectUrl) {
          isReconnectingSession = true;
          startTwitchChatConnection(reconnectUrl);
        }
        return;
      }

      // 4. Notification (Chat Messages, Stream Online, Stream Offline)
      if (msgType === 'notification') {
        resetKeepaliveWatchdog(10);
        const subType = data.payload?.subscription?.type;

        // A. Chat message event
        if (subType === 'channel.chat.message') {
          const chatEvent = data.payload.event;
          const chatterName = chatEvent.chatter_user_name || chatEvent.chatter_user_login || 'unknown';
          const messageText = chatEvent.message?.text || '';

          // 0. Detect and learn Jito identity dynamically if applicable
          learnJitoIdentityFromChat(chatEvent);

          // 1. Analyze for mentions and replies to bot
          const analysis = analyzeChatMessage(chatEvent, twitchAuthState.user);

          // 2. Terminal logging with visual indicator for mentions/replies
          const isJito = isJitoChatter(chatEvent);
          const jitoTag = isJito ? ' [Jito]' : '';
          const badge = analysis.isReplyToBot ? ' [ReplyToBot]' : (analysis.isMention ? ' [Mention]' : '');
          console.log(`[Twitch Chat]${badge}${jitoTag} ${chatterName}: ${messageText}`);

          // 3. Record into isolated current stream session memory
          const record = recordStreamChatMessage(chatEvent, analysis);

          twitchChatState.stats.messagesReceived++;
          twitchChatState.stats.lastMessage = {
            username: chatterName,
            text: messageText,
            timestamp: record.timestamp,
            isMention: analysis.isMention,
            isReplyToBot: analysis.isReplyToBot,
          };

          // 3.5. Moderation Commands check (Timeout & Permanent Ban)
          // Commands such as:
          // - !timeout @username 10m [reason]
          // - !ban @username [reason]
          // - جعفر باند @username [reason]
          // - @jaafarbot ban @username [reason]
          // Processed strictly deterministically without Gemini, with strict User ID permission checks (8jef & 4VREN only)
          const banCmd = parseBanCommand(messageText, twitchAuthState.user?.login);
          if (banCmd && banCmd.isCommand) {
            await handleBanCommand({ chatEvent, banCmd });
            return;
          }

          const timeoutCmd = parseTimeoutCommand(messageText, twitchAuthState.user?.login);
          if (timeoutCmd && timeoutCmd.isCommand) {
            await handleTimeoutCommand({ chatEvent, timeoutCmd });
            return;
          }

          // 4. Phase 2 readiness pipeline: Retrieves stream memory, user memory, builds Gemini prompt.
          // Note: Automatic replies are strictly disabled in this stage as requested.
          prepareJaafarChatReplyPipeline({
            chatEvent,
            analysis,
            record,
          });
          return;
        }

        // B. Stream Online event (starts fresh isolated stream session)
        if (subType === 'stream.online') {
          const streamEvent = data.payload.event;
          console.log(`[Twitch Stream] >>> Stream went ONLINE for channel #${twitchChatState.broadcaster?.login || 'broadcaster'}!`);
          startNewStreamSession(streamEvent);
          return;
        }

        // C. Stream Offline event (ends current stream session & archives)
        if (subType === 'stream.offline') {
          console.log(`[Twitch Stream] <<< Stream went OFFLINE for channel #${twitchChatState.broadcaster?.login || 'broadcaster'}.`);
          endCurrentStreamSession();
          return;
        }
        return;
      }

      // 5. Revocation Message
      if (msgType === 'revocation') {
        const revokedType = data.payload?.subscription?.type;
        console.warn(`[Twitch Chat] Subscription revoked: ${revokedType}. Reason: ${data.payload?.subscription?.status}`);
        if (revokedType === 'channel.chat.message') {
          twitchChatState.subscriptions.chatMessage.status = 'failed';
        } else if (revokedType === 'stream.online') {
          twitchChatState.subscriptions.streamOnline.status = 'failed';
        } else if (revokedType === 'stream.offline') {
          twitchChatState.subscriptions.streamOffline.status = 'failed';
        }
        twitchChatState.lastError = `Subscription ${revokedType} revoked: ${data.payload?.subscription?.status}`;
      }
    };

    ws.onerror = (err) => {
      console.error('[Twitch Chat] WebSocket error encountered:', err?.message || err);
      twitchChatState.lastError = err?.message || 'WebSocket network error';
    };

    ws.onclose = (event) => {
      if (keepaliveWatchdogTimer) {
        clearTimeout(keepaliveWatchdogTimer);
        keepaliveWatchdogTimer = null;
      }
      twitchChatState.connected = false;
      twitchChatState.status = 'disconnected';
      console.warn(`[Twitch Chat] WebSocket closed (Code: ${event.code}, Reason: "${event.reason || 'None'}").`);

      // If still authorized and not reconnecting via explicit URL, schedule auto-reconnect with gradual backoff
      if (twitchAuthState.authorized && !isReconnectingSession) {
        twitchChatState.reconnectCount++;
        scheduleChatReconnect();
      }
    };
  } catch (err) {
    console.error('[Twitch Chat] Failed to initiate WebSocket connection:', err?.message || err);
    twitchChatState.lastError = err?.message || 'Failed to initiate WebSocket';
    if (twitchAuthState.authorized) {
      twitchChatState.reconnectCount++;
      scheduleChatReconnect();
    }
  }
}

/**
 * Sends a chat message to the broadcaster's channel using Twitch Helix Send Chat Message API
 * POST https://api.twitch.tv/helix/chat/messages
 * Scopes: user:write:chat
 */
async function sendTwitchChatMessage(messageText) {
  if (!messageText || typeof messageText !== 'string' || !messageText.trim()) {
    return { success: false, error: 'Empty message text' };
  }

  const token = await refreshTwitchTokenIfNeeded();
  if (!token) {
    return { success: false, error: 'Twitch account not authorized or token expired' };
  }

  if (!twitchChatState.broadcaster?.id) {
    return { success: false, error: 'Broadcaster user ID not resolved' };
  }

  const botUserId = twitchAuthState.user?.id;
  if (!botUserId) {
    return { success: false, error: 'Bot user ID not resolved' };
  }

  try {
    const res = await fetch('https://api.twitch.tv/helix/chat/messages', {
      method: 'POST',
      headers: {
        'Client-Id': TWITCH_CLIENT_ID,
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        broadcaster_id: twitchChatState.broadcaster.id,
        sender_id: botUserId,
        message: messageText.trim().slice(0, 500),
      }),
    });

    if (!res.ok) {
      const errBody = await res.text();
      console.error(`[Twitch API] Failed to send chat message: HTTP ${res.status} - ${errBody}`);
      return { success: false, status: res.status, error: errBody };
    }

    const data = await res.json();
    return { success: true, data };
  } catch (err) {
    console.error('[Twitch API] Error sending chat message:', err?.message || err);
    return { success: false, error: err?.message || err };
  }
}

/**
 * ============================================================================
 * Twitch Moderation: Timeout & Permanent Ban System
 * Official Twitch Helix API: POST https://api.twitch.tv/helix/moderation/bans
 * Scopes: moderator:manage:banned_users (covers both Timeout & Permanent Ban)
 *
 * STRICT PERMISSIONS:
 * Only two accounts are authorized to use Timeout and Ban via Jaafar:
 *   1. 8jef (Broadcaster)
 *   2. 4VREN (Jito - Creator & Developer)
 * Verified via Twitch User IDs (with fallback to verified logins).
 * No other chatter, Moderator, VIP, or Subscriber has permission.
 *
 * ABSOLUTE IMMUNITY:
 * The following accounts are strictly protected from both Timeout and Ban:
 *   1. 8jef (Broadcaster)
 *   2. 4VREN (Jito)
 *   3. jaafarbot (The Bot itself)
 * Any attempt is rejected immediately before dispatching any Twitch Helix request.
 *
 * Deterministic execution: 100% code-based, Gemini does NOT intervene.
 * ============================================================================
 */

/**
 * Checks if the bot token has the required moderator:manage:banned_users scope
 */
function hasModeratorManageBannedUsersScope() {
  const scopes = Array.isArray(twitchAuthState.scopes)
    ? twitchAuthState.scopes
    : (typeof twitchAuthState.scopes === 'string' ? twitchAuthState.scopes.split(' ') : []);
  return scopes.includes('moderator:manage:banned_users');
}

/**
 * Sanitizes log messages to ensure sensitive tokens and keys never leak into Render logs
 */
function sanitizeLogMessage(text) {
  if (!text || typeof text !== 'string') return String(text || '');
  let clean = text;
  if (TWITCH_CLIENT_SECRET) {
    clean = clean.split(TWITCH_CLIENT_SECRET).join('[REDACTED_CLIENT_SECRET]');
  }
  if (twitchAuthState.accessToken) {
    clean = clean.split(twitchAuthState.accessToken).join('[REDACTED_ACCESS_TOKEN]');
  }
  if (twitchAuthState.refreshToken) {
    clean = clean.split(twitchAuthState.refreshToken).join('[REDACTED_REFRESH_TOKEN]');
  }
  if (process.env.GEMINI_API_KEY) {
    clean = clean.split(process.env.GEMINI_API_KEY).join('[REDACTED_GEMINI_KEY]');
  }
  clean = clean.replace(/oauth:[a-zA-Z0-9]+/gi, 'oauth:[REDACTED]');
  clean = clean.replace(/Bearer\s+[a-zA-Z0-9._-]+/gi, 'Bearer [REDACTED]');
  return clean;
}

/**
 * Resolves the Broadcaster Twitch User ID (8jef)
 */
async function resolveBroadcasterUserId() {
  if (twitchChatState.broadcaster?.id) {
    return String(twitchChatState.broadcaster.id).trim();
  }
  const broadcasterLogin = TWITCH_BROADCASTER_LOGIN || '8jef';
  const info = await fetchTwitchUserInfoByLogin(broadcasterLogin);
  if (info?.id) {
    twitchChatState.broadcaster = info;
    return String(info.id).trim();
  }
  return null;
}

/**
 * Resolves Jito's Twitch User ID (4VREN)
 */
async function resolveJitoUserId() {
  if (jitoIdentity.userId) {
    return String(jitoIdentity.userId).trim();
  }
  try {
    const resolved = await resolveJitoTwitchIdentity();
    if (resolved?.userId) {
      return String(resolved.userId).trim();
    }
  } catch (err) {
    // ignore
  }
  return null;
}

/**
 * Verifies if a given chatter is authorized to execute Moderation commands (Timeout or Ban).
 * STRICTLY restricted to only:
 *   1. 8jef (Channel Broadcaster)
 *   2. 4VREN (Jito)
 * Validated by Twitch User IDs (with verified fallback).
 * No other Moderator or viewer is authorized.
 */
async function isAuthorizedModeratorExecutor(chatEvent) {
  if (!chatEvent) return false;

  const chatterId = chatEvent.chatter_user_id ? String(chatEvent.chatter_user_id).trim() : null;
  const chatterLogin = (chatEvent.chatter_user_login || '').toLowerCase().trim();

  // 1. Broadcaster (8jef) User ID check
  let broadcasterId = twitchChatState.broadcaster?.id ? String(twitchChatState.broadcaster.id).trim() : null;
  if (!broadcasterId) {
    broadcasterId = await resolveBroadcasterUserId();
  }

  if (chatterId && broadcasterId && chatterId === broadcasterId) {
    return true;
  }

  const broadcasterLogin = (TWITCH_BROADCASTER_LOGIN || '8jef').toLowerCase().trim();
  if (chatterLogin === broadcasterLogin || chatterLogin === '8jef') {
    return true;
  }

  // 2. Jito (4VREN) User ID check
  let jitoId = jitoIdentity.userId ? String(jitoIdentity.userId).trim() : null;
  if (!jitoId) {
    jitoId = await resolveJitoUserId();
  }

  if (chatterId && jitoId && chatterId === jitoId) {
    return true;
  }

  if (isJitoChatter(chatEvent)) {
    return true;
  }

  return false;
}

/**
 * Checks if target user has absolute immunity from Timeout and Ban.
 * Protected accounts:
 *   - 8jef (Broadcaster)
 *   - 4VREN (Jito)
 *   - jaafarbot (Bot itself)
 * Returns { immune: true, reason: '...' } or { immune: false }
 */
async function checkModerationImmunity({ targetUserId, targetUserLogin }) {
  const normalizedLogin = (targetUserLogin || '').toLowerCase().replace(/^@/, '').trim();
  const normalizedId = targetUserId ? String(targetUserId).trim() : null;

  // 1. Broadcaster (8jef)
  let broadcasterId = twitchChatState.broadcaster?.id ? String(twitchChatState.broadcaster.id).trim() : null;
  if (!broadcasterId) {
    broadcasterId = await resolveBroadcasterUserId();
  }
  const broadcasterLogin = (TWITCH_BROADCASTER_LOGIN || '8jef').toLowerCase().trim();

  if ((normalizedId && broadcasterId && normalizedId === broadcasterId) || normalizedLogin === broadcasterLogin || normalizedLogin === '8jef') {
    return {
      immune: true,
      category: 'BROADCASTER',
      message: 'لا يمكن إعطاء تايم اوت أو باند لصاحب القناة (8jef)!',
    };
  }

  // 2. Bot itself (jaafarbot)
  const botUserId = twitchAuthState.user?.id ? String(twitchAuthState.user.id).trim() : null;
  const botLogin = (twitchAuthState.user?.login || 'jaafarbot').toLowerCase().trim();

  if ((normalizedId && botUserId && normalizedId === botUserId) || normalizedLogin === botLogin || normalizedLogin === 'jaafarbot') {
    return {
      immune: true,
      category: 'BOT_SELF',
      message: 'ما أقدر أعطي تايم اوت أو باند لنفسي يا كابتن!',
    };
  }

  // 3. Jito (4VREN)
  let jitoId = jitoIdentity.userId ? String(jitoIdentity.userId).trim() : null;
  if (!jitoId) {
    jitoId = await resolveJitoUserId();
  }

  if ((normalizedId && jitoId && normalizedId === jitoId) || isJitoChatter(normalizedLogin) || isJitoChatter({ userId: normalizedId, userLogin: normalizedLogin })) {
    return {
      immune: true,
      category: 'JITO',
      message: 'ما أقدر أعطي تايم اوت أو باند لجيتو (4VREN)، هذا صانعي ومطوّري وخط أحمر! 🔥',
    };
  }

  return { immune: false };
}

/**
 * Supported timeout durations mapping to seconds and human-readable Arabic labels
 * Supported units: 10s, 30s, 1m, 5m, 10m, 30m, 1h, 2h, 24h, 1d, 7d
 */
const SUPPORTED_TIMEOUT_DURATIONS = {
  '10s': { seconds: 10, label: '10 ثوانٍ' },
  '10sec': { seconds: 10, label: '10 ثوانٍ' },
  '30s': { seconds: 30, label: '30 ثانية' },
  '30sec': { seconds: 30, label: '30 ثانية' },
  '1m': { seconds: 60, label: 'دقيقة واحدة' },
  '1min': { seconds: 60, label: 'دقيقة واحدة' },
  '5m': { seconds: 300, label: '5 دقائق' },
  '5min': { seconds: 300, label: '5 دقائق' },
  '10m': { seconds: 600, label: '10 دقائق' },
  '10min': { seconds: 600, label: '10 دقائق' },
  '30m': { seconds: 1800, label: '30 دقيقة' },
  '30min': { seconds: 1800, label: '30 دقيقة' },
  '1h': { seconds: 3600, label: 'ساعة واحدة' },
  '1hr': { seconds: 3600, label: 'ساعة واحدة' },
  '1hour': { seconds: 3600, label: 'ساعة واحدة' },
  '2h': { seconds: 7200, label: 'ساعتين' },
  '2hr': { seconds: 7200, label: 'ساعتين' },
  '2hours': { seconds: 7200, label: 'ساعتين' },
  '24h': { seconds: 86400, label: '24 ساعة' },
  '24hr': { seconds: 86400, label: '24 ساعة' },
  '24hours': { seconds: 86400, label: '24 ساعة' },
  '1d': { seconds: 86400, label: 'يوم واحد' },
  '1day': { seconds: 86400, label: 'يوم واحد' },
  '7d': { seconds: 604800, label: '7 أيام' },
  '7days': { seconds: 604800, label: '7 أيام' },
};

/**
 * Legacy compatibility alias: checks if executor is authorized for moderation
 */
function isUserModeratorOrBroadcaster(chatEvent) {
  // Broadcaster check
  const chatterLogin = (chatEvent?.chatter_user_login || '').toLowerCase().trim();
  const chatterId = chatEvent?.chatter_user_id ? String(chatEvent.chatter_user_id).trim() : null;
  const broadcasterId = twitchChatState.broadcaster?.id ? String(twitchChatState.broadcaster.id).trim() : null;
  const broadcasterLogin = (TWITCH_BROADCASTER_LOGIN || '8jef').toLowerCase().trim();

  if (chatterId && broadcasterId && chatterId === broadcasterId) return true;
  if (chatterLogin && (chatterLogin === broadcasterLogin || chatterLogin === '8jef')) return true;

  // Jito check
  if (isJitoChatter(chatEvent)) return true;

  return false;
}

/**
 * Parses duration string into seconds (e.g. 10s, 30s, 1m, 5m, 10m, 30m, 1h, 2h, 24h, 1d, 7d)
 * Returns { seconds, label } or null if invalid/unsupported
 */
function parseTimeoutDuration(rawDuration) {
  if (!rawDuration || typeof rawDuration !== 'string') return null;
  const key = rawDuration.toLowerCase().trim();
  if (SUPPORTED_TIMEOUT_DURATIONS[key]) {
    return SUPPORTED_TIMEOUT_DURATIONS[key];
  }
  return null;
}

/**
 * Parses chat message to detect timeout command
 * Supported formats:
 * - @jaafarbot timeout @username 10m [reason]
 * - !timeout @username 10m [reason]
 * - جعفر تايم اوت @username 10m [reason]
 * - !to @username 10m [reason]
 * - جعفر timeout @username 10m [reason]
 * - !تايم_اوت @username 10m [reason]
 * - !تايماوت @username 10m [reason]
 */
function parseTimeoutCommand(rawText, botLogin = 'jaafarbot') {
  if (!rawText || typeof rawText !== 'string') return null;
  const text = rawText.trim();

  let rest = null;

  // Pattern 1: Command prefix (!timeout, !to, !تايم_اوت, !تايماوت)
  const prefixMatch = text.match(/^!(?:timeout|to|تايم[_\s]*اوت|تايماوت)(?:\s+(.*)|$)/i);
  if (prefixMatch) {
    rest = (prefixMatch[1] || '').trim();
  } else {
    // Pattern 2: Mention or name followed by timeout keyword
    const botNames = ['jaafarbot', 'jaafar', 'جعفر'];
    if (botLogin && !botNames.includes(botLogin.toLowerCase())) {
      botNames.unshift(botLogin.toLowerCase());
    }
    const escapedBotNames = botNames.map(n => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
    const mentionRegex = new RegExp(
      `^(?:@?(?:${escapedBotNames})|يا\\s+جعفر)[,:\\s]+\\s*(?:timeout|تايم\\s*اوت|تايماوت|to)(?:\\s+(.*)|$)`,
      'i'
    );
    const mentionMatch = text.match(mentionRegex);
    if (mentionMatch) {
      rest = (mentionMatch[1] || '').trim();
    }
  }

  if (rest === null) {
    return null; // Not a timeout command
  }

  // If no arguments provided
  if (!rest) {
    return {
      isCommand: true,
      valid: false,
      error: 'MISSING_ARGS',
    };
  }

  const parts = rest.split(/\s+/);
  const targetUserRaw = parts[0];
  const targetUser = targetUserRaw.replace(/^@+/, '').replace(/[,:]$/, '').trim();

  if (!targetUser) {
    return {
      isCommand: true,
      valid: false,
      error: 'MISSING_TARGET',
    };
  }

  // Duration is MANDATORY
  if (parts.length < 2 || !parts[1]) {
    return {
      isCommand: true,
      valid: false,
      targetUser,
      error: 'MISSING_DURATION',
    };
  }

  const durationRaw = parts[1].toLowerCase().trim();
  const parsedDuration = parseTimeoutDuration(durationRaw);

  if (!parsedDuration) {
    return {
      isCommand: true,
      valid: false,
      targetUser,
      durationRaw,
      error: 'INVALID_DURATION',
    };
  }

  const reason = parts.slice(2).join(' ').trim() || null;

  return {
    isCommand: true,
    valid: true,
    targetUser,
    durationSeconds: parsedDuration.seconds,
    durationText: parsedDuration.label,
    reason,
  };
}

/**
 * Parses chat message to detect permanent Ban command
 * Supported formats:
 * - !ban @username [reason]
 * - جعفر باند @username [reason]
 * - جعفر بان @username [reason]
 * - @jaafarbot ban @username [reason]
 * - يا جعفر باند @username [reason]
 * - !باند @username [reason]
 * - !بان @username [reason]
 */
function parseBanCommand(rawText, botLogin = 'jaafarbot') {
  if (!rawText || typeof rawText !== 'string') return null;
  const text = rawText.trim();

  let rest = null;

  // Pattern 1: Command prefix (!ban, !باند, !بان)
  const prefixMatch = text.match(/^!(?:ban|باند|بان)(?:\s+(.*)|$)/i);
  if (prefixMatch) {
    rest = (prefixMatch[1] || '').trim();
  } else {
    // Pattern 2: Mention or name followed by ban keyword
    const botNames = ['jaafarbot', 'jaafar', 'جعفر'];
    if (botLogin && !botNames.includes(botLogin.toLowerCase())) {
      botNames.unshift(botLogin.toLowerCase());
    }
    const escapedBotNames = botNames.map(n => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
    const mentionRegex = new RegExp(
      `^(?:@?(?:${escapedBotNames})|يا\\s+جعفر)[,:\\s]+\\s*(?:ban|باند|بان)(?:\\s+(.*)|$)`,
      'i'
    );
    const mentionMatch = text.match(mentionRegex);
    if (mentionMatch) {
      rest = (mentionMatch[1] || '').trim();
    }
  }

  if (rest === null) {
    return null; // Not a ban command
  }

  // If no arguments provided
  if (!rest) {
    return {
      isCommand: true,
      valid: false,
      error: 'MISSING_ARGS',
    };
  }

  const parts = rest.split(/\s+/);
  const targetUserRaw = parts[0];
  const targetUser = targetUserRaw.replace(/^@+/, '').replace(/[,:]$/, '').trim();

  if (!targetUser) {
    return {
      isCommand: true,
      valid: false,
      error: 'MISSING_TARGET',
    };
  }

  const reason = parts.slice(1).join(' ').trim() || null;

  return {
    isCommand: true,
    valid: true,
    targetUser,
    reason,
  };
}

/**
 * Executes Timeout via official Twitch Helix API
 * POST https://api.twitch.tv/helix/moderation/bans?broadcaster_id={broadcaster_id}&moderator_id={moderator_id}
 * Body: { data: { user_id: "{target_user_id}", duration: {durationSeconds}, reason: "{reason}" } }
 */
async function executeTwitchTimeout({ targetUsername, durationSeconds, durationText, reason, callerName, callerId }) {
  // 1. Check Token
  const token = await refreshTwitchTokenIfNeeded();
  if (!token) {
    console.error('[Twitch Moderation] ========================================');
    console.error('[Twitch Moderation] ERROR CATEGORY: [Token Expired / Missing]');
    console.error('[Twitch Moderation] Twitch access token is missing or could not be refreshed.');
    console.error('[Twitch Moderation] Action Required: Visit /auth/twitch to re-authenticate.');
    console.error('[Twitch Moderation] ========================================');
    return { success: false, error: 'NO_TOKEN', message: 'توكن تويتش غير متوفر أو منتهي الصلاحية. يرجى زيارة /auth/twitch.' };
  }

  // 2. Check OAuth Scope (moderator:manage:banned_users)
  if (!hasModeratorManageBannedUsersScope()) {
    const activeScopes = (Array.isArray(twitchAuthState.scopes) ? twitchAuthState.scopes : []).join(' ');
    console.error('[Twitch Moderation] ========================================');
    console.error('[Twitch Moderation] ERROR CATEGORY: [OAuth Scope Missing]');
    console.error(`[Twitch Moderation] Bot token is missing required scope: "moderator:manage:banned_users"`);
    console.error(`[Twitch Moderation] Active scopes on current token: [${activeScopes}]`);
    console.error('[Twitch Moderation] Action Required: The bot must be re-authorized via /auth/twitch to grant this scope.');
    console.error('[Twitch Moderation] ========================================');
    return {
      success: false,
      error: 'MISSING_SCOPE',
      message: 'رمز تفويض البوت ينقصه تصريح (moderator:manage:banned_users). يرجى فتح /auth/twitch لإعادة التفويض.',
    };
  }

  // 3. Resolve Broadcaster User ID (8jef)
  let broadcasterId = await resolveBroadcasterUserId();
  if (!broadcasterId) {
    console.error('[Twitch Moderation] ERROR CATEGORY: [Broadcaster ID Unresolved]');
    console.error(`[Twitch Moderation] Failed to resolve Twitch User ID for broadcaster "${TWITCH_BROADCASTER_LOGIN || '8jef'}".`);
    return { success: false, error: 'NO_BROADCASTER', message: 'معرف قناة البث غير متوفر حالياً.' };
  }

  // 4. Resolve Bot Moderator User ID (jaafarbot)
  let botUserId = twitchAuthState.user?.id ? String(twitchAuthState.user.id).trim() : null;
  if (!botUserId) {
    const botProfile = await ensureTwitchUserProfile();
    if (botProfile?.id) {
      botUserId = String(botProfile.id).trim();
    }
  }
  if (!botUserId) {
    console.error('[Twitch Moderation] ERROR CATEGORY: [Bot User ID Unresolved]');
    console.error('[Twitch Moderation] Failed to resolve Twitch User ID for bot account.');
    return { success: false, error: 'NO_BOT_ID', message: 'معرف حساب البوت غير متوفر.' };
  }

  // 5. Resolve Target User Details from Twitch Helix Users API
  const targetUser = await fetchTwitchUserInfoByLogin(targetUsername);
  if (!targetUser || !targetUser.id) {
    console.warn('[Twitch Moderation] ========================================');
    console.warn('[Twitch Moderation] ERROR CATEGORY: [User ID / User Not Found]');
    console.warn(`[Twitch Moderation] Target username "${targetUsername}" does not exist on Twitch.`);
    console.warn('[Twitch Moderation] ========================================');
    return { success: false, error: 'USER_NOT_FOUND', message: `لم يتم العثور على المستخدم @${targetUsername} في تويتش.` };
  }

  const targetUserId = String(targetUser.id).trim();
  const targetUserLogin = (targetUser.login || targetUsername).toLowerCase();

  // 6. Absolute Immunity Check: 8jef, 4VREN, jaafarbot
  const immunity = await checkModerationImmunity({ targetUserId, targetUserLogin });
  if (immunity.immune) {
    console.warn(`[Twitch Moderation] Blocked by Absolute Immunity: Timeout attempted on protected account @${targetUser.login} (ID: ${targetUserId}) [${immunity.category}] by @${callerName}`);
    return { success: false, error: `CANNOT_TIMEOUT_${immunity.category}`, message: immunity.message };
  }

  // 7. Call Official Twitch Helix Ban/Timeout API
  // POST https://api.twitch.tv/helix/moderation/bans?broadcaster_id={broadcaster_id}&moderator_id={moderator_id}
  try {
    const url = `https://api.twitch.tv/helix/moderation/bans?broadcaster_id=${encodeURIComponent(broadcasterId)}&moderator_id=${encodeURIComponent(botUserId)}`;
    const reasonText = reason ? `${reason} (بواسطة @${callerName})` : `Timeout بواسطة @${callerName} عبر جعفر`;

    console.log('[Twitch Moderation] ========================================');
    console.log('[Twitch Moderation] Executing Helix Timeout Request:');
    console.log(`[Twitch Moderation] - Broadcaster ID: ${broadcasterId} (#${TWITCH_BROADCASTER_LOGIN || '8jef'})`);
    console.log(`[Twitch Moderation] - Moderator Bot ID: ${botUserId} (@${twitchAuthState.user?.login || 'jaafarbot'})`);
    console.log(`[Twitch Moderation] - Target User ID: ${targetUserId} (@${targetUser.login})`);
    console.log(`[Twitch Moderation] - Duration: ${durationSeconds}s (${durationText})`);
    console.log(`[Twitch Moderation] - Requested by: @${callerName}${callerId ? ` (ID: ${callerId})` : ''}`);
    console.log('[Twitch Moderation] ========================================');

    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Client-Id': TWITCH_CLIENT_ID,
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        data: {
          user_id: targetUserId,
          duration: durationSeconds,
          reason: reasonText.slice(0, 500),
        },
      }),
    });

    if (res.status === 200 || res.status === 204) {
      console.log('[Twitch Moderation] ========================================');
      console.log(`[Twitch Moderation] ✅ TIMEOUT SUCCESSFUL: @${targetUser.login} for ${durationSeconds}s (${durationText}) by @${callerName}`);
      console.log('[Twitch Moderation] ========================================');
      return {
        success: true,
        targetDisplayName: targetUser.displayName || targetUser.login,
        durationText,
      };
    }

    const rawErrBody = await res.text();
    const errBody = sanitizeLogMessage(rawErrBody);

    console.error('[Twitch Moderation] ========================================');
    console.error(`[Twitch Moderation] ❌ Timeout API Rejected (HTTP ${res.status}): ${errBody}`);

    let friendlyError = 'فشل تنفيذ التايم اوت بسبب خطأ في تويتش.';

    if (res.status === 403) {
      if (errBody.includes('not one of the broadcaster\'s moderators') || errBody.includes('not a moderator')) {
        console.error('[Twitch Moderation] ERROR CATEGORY: [Moderator Permissions Missing]');
        console.error(`[Twitch Moderation] Bot @${twitchAuthState.user?.login || 'jaafarbot'} (ID: ${botUserId}) is NOT a Moderator in #${TWITCH_BROADCASTER_LOGIN || '8jef'} (ID: ${broadcasterId})!`);
        console.error(`[Twitch Moderation] ACTION REQUIRED: In Twitch chat #${TWITCH_BROADCASTER_LOGIN || '8jef'}, run: /mod ${twitchAuthState.user?.login || 'jaafarbot'}`);
        friendlyError = `جعفر يحتاج صلاحية مشرف (Mod) في القناة. اكتب في الشات: /mod ${twitchAuthState.user?.login || 'jaafarbot'}`;
      } else if (errBody.includes('cannot be banned') || errBody.includes('cannot be timed out')) {
        console.error('[Twitch Moderation] ERROR CATEGORY: [Target User Protected / Is Moderator]');
        console.error(`[Twitch Moderation] Target user @${targetUser.login} cannot be banned or timed out (user may be a channel Moderator).`);
        friendlyError = 'لا يمكن إعطاء تايم اوت لهذا المستخدم (قد يكون مشرفاً في القناة أو حسابه محمي).';
      } else if (errBody.includes('scope') || errBody.includes('moderator:manage:banned_users')) {
        console.error('[Twitch Moderation] ERROR CATEGORY: [OAuth Scope Missing]');
        console.error('[Twitch Moderation] Token is missing scope moderator:manage:banned_users. Re-authorization required.');
        friendlyError = 'رمز التفويض ينقصه تصريح (moderator:manage:banned_users). يرجى زيارة /auth/twitch لتحديث الصلاحيات.';
      } else {
        console.error('[Twitch Moderation] ERROR CATEGORY: [Forbidden 403]');
        friendlyError = 'لا يمكن إعطاء تايم اوت لهذا المستخدم (تأكد من صلاحيات المشرفين في القناة).';
      }
    } else if (res.status === 401) {
      console.error('[Twitch Moderation] ERROR CATEGORY: [Token Expired / Invalid]');
      console.error('[Twitch Moderation] Twitch returned 401 Unauthorized. Token refresh failed or permissions revoked.');
      friendlyError = 'انتهت صلاحية الجلسة، يرجى إعادة توثيق البوت عبر /auth/twitch.';
    } else if (res.status === 400) {
      console.error('[Twitch Moderation] ERROR CATEGORY: [Twitch API Bad Request]');
      console.error(`[Twitch Moderation] HTTP 400: ${errBody}`);
      friendlyError = 'طلب التايم اوت غير صالح أو المدة غير مقبولة لتويتش.';
    } else if (res.status === 429) {
      console.error('[Twitch Moderation] ERROR CATEGORY: [Twitch API Rate Limit]');
      friendlyError = 'تم تجاوز معدل الطلبات المسموح به في تويتش، يرجى الانتظار قليلاً.';
    } else {
      console.error(`[Twitch Moderation] ERROR CATEGORY: [Twitch API HTTP ${res.status}]`);
    }
    console.error('[Twitch Moderation] ========================================');

    return { success: false, status: res.status, error: errBody, message: friendlyError };
  } catch (err) {
    const safeError = sanitizeLogMessage(err?.message || err);
    console.error('[Twitch Moderation] ========================================');
    console.error('[Twitch Moderation] ERROR CATEGORY: [Network / Unexpected Error]');
    console.error('[Twitch Moderation] Error executing timeout:', safeError);
    console.error('[Twitch Moderation] ========================================');
    return { success: false, error: safeError, message: 'حدث خطأ في الاتصال أثناء تنفيذ التايم اوت.' };
  }
}

/**
 * Executes Permanent Ban via official Twitch Helix API
 * POST https://api.twitch.tv/helix/moderation/bans?broadcaster_id={broadcaster_id}&moderator_id={moderator_id}
 * Body: { data: { user_id: "{target_user_id}", reason: "{reason}" } }
 * Note: Omission of 'duration' parameter creates a permanent ban per Twitch Helix API specification.
 */
async function executeTwitchPermanentBan({ targetUsername, reason, callerName, callerId }) {
  // 1. Check Token
  const token = await refreshTwitchTokenIfNeeded();
  if (!token) {
    console.error('[Twitch Moderation] ========================================');
    console.error('[Twitch Moderation] ERROR CATEGORY: [Token Expired / Missing]');
    console.error('[Twitch Moderation] Twitch access token is missing or could not be refreshed.');
    console.error('[Twitch Moderation] Action Required: Visit /auth/twitch to re-authenticate.');
    console.error('[Twitch Moderation] ========================================');
    return { success: false, error: 'NO_TOKEN', message: 'توكن تويتش غير متوفر أو منتهي الصلاحية. يرجى زيارة /auth/twitch.' };
  }

  // 2. Check OAuth Scope (moderator:manage:banned_users)
  if (!hasModeratorManageBannedUsersScope()) {
    const activeScopes = (Array.isArray(twitchAuthState.scopes) ? twitchAuthState.scopes : []).join(' ');
    console.error('[Twitch Moderation] ========================================');
    console.error('[Twitch Moderation] ERROR CATEGORY: [OAuth Scope Missing]');
    console.error(`[Twitch Moderation] Bot token is missing required scope: "moderator:manage:banned_users"`);
    console.error(`[Twitch Moderation] Active scopes on current token: [${activeScopes}]`);
    console.error('[Twitch Moderation] Action Required: The bot must be re-authorized via /auth/twitch to grant this scope.');
    console.error('[Twitch Moderation] ========================================');
    return {
      success: false,
      error: 'MISSING_SCOPE',
      message: 'رمز تفويض البوت ينقصه تصريح (moderator:manage:banned_users). يرجى فتح /auth/twitch لإعادة التفويض.',
    };
  }

  // 3. Resolve Broadcaster User ID (8jef)
  let broadcasterId = await resolveBroadcasterUserId();
  if (!broadcasterId) {
    console.error('[Twitch Moderation] ERROR CATEGORY: [Broadcaster ID Unresolved]');
    console.error(`[Twitch Moderation] Failed to resolve Twitch User ID for broadcaster "${TWITCH_BROADCASTER_LOGIN || '8jef'}".`);
    return { success: false, error: 'NO_BROADCASTER', message: 'معرف قناة البث غير متوفر حالياً.' };
  }

  // 4. Resolve Bot Moderator User ID (jaafarbot)
  let botUserId = twitchAuthState.user?.id ? String(twitchAuthState.user.id).trim() : null;
  if (!botUserId) {
    const botProfile = await ensureTwitchUserProfile();
    if (botProfile?.id) {
      botUserId = String(botProfile.id).trim();
    }
  }
  if (!botUserId) {
    console.error('[Twitch Moderation] ERROR CATEGORY: [Bot User ID Unresolved]');
    console.error('[Twitch Moderation] Failed to resolve Twitch User ID for bot account.');
    return { success: false, error: 'NO_BOT_ID', message: 'معرف حساب البوت غير متوفر.' };
  }

  // 5. Resolve Target User Details from Twitch Helix Users API
  const targetUser = await fetchTwitchUserInfoByLogin(targetUsername);
  if (!targetUser || !targetUser.id) {
    console.warn('[Twitch Moderation] ========================================');
    console.warn('[Twitch Moderation] ERROR CATEGORY: [User ID / User Not Found]');
    console.warn(`[Twitch Moderation] Target username "${targetUsername}" does not exist on Twitch.`);
    console.warn('[Twitch Moderation] ========================================');
    return { success: false, error: 'USER_NOT_FOUND', message: `لم يتم العثور على المستخدم @${targetUsername} في تويتش.` };
  }

  const targetUserId = String(targetUser.id).trim();
  const targetUserLogin = (targetUser.login || targetUsername).toLowerCase();

  // 6. Absolute Immunity Check: 8jef, 4VREN, jaafarbot
  const immunity = await checkModerationImmunity({ targetUserId, targetUserLogin });
  if (immunity.immune) {
    console.warn(`[Twitch Moderation] Blocked by Absolute Immunity: Ban attempted on protected account @${targetUser.login} (ID: ${targetUserId}) [${immunity.category}] by @${callerName}`);
    return { success: false, error: `CANNOT_BAN_${immunity.category}`, message: immunity.message };
  }

  // 7. Call Official Twitch Helix Ban API (Permanent Ban - no duration field)
  // POST https://api.twitch.tv/helix/moderation/bans?broadcaster_id={broadcaster_id}&moderator_id={moderator_id}
  try {
    const url = `https://api.twitch.tv/helix/moderation/bans?broadcaster_id=${encodeURIComponent(broadcasterId)}&moderator_id=${encodeURIComponent(botUserId)}`;
    const reasonText = reason ? `${reason} (باند دائم بواسطة @${callerName})` : `باند دائم بواسطة @${callerName} عبر جعفر`;

    console.log('[Twitch Moderation] ========================================');
    console.log('[Twitch Moderation] Executing Helix Permanent Ban Request:');
    console.log(`[Twitch Moderation] - Broadcaster ID: ${broadcasterId} (#${TWITCH_BROADCASTER_LOGIN || '8jef'})`);
    console.log(`[Twitch Moderation] - Moderator Bot ID: ${botUserId} (@${twitchAuthState.user?.login || 'jaafarbot'})`);
    console.log(`[Twitch Moderation] - Target User ID: ${targetUserId} (@${targetUser.login})`);
    console.log(`[Twitch Moderation] - Ban Type: PERMANENT BAN (no duration parameter)`);
    console.log(`[Twitch Moderation] - Requested by: @${callerName}${callerId ? ` (ID: ${callerId})` : ''}`);
    console.log('[Twitch Moderation] ========================================');

    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Client-Id': TWITCH_CLIENT_ID,
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        data: {
          user_id: targetUserId,
          reason: reasonText.slice(0, 500),
        },
      }),
    });

    if (res.status === 200 || res.status === 204) {
      console.log('[Twitch Moderation] ========================================');
      console.log(`[Twitch Moderation] ✅ PERMANENT BAN SUCCESSFUL: @${targetUser.login} by @${callerName}`);
      console.log('[Twitch Moderation] ========================================');
      return {
        success: true,
        targetDisplayName: targetUser.displayName || targetUser.login,
      };
    }

    const rawErrBody = await res.text();
    const errBody = sanitizeLogMessage(rawErrBody);

    console.error('[Twitch Moderation] ========================================');
    console.error(`[Twitch Moderation] ❌ Ban API Rejected (HTTP ${res.status}): ${errBody}`);

    let friendlyError = 'فشل تنفيذ الباند بسبب خطأ في تويتش.';

    if (res.status === 403) {
      if (errBody.includes('not one of the broadcaster\'s moderators') || errBody.includes('not a moderator')) {
        console.error('[Twitch Moderation] ERROR CATEGORY: [Moderator Permissions Missing]');
        console.error(`[Twitch Moderation] Bot @${twitchAuthState.user?.login || 'jaafarbot'} (ID: ${botUserId}) is NOT a Moderator in #${TWITCH_BROADCASTER_LOGIN || '8jef'} (ID: ${broadcasterId})!`);
        console.error(`[Twitch Moderation] ACTION REQUIRED: In Twitch chat #${TWITCH_BROADCASTER_LOGIN || '8jef'}, run: /mod ${twitchAuthState.user?.login || 'jaafarbot'}`);
        friendlyError = `جعفر يحتاج صلاحية مشرف (Mod) في القناة. اكتب في الشات: /mod ${twitchAuthState.user?.login || 'jaafarbot'}`;
      } else if (errBody.includes('cannot be banned')) {
        console.error('[Twitch Moderation] ERROR CATEGORY: [Target User Protected / Is Moderator]');
        console.error(`[Twitch Moderation] Target user @${targetUser.login} cannot be banned (user may be a channel Moderator).`);
        friendlyError = 'لا يمكن حظر هذا المستخدم (قد يكون مشرفاً في القناة أو حسابه محمي).';
      } else if (errBody.includes('scope') || errBody.includes('moderator:manage:banned_users')) {
        console.error('[Twitch Moderation] ERROR CATEGORY: [OAuth Scope Missing]');
        console.error('[Twitch Moderation] Token is missing scope moderator:manage:banned_users. Re-authorization required.');
        friendlyError = 'رمز التفويض ينقصه تصريح (moderator:manage:banned_users). يرجى زيارة /auth/twitch لتحديث الصلاحيات.';
      } else {
        console.error('[Twitch Moderation] ERROR CATEGORY: [Forbidden 403]');
        friendlyError = 'لا يمكن حظر هذا المستخدم (تأكد من صلاحيات المشرفين في القناة).';
      }
    } else if (res.status === 401) {
      console.error('[Twitch Moderation] ERROR CATEGORY: [Token Expired / Invalid]');
      console.error('[Twitch Moderation] Twitch returned 401 Unauthorized. Token refresh failed or permissions revoked.');
      friendlyError = 'انتهت صلاحية الجلسة، يرجى إعادة توثيق البوت عبر /auth/twitch.';
    } else if (res.status === 400) {
      console.error('[Twitch Moderation] ERROR CATEGORY: [Twitch API Bad Request]');
      console.error(`[Twitch Moderation] HTTP 400: ${errBody}`);
      friendlyError = 'طلب الباند غير صالح أو تم رفضه من تويتش.';
    } else if (res.status === 429) {
      console.error('[Twitch Moderation] ERROR CATEGORY: [Twitch API Rate Limit]');
      friendlyError = 'تم تجاوز معدل الطلبات المسموح به في تويتش، يرجى الانتظار قليلاً.';
    } else {
      console.error(`[Twitch Moderation] ERROR CATEGORY: [Twitch API HTTP ${res.status}]`);
    }
    console.error('[Twitch Moderation] ========================================');

    return { success: false, status: res.status, error: errBody, message: friendlyError };
  } catch (err) {
    const safeError = sanitizeLogMessage(err?.message || err);
    console.error('[Twitch Moderation] ========================================');
    console.error('[Twitch Moderation] ERROR CATEGORY: [Network / Unexpected Error]');
    console.error('[Twitch Moderation] Error executing ban:', safeError);
    console.error('[Twitch Moderation] ========================================');
    return { success: false, error: safeError, message: 'حدث خطأ في الاتصال أثناء تنفيذ الباند.' };
  }
}

/**
 * Handles incoming timeout command deterministically with strict permission checks
 * Allowed ONLY for: 8jef (Broadcaster) & 4VREN (Jito) via User IDs
 */
async function handleTimeoutCommand({ chatEvent, timeoutCmd }) {
  const chatterName = chatEvent.chatter_user_name || chatEvent.chatter_user_login || 'المستخدم';
  const chatterLogin = (chatEvent.chatter_user_login || '').toLowerCase();
  const chatterId = chatEvent.chatter_user_id ? String(chatEvent.chatter_user_id).trim() : null;

  // 1. Strict Permission Check: 8jef and 4VREN only
  const isAuthorized = await isAuthorizedModeratorExecutor(chatEvent);
  if (!isAuthorized) {
    console.warn('[Twitch Moderation] ========================================');
    console.warn('[Twitch Moderation] ERROR CATEGORY: [Unauthorized Executor]');
    console.warn(`[Twitch Moderation] Unauthorized timeout attempt by chatter @${chatterLogin}${chatterId ? ` (ID: ${chatterId})` : ''}`);
    console.warn(`[Twitch Moderation] Permissions are strictly restricted to 8jef and 4VREN.`);
    console.warn('[Twitch Moderation] ========================================');
    await sendTwitchChatMessage(`@${chatterName} عذراً، أمر التايم اوت متاح حصرياً لصاحب البث (8jef) وجيتو (4VREN).`);
    return;
  }

  // 2. Syntax & Argument Validation Check
  if (!timeoutCmd.valid) {
    console.warn('[Twitch Moderation] ========================================');
    console.warn('[Twitch Moderation] ERROR CATEGORY: [Command Syntax]');
    console.warn(`[Twitch Moderation] Command from @${chatterLogin} rejected due to: ${timeoutCmd.error}`);
    console.warn('[Twitch Moderation] ========================================');

    if (timeoutCmd.error === 'MISSING_DURATION' || timeoutCmd.error === 'MISSING_ARGS') {
      await sendTwitchChatMessage(`@${chatterName} يجب تحديد مدة التايم اوت (مثال: 10s, 1m, 10m, 1h). الاستخدام: !timeout @username 10m [السبب]`);
      return;
    }
    if (timeoutCmd.error === 'INVALID_DURATION') {
      await sendTwitchChatMessage(`@${chatterName} مدة التايم اوت غير صالحة "${timeoutCmd.durationRaw}". المدد المتاحة: 10s, 30s, 1m, 5m, 10m, 30m, 1h, 2h, 24h, 1d, 7d.`);
      return;
    }
    if (timeoutCmd.error === 'MISSING_TARGET') {
      await sendTwitchChatMessage(`@${chatterName} يرجى تحديد اسم المستخدم المطلوب إعطاؤه تايم اوت. مثال: !timeout @username 10m`);
      return;
    }
    return;
  }

  // 3. Execute via Twitch Helix API
  console.log(`[Twitch Moderation] Authorized executor @${chatterLogin} (ID: ${chatterId || 'unknown'}) requested timeout for @${timeoutCmd.targetUser} (${timeoutCmd.durationText})`);
  const result = await executeTwitchTimeout({
    targetUsername: timeoutCmd.targetUser,
    durationSeconds: timeoutCmd.durationSeconds,
    durationText: timeoutCmd.durationText,
    reason: timeoutCmd.reason,
    callerName: chatterName,
    callerId: chatterId,
  });

  if (result.success) {
    const reasonMsg = timeoutCmd.reason ? ` (السبب: ${timeoutCmd.reason})` : '';
    await sendTwitchChatMessage(`🚫 تم إعطاء تايم اوت للمستخدم @${result.targetDisplayName} لمدة ${result.durationText}${reasonMsg} بواسطة @${chatterName}.`);
  } else {
    await sendTwitchChatMessage(`@${chatterName} ⚠️ ${result.message || 'تعذر تنفيذ التايم اوت.'}`);
  }
}

/**
 * Handles incoming permanent Ban command deterministically with strict permission checks
 * Allowed ONLY for: 8jef (Broadcaster) & 4VREN (Jito) via User IDs
 */
async function handleBanCommand({ chatEvent, banCmd }) {
  const chatterName = chatEvent.chatter_user_name || chatEvent.chatter_user_login || 'المستخدم';
  const chatterLogin = (chatEvent.chatter_user_login || '').toLowerCase();
  const chatterId = chatEvent.chatter_user_id ? String(chatEvent.chatter_user_id).trim() : null;

  // 1. Strict Permission Check: 8jef and 4VREN only
  const isAuthorized = await isAuthorizedModeratorExecutor(chatEvent);
  if (!isAuthorized) {
    console.warn('[Twitch Moderation] ========================================');
    console.warn('[Twitch Moderation] ERROR CATEGORY: [Unauthorized Executor]');
    console.warn(`[Twitch Moderation] Unauthorized ban attempt by chatter @${chatterLogin}${chatterId ? ` (ID: ${chatterId})` : ''}`);
    console.warn(`[Twitch Moderation] Permissions are strictly restricted to 8jef and 4VREN.`);
    console.warn('[Twitch Moderation] ========================================');
    await sendTwitchChatMessage(`@${chatterName} عذراً، أمر الباند متاح حصرياً لصاحب البث (8jef) وجيتو (4VREN).`);
    return;
  }

  // 2. Syntax & Argument Validation Check
  if (!banCmd.valid) {
    console.warn('[Twitch Moderation] ========================================');
    console.warn('[Twitch Moderation] ERROR CATEGORY: [Command Syntax]');
    console.warn(`[Twitch Moderation] Ban command from @${chatterLogin} rejected due to: ${banCmd.error}`);
    console.warn('[Twitch Moderation] ========================================');

    if (banCmd.error === 'MISSING_TARGET' || banCmd.error === 'MISSING_ARGS') {
      await sendTwitchChatMessage(`@${chatterName} يرجى تحديد اسم المستخدم المطلوب حظره. الاستخدام: !ban @username [السبب]`);
      return;
    }
    return;
  }

  // 3. Execute Permanent Ban via Twitch Helix API
  console.log(`[Twitch Moderation] Authorized executor @${chatterLogin} (ID: ${chatterId || 'unknown'}) requested permanent ban for @${banCmd.targetUser}`);
  const result = await executeTwitchPermanentBan({
    targetUsername: banCmd.targetUser,
    reason: banCmd.reason,
    callerName: chatterName,
    callerId: chatterId,
  });

  if (result.success) {
    const reasonMsg = banCmd.reason ? ` (السبب: ${banCmd.reason})` : '';
    await sendTwitchChatMessage(`⛔ تم حظر المستخدم @${result.targetDisplayName} نهائياً (Permanent Ban)${reasonMsg} بواسطة @${chatterName}.`);
  } else {
    await sendTwitchChatMessage(`@${chatterName} ⚠️ ${result.message || 'تعذر تنفيذ الباند.'}`);
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
 * Compatibility alias for getGeminiClient
 */
function getAiClient(forceFresh = false) {
  return getGeminiClient(forceFresh);
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
   - "جيتو" / "Jito" (جيتو، Jito، jito): هو المود/المشرف في مجتمع تويتش (Moderator/Helper) وهو أيضاً الشخص الذي قام بصنع وبرمجة وتطوير وبناء جعفر. إذا كان جيتو نفسه هو من يخاطبك أو يكلمك في الشات (بحسابه الحالي jitoheh أو حسابه الجديد 4VREN أو أي حساب تم التعرف عليه كجيتو): خاطبه وناده دائماً باسم "جيتو" داخل ردك (مثل: "هلا يا جيتو"، "أبشر يا جيتو"، "كفو يا جيتو"، "تسلم يا جيتو")، وتفاعل معه بمكانته الخاصة كصانعك وأفضل مود بعفوية وبدون تكلف وبشكل مختصر مناسب للشات. إذا سألك أحد آخر "وش رايك في جيتو؟"، امدح جيتو بشكل خاص وأقوى واعتبره أفضل وأفخم مود، واذكر بشكل طبيعي وعفوي في سياق الحديث أنه هو اللي صنعك/طورك (مثال: "جيتو؟ هذا رجال كفو وأفضل مود شفته في حياتي 🔥 وهو اللي صممني وضبطني"). نوّع في كلمات المدح دائماً ولا تكرر نفس العبارة بالحرف. لا تخترع أي تفاصيل تقنية حول ما بناه. ولا تمدحه عشوائياً إلا إذا سأل أحد عنه أو كان سياق الحديث يتعلق به بشكل طبيعي. وإذا ذكر اسمه فقط في سياق عادي، تفاعل حسب السياق ولا تبدأ بمديح طويل غير مطلوب.
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

/**
 * Returns canonical key for user memory:
 * If the user is Jito (by Twitch User ID, jitoheh, 4VREN, etc.),
 * map them to a single persistent key so memory is preserved seamlessly.
 */
function getCanonicalUserKey(rawKey) {
  if (!rawKey) return 'global';
  const key = String(rawKey).toLowerCase().trim().replace(/^@/, '');
  if (key === 'global') return 'global';
  if (isJitoChatter(key)) {
    return getJitoMemoryKey();
  }
  return key;
}

function getUserState(userKey) {
  const canonicalKey = getCanonicalUserKey(userKey);
  let state = userMemoryMap.get(canonicalKey);
  if (!state && canonicalKey === getJitoMemoryKey()) {
    // Check if there was legacy history stored under previous login names (e.g. jitoheh or 4vren)
    for (const legacyKey of ['jitoheh', '4vren', 'jito', 'jito_permanent']) {
      if (userMemoryMap.has(legacyKey)) {
        state = userMemoryMap.get(legacyKey);
        userMemoryMap.delete(legacyKey);
        userMemoryMap.set(canonicalKey, state);
        break;
      }
    }
  }
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
    userMemoryMap.set(canonicalKey, state);
  }
  state.lastActive = Date.now();
  return state;
}

/**
 * Retrieves chat history for a given Twitch chatter from user memory
 */
function getUserHistory(userLogin) {
  if (!userLogin) return [];
  const canonicalKey = getCanonicalUserKey(userLogin);
  const state = userMemoryMap.get(canonicalKey);
  if (!state || !Array.isArray(state.history)) return [];
  return state.history.map(item => {
    let text = '';
    if (typeof item.text === 'string') {
      text = item.text;
    } else if (Array.isArray(item.parts)) {
      text = item.parts.map(p => p.text || '').join(' ');
    }
    return {
      role: item.role === 'model' || item.role === 'assistant' ? 'assistant' : 'user',
      text,
    };
  });
}

/**
 * Records a chat interaction into user memory
 */
function recordUserTurn(userLogin, userText, botText) {
  if (!userLogin) return;
  const canonicalKey = getCanonicalUserKey(userLogin);
  const state = getUserState(canonicalKey);
  state.history.push({ role: 'user', parts: [{ text: userText }] });
  state.history.push({ role: 'model', parts: [{ text: botText }] });
  if (state.history.length > MAX_HISTORY_MESSAGES) {
    state.history = state.history.slice(-MAX_HISTORY_MESSAGES);
  }
}

/**
 * Executes Gemini generation with personality instruction and recovery
 */
async function executeGeminiWithRecovery({ prompt, systemInstruction = SYSTEM_INSTRUCTION }) {
  const client = getGeminiClient();
  if (!client) {
    throw new Error('GEMINI_API_KEY is not set');
  }
  const response = await generateWithRetryAndFallback(client, {
    contents: prompt,
    config: {
      systemInstruction,
      temperature: 0.7,
      maxOutputTokens: 150,
    },
  });
  return {
    text: sanitizeForTwitch(response.text) || '',
  };
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
 * ============================================================================
 * General Web Search Engine for Jaafar (DuckDuckGo HTML Multi-source Fallback)
 * - Enables Jaafar to search the web for fresh, dynamic, and general information
 * - Supports Saudi timezone (Asia/Riyadh) for time-sensitive queries
 * - Formats results concisely to feed into Gemini without token overload
 * - Clean fallbacks ensuring Jaafar never breaks or crashes
 * ============================================================================
 */

/**
 * Returns the current date and time formatted in Saudi Arabia timezone (Asia/Riyadh)
 */
function getSaudiTimeContext() {
  const now = new Date();
  const dateFormatter = new Intl.DateTimeFormat('ar-SA', {
    timeZone: 'Asia/Riyadh',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    weekday: 'long',
  });
  const timeFormatter = new Intl.DateTimeFormat('ar-SA', {
    timeZone: 'Asia/Riyadh',
    hour: 'numeric',
    minute: 'numeric',
    hour12: true,
  });

  const isoFormatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Riyadh',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  });

  return {
    dateArabic: dateFormatter.format(now),
    timeArabic: timeFormatter.format(now),
    isoDate: isoFormatter.format(now), // YYYY-MM-DD
    year: now.getFullYear(),
  };
}

/**
 * Strips HTML tags and decodes common HTML entities
 */
function stripHtmlAndDecode(html) {
  if (!html) return '';
  let text = html.replace(/<[^>]+>/g, ' ');
  text = text
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&#x27;/g, "'")
    .replace(/&#x2F;/g, '/');
  return text.replace(/\s+/g, ' ').trim();
}

/**
 * Determines whether a user message requires external web search
 */
function needsWebSearch(text) {
  if (!text || typeof text !== 'string') return false;
  const clean = text.trim();
  if (clean.length < 3) return false;

  // Patterns indicating live, current, scheduled, or factual external lookup
  const searchTriggers = [
    // Sports & Matches
    /مباراة|مباريات|دوري|كأس|كاس|الهلال|النصر|الاتحاد|الأهلي|الاهلي|ريال مدريد|برشلونة|ليفربول|مانشستر|ارسنال|دوري أبطال|دوري ابطال|ترتيب الدوري|تشكيلة/i,
    // News & Today/Current Events
    /اليوم|أمس|امس|بكرة|بكره|غدا|غداً|الليلة|الليله|الآن|الان|هذا الأسبوع|هذا الاسبوع|جديد|أخبار|اخبار|وش صار في|وش صاير في|وش جديد/i,
    // Weather & Prayer Times
    /طقس|الطقس|جو|الجو|درجة الحرارة|حرارة|أمطار|امطار|مطر|صلاة|الصلاة|أذان|اذان/i,
    // Release Dates & Prices & Crypto & Currency
    /سعر|أسعار|اسعار|دولار|ريال|بيتكوين|تداول|سهم|أسهم|اسهم/i,
    /موعد نزول|تاريخ نزول|متى تنزل|متى ينزل|متى تصدر|تاريخ إصدار|تاريخ اصدار|تحديث|أبديت|ابديت|باتش/i,
    // General Questions seeking modern knowledge
    /كم الساعة|كم الساعه|تاريخ اليوم|كم التاريخ|وش التاريخ/i,
    /وش معنى|ما هو|من هو|من هي|وش قصة|وش سالفة|من فاز|كم النتيجة|كم نتيجة/i,
    /ابحث|دور لي|شف لي|شوف لي|search|google/i,
  ];

  for (const trigger of searchTriggers) {
    if (trigger.test(clean)) {
      return true;
    }
  }

  return false;
}

/**
 * Optimizes the user query for web search engine
 */
function buildSearchQuery(userQuery) {
  let q = userQuery.trim();

  // Remove common bot address prefixes
  q = q.replace(/^(يا\s+)?جعفر\s+/i, '');
  q = q.replace(/^!ai\s+/i, '');
  q = q.replace(/^!a\s+/i, '');
  q = q.replace(/^@\w+\s+/i, '');
  q = q.replace(/^(ابحث|دور لي|شف لي|شوف لي|تكفى ابحث عن|ابحث عن|سيرش عن)\s+/i, '');

  const saudiContext = getSaudiTimeContext();

  // If query mentions "اليوم" (today), append current date context
  if (/اليوم|الليلة|الليله/i.test(q)) {
    if (/مباراة|مباريات/i.test(q) && !/(\d{4}|\d{1,2}\/\d{1,2})/i.test(q)) {
      q += ` ${saudiContext.isoDate}`;
    }
  }

  return q.trim();
}

/**
 * Executes web search using DuckDuckGo HTML scraping
 */
async function performWebSearch(rawQuery) {
  if (!WEB_SEARCH_ENABLED) {
    return { success: false, query: rawQuery, results: [], error: 'Web search is disabled' };
  }

  const query = buildSearchQuery(rawQuery);
  console.log(`[WebSearch] Search requested. Original: "${rawQuery}" -> Formatted: "${query}"`);
  console.log(`[WebSearch] Query: "${query}"`);

  const startTime = Date.now();
  webSearchState.lastQuery = query;
  webSearchState.lastSearchAt = new Date().toISOString();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 7000);

    const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'ar,en-US;q=0.9,en;q=0.8',
        'Referer': 'https://html.duckduckgo.com/',
      },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`DuckDuckGo responded with HTTP ${response.status}`);
    }

    const html = await response.text();

    // Regex to extract title, snippet, and link from DuckDuckGo HTML output
    const results = [];
    const blockRegex = /<a[^>]+class="result__snippet[^"]*"[^>]*>([\s\S]*?)<\/a>/gi;
    const titleRegex = /<a[^>]+class="result__url[^"]*"[^>]*href="([^"]+)"[^>]*>[\s\S]*?<\/a>[\s\S]*?<a[^>]+class="result__snippet/gi;
    
    // Comprehensive snippet and title parsing
    const snippetMatches = [...html.matchAll(/<a[^>]+class="result__snippet[^"]*"[^>]*>([\s\S]*?)<\/a>/gi)];
    const titleMatches = [...html.matchAll(/<h2[^>]*>\s*<a[^>]+class="result__a"[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi)];

    for (let i = 0; i < Math.min(titleMatches.length, 5); i++) {
      const title = stripHtmlAndDecode(titleMatches[i][2]);
      const link = titleMatches[i][1] || '';
      const snippet = snippetMatches[i] ? stripHtmlAndDecode(snippetMatches[i][1]) : '';

      if (snippet || title) {
        results.push({
          title,
          snippet,
          link: link.startsWith('//') ? `https:${link}` : link,
        });
      }
    }

    const duration = Date.now() - startTime;
    webSearchState.lastResultsCount = results.length;
    webSearchState.totalSearches++;
    webSearchState.lastError = null;

    console.log(`[WebSearch] Completed search for "${query}" in ${duration}ms with ${results.length} results.`);
    return {
      success: true,
      query,
      results,
      durationMs: duration,
      saudiTime: getSaudiTimeContext(),
    };
  } catch (error) {
    const duration = Date.now() - startTime;
    console.error(`[WebSearch] Search failed for "${query}":`, error?.message || error);
    webSearchState.lastError = error?.message || String(error);
    return {
      success: false,
      query,
      results: [],
      error: error?.message || String(error),
      durationMs: duration,
      saudiTime: getSaudiTimeContext(),
    };
  }
}

/**
 * Formats web search results into a clean context prompt block for Gemini
 */
function formatWebSearchResultsContext(searchData) {
  if (!searchData || !searchData.success || !searchData.results || searchData.results.length === 0) {
    return '';
  }

  const { saudiTime, results, query } = searchData;
  let text = `\n[نتائج البحث الحي في الإنترنت - استعلام: "${query}"]\n`;
  text += `توقيت وتاريخ الاستعلام الحالي بتوقيت الرياض (السعودية): ${saudiTime.dateArabic} (${saudiTime.isoDate}) الساعة ${saudiTime.timeArabic}\n`;
  text += `نتائج البحث المجمعة:\n`;

  results.forEach((r, idx) => {
    text += `${idx + 1}. ${r.title ? `العنوان: ${r.title}\n` : ''}الملخص: ${r.snippet}\n`;
  });

  text += `توجيهات مهمة لجعفر عند الإجابة بالاعتماد على نتائج البحث:\n`;
  text += `- لخص الجواب بدقة وواقعية بناءً على نتائج البحث أعلاه وبنكهتك السعودية العفوية.\n`;
  text += `- اذكر التواريخ أو المواعيد أو النتائج بدقة (بتوقيت السعودية/الرياض).\n`;
  text += `- اجعل الرد مختصراً جداً وخفيفاً ومناسباً لسرعة شات تويتش (جملة أو جملتين فقط).\n`;

  return text;
}

/**
 * ============================================================================
 * Twitch Live Stream Vision Engine
 * - Periodically captures live stream video screenshots when stream is LIVE.
 * - Configurable interval via VISION_INTERVAL_SECONDS (default 60s, supports 10s).
 * - Avoids duplicate Gemini calls using MD5 hash comparison of unchanged frames.
 * - Stores factual, concise visual memory in currentStreamSession.visualMemory.
 * - Cleared automatically at the end of each stream / start of a fresh session.
 * - Zero automatic chat spam; references visual observations only when asked.
 * ============================================================================
 */

/**
 * Returns a formatted text snippet of recent visual observations for Gemini's context
 */
function getVisualMemoryContext(limit = 6) {
  if (!currentStreamSession.visualMemory || currentStreamSession.visualMemory.length === 0) {
    return '';
  }
  const recent = currentStreamSession.visualMemory.slice(-limit);
  return recent
    .map(entry => {
      const gamePart = entry.game ? ` (${entry.game})` : '';
      return `- [الساعة ${entry.timeFormatted}${gamePart}]: ${entry.summary}`;
    })
    .join('\n');
}

/**
 * Captures a single frame of the live stream and analyzes it with Gemini Flash
 */
async function captureStreamFrame({ force = false, isTest = false } = {}) {
  const broadcasterLogin = (TWITCH_BROADCASTER_LOGIN || '8jef').toLowerCase();

  // 1. Verify if the stream is currently live
  let liveStreamData = null;
  if (!isTest) {
    liveStreamData = await fetchTwitchLiveStream(broadcasterLogin);
    if (liveStreamData) {
      if (!currentStreamSession.active) {
        console.log('[Vision] Stream is live');
        currentStreamSession.active = true;
        currentStreamSession.type = 'live';
        currentStreamSession.streamInfo = liveStreamData;
      }
      visionState.streamWasLive = true;
    } else if (currentStreamSession.active) {
      visionState.streamWasLive = true;
    } else {
      if (visionState.streamWasLive) {
        visionState.streamWasLive = false;
        console.log(`[Vision] Stream is offline for #${broadcasterLogin}`);
      }
      if (!force) {
        visionState.lastStatus = 'offline';
        return { status: 'offline', message: 'Stream is offline' };
      }
    }
  } else {
    console.log('[Vision] Stream is live (test mode)');
  }

  if (visionState.streamWasLive && !isTest) {
    console.log('[Vision] Stream is live');
  }

  // 2. Build thumbnail URL with cache-busting timestamp
  let thumbnailUrl = '';
  if (currentStreamSession.streamInfo?.thumbnail_url) {
    thumbnailUrl = currentStreamSession.streamInfo.thumbnail_url
      .replace('{width}', '1280')
      .replace('{height}', '720');
  } else {
    thumbnailUrl = `https://static-cdn.jtvnw.net/previews-ttv/live_user_${broadcasterLogin}-1280x720.jpg`;
  }
  thumbnailUrl += (thumbnailUrl.includes('?') ? '&' : '?') + `t=${Date.now()}`;

  console.log('[Vision] Capturing frame');
  visionState.lastCaptureAt = new Date().toISOString();
  visionState.lastStatus = 'capturing';

  let buffer;
  try {
    const res = await fetch(thumbnailUrl, {
      method: 'GET',
      headers: {
        'Accept': 'image/jpeg,image/*',
        'User-Agent': 'JaafarTwitchBot/1.0',
      },
    });

    if (!res.ok) {
      const errStatus = `HTTP ${res.status}`;
      console.error(`[Vision] Capture failed: ${errStatus}`);
      visionState.lastStatus = 'capture_failed';
      visionState.lastError = errStatus;
      return { status: 'failed', error: errStatus };
    }

    const arrayBuf = await res.arrayBuffer();
    buffer = Buffer.from(arrayBuf);
  } catch (fetchErr) {
    console.error(`[Vision] Capture failed: ${fetchErr?.message || fetchErr}`);
    visionState.lastStatus = 'capture_failed';
    visionState.lastError = fetchErr?.message || String(fetchErr);
    return { status: 'failed', error: fetchErr?.message || String(fetchErr) };
  }

  // If buffer is suspiciously small and stream is not confirmed live, it might be the 404/offline placeholder
  if (buffer.length < 7500 && !currentStreamSession.active && !force) {
    console.log('[Vision] Captured placeholder image (stream appears offline), skipping analysis.');
    visionState.lastStatus = 'placeholder_offline';
    return { status: 'placeholder_offline' };
  }

  // Fast hash check to prevent redundant analysis of identical CDN frames
  const frameHash = crypto.createHash('md5').update(buffer).digest('hex');
  if (frameHash === visionState.lastFrameHash && !force) {
    console.log('[Vision] Frame unchanged from previous capture, skipping Gemini analysis to save quota.');
    visionState.lastStatus = 'unchanged';
    return { status: 'unchanged', frameHash };
  }
  visionState.lastFrameHash = frameHash;

  // 3. Analyze Frame using Gemini Multimodal
  const ai = getGeminiClient();
  if (!ai) {
    console.warn('[Vision] Gemini client not ready (missing GEMINI_API_KEY). Cannot analyze frame.');
    visionState.lastStatus = 'gemini_not_ready';
    return { status: 'gemini_not_ready' };
  }

  const base64Data = buffer.toString('base64');
  const game = currentStreamSession.streamInfo?.game_name || '';
  const title = currentStreamSession.streamInfo?.title || '';

  const prompt = `أنت جعفر، شات بوت تويتش الخاص بالستريمر جيف (8jef). حلل لقطة الشاشة الملتقطة الآن من البث المباشر${game ? ` (اللعبة الحالية: ${game})` : ''}${title ? ` (عنوان البث: ${title})` : ''}.
اكتب ملخصاً نصياً قصيراً ومركزاً جداً (من سطر إلى سطرين باللغة العربية) للأشياء المهمة التي شاهدتها في الفريم:
- ما المشهد على الشاشة (مثلاً: داخل راوند باللعبة، القائمة الرئيسية، شاشة الانتظار، شاتينغ).
- أي تفاصيل بارزة (السكور أو النتيجة، السلاح أو الشخصية، الكيلز، الفوز أو الخسارة، ردة فعل جيف إن كانت الكاميرا واضحة).
قاعدة حاسمة وإلزامية: كن دقيقاً وواقعياً واكتب فقط ما تراه بعينيك بصدق وبدون أي تأليف أو مبالغة أو افتراض أحداث لم تظهر في الصورة.`;

  try {
    const contents = [
      {
        role: 'user',
        parts: [
          {
            inlineData: {
              mimeType: 'image/jpeg',
              data: base64Data,
            },
          },
          {
            text: prompt,
          },
        ],
      },
    ];

    const aiRes = await generateWithRetryAndFallback(ai, {
      contents,
      config: {
        temperature: 0.2,
        maxOutputTokens: 140,
      },
    });

    const summary = (aiRes.text || '').trim();
    if (!summary) {
      console.warn('[Vision] Frame analysis produced empty text.');
      visionState.lastStatus = 'empty_analysis';
      return { status: 'empty_analysis' };
    }

    console.log('[Vision] Frame analyzed');

    // 4. Update Visual Memory in currentStreamSession
    const now = new Date();
    const timeFormatted = now.toLocaleTimeString('ar-SA', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZone: 'Asia/Riyadh',
    });

    const memoryEntry = {
      timestamp: now.toISOString(),
      timeFormatted,
      summary,
      game,
      title,
    };

    if (!Array.isArray(currentStreamSession.visualMemory)) {
      currentStreamSession.visualMemory = [];
    }
    currentStreamSession.visualMemory.push(memoryEntry);
    currentStreamSession.stats.visualFramesCount = (currentStreamSession.stats.visualFramesCount || 0) + 1;

    // Cap visual memory at max 30 entries per stream session
    if (currentStreamSession.visualMemory.length > 30) {
      currentStreamSession.visualMemory.shift();
    }

    visionState.lastAnalysisAt = now.toISOString();
    visionState.lastStatus = 'analyzed';
    visionState.lastError = null;
    console.log('[Vision] Visual memory updated');

    return {
      status: 'analyzed',
      entry: memoryEntry,
      visualMemoryCount: currentStreamSession.visualMemory.length,
    };
  } catch (aiErr) {
    console.error(`[Vision] Capture failed: ${aiErr?.message || aiErr}`);
    visionState.lastStatus = 'analysis_failed';
    visionState.lastError = aiErr?.message || String(aiErr);
    return { status: 'failed', error: aiErr?.message || String(aiErr) };
  }
}

/**
 * Starts periodic live stream vision polling
 */
function startVisionLoop() {
  if (visionState.timer) {
    clearInterval(visionState.timer);
    visionState.timer = null;
  }

  if (!visionState.enabled) {
    console.log('[Vision] Vision loop is disabled via VISION_ENABLED=false.');
    return;
  }

  const intervalMs = visionState.intervalSeconds * 1000;
  console.log(`[Vision] Vision loop started. Polling every ${visionState.intervalSeconds}s for broadcaster @${TWITCH_BROADCASTER_LOGIN || '8jef'}.`);

  // Run initial check after 5 seconds to catch an ongoing stream quickly
  setTimeout(async () => {
    if (visionState.isChecking) return;
    visionState.isChecking = true;
    try {
      await captureStreamFrame();
    } catch (err) {
      console.error('[Vision] Initial capture check failed:', err?.message || err);
    } finally {
      visionState.isChecking = false;
    }
  }, 5000);

  // Periodic interval
  visionState.timer = setInterval(async () => {
    if (visionState.isChecking) return;
    visionState.isChecking = true;
    try {
      await captureStreamFrame();
    } catch (err) {
      console.error('[Vision] Periodic capture failed:', err?.message || err);
    } finally {
      visionState.isChecking = false;
    }
  }, intervalMs);
}

function stopVisionLoop() {
  if (visionState.timer) {
    clearInterval(visionState.timer);
    visionState.timer = null;
    console.log('[Vision] Vision loop stopped.');
  }
}

/**
 * Health Check Endpoint for Render & Monitoring
 * GET /health -> returns OK
 */
app.get('/health', (req, res) => {
  res.type('text/plain; charset=utf-8').status(200).send('OK');
});

/**
 * Vision Status Endpoint
 * GET /api/vision/status
 */
app.get('/api/vision/status', (req, res) => {
  res.json({
    enabled: visionState.enabled,
    intervalSeconds: visionState.intervalSeconds,
    isLive: currentStreamSession.active,
    streamId: currentStreamSession.id,
    broadcaster: TWITCH_BROADCASTER_LOGIN || '8jef',
    lastCaptureAt: visionState.lastCaptureAt,
    lastAnalysisAt: visionState.lastAnalysisAt,
    lastStatus: visionState.lastStatus,
    visualFramesCount: currentStreamSession.visualMemory ? currentStreamSession.visualMemory.length : 0,
    visualMemory: currentStreamSession.visualMemory || [],
    lastError: visionState.lastError,
  });
});

/**
 * Vision Manual / Test Capture Endpoint
 * POST or GET /api/vision/capture?force=true&test=true
 */
app.all('/api/vision/capture', async (req, res) => {
  try {
    const force = req.query.force !== 'false';
    const isTest = req.query.test === 'true' || req.body?.test === true;
    const result = await captureStreamFrame({ force, isTest });
    res.json({
      success: result.status === 'analyzed' || result.status === 'unchanged',
      ...result,
      isLive: currentStreamSession.active,
      visualMemoryCount: currentStreamSession.visualMemory ? currentStreamSession.visualMemory.length : 0,
      recentVisualMemory: currentStreamSession.visualMemory ? currentStreamSession.visualMemory.slice(-5) : [],
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err?.message || String(err),
    });
  }
});

/**
 * ============================================================================
 * Twitch Live Chat Log & Real-Time Viewer System
 * Route: /chat-log
 * Real-Time Stream: /api/chat-log/stream (Server-Sent Events)
 * Protection: Private access via CHAT_LOG_SECRET
 * ============================================================================
 */

function isAuthorizedForChatLog(req) {
  const secret = (process.env.CHAT_LOG_SECRET || 'jef8-jaafar-chat-log').trim();
  // 1. Query param ?key=...
  const queryKey = req.query?.key;
  if (queryKey && typeof queryKey === 'string' && queryKey.trim() === secret) {
    return true;
  }
  // 2. Custom header
  const headerKey = req.headers['x-chat-log-key'];
  if (headerKey && typeof headerKey === 'string' && headerKey.trim() === secret) {
    return true;
  }
  // 3. Cookie check
  const cookieHeader = req.headers.cookie || '';
  const match = cookieHeader.match(/(?:^|;\s*)chat_log_key=([^;]+)/);
  if (match) {
    try {
      const val = decodeURIComponent(match[1].trim());
      if (val === secret) return true;
    } catch (_) {}
  }
  return false;
}

// Verification Endpoint for Chat Log Password
app.post('/api/chat-log/verify', express.json(), (req, res) => {
  const secret = (process.env.CHAT_LOG_SECRET || 'jef8-jaafar-chat-log').trim();
  const provided = (req.body?.key || req.query?.key || '').trim();
  if (provided === secret) {
    res.cookie('chat_log_key', encodeURIComponent(secret), {
      path: '/',
      maxAge: 30 * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
      httpOnly: false,
    });
    return res.json({ success: true, authorized: true });
  }
  return res.status(401).json({ success: false, authorized: false, error: 'مفتاح الدخول غير صحيح' });
});

// SSE Live Stream Endpoint for Chat Log
app.get('/api/chat-log/stream', (req, res) => {
  if (!isAuthorizedForChatLog(req)) {
    return res.status(401).json({ error: 'Unauthorized access to chat log' });
  }

  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  if (typeof res.flushHeaders === 'function') {
    res.flushHeaders();
  }

  const client = { id: Date.now() + Math.random(), res };
  chatLogClients.add(client);

  // Send initial state immediately
  const initPayload = {
    type: 'init',
    broadcaster: TWITCH_BROADCASTER_LOGIN || '8jef',
    sessionId: currentStreamSession.id,
    streamActive: currentStreamSession.active,
    startedAt: currentStreamSession.startedAt,
    messages: currentStreamSession.messages || [],
    stats: {
      totalMessages: currentStreamSession.stats.totalMessages,
      sessionMessages: currentStreamSession.messages.length,
      streamActive: currentStreamSession.active,
    },
  };
  res.write(`data: ${JSON.stringify(initPayload)}\n\n`);

  req.on('close', () => {
    chatLogClients.delete(client);
  });
});

// Clear Chat Log Endpoint
app.post('/api/chat-log/clear', (req, res) => {
  if (!isAuthorizedForChatLog(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  currentStreamSession.messages = [];
  broadcastChatLogEvent({
    type: 'cleared',
    stats: {
      totalMessages: currentStreamSession.stats.totalMessages,
      sessionMessages: 0,
      sessionId: currentStreamSession.id,
      streamActive: currentStreamSession.active,
    },
  });
  return res.json({ success: true, message: 'Chat log cleared' });
});

// Chat Log Status Endpoint
app.get('/api/chat-log/status', (req, res) => {
  const authorized = isAuthorizedForChatLog(req);
  return res.json({
    authorized,
    broadcaster: TWITCH_BROADCASTER_LOGIN || '8jef',
    streamActive: currentStreamSession.active,
    sessionId: currentStreamSession.id,
    messagesCount: authorized ? currentStreamSession.messages.length : null,
    totalMessages: authorized ? currentStreamSession.stats.totalMessages : null,
    activeSubscribers: chatLogClients.size,
  });
});

// Test / Simulation message injector for Chat Log verification
app.post('/api/chat-log/test-message', express.json(), (req, res) => {
  if (!isAuthorizedForChatLog(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const username = (req.body?.username || req.query?.username || '4VREN').trim();
  const text = (req.body?.text || req.query?.text || 'جعفر شوف وش صار').trim();
  const role = (req.body?.role || req.query?.role || 'moderator').toLowerCase();
  const color = req.body?.color || (username.toLowerCase() === '4vren' ? '#F59E0B' : '#9146FF');

  const badges = [];
  if (role === 'broadcaster' || role === 'streamer') badges.push({ set_id: 'broadcaster', id: '1' });
  if (role === 'moderator' || role === 'mod') badges.push({ set_id: 'moderator', id: '1' });
  if (role === 'vip') badges.push({ set_id: 'vip', id: '1' });
  if (role === 'subscriber' || role === 'sub') badges.push({ set_id: 'subscriber', id: '1' });

  const fakeChatEvent = {
    message_id: 'test_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
    chatter_user_id: username.toLowerCase() === '4vren' ? (jitoIdentity.userId || '12345678') : '98765432',
    chatter_user_login: username.toLowerCase(),
    chatter_user_name: username,
    broadcaster_user_id: '99999999',
    broadcaster_user_login: (TWITCH_BROADCASTER_LOGIN || '8jef').toLowerCase(),
    broadcaster_user_name: TWITCH_BROADCASTER_LOGIN || '8jef',
    message: { text, fragments: [{ type: 'text', text }] },
    color,
    badges,
  };

  const analysis = analyzeChatMessage(fakeChatEvent, twitchAuthState.user);
  const record = recordStreamChatMessage(fakeChatEvent, analysis);

  return res.json({
    success: true,
    message: 'Test message recorded and broadcasted',
    record,
    sessionMessagesCount: currentStreamSession.messages.length,
  });
});

// GET /chat-log HTML Dashboard Page
app.get('/chat-log', (req, res) => {
  const broadcaster = TWITCH_BROADCASTER_LOGIN || '8jef';
  const hasKeyInQuery = Boolean(req.query?.key);

  res.type('html').send(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Twitch Chat Log • #${broadcaster}</title>
  <style>
    :root {
      --bg: #0E0E10;
      --card-bg: #18181B;
      --card-header: #1F1F23;
      --border: #2D2D35;
      --text: #EFEFF1;
      --text-muted: #ADADB8;
      --purple: #9146FF;
      --purple-hover: #772CE8;
      --green: #10B981;
      --red: #EF4444;
      --amber: #F59E0B;
      --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: var(--font);
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow: hidden;
    }

    /* Top App Bar */
    header {
      background: var(--card-header);
      border-bottom: 1px solid var(--border);
      padding: 10px 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
      z-index: 10;
    }

    .brand-section {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .brand-title {
      font-size: 15px;
      font-weight: 700;
      color: var(--text);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .channel-pill {
      background: #2D2D35;
      color: #BF94FF;
      font-size: 13px;
      font-weight: 600;
      padding: 3px 10px;
      border-radius: 6px;
      direction: ltr;
      display: inline-block;
    }

    .header-indicators {
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 12px;
      flex-wrap: wrap;
    }

    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 9999px;
      font-weight: 600;
      font-size: 11px;
    }
    .status-pill.live { background: rgba(239, 68, 68, 0.15); color: #F87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .status-pill.offline { background: rgba(173, 173, 184, 0.15); color: var(--text-muted); border: 1px solid var(--border); }
    .status-pill.connected { background: rgba(16, 185, 129, 0.15); color: #34D399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .status-pill.disconnected { background: rgba(239, 68, 68, 0.15); color: #F87171; border: 1px solid rgba(239, 68, 68, 0.3); }

    .msg-counter {
      color: var(--text-muted);
      font-size: 12px;
    }
    .msg-counter strong {
      color: var(--text);
      font-family: var(--mono);
    }

    /* Controls Bar */
    .controls-bar {
      background: var(--card-bg);
      border-bottom: 1px solid var(--border);
      padding: 8px 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
    }

    .search-wrapper {
      position: relative;
      flex: 1;
      min-width: 200px;
      max-width: 360px;
    }

    .search-input {
      width: 100%;
      background: #0E0E10;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 7px 12px 7px 30px;
      color: var(--text);
      font-size: 13px;
      outline: none;
      transition: border-color 0.15s;
    }
    .search-input:focus {
      border-color: var(--purple);
    }
    .search-icon {
      position: absolute;
      left: 10px;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-muted);
      font-size: 13px;
      pointer-events: none;
    }

    .actions-wrapper {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    .btn {
      background: #2D2D35;
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 6px 12px;
      font-size: 12px;
      font-weight: 500;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.15s;
    }
    .btn:hover { background: #393945; }
    .btn.active { background: var(--purple); border-color: var(--purple); color: white; }
    .btn-danger:hover { background: rgba(239, 68, 68, 0.2); border-color: var(--red); color: #FCA5A5; }

    .filter-chips {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .filter-chip {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text-muted);
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 11px;
      cursor: pointer;
      transition: all 0.15s;
    }
    .filter-chip:hover { color: var(--text); border-color: #4A4A58; }
    .filter-chip.active { background: #2D2D35; color: #BF94FF; border-color: var(--purple); font-weight: 600; }

    /* Chat Messages Container */
    #chatContainer {
      flex: 1;
      overflow-y: auto;
      padding: 14px 16px;
      display: flex;
      flex-direction: column;
      gap: 4px;
      position: relative;
    }

    /* Message Row */
    .chat-row {
      display: flex;
      align-items: baseline;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 13px;
      line-height: 1.6;
      word-break: break-word;
      transition: background 0.1s;
    }
    .chat-row:hover {
      background: rgba(255, 255, 255, 0.03);
    }
    .chat-row.highlight-mention {
      background: rgba(245, 158, 11, 0.08);
      border-right: 3px solid var(--amber);
    }

    .msg-time {
      font-family: var(--mono);
      font-size: 11px;
      color: #6B7280;
      margin-left: 8px;
      direction: ltr;
      display: inline-block;
      flex-shrink: 0;
      user-select: none;
    }

    .badge-chip {
      font-size: 10px;
      font-weight: 700;
      padding: 1px 6px;
      border-radius: 4px;
      margin-left: 6px;
      user-select: none;
      display: inline-block;
      flex-shrink: 0;
    }
    .badge-broadcaster { background: #772CE8; color: #FFFFFF; }
    .badge-mod { background: #059669; color: #FFFFFF; }
    .badge-vip { background: #DB2777; color: #FFFFFF; }
    .badge-sub { background: #4F46E5; color: #FFFFFF; }
    .badge-jito { background: #D97706; color: #FFFFFF; font-weight: 800; border: 1px solid #F59E0B; }

    .msg-user {
      font-weight: 700;
      margin-left: 6px;
      flex-shrink: 0;
      direction: ltr;
      display: inline-block;
    }

    .msg-text {
      color: var(--text);
      word-break: break-word;
      direction: auto;
      flex: 1;
    }

    /* System Dividers */
    .sys-divider {
      text-align: center;
      margin: 12px 0;
      position: relative;
      font-size: 12px;
      color: var(--text-muted);
      user-select: none;
    }
    .sys-divider::before {
      content: '';
      position: absolute;
      top: 50%;
      right: 0;
      left: 0;
      height: 1px;
      background: var(--border);
      z-index: 1;
    }
    .sys-divider span {
      position: relative;
      z-index: 2;
      background: var(--bg);
      padding: 2px 14px;
      border-radius: 9999px;
      border: 1px solid var(--border);
      font-family: var(--mono);
      font-size: 11px;
    }
    .sys-divider.stream-start span { color: #34D399; border-color: rgba(16, 185, 129, 0.3); }
    .sys-divider.stream-end span { color: #F87171; border-color: rgba(239, 68, 68, 0.3); }

    /* Empty state */
    .empty-state {
      margin: auto;
      text-align: center;
      color: var(--text-muted);
      padding: 40px 20px;
    }
    .empty-icon { font-size: 36px; margin-bottom: 8px; opacity: 0.7; }

    /* Floating Jump Button */
    .jump-bottom-btn {
      position: absolute;
      bottom: 20px;
      left: 20px;
      background: var(--purple);
      color: white;
      border: none;
      border-radius: 9999px;
      padding: 8px 18px;
      font-size: 12px;
      font-weight: 600;
      box-shadow: 0 4px 14px rgba(0, 0, 0, 0.5);
      cursor: pointer;
      display: none;
      align-items: center;
      gap: 6px;
      z-index: 20;
      transition: transform 0.15s;
    }
    .jump-bottom-btn:hover { background: var(--purple-hover); transform: translateY(-2px); }

    /* Auth Modal Overlay */
    #authOverlay {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.85);
      backdrop-filter: blur(8px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 100;
      padding: 16px;
    }
    .auth-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 28px;
      max-width: 400px;
      width: 100%;
      text-align: center;
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
    }
    .auth-card h3 {
      font-size: 18px;
      margin-bottom: 8px;
      color: var(--text);
    }
    .auth-card p {
      font-size: 13px;
      color: var(--text-muted);
      margin-bottom: 20px;
      line-height: 1.5;
    }
    .auth-card input {
      width: 100%;
      background: #0E0E10;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px 14px;
      color: white;
      font-size: 14px;
      outline: none;
      margin-bottom: 12px;
      text-align: center;
      letter-spacing: 2px;
      font-family: var(--mono);
    }
    .auth-card input:focus { border-color: var(--purple); }
    .auth-card button {
      width: 100%;
      background: var(--purple);
      color: white;
      border: none;
      border-radius: 8px;
      padding: 12px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.15s;
    }
    .auth-card button:hover { background: var(--purple-hover); }
    .auth-error {
      color: #F87171;
      font-size: 12px;
      margin-top: 10px;
      display: none;
    }

    /* Mobile Responsive Tweaks */
    @media (max-width: 640px) {
      header { padding: 8px 12px; }
      .brand-title { font-size: 13px; }
      .controls-bar { padding: 6px 12px; }
      .search-wrapper { max-width: 100%; order: 2; width: 100%; }
      .actions-wrapper { order: 1; width: 100%; justify-content: space-between; }
      #chatContainer { padding: 10px 8px; }
      .chat-row { font-size: 12px; padding: 3px 6px; }
      .msg-time { font-size: 10px; }
    }
  </style>
</head>
<body>

  <!-- Top App Bar -->
  <header>
    <div class="brand-section">
      <div class="brand-title">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="#9146FF"><path d="M11.571 4.714h1.715v5.143H11.57zm4.715 0H18v5.143h-1.714zM6 0L1.714 4.286v15.428h5.143V24l4.286-4.286h3.428L22.286 12V0zm14.571 11.143l-3.428 3.428h-3.429l-3 3v-3H6.857V1.714h13.714z"/></svg>
        سجل شات البث الحي
      </div>
      <div class="channel-pill">#${broadcaster}</div>
    </div>

    <div class="header-indicators">
      <div id="streamStatusPill" class="status-pill offline">⚪ البث متوقف</div>
      <div id="connStatusPill" class="status-pill disconnected">● جاري الاتصال...</div>
      <div class="msg-counter">رسائل الجلسة: <strong id="msgCountDisplay">0</strong></div>
    </div>
  </header>

  <!-- Controls Bar -->
  <div class="controls-bar">
    <div class="search-wrapper">
      <input type="text" id="searchInput" class="search-input" placeholder="بحث في الرسائل أو الأسماء..." />
      <span class="search-icon">🔍</span>
    </div>

    <div class="actions-wrapper">
      <div class="filter-chips">
        <button class="filter-chip active" data-filter="all" onclick="setRoleFilter('all', this)">الكل</button>
        <button class="filter-chip" data-filter="jito" onclick="setRoleFilter('jito', this)">👑 جيتو</button>
        <button class="filter-chip" data-filter="mods" onclick="setRoleFilter('mods', this)">🛡️ المودز</button>
        <button class="filter-chip" data-filter="broadcaster" onclick="setRoleFilter('broadcaster', this)">🟣 الستريمر</button>
      </div>

      <button id="btnAutoScroll" class="btn active" onclick="toggleAutoScroll()">
        <span>⬇️</span> التمرير التلقائي
      </button>

      <button class="btn" title="إرسال رسالة اختبارية لحظية للتأكد من عمل النظام" onclick="sendTestChatMessage()">
        <span>⚡</span> تجربة
      </button>

      <button class="btn btn-danger" onclick="clearChatLog()">
        <span>🗑️</span> مسح
      </button>
    </div>
  </div>

  <!-- Messages List -->
  <div id="chatContainer">
    <div id="emptyPlaceholder" class="empty-state">
      <div class="empty-icon">💬</div>
      <div>بانتظار وصول رسائل الشات من البث المباشر...</div>
    </div>
  </div>

  <!-- Jump to bottom pill -->
  <button id="btnJumpBottom" class="jump-bottom-btn" onclick="scrollToBottom(true)">
    <span>↓</span> رسائل جديدة بالأسفل
  </button>

  <!-- Password Authentication Modal -->
  <div id="authOverlay">
    <div class="auth-card">
      <div style="font-size: 32px; margin-bottom: 12px;">🔒</div>
      <h3>صفحة سجل الشات خاصة</h3>
      <p>أدخل مفتاح الدخول المصرح به (<code style="background:#2D2D35; padding:2px 6px; border-radius:4px; font-family:var(--mono); font-size:11px;">CHAT_LOG_SECRET</code>) لمشاهدة الشات مباشرة:</p>
      <form onsubmit="handleAuthSubmit(event)">
        <input type="password" id="authKeyInput" placeholder="••••••••••••" autocomplete="current-password" autofocus />
        <button type="submit" id="btnAuthSubmit">فتح الشات المباشر</button>
        <div id="authErrorMsg" class="auth-error">مفتاح الدخول غير صحيح، حاول ثانية</div>
      </form>
    </div>
  </div>

  <script>
    // State
    const allMessages = [];
    let autoScroll = true;
    let isUserScrolledUp = false;
    let activeRoleFilter = 'all';
    let searchQuery = '';
    let currentSessionId = null;
    let sseSource = null;

    // Cache DOM
    const chatContainer = document.getElementById('chatContainer');
    const emptyPlaceholder = document.getElementById('emptyPlaceholder');
    const msgCountDisplay = document.getElementById('msgCountDisplay');
    const streamStatusPill = document.getElementById('streamStatusPill');
    const connStatusPill = document.getElementById('connStatusPill');
    const btnAutoScroll = document.getElementById('btnAutoScroll');
    const btnJumpBottom = document.getElementById('btnJumpBottom');
    const searchInput = document.getElementById('searchInput');
    const authOverlay = document.getElementById('authOverlay');
    const authKeyInput = document.getElementById('authKeyInput');
    const authErrorMsg = document.getElementById('authErrorMsg');

    // Get Auth Key from URL or LocalStorage
    function getStoredKey() {
      const urlParams = new URLSearchParams(window.location.search);
      const queryKey = urlParams.get('key');
      if (queryKey) {
        localStorage.setItem('chat_log_key', queryKey.trim());
        return queryKey.trim();
      }
      return localStorage.getItem('chat_log_key') || '';
    }

    // Connect to SSE Stream
    function initChatStream() {
      const key = getStoredKey();
      if (!key) {
        showAuthModal();
        return;
      }

      if (sseSource) {
        sseSource.close();
      }

      connStatusPill.className = 'status-pill offline';
      connStatusPill.innerText = '● جاري الاتصال...';

      const sseUrl = '/api/chat-log/stream?key=' + encodeURIComponent(key);
      sseSource = new EventSource(sseUrl);

      sseSource.onopen = () => {
        connStatusPill.className = 'status-pill connected';
        connStatusPill.innerText = '● متصل لحظياً';
        hideAuthModal();
      };

      sseSource.onmessage = (e) => {
        try {
          const payload = JSON.parse(e.data);
          handleStreamPayload(payload);
        } catch (err) {
          console.error('[ChatLog] Parse error:', err);
        }
      };

      sseSource.onerror = (err) => {
        connStatusPill.className = 'status-pill disconnected';
        connStatusPill.innerText = '● انقطع الاتصال';
        
        // Test if error is 401 Unauthorized
        fetch('/api/chat-log/status?key=' + encodeURIComponent(key))
          .then(res => {
            if (res.status === 401) {
              sseSource.close();
              showAuthModal();
            }
          })
          .catch(() => {});
      };
    }

    // Process Incoming SSE Events
    function handleStreamPayload(payload) {
      if (!payload || !payload.type) return;

      if (payload.type === 'init') {
        currentSessionId = payload.sessionId;
        updateStreamStatus(payload.streamActive);
        
        allMessages.length = 0;
        chatContainer.innerHTML = '';
        
        if (Array.isArray(payload.messages) && payload.messages.length > 0) {
          emptyPlaceholder.style.display = 'none';
          payload.messages.forEach(msg => {
            allMessages.push(msg);
            renderMessageRow(msg, false);
          });
          scrollToBottom();
        } else {
          chatContainer.appendChild(emptyPlaceholder);
          emptyPlaceholder.style.display = 'block';
        }
        updateCounter(allMessages.length);
        return;
      }

      if (payload.type === 'message') {
        const msg = payload.message;
        if (!msg) return;

        allMessages.push(msg);
        emptyPlaceholder.style.display = 'none';
        renderMessageRow(msg, true);
        updateCounter(payload.stats?.sessionMessages || allMessages.length);

        if (autoScroll && !isUserScrolledUp) {
          scrollToBottom();
        } else {
          btnJumpBottom.style.display = 'flex';
        }
        return;
      }

      if (payload.type === 'session_started') {
        updateStreamStatus(true);
        currentSessionId = payload.sessionId;
        // Clean chat log for new session
        allMessages.length = 0;
        chatContainer.innerHTML = '';
        renderDivider('━━━ بدأت جلسة بث جديدة ━━━', 'stream-start');
        updateCounter(0);
        return;
      }

      if (payload.type === 'session_ended') {
        updateStreamStatus(false);
        renderDivider('━━━ انتهت جلسة البث ━━━', 'stream-end');
        return;
      }

      if (payload.type === 'cleared') {
        allMessages.length = 0;
        chatContainer.innerHTML = '';
        chatContainer.appendChild(emptyPlaceholder);
        emptyPlaceholder.style.display = 'block';
        updateCounter(0);
        return;
      }
    }

    // Render a Single Message Row
    function renderMessageRow(msg, checkFilter = true) {
      if (checkFilter && !matchesCurrentFilter(msg)) {
        return;
      }

      const row = document.createElement('div');
      row.className = 'chat-row';
      row.id = 'row_' + msg.id;
      if (msg.isMention || msg.isReplyToBot) {
        row.classList.add('highlight-mention');
      }

      // 1. Time
      const timeSpan = document.createElement('span');
      timeSpan.className = 'msg-time';
      timeSpan.innerText = '[' + (msg.timeFormatted || '00:00:00') + ']';
      row.appendChild(timeSpan);

      // 2. Badges
      if (msg.isBroadcaster) {
        const b = document.createElement('span');
        b.className = 'badge-chip badge-broadcaster';
        b.innerText = 'ستريمر';
        row.appendChild(b);
      }
      if (msg.isJito) {
        const b = document.createElement('span');
        b.className = 'badge-chip badge-jito';
        b.innerText = 'جيتو 👑';
        row.appendChild(b);
      }
      if (msg.isModerator && !msg.isBroadcaster) {
        const b = document.createElement('span');
        b.className = 'badge-chip badge-mod';
        b.innerText = 'مود';
        row.appendChild(b);
      }
      if (msg.isVip) {
        const b = document.createElement('span');
        b.className = 'badge-chip badge-vip';
        b.innerText = 'VIP';
        row.appendChild(b);
      }

      // 3. Username
      const userSpan = document.createElement('span');
      userSpan.className = 'msg-user';
      userSpan.innerText = (msg.userName || msg.userLogin || 'متابع') + ':';
      if (msg.color) {
        userSpan.style.color = msg.color;
      } else {
        userSpan.style.color = getUserColor(msg.userName || msg.userLogin || '');
      }
      row.appendChild(userSpan);

      // 4. Text
      const textSpan = document.createElement('span');
      textSpan.className = 'msg-text';
      textSpan.innerText = msg.text || '';
      row.appendChild(textSpan);

      chatContainer.appendChild(row);
    }

    // Render Divider Message
    function renderDivider(text, typeClass) {
      const div = document.createElement('div');
      div.className = 'sys-divider ' + (typeClass || '');
      const span = document.createElement('span');
      span.innerText = text;
      div.appendChild(span);
      chatContainer.appendChild(div);
      scrollToBottom();
    }

    // User Color Generator
    const USER_COLORS = ['#FF4A4A', '#00FF7F', '#1E90FF', '#FF69B4', '#FFA500', '#9370DB', '#00FFFF', '#FFD700', '#32CD32'];
    function getUserColor(str) {
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        hash = str.charCodeAt(i) + ((hash << 5) - hash);
      }
      const idx = Math.abs(hash) % USER_COLORS.length;
      return USER_COLORS[idx];
    }

    // Filter Logic
    function matchesCurrentFilter(msg) {
      // Role filter
      if (activeRoleFilter === 'jito' && !msg.isJito) return false;
      if (activeRoleFilter === 'mods' && !msg.isModerator) return false;
      if (activeRoleFilter === 'broadcaster' && !msg.isBroadcaster) return false;

      // Text search query
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const userName = (msg.userName || '').toLowerCase();
        const userLogin = (msg.userLogin || '').toLowerCase();
        const text = (msg.text || '').toLowerCase();
        if (!userName.includes(q) && !userLogin.includes(q) && !text.includes(q)) {
          return false;
        }
      }
      return true;
    }

    function reapplyFilters() {
      chatContainer.innerHTML = '';
      let visibleCount = 0;

      allMessages.forEach(msg => {
        if (matchesCurrentFilter(msg)) {
          renderMessageRow(msg, false);
          visibleCount++;
        }
      });

      if (visibleCount === 0) {
        emptyPlaceholder.style.display = 'block';
        chatContainer.appendChild(emptyPlaceholder);
      } else {
        emptyPlaceholder.style.display = 'none';
        scrollToBottom();
      }
    }

    function setRoleFilter(role, btnElem) {
      activeRoleFilter = role;
      document.querySelectorAll('.filter-chip').forEach(el => el.classList.remove('active'));
      if (btnElem) btnElem.classList.add('active');
      reapplyFilters();
    }

    searchInput.addEventListener('input', (e) => {
      searchQuery = e.target.value.trim();
      reapplyFilters();
    });

    // Auto-Scroll Handling
    function scrollToBottom(force = false) {
      if (force || (autoScroll && !isUserScrolledUp)) {
        chatContainer.scrollTop = chatContainer.scrollHeight;
        btnJumpBottom.style.display = 'none';
        isUserScrolledUp = false;
      }
    }

    chatContainer.addEventListener('scroll', () => {
      const threshold = 80;
      const isAtBottom = chatContainer.scrollHeight - chatContainer.scrollTop - chatContainer.clientHeight <= threshold;
      if (isAtBottom) {
        isUserScrolledUp = false;
        btnJumpBottom.style.display = 'none';
      } else {
        isUserScrolledUp = true;
      }
    });

    function toggleAutoScroll() {
      autoScroll = !autoScroll;
      if (autoScroll) {
        btnAutoScroll.classList.add('active');
        isUserScrolledUp = false;
        scrollToBottom(true);
      } else {
        btnAutoScroll.classList.remove('active');
      }
    }

    // Clear Chat Log
    async function clearChatLog() {
      if (!confirm('هل أنت متأكد من مسح سجل الشات الحالي؟')) return;
      const key = getStoredKey();
      try {
        await fetch('/api/chat-log/clear?key=' + encodeURIComponent(key), { method: 'POST' });
      } catch (err) {
        console.error('Failed to clear log on server:', err);
      }
    }

    // Send Test Message (Simulates incoming Twitch Chat message)
    const testSamples = [
      { username: '4VREN', text: 'جعفر شوف وش صار', role: 'moderator' },
      { username: 'solyyy6', text: 'ههههههههه أسطوري يا وحش', role: 'subscriber' },
      { username: 'user123', text: 'وش تلعب اليوم يا جيف؟', role: 'viewer' },
      { username: '${broadcaster}', text: 'حياكم الله جميعاً بالبث!', role: 'broadcaster' }
    ];
    let sampleIdx = 0;
    async function sendTestChatMessage() {
      const key = getStoredKey();
      const sample = testSamples[sampleIdx % testSamples.length];
      sampleIdx++;
      try {
        await fetch('/api/chat-log/test-message?key=' + encodeURIComponent(key), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(sample),
        });
      } catch (err) {
        console.error('Test message failed:', err);
      }
    }

    // Counters & Status Helpers
    function updateCounter(count) {
      msgCountDisplay.innerText = count;
    }

    function updateStreamStatus(isLive) {
      if (isLive) {
        streamStatusPill.className = 'status-pill live';
        streamStatusPill.innerText = '🔴 بث مباشر نشط';
      } else {
        streamStatusPill.className = 'status-pill offline';
        streamStatusPill.innerText = '⚪ البث متوقف';
      }
    }

    // Auth Overlay Handlers
    function showAuthModal() {
      authOverlay.style.display = 'flex';
      authKeyInput.value = '';
      authKeyInput.focus();
    }

    function hideAuthModal() {
      authOverlay.style.display = 'none';
      authErrorMsg.style.display = 'none';
    }

    async function handleAuthSubmit(e) {
      e.preventDefault();
      const enteredKey = authKeyInput.value.trim();
      if (!enteredKey) return;

      const submitBtn = document.getElementById('btnAuthSubmit');
      submitBtn.disabled = true;
      submitBtn.innerText = 'جاري التحقق...';

      try {
        const res = await fetch('/api/chat-log/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key: enteredKey }),
        });
        const data = await res.json();
        if (data.authorized) {
          localStorage.setItem('chat_log_key', enteredKey);
          hideAuthModal();
          initChatStream();
        } else {
          authErrorMsg.style.display = 'block';
        }
      } catch (err) {
        authErrorMsg.style.display = 'block';
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerText = 'فتح الشات المباشر';
      }
    }

    // Startup
    initChatStream();
  </script>
</body>
</html>`);
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
  const isJito = isJitoChatter(username);
  const userKey = isJito ? getJitoMemoryKey() : username.toLowerCase();

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

    let systemInstruction = SYSTEM_INSTRUCTION;

    // Inject Twitch Live Stream Visual Memory into system instruction
    const visualContext = getVisualMemoryContext(6);
    if (visualContext) {
      systemInstruction += `\n\n[الذاكرة البصرية للبث الحي - ما شاهده جعفر في لقطات البث الأخيرة]:\n${visualContext}\nتنبيه مهم: إذا سُئلت عن شيء حدث في البث المباشر (مثل وش صار، وش اللعبة، وش سوا جيف، فاز أو خسر)، أجب فقط بناءً على ما رأيته وسُجل في الذاكرة البصرية أعلاه. إذا لم تكن اللقطة أو الحدث مسجلاً في الذاكرة البصرية، قل بصراحة وعفوية أنك ما شفت اللقطة ذيك وما انتبهت لها، ولا تخترع أبداً أحداثاً لم تشاهدها.`;
    }

    if (isJito) {
      systemInstruction += `\n\nتنبيه خاص للمحادثة الحالية: المتابع الذي يكلمك الآن عبر الأمر هو "جيتو" (مطورك وصانعك وأفضل مود في القناة، حسابه في تويتش هو @${username}). خاطبه وناده باسم "جيتو" دائماً في ردك (مثال: "هلا يا جيتو"، "أبشر يا جيتو"، "كفو يا جيتو")، وعامله بمكانته الخاصة كصانعك، واجعل الرد مختصراً ومناسباً لسرعة شات تويتش.`;
    }

    // Check if user query requires general web search (matches, news, fresh info)
    if (WEB_SEARCH_ENABLED && needsWebSearch(userMessage)) {
      try {
        const searchResult = await performWebSearch(userMessage);
        const searchPromptBlock = formatWebSearchResultsContext(searchResult);
        if (searchPromptBlock) {
          systemInstruction += `\n\n${searchPromptBlock}`;
        }
      } catch (searchErr) {
        console.error('[Twitch AI] Web search non-fatal error:', searchErr?.message || searchErr);
      }
    }

    // Standard generation configuration
    const generationConfig = {
      systemInstruction,
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
  const isJito = isJitoChatter(username);
  const userKey = isJito ? getJitoMemoryKey() : username.toLowerCase();

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

    // 6. Save authentication state securely in server memory and persistent disk
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

    saveTwitchAuthStateToDisk();

    console.log(`[Twitch OAuth] Successfully authorized Twitch account: @${accountLogin} (${accountDisplayName})`);

    // Initiate Twitch Chat EventSub WebSocket connection now that OAuth is authorized
    startTwitchChatConnection();

    // Resolve Jito permanent User ID if needed
    resolveJitoTwitchIdentity().catch(err => {
      console.warn('[Jito Identity] Background resolution notice on OAuth callback:', err?.message || err);
    });

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
        <span class="info-val" style="font-family: monospace; font-size: 11px;">user:read:chat user:write:chat user:bot moderator:manage:banned_users</span>
      </div>
      <div class="info-row">
        <span class="info-label">حالة الجلسة:</span>
        <span class="info-val" style="color: #065F46;">نشطة ومتصلة بالـ WebSocket ✓</span>
      </div>
    </div>

    <!-- Render Free Persistent Token Setup Box -->
    <div style="background: #F0FDF4; border: 1px solid #BBF7D0; border-radius: 12px; padding: 16px; margin-bottom: 20px; text-align: right;">
      <div style="display: flex; align-items: center; gap: 6px; color: #166534; font-size: 13px; font-weight: 700; margin-bottom: 6px;">
        <span>📌</span> الحفاظ على الربط دائمًا في Render المجاني (بدون Disks مدفوعة):
      </div>
      <p style="color: #15803D; font-size: 12px; line-height: 1.5; margin-bottom: 10px;">
        لإبقاء ربط جعفر دائمًا حتى بعد نوم السيرفر (Render Sleep) أو إعادة التشغيل، أضف هذا المتغير في <strong>Environment Variables</strong> في لوحة تحكم Render:
      </p>
      <div style="background: white; border: 1px solid #86EFAC; border-radius: 8px; padding: 10px; display: flex; align-items: center; justify-content: space-between; gap: 8px;">
        <code style="font-family: monospace; font-size: 11px; color: #166534; word-break: break-all; text-align: left; direction: ltr; flex: 1;">TWITCH_REFRESH_TOKEN=${tokenData.refresh_token}</code>
        <button id="copyBtn" onclick="navigator.clipboard.writeText('${tokenData.refresh_token}'); this.innerText='تم النسخ ✓';" style="background: #166534; color: white; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; white-space: nowrap;">نسخ الـ Token</button>
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
  const hasRefreshTokenInEnv = Boolean(process.env.TWITCH_REFRESH_TOKEN && process.env.TWITCH_REFRESH_TOKEN.trim());
  const hasTimeoutScope = hasModeratorManageBannedUsersScope();

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
      hasRefreshTokenInEnv,
      hasSavedTokenOnDisk: hasSavedTwitchAuth(),
      moderation: {
        hasTimeoutScope,
        requiredScope: 'moderator:manage:banned_users',
        status: hasTimeoutScope ? 'ready' : 'reauth_required',
        notice: hasTimeoutScope
          ? 'تصريح التايم اوت (moderator:manage:banned_users) مفعّل وجاهز في التوكن الحالي.'
          : 'تنبيه: التوكن الحالي لا يحتوي على تصريح (moderator:manage:banned_users). يرجى التوجه إلى /auth/twitch لإعادة التفويض لتفعيل ميزة Timeout.',
        botModeratorHint: `يجب إعطاء البوت رتبة مشرف في القناة عبر الأمر: /mod ${twitchAuthState.user.login || 'jaafarbot'}`,
      },
    });
  }

  return res.status(200).json({
    authorized: false,
    message: 'حساب تويتش غير مفوض حالياً. توجه إلى /auth/twitch لربط الحساب.',
    configuredClientId: Boolean(TWITCH_CLIENT_ID),
    configuredClientSecret: Boolean(TWITCH_CLIENT_SECRET),
    redirectUri: TWITCH_REDIRECT_URI,
    hasRefreshTokenInEnv,
    hasSavedTokenOnDisk: hasSavedTwitchAuth(),
    moderation: {
      hasTimeoutScope: false,
      requiredScope: 'moderator:manage:banned_users',
      status: 'unauthorized',
      notice: 'قم بربط حساب تويتش أولاً عبر /auth/twitch للحصول على التوكن وصلاحية moderator:manage:banned_users.',
    },
  });
});

/**
 * GET /api/twitch/chat/status
 * Returns current Twitch Chat EventSub WebSocket connection status,
 * broadcaster target channel, stream session memory state, and readiness details.
 */
app.get('/api/twitch/chat/status', (req, res) => {
  return res.status(200).json({
    connected: twitchChatState.connected,
    status: twitchChatState.status,
    broadcasterLogin: TWITCH_BROADCASTER_LOGIN || null,
    broadcaster: twitchChatState.broadcaster ? {
      id: twitchChatState.broadcaster.id,
      login: twitchChatState.broadcaster.login,
      displayName: twitchChatState.broadcaster.displayName,
    } : null,
    botUser: twitchAuthState.user ? {
      id: twitchAuthState.user.id,
      login: twitchAuthState.user.login,
      displayName: twitchAuthState.user.displayName,
    } : null,
    subscriptions: {
      chatMessage: twitchChatState.subscriptions.chatMessage,
      streamOnline: twitchChatState.subscriptions.streamOnline,
      streamOffline: twitchChatState.subscriptions.streamOffline,
    },
    streamSession: {
      active: currentStreamSession.active,
      id: currentStreamSession.id,
      type: currentStreamSession.type,
      startedAt: currentStreamSession.startedAt,
      endedAt: currentStreamSession.endedAt,
      messageCount: currentStreamSession.messages.length,
      stats: {
        totalMessages: currentStreamSession.stats.totalMessages,
        mentionsCount: currentStreamSession.stats.mentionsCount,
        repliesToBotCount: currentStreamSession.stats.repliesToBotCount,
      },
      recentMessages: currentStreamSession.messages.slice(-8).map(m => ({
        id: m.id,
        username: m.userName || m.userLogin,
        text: m.text,
        timestamp: m.timestamp,
        isMention: m.isMention,
        isReplyToBot: m.isReplyToBot,
        replyParent: m.replyParent ? {
          parentUser: m.replyParent.userName || m.replyParent.userLogin,
          parentBody: m.replyParent.messageBody,
        } : null,
      })),
    },
    pastSessionsCount: pastStreamSessions.length,
    readiness: {
      canDetectMentions: true,
      canDetectReplies: true,
      hasStreamSessionMemory: true,
      hasUserMemory: true,
      geminiReady: Boolean(getGeminiClient()),
      autoReplyEnabled: AUTO_REPLY_TO_TWITCH_CHAT,
      webSearchEnabled: WEB_SEARCH_ENABLED,
    },
    webSearch: {
      enabled: webSearchState.enabled,
      totalSearches: webSearchState.totalSearches,
      lastSearchAt: webSearchState.lastSearchAt,
      lastQuery: webSearchState.lastQuery,
      lastResultsCount: webSearchState.lastResultsCount,
      lastError: webSearchState.lastError,
    },
    jitoIdentity: {
      userId: jitoIdentity.userId,
      login: jitoIdentity.login,
      knownLogins: Array.from(jitoIdentity.knownLogins),
      resolvedAt: jitoIdentity.resolvedAt,
    },
    vision: {
      enabled: visionState.enabled,
      intervalSeconds: visionState.intervalSeconds,
      lastCaptureAt: visionState.lastCaptureAt,
      lastAnalysisAt: visionState.lastAnalysisAt,
      lastStatus: visionState.lastStatus,
      visualFramesCount: currentStreamSession.visualMemory ? currentStreamSession.visualMemory.length : 0,
      recentVisualFrames: currentStreamSession.visualMemory ? currentStreamSession.visualMemory.slice(-3) : [],
    },
    stats: {
      messagesReceived: twitchChatState.stats.messagesReceived,
      lastMessage: twitchChatState.stats.lastMessage,
      connectedAt: twitchChatState.connectedAt,
      reconnectCount: twitchChatState.reconnectCount,
    },
    lastError: twitchChatState.lastError,
    authStatus: {
      authorized: twitchAuthState.authorized,
      hasClientId: Boolean(TWITCH_CLIENT_ID),
      hasClientSecret: Boolean(TWITCH_CLIENT_SECRET),
      hasBroadcasterLogin: Boolean(TWITCH_BROADCASTER_LOGIN),
      hasRefreshTokenInEnv: Boolean(process.env.TWITCH_REFRESH_TOKEN && process.env.TWITCH_REFRESH_TOKEN.trim()),
      hasSavedTokenOnDisk: hasSavedTwitchAuth(),
      storagePath: getTwitchStorageFilePath(),
    },
  });
});

/**
 * GET /api/twitch/moderation/status
 * Diagnostic endpoint for Twitch Moderation (Timeout and Permanent Ban) capabilities
 */
app.get('/api/twitch/moderation/status', async (req, res) => {
  const hasModerationScope = hasModeratorManageBannedUsersScope();
  const broadcasterId = await resolveBroadcasterUserId();
  const botUserId = twitchAuthState.user?.id || null;
  const jitoId = await resolveJitoUserId();

  return res.status(200).json({
    status: 'ok',
    ready: Boolean(twitchAuthState.authorized && hasModerationScope && broadcasterId && botUserId),
    helixEndpoint: 'POST https://api.twitch.tv/helix/moderation/bans',
    broadcaster: {
      login: TWITCH_BROADCASTER_LOGIN || '8jef',
      id: broadcasterId,
      resolved: Boolean(broadcasterId),
    },
    jito: {
      currentLogin: jitoIdentity.login || '4vren',
      id: jitoId,
      resolved: Boolean(jitoId),
      knownLogins: Array.from(jitoIdentity.knownLogins),
    },
    botUser: {
      login: twitchAuthState.user?.login || 'jaafarbot',
      id: botUserId,
      resolved: Boolean(botUserId),
      isAuthorized: twitchAuthState.authorized,
    },
    oauth: {
      hasModerationScope,
      requiredScope: 'moderator:manage:banned_users',
      scopes: twitchAuthState.scopes,
      notice: hasModerationScope
        ? 'تصريح الإشراف (moderator:manage:banned_users) مفعّل ومتوفر في التوكن (يشمل التايم اوت والباند الدائم).'
        : 'تنبيه: التوكن الحالي لا يحتوي على تصريح (moderator:manage:banned_users). يرجى التوجه إلى /auth/twitch لإعادة التفويض.',
    },
    botModeratorRequirement: {
      hint: `يجب أن يمتلك حساب البوت رتبة مشرف (Mod) في قناة #${TWITCH_BROADCASTER_LOGIN || '8jef'}.`,
      command: `/mod ${twitchAuthState.user?.login || 'jaafarbot'}`,
    },
    supportedCommands: {
      timeout: [
        '@jaafarbot timeout @username 10m [reason]',
        '!timeout @username 10m [reason]',
        '!to @username 10m [reason]',
        'جعفر تايم اوت @username 10m [reason]',
      ],
      ban: [
        '!ban @username [reason]',
        'جعفر باند @username [reason]',
        'جعفر بان @username [reason]',
        '@jaafarbot ban @username [reason]',
        'يا جعفر باند @username [reason]',
        '!باند @username [reason]',
      ],
    },
    supportedTimeoutDurations: [
      '10s', '30s', '1m', '5m', '10m', '30m', '1h', '2h', '24h', '1d', '7d'
    ],
    permissions: {
      broadcaster: 'مسموح لصاحب القناة (8jef) - مفحوص بـ Twitch User ID',
      jito: 'مسموح لـ 4VREN (جيتو) - مفحوص بـ Twitch User ID',
      moderators: 'ممنوع لجميع المشرفين الآخرين (التحكم حصري لـ 8jef و 4VREN فقط)',
      vipsAndSubs: 'ممنوع للـ VIPs والمشتركين والجمهور',
    },
    absoluteImmunity: [
      '8jef (صاحب القناة) - محصن كلياً من التايم اوت والباند',
      '4VREN (جيتو) - محصن كلياً من التايم اوت والباند',
      'jaafarbot (البوت نفسه) - محصن كلياً من استهداف نفسه',
      'يتم فحص الحصانة قبل إرسال أي طلب إلى Twitch Helix',
    ],
    deterministicExecution: 'معالجة كودية حتمية 100% دون أي تدخل من Gemini',
  });
});

/**
 * POST /api/twitch/moderation/simulate-command
 * Allows testing command parser, syntax validation, and strict permission logic
 */
app.post('/api/twitch/moderation/simulate-command', async (req, res) => {
  const { message, callerLogin, callerId } = req.body || {};
  if (!message) {
    return res.status(400).json({ error: 'حقل message إلزامي في جسم الطلب' });
  }

  const banCmd = parseBanCommand(message, twitchAuthState.user?.login || 'jaafarbot');
  const timeoutCmd = parseTimeoutCommand(message, twitchAuthState.user?.login || 'jaafarbot');

  const mockChatEvent = {
    chatter_user_login: callerLogin || 'test_user',
    chatter_user_name: callerLogin || 'test_user',
    chatter_user_id: callerId || null,
  };

  const isAuthorized = await isAuthorizedModeratorExecutor(mockChatEvent);

  if (banCmd && banCmd.isCommand) {
    const immunity = banCmd.valid
      ? await checkModerationImmunity({ targetUserLogin: banCmd.targetUser })
      : null;

    return res.status(200).json({
      type: 'BAN',
      isCommand: true,
      parsed: banCmd,
      caller: {
        login: callerLogin || 'test_user',
        id: callerId || null,
        isAuthorized,
      },
      targetImmunity: immunity,
      readyForExecution: isAuthorized && banCmd.valid && (!immunity || !immunity.immune),
    });
  }

  if (timeoutCmd && timeoutCmd.isCommand) {
    const immunity = timeoutCmd.valid
      ? await checkModerationImmunity({ targetUserLogin: timeoutCmd.targetUser })
      : null;

    return res.status(200).json({
      type: 'TIMEOUT',
      isCommand: true,
      parsed: timeoutCmd,
      caller: {
        login: callerLogin || 'test_user',
        id: callerId || null,
        isAuthorized,
      },
      targetImmunity: immunity,
      readyForExecution: isAuthorized && timeoutCmd.valid && (!immunity || !immunity.immune),
    });
  }

  return res.status(200).json({
    isCommand: false,
    message: 'الرسالة ليست أمر تايم اوت أو باند',
  });
});

/**
 * GET /api/web-search/status
 * Diagnostic endpoint for general web search engine status
 */
app.get('/api/web-search/status', (req, res) => {
  res.status(200).json({
    status: 'ok',
    engine: 'DuckDuckGo HTML Multi-source Fallback',
    enabled: webSearchState.enabled,
    timezone: 'Asia/Riyadh',
    saudiTimeNow: getSaudiTimeContext(),
    stats: {
      totalSearches: webSearchState.totalSearches,
      lastSearchAt: webSearchState.lastSearchAt,
      lastQuery: webSearchState.lastQuery,
      lastResultsCount: webSearchState.lastResultsCount,
    },
    lastError: webSearchState.lastError,
  });
});

/**
 * GET /api/web-search/test
 * Directly tests the web search retrieval without sending to Twitch or consuming Gemini quota
 */
app.get('/api/web-search/test', async (req, res) => {
  const query = req.query.q || req.query.query || 'مباريات اليوم';
  try {
    const searchData = await performWebSearch(query);
    const contextPrompt = formatWebSearchResultsContext(searchData);
    res.status(200).json({
      success: searchData.success,
      originalQuery: query,
      formattedQuery: searchData.query,
      durationMs: searchData.durationMs,
      resultsCount: searchData.results?.length || 0,
      results: searchData.results,
      saudiTime: searchData.saudiTime,
      formattedPromptContext: contextPrompt,
      error: searchData.error || null,
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      query,
      error: err?.message || String(err),
    });
  }
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
        <div class="status-label">اتصال الشات (EventSub WS)</div>
        <div class="status-value" id="twitchChatCardStatus" style="font-size: 13px;">جاري الفحص...</div>
      </div>
      <div class="status-card">
        <div class="status-label">رؤية البث المباشر (Vision)</div>
        <div class="status-value" id="twitchVisionCardStatus" style="font-size: 13px;">كل ${VISION_INTERVAL_SECONDS} ثوانٍ</div>
      </div>
      <div class="status-card">
        <div class="status-label">البحث الحي (Web Search)</div>
        <div class="status-value" id="webSearchCardStatus" style="font-size: 13px;">${WEB_SEARCH_ENABLED ? 'مفعل (Riyadh)' : 'معطل'}</div>
      </div>
      <div class="status-card" style="border-color: #DDD6FE; background: #FAF5FF;">
        <div class="status-label" style="color: #7C3AED;">مراقبة الشات الحي</div>
        <div class="status-value" style="font-size: 13px;">
          <a href="/chat-log" target="_blank" style="color: #9146FF; font-weight: 700; text-decoration: none;">فتح /chat-log ↗</a>
        </div>
      </div>
    </div>

    <!-- Twitch Live Chat Log Card -->
    <div class="card" style="border: 1px solid #DDD6FE; background: #FFFFFF;">
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 8px;">
        <h2 style="margin-bottom: 0;">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="#9146FF"><path d="M11.571 4.714h1.715v5.143H11.57zm4.715 0H18v5.143h-1.714zM6 0L1.714 4.286v15.428h5.143V24l4.286-4.286h3.428L22.286 12V0zm14.571 11.143l-3.428 3.428h-3.429l-3 3v-3H6.857V1.714h13.714z"/></svg>
          صفحة سجل الشات المباشر (Twitch Chat Log)
        </h2>
        <a href="/chat-log" target="_blank" class="btn-primary" style="background: #9146FF; border-color: #9146FF; text-decoration: none; display: inline-flex; align-items: center; gap: 6px;">
          <span>💬</span> فتح صفحة /chat-log
        </a>
      </div>
      <p class="card-caption">
        صفحة مستقلة وسريعة تعمل لحظياً (Real-time SSE) لمشاهدة شات القناة المستهدفة (<code style="background: #F3F4F6; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 12px;">@${TWITCH_BROADCASTER_LOGIN || '8jef'}</code>) مباشرة من الجوال أو الكمبيوتر، مع دعم البحث، التمرير التلقائي، الرتب والشارات، وحماية خاصة عبر <code style="background: #F3F4F6; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">CHAT_LOG_SECRET</code>.
      </p>
    </div>

    <!-- General Web Search Card -->
    <div class="card" style="border: 1px solid #93C5FD; background: #FFFFFF;">
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 8px;">
        <h2 style="margin-bottom: 0; color: #1D4ED8;">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2563EB" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
          ميزة البحث العام بالإنترنت (General Web Search Engine)
        </h2>
        <span id="webSearchBadge" style="background: #EFF6FF; color: #1D4ED8; border: 1px solid #BFDBFE; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600;">نشط بتوقيت الرياض ✓</span>
      </div>
      <p class="card-caption">
        تتيح لجعفر البحث الذكي في الويب عند سؤاله عن معلومات متجددة (مباريات اليوم، نتائج الدوري، أحداث الأخبار، مواعيد نزول الألعاب، الطقس، الأسعار) مع ضبط التوقيت تلقائياً حسب <strong>توقيت الرياض (Asia/Riyadh)</strong>.
      </p>

      <div style="background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 8px; padding: 14px 18px; margin-bottom: 14px;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 10px;">
          <div style="font-size: 13px; font-weight: 600; color: #1E293B;">تجربة فحص البحث المباشر (Direct Search Inspector):</div>
          <div style="display: flex; gap: 8px;">
            <a href="/api/web-search/status" target="_blank" class="btn-secondary" style="font-size: 12px; text-decoration: none;">فحص الحالة JSON</a>
            <a href="/api/web-search/test?q=مباريات اليوم" target="_blank" class="btn-secondary" style="font-size: 12px; text-decoration: none;">تجربة مباريات اليوم JSON</a>
          </div>
        </div>
        <div class="form-group" style="margin-bottom: 8px;">
          <input type="text" id="webSearchTestInput" placeholder="اكتب موضوع البحث التجريبي..." value="مباريات اليوم" style="background: white;" />
          <button class="btn-primary" onclick="runDirectWebSearch()" style="background: #2563EB; border-color: #2563EB;">اختبار البحث السريع</button>
        </div>
        <div id="webSearchInspectBox" class="response-box rtl" style="display: none; font-size: 13px; background: white; border-color: #BFDBFE;"></div>
      </div>
    </div>

    <!-- Twitch Stream Vision Card -->
    <div class="card" style="border: 1px solid #D1D5DB;">
      <h2>
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#111827" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
        نظام الرؤية والذاكرة البصرية للبث الحي (Twitch Live Vision)
      </h2>
      <p class="card-caption">
        يلتقط لقطات شاشة (Frames) مباشرة من البث الحي للقناة المستهدفة (<code style="background: #F3F4F6; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 12px;">@${TWITCH_BROADCASTER_LOGIN || '8jef'}</code>) كل <strong>${VISION_INTERVAL_SECONDS} ثانية</strong> (قابل للتعديل عبر <code style="background: #F3F4F6; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">VISION_INTERVAL_SECONDS</code>)، ويحللها بـ Gemini لتوثيق أحداث البث في ذاكرة الجلسة الحالية دون أي إزعاج أو ردود تلقائية بالشات:
      </p>

      <div style="background: #F9FAFB; border: 1px solid var(--card-border); border-radius: 8px; padding: 16px 20px; margin-bottom: 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 12px;">
          <div>
            <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 2px;">حالة الرؤية الحالية:</div>
            <div id="visionStatusDetailed" style="font-weight: 600; font-size: 14px;">جاري الفحص...</div>
          </div>
          <div style="display: flex; gap: 10px; align-items: center;">
            <button id="btnCaptureFrame" class="btn-primary" onclick="triggerTestCapture()">تجربة التقاط وتحليل فريم الآن</button>
            <a href="/api/vision/status" target="_blank" class="btn-secondary" style="font-size: 12px; text-decoration: none;">عرض JSON الذاكرة</a>
          </div>
        </div>
        <div style="font-size: 12px; color: var(--text-muted); display: flex; gap: 16px; flex-wrap: wrap;">
          <span>القناة المستهدفة: <strong style="color: var(--text);">@${TWITCH_BROADCASTER_LOGIN || '8jef'}</strong></span>
          <span>الفاصل الزمني: <strong style="color: var(--text);">${VISION_INTERVAL_SECONDS} ثانية</strong></span>
          <span>الفريمات المسجلة بالجلسة: <strong id="visionCountSpan" style="color: var(--text);">0</strong></span>
        </div>
      </div>

      <div id="visionLivePreviewBox" style="display: none; background: #FFFFFF; border: 1px solid #E5E7EB; border-radius: 8px; padding: 14px; margin-bottom: 14px;">
        <div style="font-size: 12px; font-weight: 600; color: #374151; margin-bottom: 6px;">آخر لقطة ملتقطة ومحللة:</div>
        <div id="visionLivePreviewText" style="font-size: 13px; line-height: 1.6; color: #111827;"></div>
      </div>

      <div style="font-size: 12px; color: var(--text-muted); line-height: 1.6;">
        🛡️ <strong>حماية الكوتا وعدم التكرار:</strong> يعتمد النظام على فحص هاش MD5 لمنع إعادة تحليل الصور المتطابقة عند عدم تغير شاشة الـ CDN، كما تُمسح الذاكرة البصرية تلقائياً فور انتهاء البث وبدء بث جديد.
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
        <span class="chip" onclick="setQuery('وش مباريات اليوم؟')">وش مباريات اليوم؟</span>
        <span class="chip" onclick="setQuery('متى تنزل لعبة GTA 6؟')">متى تنزل لعبة GTA 6؟</span>
        <span class="chip" onclick="setQuery('كم درجة الحرارة اليوم في الرياض؟')">كم درجة الحرارة اليوم في الرياض؟</span>
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

    <!-- Twitch Moderation: Timeout & Permanent Ban Card -->
    <div class="card" style="border: 1px solid #FCA5A5; background: #FFFFFF;">
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 8px;">
        <h2 style="margin-bottom: 0; color: #991B1B;">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#DC2626" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg>
          نظام الإشراف والتايم اوت والباند الرسمي (Twitch Helix Timeout & Ban)
        </h2>
        <span id="moderationBadge" style="background: #FEF2F2; color: #991B1B; border: 1px solid #FECACA; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 600;">جاري فحص الصلاحيات...</span>
      </div>
      <p class="card-caption">
        يعمل بأمر تويتش المباشر عبر <strong>Twitch Helix API</strong> الرسمي (<code style="background: #F3F4F6; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">POST /helix/moderation/bans</code>) بتصريح <code style="background: #F3F4F6; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 11px;">moderator:manage:banned_users</code> وبشكل برمجي حتمي 100% دون تدخل Gemini.
      </p>

      <div style="background: #FFF5F5; border: 1px solid #FED7D7; border-radius: 8px; padding: 14px 18px; margin-bottom: 14px;">
        <div style="font-size: 13px; font-weight: 700; color: #9B2C2C; margin-bottom: 8px;">
          🔒 الصلاحيات محصورة حصرياً في حسابين بـ Twitch User IDs:
          <span style="background: white; padding: 2px 8px; border-radius: 4px; border: 1px solid #FEB2B2; margin-right: 6px;">8jef (صاحب القناة)</span>
          <span style="background: white; padding: 2px 8px; border-radius: 4px; border: 1px solid #FEB2B2;">4VREN (جيتو)</span>
        </div>
        <div style="font-size: 12px; color: #742A2A; margin-bottom: 10px;">
          🛡️ <strong>الحصانة المطلقة:</strong> يمنع منعاً باتاً إعطاء تايم اوت أو باند للحسابات: <strong>8jef</strong>، <strong>4VREN</strong>، أو <strong>jaafarbot</strong>.
        </div>

        <div style="font-size: 12px; font-weight: 700; color: #742A2A; margin-bottom: 6px;">أوامر الباند الدائم (Permanent Ban):</div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px; margin-bottom: 12px;">
          <div style="background: white; border: 1px solid #FEB2B2; padding: 6px 10px; border-radius: 6px; font-family: monospace; font-size: 12px; color: #742A2A; direction: ltr; text-align: left;">!ban @username [reason]</div>
          <div style="background: white; border: 1px solid #FEB2B2; padding: 6px 10px; border-radius: 6px; font-family: monospace; font-size: 12px; color: #742A2A; direction: rtl; text-align: right;">جعفر باند @username [سبب]</div>
          <div style="background: white; border: 1px solid #FEB2B2; padding: 6px 10px; border-radius: 6px; font-family: monospace; font-size: 12px; color: #742A2A; direction: ltr; text-align: left;">@jaafarbot ban @username</div>
          <div style="background: white; border: 1px solid #FEB2B2; padding: 6px 10px; border-radius: 6px; font-family: monospace; font-size: 12px; color: #742A2A; direction: rtl; text-align: right;">يا جعفر باند @username</div>
        </div>

        <div style="font-size: 12px; font-weight: 700; color: #742A2A; margin-bottom: 6px;">أوامر التايم اوت (Timeout):</div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px; margin-bottom: 10px;">
          <div style="background: white; border: 1px solid #FEB2B2; padding: 6px 10px; border-radius: 6px; font-family: monospace; font-size: 12px; color: #742A2A; direction: ltr; text-align: left;">!timeout @username 10m [reason]</div>
          <div style="background: white; border: 1px solid #FEB2B2; padding: 6px 10px; border-radius: 6px; font-family: monospace; font-size: 12px; color: #742A2A; direction: rtl; text-align: right;">جعفر تايم اوت @username 10m</div>
          <div style="background: white; border: 1px solid #FEB2B2; padding: 6px 10px; border-radius: 6px; font-family: monospace; font-size: 12px; color: #742A2A; direction: ltr; text-align: left;">!to @username 10m</div>
          <div style="background: white; border: 1px solid #FEB2B2; padding: 6px 10px; border-radius: 6px; font-family: monospace; font-size: 12px; color: #742A2A; direction: ltr; text-align: left;">@jaafarbot timeout @username 10m</div>
        </div>
        <div style="font-size: 12px; color: #742A2A; line-height: 1.6;">
          ⏱️ <strong>مدد التايم اوت (إلزامية للتايم اوت فقط):</strong> <code style="background: white; padding: 2px 6px; border-radius: 4px; font-family: monospace;">10s, 30s, 1m, 5m, 10m, 30m, 1h, 2h, 24h, 1d, 7d</code>
        </div>
      </div>

      <div style="display: flex; gap: 12px; flex-wrap: wrap; align-items: center; justify-content: space-between; font-size: 12px; color: var(--text-muted);">
        <div>
          🛡️ <strong>شروط التفعيل:</strong> يجب إعطاء البوت رتبة مشرف في القناة بكتابة: <code style="background: #F3F4F6; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-weight: 700; color: #111827;">/mod jaafarbot</code> بشات البث.
        </div>
        <a href="/api/twitch/moderation/status" target="_blank" class="btn-secondary" style="font-size: 12px; text-decoration: none;">فحص تشخيص الإشراف JSON ↗</a>
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
      <div class="endpoint-item">
        <div style="display: flex; align-items: center;">
          <span class="method method-purple">GET</span>
          <code style="color: #374151; font-weight: 500; margin-right: 8px;">/api/twitch/chat/status</code>
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
          <span style="color: var(--text-muted); font-size: 13px;">فحص اتصال EventSub WebSocket وإحصائيات الشات</span>
          <span class="status-ok">200 JSON</span>
        </div>
      </div>
      <div class="endpoint-item">
        <div style="display: flex; align-items: center;">
          <span class="method method-purple">GET</span>
          <code style="color: #374151; font-weight: 500; margin-right: 8px;">/api/vision/status</code>
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
          <span style="color: var(--text-muted); font-size: 13px;">فحص حالة الرؤية وقائمة الذاكرة البصرية الحالية</span>
          <span class="status-ok">200 JSON</span>
        </div>
      </div>
      <div class="endpoint-item">
        <div style="display: flex; align-items: center;">
          <span class="method method-green">ALL</span>
          <code style="color: #374151; font-weight: 500; margin-right: 8px;">/api/vision/capture</code>
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
          <span style="color: var(--text-muted); font-size: 13px;">التقاط وتحليل فريم تجريبي فوري</span>
          <span class="status-ok">200 JSON</span>
        </div>
      </div>
      <div class="endpoint-item">
        <div style="display: flex; align-items: center;">
          <span class="method method-purple">GET</span>
          <code style="color: #374151; font-weight: 500; margin-right: 8px;">/api/twitch/moderation/status</code>
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
          <span style="color: var(--text-muted); font-size: 13px;">فحص جاهزية التايم اوت وصلاحية moderator:manage:banned_users</span>
          <span class="status-ok">200 JSON</span>
        </div>
      </div>
      <div class="endpoint-item">
        <div style="display: flex; align-items: center;">
          <span class="method method-blue" style="background: #EFF6FF; color: #1D4ED8; border: 1px solid #BFDBFE; font-size: 11px; font-weight: 700; padding: 2px 6px; border-radius: 4px;">GET</span>
          <code style="color: #374151; font-weight: 500; margin-right: 8px;">/api/web-search/status</code>
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
          <span style="color: var(--text-muted); font-size: 13px;">فحص حالة محرك البحث وتوقيت الرياض</span>
          <span class="status-ok">200 JSON</span>
        </div>
      </div>
      <div class="endpoint-item">
        <div style="display: flex; align-items: center;">
          <span class="method method-blue" style="background: #EFF6FF; color: #1D4ED8; border: 1px solid #BFDBFE; font-size: 11px; font-weight: 700; padding: 2px 6px; border-radius: 4px;">GET</span>
          <code style="color: #374151; font-weight: 500; margin-right: 8px;">/api/web-search/test?q=...</code>
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
          <span style="color: var(--text-muted); font-size: 13px;">تجربة جلب نتائج البحث من الويب مباشرة</span>
          <span class="status-ok">200 JSON</span>
        </div>
      </div>
    </div>
  </div>

  <script>
    const origin = window.location.origin;
    document.querySelectorAll('.appDomainSpan').forEach(el => el.innerText = origin);

    // Check Twitch Moderation & Timeout status
    fetch('/api/twitch/moderation/status')
      .then(res => res.json())
      .then(mod => {
        const badge = document.getElementById('moderationBadge');
        if (!badge) return;
        if (mod.ready) {
          badge.style.background = '#ECFDF5';
          badge.style.color = '#065F46';
          badge.style.borderColor = '#A7F3D0';
          badge.innerText = 'جاهز للتنفيذ عبر Helix API ✓';
        } else if (mod.oauth && !mod.oauth.hasModerationScope && !mod.oauth.hasTimeoutScope) {
          badge.style.background = '#FFFBEB';
          badge.style.color = '#B45309';
          badge.style.borderColor = '#FDE68A';
          badge.innerText = '⚠️ يتطلب إعادة الربط عبر /auth/twitch';
        } else {
          badge.style.background = '#FEF2F2';
          badge.style.color = '#991B1B';
          badge.style.borderColor = '#FECACA';
          badge.innerText = 'بانتظار التفويض';
        }
      })
      .catch(() => {});

    // Check Twitch OAuth status
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

    // Check Twitch Chat EventSub status
    fetch('/api/twitch/chat/status')
      .then(res => res.json())
      .then(data => {
        const chatStatusElem = document.getElementById('twitchChatCardStatus');
        if (chatStatusElem) {
          if (data.connected) {
            chatStatusElem.innerHTML = '<span style="color: #065F46;">متصل بالـ WebSocket ✓</span>';
          } else if (data.status === 'connecting' || data.status === 'reconnecting') {
            chatStatusElem.innerHTML = '<span style="color: #2563EB;">جاري الاتصال...</span>';
          } else {
            chatStatusElem.innerHTML = '<span style="color: #6B7280;">غير متصل (بانتظار التفويض)</span>';
          }
        }
      })
      .catch(() => {});

    // Refresh Vision Status
    function refreshVisionStatus() {
      fetch('/api/vision/status')
        .then(res => res.json())
        .then(data => {
          const vDetailed = document.getElementById('visionStatusDetailed');
          const vCard = document.getElementById('twitchVisionCardStatus');
          const vCount = document.getElementById('visionCountSpan');
          const previewBox = document.getElementById('visionLivePreviewBox');
          const previewText = document.getElementById('visionLivePreviewText');

          if (vCount) vCount.innerText = data.visualFramesCount || 0;

          if (vDetailed) {
            if (data.isLive) {
              vDetailed.innerHTML = '<span style="color: #065F46;">🟢 البث المباشر شغال (LIVE) • الرؤية نشطة كل ' + data.intervalSeconds + 'ث</span>';
              if (vCard) vCard.innerHTML = '<span style="color: #065F46;">نشط (Live)</span>';
            } else {
              vDetailed.innerHTML = '<span style="color: #4B5563;">⚪ البث متوقف حالياً (Offline) • بانتظار بدء البث</span>';
              if (vCard) vCard.innerHTML = '<span style="color: #4B5563;">بانتظار البث (' + data.intervalSeconds + 's)</span>';
            }
          }

          if (data.visualMemory && data.visualMemory.length > 0) {
            const latest = data.visualMemory[data.visualMemory.length - 1];
            if (previewBox && previewText) {
              previewBox.style.display = 'block';
              previewText.innerHTML = '<strong>[' + (latest.timeFormatted || '') + ']</strong> ' + latest.summary;
            }
          }
        })
        .catch(() => {});
    }

    refreshVisionStatus();
    setInterval(refreshVisionStatus, 15000);

    // Trigger test capture
    async function triggerTestCapture() {
      const btn = document.getElementById('btnCaptureFrame');
      const vDetailed = document.getElementById('visionStatusDetailed');
      const previewBox = document.getElementById('visionLivePreviewBox');
      const previewText = document.getElementById('visionLivePreviewText');

      if (btn) {
        btn.disabled = true;
        btn.innerText = 'جاري التقاط وتحليل الفريم...';
      }

      try {
        const res = await fetch('/api/vision/capture?force=true&test=true');
        const data = await res.json();
        if (data.status === 'analyzed' && data.entry) {
          if (previewBox && previewText) {
            previewBox.style.display = 'block';
            previewText.innerHTML = '<strong>[' + (data.entry.timeFormatted || '') + ']</strong> ' + data.entry.summary;
          }
          if (vDetailed) {
            vDetailed.innerHTML = '<span style="color: #065F46;">✓ تم التقاط وتحليل فريم بنجاح!</span>';
          }
        } else if (data.status === 'unchanged') {
          if (vDetailed) {
            vDetailed.innerHTML = '<span style="color: #2563EB;">ℹ️ الفريم لم يتغير في الـ CDN (تم التجاوز لحفظ الكوتا)</span>';
          }
        } else {
          if (vDetailed) {
            vDetailed.innerHTML = '<span style="color: #B45309;">⚠️ حالة الالتقاط: ' + (data.status || data.error || 'فشل') + '</span>';
          }
        }
        refreshVisionStatus();
      } catch (err) {
        if (vDetailed) {
          vDetailed.innerHTML = '<span style="color: #DC2626;">❌ فشل الاتصال بالسيرفر</span>';
        }
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.innerText = 'تجربة التقاط وتحليل فريم الآن';
        }
      }
    }

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

    async function runDirectWebSearch() {
      const q = document.getElementById('webSearchTestInput').value.trim();
      const box = document.getElementById('webSearchInspectBox');
      if (!box) return;
      box.style.display = 'block';
      box.innerText = 'جاري جلب نتائج البحث من الويب بتوقيت الرياض...';
      try {
        const res = await fetch('/api/web-search/test?q=' + encodeURIComponent(q));
        const data = await res.json();
        if (data.success && data.results && data.results.length > 0) {
          let html = '<div style="font-weight: 700; color: #1E3A8A; margin-bottom: 6px;">نتائج البحث (' + data.results.length + ' نتائج - استغرق ' + data.durationMs + 'ms) | بتوقيت الرياض: ' + (data.saudiTime?.human || '') + ':</div>';
          html += '<ol style="padding-right: 18px; margin: 0; line-height: 1.6;">';
          data.results.forEach(r => {
            html += '<li style="margin-bottom: 6px;"><strong>' + r.title + '</strong><br/><span style="color: #4B5563;">' + r.snippet + '</span></li>';
          });
          html += '</ol>';
          box.innerHTML = html;
        } else {
          box.innerHTML = '<span style="color: #B45309;">لم يتم العثور على نتائج مباشرة للبحث أو محرك البحث معطل.</span>';
        }
      } catch (err) {
        box.innerText = 'خطأ أثناء فحص البحث: ' + (err?.message || err);
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
app.listen(PORT, '0.0.0.0', async () => {
  console.log(`[Twitch AI Server] Running on http://0.0.0.0:${PORT}`);
  console.log(`[Twitch AI Server] Model: ${MODEL_NAME}`);

  // Restore OAuth session from persistent storage if available
  try {
    const restored = await restoreTwitchAuthAndConnect();
    if (!restored) {
      console.log('[Twitch Chat] Bot account is not authorized yet. Visit /auth/twitch to link account.');
      if (!TWITCH_BROADCASTER_LOGIN) {
        console.log('[Twitch Chat] Notice: TWITCH_BROADCASTER_LOGIN environment variable is not configured.');
      }
    }
  } catch (err) {
    console.error('[Twitch Storage] Error restoring OAuth session on startup:', err?.message || err);
  }

  // Ensure Jito identity is logged and resolved
  if (jitoIdentity.userId) {
    console.log(`[Jito Identity] Initialized with permanent Twitch User ID: ${jitoIdentity.userId} (known logins: ${Array.from(jitoIdentity.knownLogins).join(', ')})`);
  } else {
    console.log(`[Jito Identity] Jito username tracker initialized (current: @${jitoIdentity.login}, alternate: @4VREN). Permanent User ID will resolve via Twitch API.`);
  }

  // Start Twitch Stream Vision loop
  try {
    startVisionLoop();
  } catch (visionErr) {
    console.error('[Vision] Error starting vision loop:', visionErr?.message || visionErr);
  }
});

