# Twitch AI Chatbot API (Nightbot + Gemini)

A lightweight, standalone Node.js backend API built for Twitch chatbots (Nightbot). Powered by Google's official Gemini Node.js SDK (`@google/genai`), this server returns spontaneous, natural Saudi Arabic responses formatted strictly as plain text for Twitch chat.

---

## 📁 Project Structure

```text
twitch-ai/
├── package.json
├── src/
│   └── server.js
├── .gitignore
├── .env.example
└── README.md
```

- **`src/server.js`**: Complete Express server with `/health`, `/api/ai`, and test console.
- **`package.json`**: Standard dependencies (`express`, `cors`, `dotenv`, `@google/genai`) and `npm start` script.
- **`.gitignore`**: Ignores `node_modules` and `.env` credentials.

---

## 🚀 Endpoints

### 1. Health Check
- **URL**: `GET /health`
- **Response**: Plain text `OK` (HTTP 200)
- **Purpose**: Verifies that the server is alive (used by Render health checks).

### 2. Twitch AI Chatbot (with Memory)
- **URL**: `GET /api/ai?q=VIEWER_MESSAGE&user=VIEWER_USERNAME`
- **Response**: Plain text only (HTTP 200)
- **Features**: Remembers conversation context per user in memory.

### 3. Answer Evaluation Endpoint (!a)
- **URL**: `GET /api/answer?q=ANSWER&user=VIEWER_USERNAME`
- **Response**: Plain text only (HTTP 200)
- **Features**: Evaluates viewer answers to the AI's recent questions. Returns `ما عندي سؤال لك الحين 😂` if no question is pending.

---

## ⚙️ Environment Variables

| Variable | Required | Description | Example |
| :--- | :---: | :--- | :--- |
| `GEMINI_API_KEY` | **Yes** | Your Google Gemini API Key | `AIzaSy...` |
| `PORT` | No | Server port (Render assigns automatically) | `3000` |
| `GEMINI_MODEL` | No | Gemini Flash model name | `gemini-3.1-flash-lite` (default) or `gemini-3.8-flash` |

---

## 📦 Deployment to Render (Step-by-Step)

### Step 1: Create a GitHub Repository
1. Go to [GitHub](https://github.com) and click **New Repository**.
2. Name it `twitch-ai` (Public or Private).
3. Push your project files to GitHub.

### Step 2: Create Web Service on Render
1. Go to your [Render Dashboard](https://dashboard.render.com).
2. Click **New +** → **Web Service**.
3. Connect your GitHub account and choose the `twitch-ai` repository.

### Step 3: Configure Render Settings
- **Name**: `twitch-ai` (or any custom name)
- **Runtime**: `Node`
- **Build Command**: `npm install`
- **Start Command**: `npm start`
- **Plan**: `Free`

### Step 4: Add Environment Variable
1. Under **Environment Variables**, click **Add Environment Variable**.
2. Key: `GEMINI_API_KEY`
3. Value: *Paste your Google Gemini API Key* (obtainable free from [Google AI Studio](https://aistudio.google.com/app/apikey)).
4. Click **Deploy Web Service**.

---

## 🤖 Nightbot Setup (Twitch Chat)

Once deployed, copy your Render URL (e.g., `https://twitch-bot-jeffe.onrender.com`).

Add these commands to your Twitch chat:

1. **General Chatbot Command (`!ai`)**:
```text
!commands add !ai $(urlfetch https://YOUR-RENDER-APP.onrender.com/api/ai?q=$(querystring)&user=$(user))
```

2. **Answer Evaluation Command (`!a`)**:
```text
!commands add !a $(urlfetch https://YOUR-RENDER-APP.onrender.com/api/answer?q=$(querystring)&user=$(user))
```

### Testing in Twitch Chat:
- Viewer: `!ai اسألني سؤال`
- Nightbot: `أبشر يا وحش! وش هي عاصمة فرنسا؟ أجب بأمر !a`
- Viewer: `!a باريس`
- Nightbot: `كفو والله، صح مية بالمية يا وحش! 🔥`
- Viewer: `!a برلين` (after already answered)
- Nightbot: `ما عندي سؤال لك الحين 😂`

---

## 💻 Local Development

```bash
# 1. Install dependencies
npm install

# 2. Set your Gemini API key in .env
echo "GEMINI_API_KEY=your_key_here" > .env

# 3. Start the server
npm start
```

Open `http://localhost:3000` in your browser to access the interactive web test console.
