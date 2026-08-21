# FridgeAI Backend

Secure proxy server that keeps your Anthropic API key hidden from users.

## Deploy to Railway (free, takes 5 minutes)

### Step 1 — Create a Railway account
Go to railway.app and sign up with GitHub.

### Step 2 — Create a new project
1. Click "New Project"
2. Click "Deploy from GitHub repo"
3. Connect your GitHub account if not already done
4. Upload this folder to a new GitHub repo called "fridgeai-backend"
   - Go to github.com → New repository → "fridgeai-backend"
   - Upload all files from this folder

### Step 3 — Set your API key
In Railway, click your project → Variables tab → Add:
  - Name:  ANTHROPIC_API_KEY
  - Value: your key from console.anthropic.com (starts with sk-ant-...)

### Step 4 — Deploy
Railway deploys automatically. Click your project to see the URL —
it will look like: https://fridgeai-backend-production.up.railway.app

### Step 5 — Update the app
Copy your Railway URL and in index.html replace:
  const BACKEND_URL = "YOUR_BACKEND_URL_HERE";
with:
  const BACKEND_URL = "https://fridgeai-backend-production.up.railway.app";

That's it — your API key is now hidden and the app routes through your server.

## Rate limits explained

The server blocks users who make too many requests:
- General: 60 requests per 15 minutes
- Scans: 20 scans per hour

These limits only affect bad actors. Normal users will never hit them.

## Cost
Railway free tier includes $5/month credit which is more than enough
for a hobby/small app. The server uses almost no resources since it's
just forwarding requests.
