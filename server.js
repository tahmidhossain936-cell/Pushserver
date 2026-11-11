const express = require('express');
const admin   = require('firebase-admin');
const cors    = require('cors');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const app = express();

// ════════════════════════════════════════════════════════════
// MIDDLEWARES
// ════════════════════════════════════════════════════════════
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// ════════════════════════════════════════════════════════════
// 1. FIREBASE ADMIN INITIALIZATION (FIXED)
// ════════════════════════════════════════════════════════════
function initFirebase() {
  if (admin.apps.length > 0) return admin.app();

  // ১. এনভায়রনমেন্ট ভ্যারিয়েবল থেকে চেক
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
      let raw = process.env.FIREBASE_SERVICE_ACCOUNT.trim();
      // বেস৬৪ এনকোডেড থাকলে ডিকোড করা
      if (!raw.startsWith('{')) {
        raw = Buffer.from(raw, 'base64').toString('utf8');
      }
      const creds = JSON.parse(raw);

      // Private Key ফিক্স (\\n -> \n)
      if (creds.private_key) {
        creds.private_key = creds.private_key.replace(/\\n/g, '\n');
      }

      return admin.initializeApp({ credential: admin.credential.cert(creds) });
    } catch (err) {
      console.error('⚠️ Invalid FIREBASE_SERVICE_ACCOUNT JSON:', err.message);
    }
  }

  // ২. লোকাল ফাইল থেকে চেক
  const keyPath = path.join(__dirname, 'serviceAccountKey.json');
  if (fs.existsSync(keyPath)) {
    try {
      const creds = require(keyPath);
      if (creds.private_key) {
        creds.private_key = creds.private_key.replace(/\\n/g, '\n');
      }
      return admin.initializeApp({ credential: admin.credential.cert(creds) });
    } catch (err) {
      console.error('⚠️ Failed to load serviceAccountKey.json:', err.message);
    }
  }

  // ৩. ডিফল্ট গুগল ক্রেডেনশিয়াল (GCP/Firebase ক্লাউড রান/ফাংশনে থাকলে)
  try {
    return admin.initializeApp({ credential: admin.credential.applicationDefault() });
  } catch (err) {
    console.error('❌ FATAL: Firebase credentials could not be initialized!');
    process.exit(1);
  }
}

initFirebase();
const db = admin.firestore();

// ════════════════════════════════════════════════════════════
// 2. HELPERS & VALIDATORS
// ════════════════════════════════════════════════════════════

function sanitizeAppId(appId) {
  if (typeof appId !== 'string') return null;
  const trimmed = appId.trim();
  const isValid = (
    trimmed.length >= 3 &&
    trimmed.length <= 100 &&
    /^[a-zA-Z0-9._\-]+$/.test(trimmed) &&
    !trimmed.startsWith('__') &&
    trimmed !== '.' &&
    trimmed !== '..'
  );
  return isValid ? trimmed : null;
}

function isValidToken(token) {
  return typeof token === 'string' && token.trim().length > 10;
}

function tokenDocId(token) {
  return crypto.createHash('sha256').update(token.trim()).digest('hex');
}

function devicesRef(appId) {
  return db.collection('push_tokens').doc(appId).collection('devices');
}

function appMetaRef(appId) {
  return db.collection('push_app_meta').doc(appId);
}

function chunkArray(array, size = 500) {
  const result = [];
  for (let i = 0; i < array.length; i += size) {
    result.push(array.slice(i, i + size));
  }
  return result;
}

// FCM Data Payload-এর সব ভ্যালু স্ট্রিং হওয়া বাধ্যতামূলক
function sanitizeDataPayload(rawCustomData, defaultData = {}) {
  const validCustom = (rawCustomData && typeof rawCustomData === 'object' && !Array.isArray(rawCustomData))
    ? rawCustomData
    : {};
  const merged = { ...defaultData, ...validCustom };
  const sanitized = {};

  for (const [key, val] of Object.entries(merged)) {
    if (val !== undefined && val !== null) {
      sanitized[String(key)] = typeof val === 'object' ? JSON.stringify(val) : String(val);
    }
  }
  return sanitized;
}

// Android, iOS এবং Web সব প্ল্যাটফর্মের জন্য নিরাপদ মেসেজ পে-লোড তৈরি
function buildPayload({ title, body, imageUrl, customData }) {
  const t = String(title || 'Notification');
  const b = String(body || '');
  const img = (typeof imageUrl === 'string' && imageUrl.trim().startsWith('http')) 
    ? imageUrl.trim() 
    : null;

  const dataPayload = sanitizeDataPayload(customData, {
    title: t,
    body: b,
    ...(img ? { imageUrl: img } : {})
  });

  const payload = {
    notification: {
      title: t,
      body: b,
      ...(img ? { imageUrl: img } : {})
    },
    data: dataPayload,
    android: {
      priority: 'high',
      notification: {
        sound: 'default',
        channelId: 'default',
        ...(img ? { imageUrl: img } : {})
      }
    },
    apns: {
      payload: {
        aps: {
          sound: 'default',
          mutableContent: true
        }
      },
      // undefined দিলে FCM এরর দিতে পারে, তাই শুধু ইমেজ থাকলে যোগ করা হয়েছে
      ...(img ? { fcmOptions: { imageUrl: img } } : {})
    },
    webpush: {
      headers: {
        Urgency: 'high'
      },
      notification: {
        requireInteraction: false,
        ...(img ? { image: img } : {})
      }
    }
  };

  return payload;
}

// সিকিউরিটি গার্ড মিডলওয়্যার (ঐচ্ছিক: .env-তে API_SECRET_KEY দিলে কাজ করবে)
function authMiddleware(req, res, next) {
  const secretKey = process.env.API_SECRET_KEY;
  if (!secretKey) return next(); // কি সেট না করা থাকলে ওপেন থাকবে

  const authHeader = req.headers['authorization'] || req.headers['x-api-key'];
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7).trim() : authHeader?.trim();

  if (token !== secretKey) {
    return res.status(401).json({ success: false, error: 'Unauthorized: Invalid or missing API key' });
  }
  next();
}

// ════════════════════════════════════════════════════════════
// 3. ROUTES
// ════════════════════════════════════════════════════════════

app.get('/', (req, res) => {
  res.json({ status: 'online', service: 'Push Notification Server', timestamp: Date.now() });
});

// GET /app-status?appId=com.myapp.xyz
app.get('/app-status', async (req, res) => {
  const appId = sanitizeAppId(req.query.appId);
  if (!appId) return res.status(400).json({ success: false, error: 'Valid appId required' });

  try {
    const [metaDoc, countSnap] = await Promise.all([
      appMetaRef(appId).get(),
      devicesRef(appId).count().get()
    ]);

    res.json({
      success:      true,
      appId,
      registered:   metaDoc.exists,
      registeredAt: metaDoc.exists ? metaDoc.data()?.registeredAt || null : null,
      tokenCount:   countSnap.data()?.count || 0
    });
  } catch (e) {
    console.error('App-status error:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /register-app  { appId }
app.post('/register-app', authMiddleware, async (req, res) => {
  const body = req.body || {};
  const appId = sanitizeAppId(body.appId);
  if (!appId) return res.status(400).json({ success: false, error: 'Valid appId required' });

  try {
    const ref = appMetaRef(appId);
    const doc = await ref.get();
    const now = Date.now();

    await ref.set({
      appId,
      registeredAt: doc.exists ? (doc.data()?.registeredAt || now) : now,
      updatedAt:    now
    }, { merge: true });

    res.json({ success: true, message: 'App registered successfully', appId });
  } catch (e) {
    console.error('Register-app error:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /register-token  { token, appId, userAgent }
app.post('/register-token', async (req, res) => {
  const body = req.body || {};
  const token = typeof body.token === 'string' ? body.token.trim() : null;
  const appId = sanitizeAppId(body.appId);
  const userAgent = body.userAgent;

  if (!isValidToken(token)) return res.status(400).json({ success: false, error: 'Valid token required' });
  if (!appId) return res.status(400).json({ success: false, error: 'Valid appId required' });

  try {
    const docId = tokenDocId(token);
    const now = Date.now();

    await devicesRef(appId).doc(docId).set({
      token,
      appId,
      userAgent: String(userAgent || '').substring(0, 255),
      updatedAt: now
    }, { merge: true });

    res.json({ success: true, message: 'Token saved successfully' });
  } catch (e) {
    console.error('Register-token error:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET /tokens?appId=com.myapp.xyz&limit=100
app.get('/tokens', authMiddleware, async (req, res) => {
  const appId = sanitizeAppId(req.query.appId);
  if (!appId) return res.status(400).json({ success: false, error: 'Valid appId required' });

  const parsedLimit = parseInt(req.query.limit, 10);
  const limit = (!isNaN(parsedLimit) && parsedLimit > 0) ? Math.min(parsedLimit, 1000) : 100;

  try {
    const snap = await devicesRef(appId).limit(limit).get();
    const tokens = snap.docs.map(d => {
      const data = d.data();
      return {
        token:     data.token,
        updatedAt: data.updatedAt || null,
        userAgent: data.userAgent || ''
      };
    });

    res.json({ success: true, appId, count: tokens.length, tokens });
  } catch (e) {
    console.error('Get-tokens error:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

// POST /send-notification  { token, title, body, imageUrl, data, appId? }
app.post('/send-notification', authMiddleware, async (req, res) => {
  const body = req.body || {};
  const token = typeof body.token === 'string' ? body.token.trim() : null;
  const appId = sanitizeAppId(body.appId);

  if (!isValidToken(token)) return res.status(400).json({ success: false, error: 'Valid token required' });

  try {
    const payload = buildPayload({
      title: body.title,
      body: body.body,
      imageUrl: body.imageUrl,
      customData: body.data
    });

    const message = {
      ...payload,
      token
    };

    const msgId = await admin.messaging().send(message);
    res.json({ success: true, messageId: msgId });
  } catch (e) {
    console.error('Send error:', e.message);

    // টোকেন অবৈধ হলে তা ডাটাবেজ থেকে ক্লিনআপ করা
    const isTokenInvalid = 
      e.code === 'messaging/registration-token-not-registered' ||
      e.code === 'messaging/invalid-registration-token';

    if (isTokenInvalid && appId) {
      devicesRef(appId).doc(tokenDocId(token)).delete().catch(() => {});
    }

    res.status(e.code?.startsWith('messaging/') ? 400 : 500).json({
      success: false,
      error: e.message,
      code: e.code || 'UNKNOWN_ERROR'
    });
  }
});

// POST /send-all  { appId, title, body, imageUrl, data }
app.post('/send-all', authMiddleware, async (req, res) => {
  const body = req.body || {};
  const appId = sanitizeAppId(body.appId);

  if (!appId) return res.status(400).json({ success: false, error: 'Valid appId required' });

  try {
    // শুধু token ফিল্ড রিড করে ব্যান্ডউইথ ও মেমোরি বাঁচানো
    const snap = await devicesRef(appId).select('token').get();
    if (snap.empty) {
      return res.status(404).json({ success: false, error: 'No devices found for this app' });
    }

    const deviceRecords = snap.docs
      .map(doc => ({ ref: doc.ref, token: doc.data()?.token }))
      .filter(item => isValidToken(item.token));

    if (deviceRecords.length === 0) {
      return res.status(404).json({ success: false, error: 'No valid tokens found' });
    }

    const payload = buildPayload({
      title: body.title,
      body: body.body,
      imageUrl: body.imageUrl,
      customData: body.data
    });

    const chunks = chunkArray(deviceRecords, 500); // FCM multicast সীমা ৫০০
    let totalSuccess = 0;
    let totalFailure = 0;
    const tokensToDeleteRefsMap = new Map();

    // একসাথে ৩টি করে ব্যাচ পাঠিয়ে রিকোয়েস্ট স্পিড বাড়ানো
    const CONCURRENCY_LIMIT = 3;
    for (let i = 0; i < chunks.length; i += CONCURRENCY_LIMIT) {
      const activeChunks = chunks.slice(i, i + CONCURRENCY_LIMIT);

      await Promise.all(activeChunks.map(async (chunk) => {
        const tokens = chunk.map(item => item.token.trim());
        const multicastMessage = { ...payload, tokens };

        try {
          const response = await admin.messaging().sendEachForMulticast(multicastMessage);
          totalSuccess += response.successCount;
          totalFailure += response.failureCount;

          response.responses.forEach((resItem, idx) => {
            if (!resItem.success) {
              const errCode = resItem.error?.code;
              if (
                errCode === 'messaging/registration-token-not-registered' ||
                errCode === 'messaging/invalid-registration-token'
              ) {
                // Map ব্যবহার করায় ডুপ্লিকেট রেফারেন্স ঢুকবে না
                tokensToDeleteRefsMap.set(chunk[idx].ref.path, chunk[idx].ref);
              }
            }
          });
        } catch (chunkErr) {
          console.error('Batch Multicast Error:', chunkErr.message);
          totalFailure += chunk.length;
        }
      }));
    }

    // অবৈধ টোকেনগুলো ফায়ারস্টোর থেকে ব্যাচ ডিলিট (ম্যাক্স ৪০০ টি করে)
    const tokensToDeleteRefs = Array.from(tokensToDeleteRefsMap.values());
    if (tokensToDeleteRefs.length > 0) {
      const deleteBatches = chunkArray(tokensToDeleteRefs, 400);
      for (const dChunk of deleteBatches) {
        const batch = db.batch();
        dChunk.forEach(ref => batch.delete(ref));
        await batch.commit().catch(err => console.error('Batch delete commit error:', err.message));
      }
      console.log(`[${appId}] Cleaned up ${tokensToDeleteRefs.length} invalid tokens.`);
    }

    res.json({
      success:       true,
      appId,
      totalDevices:  deviceRecords.length,
      successCount:  totalSuccess,
      failureCount:  totalFailure,
      cleanedTokens: tokensToDeleteRefs.length
    });
  } catch (e) {
    console.error('Send-all error:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

// DELETE /token
app.delete('/token', async (req, res) => {
  const body = req.body || {};
  const rawAppId = req.query.appId || body.appId;
  const rawToken = req.query.token || body.token;

  const appId = sanitizeAppId(rawAppId);
  const token = typeof rawToken === 'string' ? rawToken.trim() : null;

  if (!appId || !isValidToken(token)) {
    return res.status(400).json({ success: false, error: 'Valid appId and token required' });
  }

  try {
    await devicesRef(appId).doc(tokenDocId(token)).delete();
    res.json({ success: true, message: 'Token deleted successfully' });
  } catch (e) {
    console.error('Delete token error:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ════════════════════════════════════════════════════════════
// 4. GLOBAL ERROR & NOT FOUND HANDLERS
// ════════════════════════════════════════════════════════════
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Route not found' });
});

app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ success: false, error: 'Malformed JSON payload' });
  }
  console.error('Unhandled Server Error:', err);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// ════════════════════════════════════════════════════════════
// PROCESS HANDLING & LISTEN
// ════════════════════════════════════════════════════════════
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Promise Rejection:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

const PORT = process.env.PORT || 7860;
app.listen(PORT, () => {
  console.log(`🚀 Push Server running cleanly on port ${PORT}`);
});
