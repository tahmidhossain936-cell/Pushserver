import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import admin from 'firebase-admin';

// ==========================================
// 1. Firebase Admin SDK Initialization
// ==========================================
if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  console.error('FATAL: FIREBASE_SERVICE_ACCOUNT_JSON environment variable is not defined.');
  process.exit(1);
}

let serviceAccount;
try {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
} catch (error) {
  console.error('FATAL: Failed to parse FIREBASE_SERVICE_ACCOUNT_JSON:', error.message);
  process.exit(1);
}

const firebaseApp = admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  projectId: process.env.FIREBASE_PROJECT_ID || serviceAccount.project_id
});

const db = admin.firestore(firebaseApp);
const auth = admin.auth(firebaseApp);
const messaging = admin.messaging(firebaseApp);

// ==========================================
// 2. Express Server Configuration
// ==========================================
const app = express();

app.use(helmet());

// CORS Configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map((origin) => origin.trim())
  : ['*'];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Blocked by CORS policy'));
      }
    },
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
  })
);

app.use(express.json({ limit: '1mb' }));

// ==========================================
// 3. Security Middlewares
// ==========================================
const verifyFirebaseToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized: Missing or invalid Authorization header.'
    });
  }

  const token = authHeader.split('Bearer ')[1].trim();

  try {
    const decodedToken = await auth.verifyIdToken(token);
    req.user = decodedToken;
    return next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized: Invalid or expired Firebase ID token.'
    });
  }
};

const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.admin !== true) {
    return res.status(403).json({
      success: false,
      message: 'Forbidden: Admin privileges required.'
    });
  }
  return next();
};

// ==========================================
// 4. Utility Functions
// ==========================================
const cleanupInvalidTokens = async (invalidTokens) => {
  if (!invalidTokens || invalidTokens.length === 0) return 0;

  try {
    const batchSize = 450;
    let deletedCount = 0;

    for (let i = 0; i < invalidTokens.length; i += batchSize) {
      const chunk = invalidTokens.slice(i, i + batchSize);
      const snapshot = await db.collection('devices').where('fcmToken', 'in', chunk).get();

      if (!snapshot.empty) {
        const writeBatch = db.batch();
        snapshot.docs.forEach((doc) => {
          writeBatch.delete(doc.ref);
          deletedCount++;
        });
        await writeBatch.commit();
      }
    }

    return deletedCount;
  } catch (error) {
    console.error('Error cleaning up invalid FCM tokens:', error.message);
    return 0;
  }
};

const chunkArray = (array, size) => {
  const chunks = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
};

// ==========================================
// 5. API Routes
// ==========================================

// Health Check
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Firebase Push Notification Server is active.',
    timestamp: new Date().toISOString()
  });
});

// Register or Update Device
app.post('/api/devices/register', async (req, res) => {
  try {
    const { deviceId, fcmToken, platform = 'android', deviceModel, appVersion } = req.body;

    if (!deviceId || typeof deviceId !== 'string' || !deviceId.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Field "deviceId" is required and must be a valid string.'
      });
    }

    if (!fcmToken || typeof fcmToken !== 'string' || !fcmToken.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Field "fcmToken" is required and must be a valid string.'
      });
    }

    const deviceRef = db.collection('devices').doc(deviceId.trim());

    await deviceRef.set(
      {
        deviceId: deviceId.trim(),
        fcmToken: fcmToken.trim(),
        platform: String(platform).toLowerCase(),
        deviceModel: deviceModel ? String(deviceModel) : null,
        appVersion: appVersion ? String(appVersion) : null,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      },
      { merge: true }
    );

    return res.status(200).json({
      success: true,
      message: 'Device successfully registered/updated.'
    });
  } catch (error) {
    console.error('Device registration error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Failed to register device.'
    });
  }
});

// Remove Device
app.delete('/api/devices/:deviceId', verifyFirebaseToken, requireAdmin, async (req, res) => {
  try {
    const { deviceId } = req.params;

    if (!deviceId) {
      return res.status(400).json({
        success: false,
        message: 'Parameter "deviceId" is required.'
      });
    }

    const deviceRef = db.collection('devices').doc(deviceId.trim());
    const doc = await deviceRef.get();

    if (!doc.exists) {
      return res.status(404).json({
        success: false,
        message: 'Device not found.'
      });
    }

    await deviceRef.delete();

    return res.status(200).json({
      success: true,
      message: 'Device successfully removed.'
    });
  } catch (error) {
    console.error('Device delete error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Failed to remove device.'
    });
  }
});

// List All Devices
app.get('/api/devices', verifyFirebaseToken, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 500);
    const snapshot = await db.collection('devices').orderBy('updatedAt', 'desc').limit(limit).get();

    const devices = [];
    snapshot.forEach((doc) => {
      const data = doc.data();
      devices.push({
        id: doc.id,
        ...data,
        createdAt: data.createdAt ? data.createdAt.toDate().toISOString() : null,
        updatedAt: data.updatedAt ? data.updatedAt.toDate().toISOString() : null
      });
    });

    return res.status(200).json({
      success: true,
      count: devices.length,
      devices
    });
  } catch (error) {
    console.error('Device list fetch error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Failed to retrieve devices.'
    });
  }
});

// Send Push Notification to All Devices
app.post('/api/notifications/all', verifyFirebaseToken, requireAdmin, async (req, res) => {
  try {
    const { title, body, imageUrl, data } = req.body;

    if (!title || !body) {
      return res.status(400).json({
        success: false,
        message: 'Both "title" and "body" are required.'
      });
    }

    const snapshot = await db.collection('devices').get();

    if (snapshot.empty) {
      return res.status(404).json({
        success: false,
        message: 'No registered devices found.'
      });
    }

    const tokens = [];
    snapshot.forEach((doc) => {
      const docData = doc.data();
      if (docData.fcmToken) {
        tokens.push(docData.fcmToken);
      }
    });

    if (tokens.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'No valid FCM tokens available for dispatch.'
      });
    }

    // FCM Multicast Batching (Max 500 per batch)
    const batches = chunkArray(tokens, 500);
    let totalSuccessCount = 0;
    let totalFailureCount = 0;
    const invalidTokens = [];

    const payloadNotification = {
      title: String(title),
      body: String(body),
      ...(imageUrl && typeof imageUrl === 'string' && imageUrl.trim() !== '' ? { imageUrl: imageUrl.trim() } : {})
    };

    const sanitizedData = {};
    if (data && typeof data === 'object') {
      Object.keys(data).forEach((key) => {
        sanitizedData[key] = String(data[key]);
      });
    }

    for (const batchTokens of batches) {
      const message = {
        notification: payloadNotification,
        data: sanitizedData,
        tokens: batchTokens
      };

      const response = await messaging.sendEachForMulticast(message);

      totalSuccessCount += response.successCount;
      totalFailureCount += response.failureCount;

      response.responses.forEach((resp, index) => {
        if (!resp.success && resp.error) {
          const errorCode = resp.error.code;
          if (
            errorCode === 'messaging/invalid-registration-token' ||
            errorCode === 'messaging/registration-token-not-registered'
          ) {
            invalidTokens.push(batchTokens[index]);
          }
        }
      });
    }

    // Cleanup invalid tokens
    const cleanedUpCount = await cleanupInvalidTokens(invalidTokens);

    // Save Record to "notifications" Collection
    const notificationRecord = {
      target: 'all',
      title,
      body,
      imageUrl: imageUrl || null,
      data: sanitizedData,
      totalTargets: tokens.length,
      successCount: totalSuccessCount,
      failureCount: totalFailureCount,
      cleanedUpTokens: cleanedUpCount,
      sentBy: req.user.uid,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    const docRef = await db.collection('notifications').add(notificationRecord);

    return res.status(200).json({
      success: true,
      message: 'Multicast notification dispatch complete.',
      notificationId: docRef.id,
      stats: {
        totalTargets: tokens.length,
        successCount: totalSuccessCount,
        failureCount: totalFailureCount,
        cleanedUpTokens: cleanedUpCount
      }
    });
  } catch (error) {
    console.error('Multicast notification error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Failed to send notification to all devices.'
    });
  }
});

// Send Push Notification to a Specific Device
app.post('/api/notifications/device', verifyFirebaseToken, requireAdmin, async (req, res) => {
  try {
    const { deviceId, fcmToken, title, body, imageUrl, data } = req.body;

    if (!deviceId && !fcmToken) {
      return res.status(400).json({
        success: false,
        message: 'Either "deviceId" or "fcmToken" must be provided.'
      });
    }

    if (!title || !body) {
      return res.status(400).json({
        success: false,
        message: 'Both "title" and "body" are required.'
      });
    }

    let targetToken = fcmToken;
    let targetDeviceId = deviceId;

    if (!targetToken && targetDeviceId) {
      const deviceDoc = await db.collection('devices').doc(targetDeviceId.trim()).get();
      if (!deviceDoc.exists) {
        return res.status(404).json({
          success: false,
          message: 'Device not found in registry.'
        });
      }
      targetToken = deviceDoc.data().fcmToken;
    }

    if (!targetToken) {
      return res.status(400).json({
        success: false,
        message: 'No active FCM token found for the device.'
      });
    }

    const sanitizedData = {};
    if (data && typeof data === 'object') {
      Object.keys(data).forEach((key) => {
        sanitizedData[key] = String(data[key]);
      });
    }

    const message = {
      token: targetToken,
      notification: {
        title: String(title),
        body: String(body),
        ...(imageUrl && typeof imageUrl === 'string' && imageUrl.trim() !== '' ? { imageUrl: imageUrl.trim() } : {})
      },
      data: sanitizedData
    };

    try {
      const messageId = await messaging.send(message);

      const notificationRecord = {
        target: 'device',
        targetDeviceId: targetDeviceId || null,
        targetToken,
        title,
        body,
        imageUrl: imageUrl || null,
        data: sanitizedData,
        messageId,
        sentBy: req.user.uid,
        status: 'delivered',
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      };

      const docRef = await db.collection('notifications').add(notificationRecord);

      return res.status(200).json({
        success: true,
        message: 'Notification sent successfully.',
        notificationId: docRef.id,
        fcmMessageId: messageId
      });
    } catch (fcmError) {
      if (
        fcmError.code === 'messaging/invalid-registration-token' ||
        fcmError.code === 'messaging/registration-token-not-registered'
      ) {
        if (targetDeviceId) {
          await db.collection('devices').doc(targetDeviceId.trim()).delete();
        } else {
          await cleanupInvalidTokens([targetToken]);
        }
      }

      console.error('Targeted FCM dispatch failed:', fcmError.message);
      return res.status(400).json({
        success: false,
        message: 'Targeted FCM dispatch failed.',
        code: fcmError.code || 'UNKNOWN_FCM_ERROR'
      });
    }
  } catch (error) {
    console.error('Direct notification error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Failed to process notification request.'
    });
  }
});

// Get Notification History
app.get('/api/notifications', verifyFirebaseToken, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);

    const snapshot = await db
      .collection('notifications')
      .orderBy('createdAt', 'desc')
      .limit(limit)
      .get();

    const notifications = [];
    snapshot.forEach((doc) => {
      const docData = doc.data();
      notifications.push({
        id: doc.id,
        ...docData,
        createdAt: docData.createdAt ? docData.createdAt.toDate().toISOString() : null
      });
    });

    return res.status(200).json({
      success: true,
      count: notifications.length,
      notifications
    });
  } catch (error) {
    console.error('Notification history fetch error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Failed to retrieve notification history.'
    });
  }
});

// ==========================================
// 6. Global 404 & Error Handling
// ==========================================
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found.'
  });
});

app.use((err, req, res, next) => {
  console.error('Unhandled Server Error:', err.message);
  res.status(500).json({
    success: false,
    message: 'An internal server error occurred.'
  });
});

// ==========================================
// 7. Process & Port Listener
// ==========================================
const PORT = process.env.PORT || 10000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Push Notification Server is running on port ${PORT}`);
});
