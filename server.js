
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const admin = require("firebase-admin");
const { google } = require("googleapis");

const app = express();

const PORT = process.env.PORT || 10000;
const FRONTEND_URL = process.env.FRONTEND_URL;

const DASHBOARD_URL =
  "https://mrjony127.github.io/JONYMAILWEB/";

const REQUIRED_ENV = [
  "FRONTEND_URL",
  "FIREBASE_PROJECT_ID",
  "FIREBASE_CLIENT_EMAIL",
  "FIREBASE_PRIVATE_KEY",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "GOOGLE_REDIRECT_URI",
  "TOKEN_ENCRYPTION_KEY",
  "STATE_SECRET"
];

for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error("Missing environment variable:", key);
    process.exit(1);
  }
}

if (!/^[a-f0-9]{64}$/i.test(process.env.TOKEN_ENCRYPTION_KEY)) {
  console.error("TOKEN_ENCRYPTION_KEY must be 64 hexadecimal characters.");
  process.exit(1);
}

const ENCRYPTION_KEY = Buffer.from(
  process.env.TOKEN_ENCRYPTION_KEY,
  "hex"
);

/* CORS CONFIGURATION */

let allowedOrigins;

try {
  allowedOrigins = [
    new URL(FRONTEND_URL).origin,
    "https://mrjony127.github.io",
    "http://localhost:3000",
    "http://127.0.0.1:5500"
  ];
} catch (error) {
  console.error("Invalid FRONTEND_URL:", error.message);
  process.exit(1);
}

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    console.error("Blocked CORS origin:", origin);
    return callback(new Error("Origin not allowed by CORS"));
  },
  methods: ["GET", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "1mb" }));

/* FIREBASE */

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n")
    })
  });
}

const db = admin.firestore();

/* GOOGLE OAUTH */

const oauthClient = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

const SCOPES = [
  "openid",
  "email",
  "https://www.googleapis.com/auth/gmail.readonly"
];

/* TOKEN ENCRYPTION */

function encryptToken(value) {
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    ENCRYPTION_KEY,
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  return [
    iv.toString("hex"),
    tag.toString("hex"),
    encrypted.toString("hex")
  ].join(":");
}

function decryptToken(value) {
  let iv;
  let tag;
  let encrypted;

  if (value && typeof value === "object") {
    iv = Buffer.from(value.iv, "hex");
    tag = Buffer.from(value.tag, "hex");
    encrypted = Buffer.from(value.data, "hex");
  } else if (typeof value === "string") {
    const parts = value.split(":");

    if (parts.length !== 3) {
      throw new Error("Invalid encrypted Gmail token format.");
    }

    iv = Buffer.from(parts[0], "hex");
    tag = Buffer.from(parts[1], "hex");
    encrypted = Buffer.from(parts[2], "hex");
  } else {
    throw new Error("Gmail refresh token is missing.");
  }

  if (iv.length !== 12 || tag.length !== 16 || !encrypted.length) {
    throw new Error("Invalid encrypted Gmail token data.");
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    ENCRYPTION_KEY,
    iv
  );

  decipher.setAuthTag(tag);

  return Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]).toString("utf8");
}

function getStoredRefreshToken(account) {
  if (account.encryptedRefreshToken) {
    return decryptToken(account.encryptedRefreshToken);
  }

  if (account.refreshToken) {
    return decryptToken(account.refreshToken);
  }

  return null;
}

/* OAUTH STATE */

function createOAuthState(uid) {
  const payload = Buffer.from(JSON.stringify({
    uid,
    time: Date.now(),
    nonce: crypto.randomBytes(16).toString("hex")
  })).toString("base64url");

  const signature = crypto
    .createHmac("sha256", process.env.STATE_SECRET)
    .update(payload)
    .digest("hex");

  return payload + "." + signature;
}

function verifyOAuthState(state) {
  const parts = String(state || "").split(".");

  if (parts.length !== 2) {
    throw new Error("Invalid OAuth state.");
  }

  const [payload, signature] = parts;

  const expected = crypto
    .createHmac("sha256", process.env.STATE_SECRET)
    .update(payload)
    .digest("hex");

  const a = Buffer.from(signature, "hex");
  const b = Buffer.from(expected, "hex");

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new Error("OAuth state verification failed.");
  }

  const data = JSON.parse(
    Buffer.from(payload, "base64url").toString("utf8")
  );

  if (
    !data.uid ||
    !data.time ||
    Date.now() - data.time > 10 * 60 * 1000 ||
    data.time > Date.now() + 60 * 1000
  ) {
    throw new Error("OAuth request expired.");
  }

  return data;
}

/* FIREBASE AUTH */

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authentication required."
      });
    }

    const token = header.slice(7);

    req.user = await admin.auth().verifyIdToken(token);

    next();
  } catch (error) {
    console.error("Authentication error:", error.message);

    return res.status(401).json({
      success: false,
      message: "Invalid or expired login session."
    });
  }
}

/* FIRESTORE HELPERS */

function accountCollection(uid) {
  return db.collection("users")
    .doc(uid)
    .collection("gmailAccounts");
}

function accountDocumentId(email) {
  return Buffer.from(email.toLowerCase()).toString("base64url");
}

async function getAccount(uid, accountId) {
  if (!accountId || typeof accountId !== "string") {
    throw new Error("Gmail account ID is required.");
  }

  const snapshot = await accountCollection(uid).doc(accountId).get();

  if (!snapshot.exists) {
    throw new Error("Gmail account not found.");
  }

  return {
    id: snapshot.id,
    ...snapshot.data()
  };
}

/* GMAIL CLIENT */

async function getGmail(uid, accountId) {
  const account = await getAccount(uid, accountId);

  const refreshToken = getStoredRefreshToken(account);

  if (!refreshToken) {
    throw new Error(
      "Gmail refresh token is missing. Reconnect this account."
    );
  }

  if (!account.encryptedRefreshToken) {
    await accountCollection(uid).doc(accountId).set({
      encryptedRefreshToken: encryptToken(refreshToken),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    console.log("Legacy Gmail token migrated:", account.email);
  }

  const auth = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );

  auth.setCredentials({
    refresh_token: refreshToken
  });

  const gmail = google.gmail({
    version: "v1",
    auth
  });

  return { gmail, account };
}

/* EMAIL HELPERS */

function getHeader(headers, name) {
  const header = (headers || []).find(
    item => item.name.toLowerCase() === name.toLowerCase()
  );

  return header ? header.value : "";
}

function decodeBase64Url(value) {
  if (!value) return "";

  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  return Buffer.from(normalized, "base64").toString("utf8");
}

function extractBody(payload) {
  if (!payload) return "";

  let plain = "";
  let html = "";

  function walk(part) {
    if (!part) return;

    const mime = (part.mimeType || "").toLowerCase();

    if (part.body && part.body.data) {
      const decoded = decodeBase64Url(part.body.data);

      if (mime === "text/plain" && !plain) {
        plain = decoded;
      } else if (mime === "text/html" && !html) {
        html = decoded;
      }
    }

    (part.parts || []).forEach(walk);
  }

  walk(payload);

  if (plain) return plain;

  if (html) {
    return html
      .replace(/<script[\s\S]*?<\/script>/gi, "")
      .replace(/<style[\s\S]*?<\/style>/gi, "")
      .replace(/<br\s*\/?>/gi, "\n")
      .replace(/<\/(p|div|tr|h[1-6])>/gi, "\n")
      .replace(/<[^>]*>/g, " ")
      .replace(/&nbsp;/gi, " ")
      .replace(/&amp;/gi, "&")
      .replace(/&lt;/gi, "<")
      .replace(/&gt;/gi, ">")
      .replace(/&quot;/gi, '"')
      .replace(/&#39;/gi, "'")
      .replace(/[ \t]+\n/g, "\n")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
  }

  return "";
}

function mapMessage(message, account) {
  const headers = message.payload?.headers || [];
  const labels = message.labelIds || [];

  return {
    id: message.id,
    threadId: message.threadId,
    from: getHeader(headers, "From"),
    to: getHeader(headers, "To"),
    subject: getHeader(headers, "Subject") || "(No subject)",
    snippet: message.snippet || "",
    date: message.internalDate
      ? new Date(Number(message.internalDate)).toISOString()
      : getHeader(headers, "Date"),
    unread: labels.includes("UNREAD"),
    labelIds: labels,
    email: account.email,
    accountId: account.id
  };
}

/* HEALTH CHECK */

app.get("/", (req, res) => {
  res.json({
    name: "JONY MAIL",
    backend: "online",
    firebase: "connected",
    status: "success"
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    backend: "online",
    firebase: "connected"
  });
});

/* CONNECT GMAIL */

app.post("/api/gmail/connect", requireAuth, async (req, res) => {
  try {
    const uid = req.user.uid;

    const existing = await accountCollection(uid).get();

    if (existing.size >= 20) {
      return res.status(400).json({
        success: false,
        message: "Maximum 20 Gmail accounts allowed."
      });
    }

    const state = createOAuthState(uid);

    const authUrl = oauthClient.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      include_granted_scopes: true,
      scope: SCOPES,
      state
    });

    res.json({
      success: true,
      authUrl
    });

  } catch (error) {
    console.error("Connect error:", error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

/* GOOGLE OAUTH CALLBACK */

app.get("/api/gmail/callback", async (req, res) => {
  try {
    if (req.query.error) {
      return res.redirect(
        DASHBOARD_URL + "?gmail_error=" +
        encodeURIComponent(String(req.query.error))
      );
    }

    const { code, state } = req.query;

    if (!code || !state) {
      throw new Error(
        "Missing Google authorization code or state."
      );
    }

    const stateData = verifyOAuthState(state);
    const uid = stateData.uid;

    const { tokens } = await oauthClient.getToken(String(code));

    if (!tokens.access_token) {
      throw new Error(
        "Google did not return an access token."
      );
    }

    oauthClient.setCredentials(tokens);

    const oauth2 = google.oauth2({
      auth: oauthClient,
      version: "v2"
    });

    const userInfo = await oauth2.userinfo.get();
    const email = userInfo.data.email;

    if (!email) {
      throw new Error(
        "Could not identify the Gmail account."
      );
    }

    const accountId = accountDocumentId(email);

    const accountRef = accountCollection(uid).doc(accountId);
    const oldAccount = await accountRef.get();

    let refreshToken = tokens.refresh_token || null;

    if (!refreshToken && oldAccount.exists) {
      refreshToken = getStoredRefreshToken(oldAccount.data());
    }

    if (!refreshToken) {
      throw new Error(
        "Google did not provide a refresh token. Remove this app from your Google Account permissions and connect again."
      );
    }

    const allAccounts = await accountCollection(uid).get();

    if (!oldAccount.exists && allAccounts.size >= 20) {
      throw new Error(
        "Maximum 20 Gmail accounts allowed."
      );
    }

    await accountRef.set({
      email,
      connected: true,
      encryptedRefreshToken: encryptToken(refreshToken),
      connectedAt: oldAccount.exists
        ? oldAccount.data().connectedAt ||
          admin.firestore.FieldValue.serverTimestamp()
        : admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    console.log("Gmail account connected:", email);

    return res.redirect(
      DASHBOARD_URL + "?gmail_connected=1"
    );

  } catch (error) {
    console.error("OAuth callback error:", error);

    return res.redirect(
      DASHBOARD_URL + "?gmail_error=" +
      encodeURIComponent(error.message || "connection_failed")
    );
  }
});

/* LIST CONNECTED ACCOUNTS */

app.get("/api/gmail/accounts", requireAuth, async (req, res) => {
  try {
    const snapshot = await accountCollection(req.user.uid).get();

    const accounts = snapshot.docs
      .filter(doc => doc.data().connected !== false)
      .map(doc => ({
        id: doc.id,
        email: doc.data().email,
        connectedAt: doc.data().connectedAt || null
      }));

    res.json({
      success: true,
      accounts
    });

  } catch (error) {
    console.error("Accounts error:", error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

/* LIST GMAIL LABELS */

app.get("/api/gmail/labels", requireAuth, async (req, res) => {
  try {
    const accountId = String(req.query.accountId || "");

    const { gmail } = await getGmail(
      req.user.uid,
      accountId
    );

    const response = await gmail.users.labels.list({
      userId: "me"
    });

    const labels = (response.data.labels || []).map(label => ({
      id: label.id,
      name: label.name,
      type: label.type
    }));

    res.json({
      success: true,
      labels
    });

  } catch (error) {
    console.error("Labels error:", error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

/* LIST EMAIL MESSAGES */

app.get("/api/gmail/messages", requireAuth, async (req, res) => {
  try {
    const accountId = String(req.query.accountId || "");

    if (!accountId) {
      return res.status(400).json({
        success: false,
        message: "accountId required."
      });
    }

    const labelId = String(req.query.labelId || "INBOX");

    const maxResults = Math.min(
      Math.max(
        parseInt(req.query.maxResults || "40", 10) || 40,
        1
      ),
      100
    );

    const { gmail, account } = await getGmail(
      req.user.uid,
      accountId
    );

    const listOptions = {
      userId: "me",
      maxResults
    };

    if (labelId && labelId !== "ALL_MAIL") {
      listOptions.labelIds = [labelId];
    }

    if (labelId === "SPAM" || labelId === "TRASH") {
      listOptions.includeSpamTrash = true;
    }

    if (req.query.pageToken) {
      listOptions.pageToken = String(req.query.pageToken);
    }

    const listResponse = await gmail.users.messages.list(
      listOptions
    );

    const items = listResponse.data.messages || [];

    const details = await Promise.all(
      items.map(async item => {
        try {
          const response = await gmail.users.messages.get({
            userId: "me",
            id: item.id,
            format: "metadata",
            metadataHeaders: [
              "From",
              "To",
              "Subject",
              "Date"
            ]
          });

          return mapMessage(response.data, account);

        } catch (error) {
          console.error(
            "Message metadata error:",
            error.message
          );

          return null;
        }
      })
    );

    res.json({
      success: true,
      messages: details.filter(Boolean),
      nextPageToken: listResponse.data.nextPageToken || null,
      resultSizeEstimate:
        listResponse.data.resultSizeEstimate || 0
    });

  } catch (error) {
    console.error("Messages error:", error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

/* READ ONE EMAIL */

app.get("/api/gmail/message", requireAuth, async (req, res) => {
  try {
    const accountId = String(req.query.accountId || "");
    const messageId = String(req.query.id || "");

    if (!accountId || !messageId) {
      return res.status(400).json({
        success: false,
        message: "accountId and id required."
      });
    }

    const { gmail, account } = await getGmail(
      req.user.uid,
      accountId
    );

    const response = await gmail.users.messages.get({
      userId: "me",
      id: messageId,
      format: "full"
    });

    const message = response.data;
    const headers = message.payload?.headers || [];

    res.json({
      success: true,
      message: {
        id: message.id,
        threadId: message.threadId,
        from: getHeader(headers, "From"),
        to: getHeader(headers, "To"),
        subject:
          getHeader(headers, "Subject") || "(No subject)",
        date: message.internalDate
          ? new Date(
              Number(message.internalDate)
            ).toISOString()
          : getHeader(headers, "Date"),
        snippet: message.snippet || "",
        body: extractBody(message.payload),
        labelIds: message.labelIds || [],
        email: account.email,
        accountId: account.id
      }
    });

  } catch (error) {
    console.error("Read message error:", error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

/* DISCONNECT GMAIL ACCOUNT */

app.delete(
  "/api/gmail/accounts/:id",
  requireAuth,
  async (req, res) => {
    try {
      const accountRef = accountCollection(req.user.uid)
        .doc(req.params.id);

      const snapshot = await accountRef.get();

      if (!snapshot.exists) {
        return res.status(404).json({
          success: false,
          message: "Gmail account not found."
        });
      }

      await accountRef.delete();

      res.json({
        success: true,
        message: "Gmail account disconnected."
      });

    } catch (error) {
      console.error("Disconnect error:", error);

      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

/* ERROR HANDLER */

app.use((error, req, res, next) => {
  console.error("Server error:", error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    success: false,
    message: "Internal server error."
  });
});

/* START SERVER */

app.listen(PORT, "0.0.0.0", () => {
  console.log("==================================");
  console.log("       JONY MAIL BACKEND");
  console.log("==================================");
  console.log("Server running on port:", PORT);
  console.log("Firebase Admin: initialized");
  console.log("Gmail OAuth: configured");
  console.log("Allowed origins:", allowedOrigins);
});
