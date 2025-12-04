const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const https = require('https');
const sequelize = require('./database');
const { Order, AuthCode, Session } = require('./models');

const http = require('http');
const { Server } = require('socket.io');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;

// Email configuration (Resend)
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const EMAIL_FROM = process.env.EMAIL_FROM || 'onboarding@resend.dev';
const SITE_URL = process.env.SITE_URL || 'https://astroshift.io';

// Load config - handle both local and production environments
const configPath = path.join(__dirname, 'config', 'config.json');
let config;

try {
  if (fs.existsSync(configPath)) {
    config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  } else {
    // Default config if file doesn't exist
    config = {
      admin: {
        username: "admin",
        passwordHash: "$2b$10$placeholder",
        secretPath: "ctrl-panel-x7k9m2"
      },
      fixedFloat: {
        apiKey: "",
        apiSecret: "",
        baseUrl: "https://ff.io/api/v2"
      },
      fees: {
        astroShiftMarkup: 1.0,
        fiatProcessingFee: 5.5
      },
      paymentMethods: {
        cashapp: { enabled: false, cashtag: "", displayName: "Cash App" },
        zelle: { enabled: false, email: "", displayName: "Zelle" },
        paypal: { enabled: false, email: "", displayName: "PayPal" }
      },
      session: {
        secret: "change-this-to-random-string-in-production",
        maxAge: 86400000
      }
    };
  }

  // Override with environment variables if set (for Railway)
  if (process.env.FF_API_KEY) config.fixedFloat.apiKey = process.env.FF_API_KEY;
  if (process.env.FF_API_SECRET) config.fixedFloat.apiSecret = process.env.FF_API_SECRET;
  if (process.env.ADMIN_USER) config.admin.username = process.env.ADMIN_USER;
  if (process.env.ADMIN_PASSWORD_HASH) config.admin.passwordHash = process.env.ADMIN_PASSWORD_HASH;
  if (process.env.ADMIN_PATH) config.admin.secretPath = process.env.ADMIN_PATH;
  if (process.env.SESSION_SECRET) config.session.secret = process.env.SESSION_SECRET;

  // Payment methods from env vars
  if (process.env.CASHAPP_ENABLED === 'true') {
    config.paymentMethods.cashapp.enabled = true;
    config.paymentMethods.cashapp.cashtag = process.env.CASHAPP_TAG || '';
  }
  if (process.env.ZELLE_ENABLED === 'true') {
    config.paymentMethods.zelle.enabled = true;
    config.paymentMethods.zelle.email = process.env.ZELLE_EMAIL || '';
  }
  if (process.env.PAYPAL_ENABLED === 'true') {
    config.paymentMethods.paypal.enabled = true;
    config.paymentMethods.paypal.email = process.env.PAYPAL_EMAIL || '';
  }

} catch (err) {
  console.error('Error loading config:', err);
  process.exit(1);
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Serve index.html for root route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Trust proxy (needed for Railway/Cloudflare)
app.set('trust proxy', 1);

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: false, // Disable CSP for now to avoid breaking scripts
}));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter); // Apply rate limiting to API routes

// Session for admin panel
const isProduction = process.env.NODE_ENV === 'production' || process.env.RAILWAY_ENVIRONMENT === 'production' || process.env.PORT;

app.use(session({
  secret: config.session.secret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: config.session.maxAge,
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'none' : 'lax'
  }
}));

// ============================================
// HELPER FUNCTIONS
// ============================================

function saveConfig() {
  try {
    const configDir = path.dirname(configPath);
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  } catch (err) {
    console.error('Error saving config:', err);
  }
}

function generateFFSignature(data) {
  const jsonData = JSON.stringify(data);
  return crypto
    .createHmac('sha256', config.fixedFloat.apiSecret)
    .update(jsonData)
    .digest('hex');
}

async function ffApiRequest(endpoint, data = {}) {
  return new Promise((resolve, reject) => {
    const jsonData = JSON.stringify(data);
    const signature = generateFFSignature(data);

    const options = {
      hostname: 'ff.io',
      port: 443,
      path: `/api/v2/${endpoint}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=UTF-8',
        'X-API-KEY': config.fixedFloat.apiKey,
        'X-API-SIGN': signature,
        'Content-Length': Buffer.byteLength(jsonData)
      }
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch {
          reject(new Error('Invalid JSON response from FixedFloat'));
        }
      });
    });

    req.on('error', reject);
    req.write(jsonData);
    req.end();
  });
}

function applyAstroShiftFee(amount, isFiat = false) {
  let totalFeePercent = config.fees.astroShiftMarkup;
  if (isFiat) {
    totalFeePercent += config.fees.fiatProcessingFee;
  }
  return amount * (1 - totalFeePercent / 100);
}

// ============================================
// EMAIL FUNCTIONS (Resend)
// ============================================

async function sendEmail(to, subject, html) {
  if (!RESEND_API_KEY) {
    console.log('Email not configured. Would send to:', to, 'Subject:', subject);
    return false;
  }

  return new Promise((resolve) => {
    const data = JSON.stringify({
      from: EMAIL_FROM,
      to: [to],
      subject: subject,
      html: html
    });

    const options = {
      hostname: 'api.resend.com',
      port: 443,
      path: '/emails',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        if (res.statusCode === 200 || res.statusCode === 201) {
          console.log('Email sent to:', to);
          resolve(true);
        } else {
          console.error('Resend error:', res.statusCode, body);
          resolve(false);
        }
      });
    });

    req.on('error', (error) => {
      console.error('Email error:', error);
      resolve(false);
    });

    req.write(data);
    req.end();
  });
}

function generateEmailTemplate(title, content, buttonText, buttonUrl, footerNote) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="margin:0;padding:0;background:#f5f5f5;font-family:Arial,Helvetica,sans-serif;">
      <div style="max-width:500px;margin:0 auto;padding:30px 15px;">
        <!-- Header -->
        <div style="background:linear-gradient(135deg,#4f7eff,#06b6d4);padding:20px;border-radius:8px 8px 0 0;text-align:center;">
          <h1 style="color:white;margin:0;font-size:22px;font-weight:700;letter-spacing:0.5px;">AstroShift</h1>
        </div>
        
        <!-- Content -->
        <div style="background:#ffffff;padding:30px;border-radius:0 0 8px 8px;border:1px solid #e5e5e5;border-top:none;">
          <h2 style="color:#1a1a2e;margin:0 0 20px 0;font-size:16px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">${title}</h2>
          ${content}
          ${buttonText && buttonUrl ? `
            <div style="text-align:center;margin:25px 0;">
              <a href="${buttonUrl}" style="background:#1a1a2e;color:white;padding:12px 30px;border-radius:4px;text-decoration:none;font-weight:600;font-size:14px;display:inline-block;">${buttonText}</a>
            </div>
          ` : ''}
          ${footerNote ? `
            <div style="margin-top:25px;padding-top:20px;border-top:1px solid #eee;">
              ${footerNote}
            </div>
          ` : ''}
        </div>
        
        <!-- Footer -->
        <div style="text-align:center;padding:20px;color:#999;font-size:12px;">
          <p style="margin:0;">AstroShift Team</p>
          <p style="margin:5px 0 0 0;color:#4f7eff;">support@astroshift.io</p>
        </div>
      </div>
    </body>
    </html>
  `;
}

async function sendOrderCreatedEmail(order, email) {
  const content = `
    <p style="color:#666;font-size:14px;margin:0 0 15px 0;">Your order ID is <strong style="color:#1a1a2e;font-size:18px;">${order.id}</strong></p>
    
    <div style="background:#f8f9fa;border-radius:6px;padding:15px;margin:20px 0;text-align:center;">
      <p style="color:#1a1a2e;font-size:18px;font-weight:600;margin:0;">
        ${order.fromAmount} ${order.fromCcy} <span style="color:#4f7eff;">→</span> ${order.toAmount} ${order.toCcy}
      </p>
    </div>
    
    <table style="width:100%;font-size:14px;border-collapse:collapse;">
      <tr>
        <td style="padding:10px 0;color:#666;border-bottom:1px solid #eee;">Order type</td>
        <td style="padding:10px 0;text-align:right;color:#1a1a2e;border-bottom:1px solid #eee;">${order.type === 'fiat-to-crypto' ? 'Fiat to Crypto' : 'Crypto Exchange'}</td>
      </tr>
      <tr>
        <td style="padding:10px 0;color:#666;border-bottom:1px solid #eee;">Order status</td>
        <td style="padding:10px 0;text-align:right;color:#f59e0b;font-weight:600;border-bottom:1px solid #eee;">NEW</td>
      </tr>
      <tr>
        <td style="padding:10px 0;color:#666;border-bottom:1px solid #eee;">Send</td>
        <td style="padding:10px 0;text-align:right;color:#1a1a2e;border-bottom:1px solid #eee;">${order.fromAmount} ${order.fromCcy}</td>
      </tr>
      <tr>
        <td style="padding:10px 0;color:#666;border-bottom:1px solid #eee;">Receive</td>
        <td style="padding:10px 0;text-align:right;color:#1a1a2e;border-bottom:1px solid #eee;">${order.toAmount} ${order.toCcy}</td>
      </tr>
      <tr>
        <td style="padding:10px 0;color:#666;">Receiving address</td>
        <td style="padding:10px 0;text-align:right;color:#1a1a2e;word-break:break-all;font-size:12px;font-family:monospace;">${order.toAddress}</td>
      </tr>
    </table>
  `;

  const footerNote = `
    <p style="color:#f59e0b;font-size:13px;margin:0;"><strong>Attention!</strong> These details are valid only for this order. When you recreate the order details will be different.</p>
  `;

  const html = generateEmailTemplate(
    'YOU HAVE SUBSCRIBED TO NOTIFICATIONS',
    content,
    'Check order',
    `${SITE_URL}/order.html?id=${order.id}`,
    footerNote
  );

  return sendEmail(email, `Order ${order.id.substring(0, 8).toUpperCase()} - AstroShift`, html);
}





async function sendVerificationCode(email, code) {
  const content = `
    <p style="color:#666;font-size:14px;margin:0 0 15px 0;">Use this code to log in to your AstroShift account:</p>
    <div style="background:#f8f9fa;border-radius:6px;padding:25px;text-align:center;margin:20px 0;">
      <span style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#1a1a2e;">${code}</span>
    </div>
    <p style="color:#666;font-size:13px;">This code expires in 10 minutes. If you didn't request this code, you can ignore this email.</p>
  `;

  const html = generateEmailTemplate('YOUR VERIFICATION CODE', content, null, null, null);

  return sendEmail(email, `${code} - Your AstroShift verification code`, html);
}

// ============================================
// WALLET ADDRESS VALIDATION
// ============================================

const walletPatterns = {
  BTC: /^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$/,
  ETH: /^0x[a-fA-F0-9]{40}$/,
  USDT: /^(0x[a-fA-F0-9]{40}|T[a-zA-Z0-9]{33})$/, // ERC20 or TRC20
  USDTETH: /^0x[a-fA-F0-9]{40}$/,
  USDTTRC20: /^T[a-zA-Z0-9]{33}$/,
  USDTBSC: /^0x[a-fA-F0-9]{40}$/,
  LTC: /^(L|M|ltc1)[a-zA-HJ-NP-Z0-9]{25,62}$/,
  XRP: /^r[0-9a-zA-Z]{24,34}$/,
  DOGE: /^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$/,
  TRX: /^T[a-zA-Z0-9]{33}$/,
  SOL: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/,
  XLM: /^G[A-Z2-7]{55}$/,
  ADA: /^addr1[a-z0-9]{58,}$/,
  DOT: /^1[a-zA-Z0-9]{47}$/,
  MATIC: /^0x[a-fA-F0-9]{40}$/,
  AVAX: /^0x[a-fA-F0-9]{40}$/,
  LINK: /^0x[a-fA-F0-9]{40}$/,
  UNI: /^0x[a-fA-F0-9]{40}$/,
  SHIB: /^0x[a-fA-F0-9]{40}$/,
  BCH: /^(bitcoincash:)?[qp][a-z0-9]{41}$/i,
  XMR: /^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$/,
  BNB: /^(bnb1)[a-z0-9]{38}$|^0x[a-fA-F0-9]{40}$/,
  ATOM: /^cosmos1[a-z0-9]{38}$/,
  FIL: /^f[0-9][a-zA-Z0-9]{39,}$/
};

function validateWalletAddress(address, currency) {
  // Normalize currency code
  const curr = currency.toUpperCase().replace('ERC20', '').replace('TRC20', '').replace('BSC', '');

  // Check if we have a pattern for this currency
  let pattern = walletPatterns[currency.toUpperCase()] || walletPatterns[curr];

  // For ERC-20 tokens, use ETH pattern
  if (!pattern && (currency.includes('ERC20') || currency.includes('ETH'))) {
    pattern = walletPatterns.ETH;
  }

  // For TRC-20 tokens, use TRX pattern
  if (!pattern && currency.includes('TRC20')) {
    pattern = walletPatterns.TRX;
  }

  // For BSC tokens, use ETH pattern (same format)
  if (!pattern && currency.includes('BSC')) {
    pattern = walletPatterns.ETH;
  }

  // If no specific pattern, do basic validation
  if (!pattern) {
    return address.length >= 20 && address.length <= 120 && /^[a-zA-Z0-9]+$/.test(address);
  }

  return pattern.test(address);
}

// ============================================
// ADMIN AUTHENTICATION MIDDLEWARE
// ============================================

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
    return next();
  }
  res.status(401).json({ error: 'Unauthorized' });
}

// ============================================
// USER AUTHENTICATION ROUTES
// ============================================

// Send verification code
app.post('/api/auth/send-code', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, error: 'Invalid email address' });
    }

    // Check rate limiting (max 3 attempts per 10 minutes)
    const existing = await AuthCode.findByPk(email);
    if (existing && existing.attempts >= 3 && Date.now() < existing.rateLimit) {
      return res.status(429).json({ success: false, error: 'Too many attempts. Please wait 10 minutes.' });
    }

    // Generate 6-digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();

    // Store code (expires in 10 minutes)
    if (existing) {
      await existing.update({
        code,
        expires: new Date(Date.now() + 10 * 60 * 1000),
        attempts: existing.attempts + 1,
        rateLimit: new Date(Date.now() + 10 * 60 * 1000)
      });
    } else {
      await AuthCode.create({
        email,
        code,
        expires: new Date(Date.now() + 10 * 60 * 1000),
        attempts: 1,
        rateLimit: new Date(Date.now() + 10 * 60 * 1000)
      });
    }

    // Send email
    const sent = await sendVerificationCode(email, code);

    if (sent || !RESEND_API_KEY) {
      // In dev mode without email, log the code
      if (!RESEND_API_KEY) {
        console.log(`[DEV] Verification code for ${email}: ${code}`);
      }
      res.json({ success: true });
    } else {
      res.status(500).json({ success: false, error: 'Failed to send email' });
    }
  } catch (error) {
    console.error('Send code error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Verify code
app.post('/api/auth/verify-code', async (req, res) => {
  try {
    const { email, code } = req.body;

    const stored = await AuthCode.findByPk(email);

    if (!stored || new Date() > stored.expires) {
      return res.status(400).json({ success: false, error: 'Code expired. Please request a new one.' });
    }

    if (stored.code !== code) {
      return res.status(400).json({ success: false, error: 'Invalid code' });
    }

    // Code is valid - clear it
    await stored.destroy();

    // Generate auth token
    const token = uuidv4();
    await Session.create({
      token,
      email,
      expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
    });

    res.json({ success: true, token });
  } catch (error) {
    console.error('Verify code error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Get user orders
app.get('/api/user/orders', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const session = await Session.findByPk(token);
  if (!session || new Date() > session.expires) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  // Use case-insensitive email matching
  const userOrdersList = await Order.findAll({
    where: sequelize.where(
      sequelize.fn('LOWER', sequelize.col('email')),
      session.email.toLowerCase()
    ),
    order: [['createdAt', 'DESC']]
  });

  res.json({ success: true, orders: userOrdersList });
});

// Subscribe to order notifications
app.post('/api/order/:id/subscribe', async (req, res) => {
  const { id } = req.params;
  const { email } = req.body;

  const order = await Order.findByPk(id);
  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  // Update order with email
  await order.update({ email });

  // Send confirmation email
  await sendOrderCreatedEmail(order, email);

  res.json({ success: true });
});

// Validate wallet address
app.post('/api/validate-address', (req, res) => {
  const { address, currency } = req.body;

  if (!address || !currency) {
    return res.status(400).json({ valid: false, error: 'Missing address or currency' });
  }

  const valid = validateWalletAddress(address, currency);
  res.json({ valid, currency });
});

// ============================================
// PUBLIC API ROUTES
// ============================================

// Get available currencies from FixedFloat
app.get('/api/currencies', async (req, res) => {
  try {
    const result = await ffApiRequest('ccies', {});
    res.json(result);
  } catch {
    res.status(500).json({ error: 'Failed to fetch currencies' });
  }
});

// Get exchange rate with AstroShift markup
app.post('/api/price', async (req, res) => {
  try {
    const { fromCcy, toCcy, amount, direction, type } = req.body;

    // Check if source is fiat
    const isFiat = ['CASHAPP', 'ZELLE', 'PAYPAL'].includes(fromCcy.toUpperCase());

    if (isFiat) {
      // For fiat, try different USDT types as bridge currency
      const usdtOptions = ['USDTETH', 'USDT', 'USDTTRC20', 'USDTBSC'];
      let result = null;

      for (const usdtType of usdtOptions) {
        result = await ffApiRequest('price', {
          fromCcy: usdtType,
          toCcy: toCcy,
          amount: amount,
          direction: direction || 'from',
          type: type || 'fixed'
        });

        if (result.code === 0) break;
      }

      if (result && result.code === 0) {
        // Apply our fiat processing fee
        const adjustedAmount = applyAstroShiftFee(parseFloat(result.data.to.amount), true);
        result.data.to.amount = adjustedAmount.toFixed(8);
        result.data.astroShiftFee = config.fees.astroShiftMarkup + config.fees.fiatProcessingFee;
      }

      res.json(result);
    } else {
      // Crypto to crypto - use FixedFloat directly with our affiliate fee
      const result = await ffApiRequest('price', {
        fromCcy: fromCcy,
        toCcy: toCcy,
        amount: amount,
        direction: direction || 'from',
        type: type || 'fixed',
        afftax: config.fees.astroShiftMarkup // Add our 1% markup
      });

      if (result.code === 0) {
        result.data.astroShiftFee = config.fees.astroShiftMarkup;
      }

      res.json(result);
    }
  } catch (error) {
    console.error('Price API error:', error);
    res.status(500).json({ error: 'Failed to get price quote' });
  }
});

// Create exchange order
app.post('/api/order/create', async (req, res) => {
  try {
    const { fromCcy, toCcy, amount, toAddress, type, email } = req.body;

    const isFiat = ['CASHAPP', 'ZELLE', 'PAYPAL'].includes(fromCcy.toUpperCase());

    // Validate wallet address
    if (!validateWalletAddress(toAddress, toCcy)) {
      return res.status(400).json({
        error: `Invalid ${toCcy} wallet address`
      });
    }

    // Minimum $5 for fiat payments
    if (isFiat && parseFloat(amount) < 5) {
      return res.status(400).json({
        error: 'Minimum amount for fiat payments is $5.00'
      });
    }

    if (isFiat) {
      // Create internal fiat order
      const paymentMethod = fromCcy.toLowerCase();
      const methodConfig = config.paymentMethods[paymentMethod];

      if (!methodConfig || !methodConfig.enabled) {
        return res.status(400).json({
          error: `${methodConfig?.displayName || fromCcy} is currently disabled`
        });
      }

      // Try to get the crypto amount they'll receive using USDT as bridge
      // FixedFloat uses different USDT tickers - try the most common ones
      const usdtOptions = ['USDTETH', 'USDT', 'USDTTRC20', 'USDTBSC'];
      let priceResult = null;


      for (const usdtType of usdtOptions) {
        console.log(`Trying USDT type: ${usdtType}`);
        priceResult = await ffApiRequest('price', {
          fromCcy: usdtType,
          toCcy: toCcy,
          amount: amount,
          direction: 'from',
          type: type || 'fixed'
        });

        console.log(`FixedFloat price response for ${usdtType}:`, JSON.stringify(priceResult));

        if (priceResult.code === 0) {
          // usedUsdtType = usdtType;
          break;
        }
      }

      if (!priceResult || priceResult.code !== 0) {
        const errorMsg = priceResult?.msg || priceResult?.error || 'Unable to get exchange rate. Please try a different cryptocurrency.';
        console.error('FixedFloat price error:', errorMsg);
        return res.status(400).json({ error: errorMsg });
      }

      const adjustedAmount = applyAstroShiftFee(parseFloat(priceResult.data.to.amount), true);

      // Create internal order
      const orderId = uuidv4();
      const orderData = {
        id: orderId,
        type: 'fiat-to-crypto',
        status: 'awaiting_payment',
        fromCcy: fromCcy.toUpperCase(),
        toCcy: toCcy,
        fromAmount: amount,
        toAmount: adjustedAmount.toFixed(8),
        toAddress: toAddress,
        paymentMethod: paymentMethod,
        paymentInfo: {
          type: paymentMethod,
          destination: paymentMethod === 'cashapp' ? methodConfig.cashtag : methodConfig.email
        },
        expiresAt: new Date(Date.now() + 30 * 60 * 1000), // 30 min expiry
        transactionId: null,
        ffOrderId: null,
        email: email || null
      };

      const order = await Order.create(orderData);

      res.json({
        code: 0,
        data: {
          id: orderId,
          type: order.type,
          status: order.status,
          from: {
            currency: order.fromCcy,
            amount: order.fromAmount
          },
          to: {
            currency: order.toCcy,
            amount: order.toAmount,
            address: order.toAddress
          },
          payment: order.paymentInfo,
          expiresAt: order.expiresAt
        }
      });

      // Send email notification if provided
      if (email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        sendOrderCreatedEmail(order, email);
      }

    } else {
      // Crypto to crypto - create order on FixedFloat
      const result = await ffApiRequest('create', {
        fromCcy: fromCcy,
        toCcy: toCcy,
        amount: amount,
        toAddress: toAddress,
        type: type || 'fixed',
        afftax: config.fees.astroShiftMarkup
      });

      if (result.code === 0) {
        // Store order reference
        const orderId = result.data.id;
        const orderData = {
          id: orderId,
          type: 'crypto-to-crypto',
          ffOrderId: orderId,
          status: result.data.status,
          fromCcy: fromCcy,
          toCcy: toCcy,
          fromAmount: result.data.from?.amount || amount,
          toAmount: result.data.to?.amount,
          toAddress: toAddress,
          email: email || null
        };
        const order = await Order.create(orderData);

        // Send email notification if provided
        if (email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          sendOrderCreatedEmail(order, email);
        }
      }

      res.json(result);
    }
  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// Get order status
app.get('/api/order/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const order = await Order.findByPk(id);

    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    if (order.type === 'crypto-to-crypto' && order.ffOrderId) {
      // Fetch status from FixedFloat
      const result = await ffApiRequest('order', { id: order.ffOrderId });
      if (result.code === 0) {
        await order.update({ status: result.data.status });

        // Emit update to room
        io.to(order.id).emit('order_update', {
          status: result.data.status,
          updatedAt: new Date()
        });
      }
      res.json(result);
    } else {
      // Return internal order status
      res.json({
        code: 0,
        data: order
      });
    }
  } catch {
    res.status(500).json({ error: 'Failed to get order status' });
  }
});

// Submit payment confirmation (for fiat orders)
app.post('/api/order/:id/confirm-payment', async (req, res) => {
  try {
    const { id } = req.params;
    const { transactionId } = req.body;

    const order = await Order.findByPk(id);

    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    if (order.type !== 'fiat-to-crypto') {
      return res.status(400).json({ error: 'This order does not require payment confirmation' });
    }

    await order.update({
      transactionId,
      status: 'payment_submitted',
      paymentSubmittedAt: new Date()
    });

    res.json({
      code: 0,
      message: 'Payment confirmation submitted. Your order is being processed.',
      data: order
    });
  } catch {
    res.status(500).json({ error: 'Failed to confirm payment' });
  }
});

// Get enabled payment methods (public)
app.get('/api/payment-methods', (req, res) => {
  const methods = {};
  for (const [key, value] of Object.entries(config.paymentMethods)) {
    if (value.enabled) {
      methods[key] = {
        displayName: value.displayName,
        type: key === 'cashapp' ? 'cashtag' : 'email'
      };
    }
  }
  res.json(methods);
});

// ============================================
// ADMIN API ROUTES
// ============================================

// Admin login page (serve HTML)
app.get(`/${config.admin.secretPath}`, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin', 'login.html'));
});

// Admin dashboard (serve HTML)
app.get(`/${config.admin.secretPath}/dashboard`, (req, res) => {
  if (!req.session.isAdmin) {
    return res.redirect(`/${config.admin.secretPath}`);
  }
  res.sendFile(path.join(__dirname, 'admin', 'dashboard.html'));
});

// Admin login API
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;

  if (username === config.admin.username) {
    const isValid = await bcrypt.compare(password, config.admin.passwordHash);
    if (isValid) {
      req.session.isAdmin = true;
      return res.json({ success: true, redirect: `/${config.admin.secretPath}/dashboard` });
    }
  }

  res.status(401).json({ error: 'Invalid credentials' });
});

// Admin logout
app.post('/api/admin/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Get current config (admin only)
app.get('/api/admin/config', requireAdmin, (req, res) => {
  // Don't send sensitive data
  const safeConfig = {
    fees: config.fees,
    paymentMethods: config.paymentMethods,
    fixedFloat: {
      apiKey: config.fixedFloat.apiKey ? '••••••••' + config.fixedFloat.apiKey.slice(-4) : '',
      hasSecret: !!config.fixedFloat.apiSecret
    }
  };
  res.json(safeConfig);
});

// Update payment methods (admin only)
app.put('/api/admin/payment-methods', requireAdmin, (req, res) => {
  const { paymentMethods } = req.body;

  for (const [key, value] of Object.entries(paymentMethods)) {
    if (config.paymentMethods[key]) {
      config.paymentMethods[key] = {
        ...config.paymentMethods[key],
        ...value
      };
    }
  }

  saveConfig();
  res.json({ success: true, paymentMethods: config.paymentMethods });
});

// Update FixedFloat API credentials (admin only)
app.put('/api/admin/ff-credentials', requireAdmin, (req, res) => {
  const { apiKey, apiSecret } = req.body;

  if (apiKey) config.fixedFloat.apiKey = apiKey;
  if (apiSecret) config.fixedFloat.apiSecret = apiSecret;

  saveConfig();
  res.json({ success: true });
});

// Update fees (admin only)
app.put('/api/admin/fees', requireAdmin, (req, res) => {
  const { astroShiftMarkup, fiatProcessingFee } = req.body;

  if (astroShiftMarkup !== undefined) config.fees.astroShiftMarkup = parseFloat(astroShiftMarkup);
  if (fiatProcessingFee !== undefined) config.fees.fiatProcessingFee = parseFloat(fiatProcessingFee);

  saveConfig();
  res.json({ success: true, fees: config.fees });
});

// Get all orders (admin only)
app.get('/api/admin/orders', requireAdmin, async (req, res) => {
  const { status, type, limit = 50 } = req.query;

  const where = {};
  if (status) where.status = status;
  if (type) where.type = type;

  const orderList = await Order.findAll({
    where,
    order: [['createdAt', 'DESC']],
    limit: parseInt(limit)
  });

  res.json(orderList);
});

// Update order status (admin only)
app.put('/api/admin/orders/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { status, notes } = req.body;

  const order = await Order.findByPk(id);
  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }

  const updates = { updatedAt: new Date() };
  if (status) updates.status = status;
  if (notes) updates.adminNotes = notes;

  // If approving a fiat order, we need to execute the crypto send
  if (status === 'approved' && order.type === 'fiat-to-crypto' && !order.ffOrderId) {
    try {
      // Create the actual FixedFloat order to send crypto
      const ffResult = await ffApiRequest('create', {
        fromCcy: 'USDTTRC20', // We send USDT
        toCcy: order.toCcy,
        amount: order.toAmount,
        toAddress: order.toAddress,
        type: 'fixed'
      });

      if (ffResult.code === 0) {
        updates.ffOrderId = ffResult.data.id;
        updates.ffDepositAddress = ffResult.data.from.address;
        updates.status = 'processing';
      } else {
        updates.status = 'error';
        // We can't easily add errorMessage to the model without migration, so we log it
        console.error('FixedFloat error:', ffResult.msg);
        updates.adminNotes = (updates.adminNotes || '') + `\nError: ${ffResult.msg}`;
      }
    } catch (error) {
      updates.status = 'error';
      updates.adminNotes = (updates.adminNotes || '') + `\nError: ${error.message}`;
    }
  }

  await order.update(updates);
  res.json({ success: true, order });
});

// Change admin password (admin only)
app.put('/api/admin/password', requireAdmin, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  const isValid = await bcrypt.compare(currentPassword, config.admin.passwordHash);
  if (!isValid) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }

  config.admin.passwordHash = await bcrypt.hash(newPassword, 10);
  saveConfig();

  res.json({ success: true });
});

// ============================================
// INITIALIZE & START SERVER
// ============================================

async function initialize() {
  // If no password hash exists, create default (admin/admin)
  if (config.admin.passwordHash === '$2b$10$placeholder') {
    config.admin.passwordHash = await bcrypt.hash('admin123', 10);
    saveConfig();
    console.log('⚠️  Default admin password set: admin123');
    console.log('⚠️  Please change this immediately!');
  }
}

initialize().then(async () => {
  try {
    await sequelize.sync();
    console.log('📦 Database synced');
  } catch (err) {
    console.error('❌ Database sync failed:', err);
  }

  // Socket.io connection
  io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    socket.on('join_order', (orderId) => {
      socket.join(orderId);
      console.log(`Socket ${socket.id} joined order room: ${orderId}`);
    });

    socket.on('disconnect', () => {
      console.log('Client disconnected:', socket.id);
    });
  });

  server.listen(PORT, () => {
    console.log(`🚀 AstroShift server running on port ${PORT}`);
    console.log(`📍 Admin panel: http://localhost:${PORT}/${config.admin.secretPath}`);
  });
});
