# AstroShift.io - Cryptocurrency Exchange Platform

A full-featured cryptocurrency exchange platform with fiat-to-crypto support via Cash App, Zelle, and PayPal, plus crypto-to-crypto exchanges powered by FixedFloat API.

## Features

- **Fiat-to-Crypto Exchange**: Accept payments via Cash App, Zelle, and PayPal
- **Crypto-to-Crypto Exchange**: Powered by FixedFloat API with your markup
- **Admin Panel**: Hidden URL with secure login
- **Order Management**: Track and approve orders
- **Configurable Fees**: Set your own markup percentage
- **Real-time Pricing**: Live rates from FixedFloat

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Settings

Edit `config/config.json`:

```json
{
  "admin": {
    "username": "admin",
    "secretPath": "your-secret-admin-path"
  },
  "fixedFloat": {
    "apiKey": "YOUR_FF_API_KEY",
    "apiSecret": "YOUR_FF_API_SECRET"
  },
  "fees": {
    "astroShiftMarkup": 1.0,
    "fiatProcessingFee": 5.5
  }
}
```

### 3. Start the Server

```bash
npm start
```

The server will run on `http://localhost:3000`

## Admin Panel Access

- **URL**: `http://localhost:3000/ctrl-panel-x7k9m2` (change `secretPath` in config)
- **Default Login**: `admin` / `admin123`
- **⚠️ IMPORTANT**: Change the password immediately after first login!

## Admin Panel Features

### Dashboard
- View order statistics
- Monitor pending/processing orders
- Quick access to recent orders

### Payment Methods
- Enable/disable Cash App, Zelle, PayPal
- Configure your payment addresses/emails
- Toggle methods on/off instantly

### Orders
- View all orders with filtering
- Approve fiat payments
- Track order status
- View transaction details

### Settings
- Update FixedFloat API credentials
- Adjust fee percentages
- Change admin password

## How It Works

### Fiat-to-Crypto Flow

1. User selects Cash App/Zelle/PayPal → Crypto
2. User enters amount and wallet address
3. System creates order with your payment info
4. User sends payment and enters transaction ID
5. **You verify payment in admin panel**
6. Approve order → System executes crypto transfer via FixedFloat
7. Crypto sent to user's wallet

### Crypto-to-Crypto Flow

1. User selects crypto pair
2. System gets rate from FixedFloat (+ your 1% markup)
3. Order created on FixedFloat
4. User sends crypto to deposit address
5. FixedFloat processes exchange automatically
6. User receives crypto

## API Endpoints

### Public

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/currencies` | GET | Get available currencies |
| `/api/price` | POST | Get exchange rate quote |
| `/api/order/create` | POST | Create new order |
| `/api/order/:id` | GET | Get order status |
| `/api/order/:id/confirm-payment` | POST | Confirm fiat payment |
| `/api/payment-methods` | GET | Get enabled payment methods |

### Admin (requires authentication)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/login` | POST | Admin login |
| `/api/admin/logout` | POST | Admin logout |
| `/api/admin/config` | GET | Get current config |
| `/api/admin/payment-methods` | PUT | Update payment methods |
| `/api/admin/ff-credentials` | PUT | Update FixedFloat API |
| `/api/admin/fees` | PUT | Update fee settings |
| `/api/admin/orders` | GET | Get all orders |
| `/api/admin/orders/:id` | PUT | Update order status |
| `/api/admin/password` | PUT | Change admin password |

## FixedFloat API Setup

1. Go to [ff.io](https://ff.io) and create an account
2. Navigate to the API section
3. Generate your API Key and API Secret
4. Enter these in the admin panel Settings page

## Fee Structure

- **FixedFloat Base Fee**: 1% (fixed) or 0.5% (float)
- **Your Markup** (`astroShiftMarkup`): Default 1% (configurable)
- **Fiat Processing Fee** (`fiatProcessingFee`): Default 5.5% (configurable)

Total fee for fiat: `astroShiftMarkup + fiatProcessingFee` = 6.5%
Total fee for crypto: `astroShiftMarkup` = 1% (on top of FF's fee)

## Security Recommendations

1. **Change default admin password immediately**
2. **Use a random, long string for `secretPath`**
3. **Enable HTTPS in production** (set `cookie.secure: true`)
4. **Use environment variables for sensitive config**
5. **Add rate limiting in production**
6. **Use a proper database instead of in-memory storage**

## Production Deployment

For production, you should:

1. Use a database (MongoDB, PostgreSQL) instead of in-memory orders
2. Add SSL/HTTPS
3. Set up proper session storage (Redis)
4. Add rate limiting
5. Set up monitoring and logging
6. Configure proper CORS settings
7. Use environment variables for secrets

## File Structure

```
astroshift/
├── server.js           # Main Express server
├── package.json        # Dependencies
├── config/
│   └── config.json     # Configuration file
├── admin/
│   ├── login.html      # Admin login page
│   └── dashboard.html  # Admin dashboard
└── public/
    ├── index.html      # Main exchange page
    └── order.html      # Order/checkout page
```

## Legal Notice

**Important**: Operating a money exchange service typically requires:
- Money Services Business (MSB) registration with FinCEN (USA)
- State money transmitter licenses
- KYC/AML compliance procedures
- PCI compliance for card payments

Consult with a compliance attorney before launching.

## Support

For issues with the FixedFloat API, refer to their documentation at [ff.io/api](https://ff.io/api)

---

Built with 💜 for AstroShift.io
