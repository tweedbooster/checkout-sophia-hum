const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const ALLOWED_ORIGINS = ['https://pay.seoloja.store', 'http://localhost:3000', 'http://127.0.0.1:5500'];
const ipRequests = new Map();
export default async function handler(req, res) {
  const origin = req.headers.origin;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 60 * 1000;
  const maxRequests = 7;
  if (ip !== 'unknown') {
    const requestHistory = ipRequests.get(ip) || [];
    const recentRequests = requestHistory.filter(time => now - time < windowMs);
    if (recentRequests.length >= maxRequests) {
      console.warn(`[SECURITY] Bot bloqueado por Rate Limit. IP: ${ip}`);
      return res.status(429).json({ error: 'Demasiadas solicitudes. Por favor, inténtalo de nuevo en unos minutos.' });
    }
    recentRequests.push(now);
    ipRequests.set(ip, recentRequests);
  }
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', 'https://pay.seoloja.store'); 
  }
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Methods', 'OPTIONS,POST');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }
  try {
    const { amount, metadata, paymentIntentId } = req.body;
    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount < 1.00 || parsedAmount > 500000) {
      return res.status(400).json({ error: 'Invalid amount. Must be between 1.00 and 500,000.00' });
    }
    const amountInCents = Math.round(parsedAmount * 100);
    let paymentIntent;
    if (paymentIntentId) {
      paymentIntent = await stripe.paymentIntents.update(paymentIntentId, {
        amount: amountInCents,
        metadata: metadata || {},
        description: (metadata && metadata.order_bump === 'true') ? 'Order + Processing Fees' : 'Online Order',
      });
    } else {
      paymentIntent = await stripe.paymentIntents.create({
        amount: amountInCents,
        currency: 'usd',
        automatic_payment_methods: {
          enabled: true,
        },
        metadata: metadata || {},
        description: (metadata && metadata.order_bump === 'true') ? 'Order + Processing Fees' : 'Online Order',
      });
    }
    res.status(200).json({
      clientSecret: paymentIntent.client_secret,
    });
  } catch (error) {
    console.error('Erro no Stripe:', error);
    res.status(500).json({ error: error.message });
  }
}
