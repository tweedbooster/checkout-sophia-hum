const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Domínios autorizados para evitar ataques de Card Testing de outras origens
const ALLOWED_ORIGINS = ['https://pay.seoloja.store', 'http://localhost:3000', 'http://127.0.0.1:5500'];

// Memória temporária para Rate Limiting (Bloqueia Bots)
const ipRequests = new Map();

export default async function handler(req, res) {
  const origin = req.headers.origin;
  
  // Rate Limiter: Pega o IP real do usuário através da Vercel
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 60 * 1000; // Janela de 1 minuto
  const maxRequests = 7; // Máximo de 7 tentativas de checkout por IP por minuto

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
    // Bloqueia tentativas de outras origens (CORS estrito)
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
    const { amount, metadata } = req.body;

    // VULNERABILITY FIX: Validação robusta de Tipos e Limites
    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount < 1.00 || parsedAmount > 500000) {
      return res.status(400).json({ error: 'Invalid amount. Must be between 1.00 and 500,000.00' });
    }

    // Converte o valor para centavos (Stripe exige assim. Ex: $50 vira 5000)
    const amountInCents = Math.round(parsedAmount * 100);

    // Cria o PaymentIntent
    const paymentIntent = await stripe.paymentIntents.create({
      amount: amountInCents,
      currency: 'usd',
      // automatic_payment_methods liga Apple Pay, Google Pay e Cartão automaticamente
      automatic_payment_methods: {
        enabled: true,
      },
      // Injeta os dados das UTMs para o UTMify ler no Webhook
      metadata: metadata || {},
    });

    res.status(200).json({
      clientSecret: paymentIntent.client_secret,
    });
  } catch (error) {
    console.error('Erro no Stripe:', error);
    res.status(500).json({ error: error.message });
  }
}
