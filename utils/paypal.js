const checkoutNodeJssdk = require('@paypal/checkout-server-sdk');

// Configuración del entorno (sandbox o live)
function environment() {
  const clientId = process.env.PAYPAL_CLIENT_ID;
  const clientSecret = process.env.PAYPAL_CLIENT_SECRET;
  return new checkoutNodeJssdk.core.SandboxEnvironment(clientId, clientSecret);
}

// Cliente PayPal
function client() {
  return new checkoutNodeJssdk.core.PayPalHttpClient(environment());
}

module.exports = {
  client,
  orders: checkoutNodeJssdk.orders,
};
