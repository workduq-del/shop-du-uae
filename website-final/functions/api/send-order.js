const json = (status, body) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

async function encryptPayload(value, secret) {
  const encoder = new TextEncoder();

  // Create a 256-bit key from the server-side secret.
  const keyBytes = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(secret)
  );

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  // AES-GCM uses a 12-byte random IV.
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, tagLength: 128 },
    key,
    encoder.encode(JSON.stringify(value))
  );

  // Web Crypto appends the 16-byte authentication tag.
  // Separate it to preserve your original email format.
  const encrypted = new Uint8Array(encryptedBuffer);
  const ciphertext = encrypted.slice(0, encrypted.length - 16);
  const authTag = encrypted.slice(encrypted.length - 16);

  return {
    algorithm: "AES-256-GCM",
    iv: toBase64(iv),
    authTag: toBase64(authTag),
    ciphertext: toBase64(ciphertext)
  };
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[ch]));
}

export async function onRequestPost({ request, env }) {
  const {
    RESEND_API_KEY,
    ORDER_NOTIFICATION_EMAIL,
    RESEND_FROM_EMAIL,
    ORDER_ENCRYPTION_SECRET
  } = env;

  if (
    !RESEND_API_KEY ||
    !ORDER_NOTIFICATION_EMAIL ||
    !RESEND_FROM_EMAIL ||
    !ORDER_ENCRYPTION_SECRET
  ) {
    return json(500, {
      ok: false,
      error: "Order notifications are not configured on the server."
    });
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(400, {
      ok: false,
      error: "Invalid request."
    });
  }

  const order = body && body.order;

  if (!order || typeof order !== "object" || Array.isArray(order)) {
    return json(400, {
      ok: false,
      error: "Missing order details."
    });
  }

  const customerName = String(order.fullName || "").trim().slice(0, 160);
  const customerPhone = String(order.mobileNumber || "").trim().slice(0, 40);
  const reference = String(order.orderReference || "").trim().slice(0, 40);

  if (!customerName || !customerPhone || !reference) {
    return json(400, {
      ok: false,
      error: "Customer name, phone number and order reference are required."
    });
  }

  // Never encrypt, store or email payment-card credentials.
  const safeOrder = { ...order };

  for (const key of Object.keys(safeOrder)) {
    if (/card|cvv|cvc|security.?code|pan/i.test(key)) {
      delete safeOrder[key];
    }
  }

  let encrypted;
  try {
    encrypted = await encryptPayload(safeOrder, ORDER_ENCRYPTION_SECRET);
  } catch (error) {
    console.error("Encryption failed:", error.message);
    return json(500, {
      ok: false,
      error: "Could not securely process the order."
    });
  }

  const encryptedText = JSON.stringify(encrypted, null, 2);

  const html = `
    <h2>New DU Store order notification</h2>
    <p><strong>Customer:</strong> ${escapeHtml(customerName)}</p>
    <p><strong>Phone:</strong> ${escapeHtml(customerPhone)}</p>
    <p><strong>Reference ID:</strong> ${escapeHtml(reference)}</p>
    <p>The order payload below is encrypted with AES-256-GCM.
    It does not contain card number, expiry or CVV.</p>
    <pre style="white-space:pre-wrap;word-break:break-all;background:#f4f4f4;padding:12px">${escapeHtml(encryptedText)}</pre>
  `;

  try {
    const resendResponse = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: RESEND_FROM_EMAIL,
        to: [ORDER_NOTIFICATION_EMAIL],
        subject: `DU Store order ${reference}`,
        html
      })
    });

    if (!resendResponse.ok) {
      const errorText = await resendResponse.text();

      console.error(
        "Resend request failed:",
        resendResponse.status,
        errorText.slice(0, 500)
      );

      return json(502, {
        ok: false,
        error: "Email delivery failed. Please try again later."
      });
    }

    return json(200, {
      ok: true,
      reference
    });

  } catch (error) {
    console.error("Resend connection error:", error.message);

    return json(502, {
      ok: false,
      error: "Email service is temporarily unavailable."
    });
  }
}