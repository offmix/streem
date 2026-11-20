
const OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions";

const corsHeaders = {
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "86400"
};

function cors(origin) {
  const allowed =
    origin === "https://script.google.com" ||
    origin.endsWith(".googleusercontent.com");

  return allowed
    ? { ...corsHeaders, "Access-Control-Allow-Origin": origin, "Vary": "Origin" }
    : corsHeaders;
}

function json(data, status, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

function base64UrlToBytes(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function verifySignature(payload, signature, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  return crypto.subtle.verify(
    "HMAC",
    key,
    base64UrlToBytes(signature),
    new TextEncoder().encode(payload)
  );
}

async function readTicket(body, env) {
  if (!body || typeof body.ticket !== "string" ||
      typeof body.signature !== "string") {
    throw new Error("認証情報がありません。");
  }

  if (body.ticket.length > 180000) {
    throw new Error("リクエストが大きすぎます。");
  }

  const valid = await verifySignature(
    body.ticket,
    body.signature,
    env.STREAM_SHARED_SECRET
  );

  if (!valid) throw new Error("認証に失敗しました。");

  let data;
  try {
    data = JSON.parse(
      new TextDecoder().decode(base64UrlToBytes(body.ticket))
    );
  } catch {
    throw new Error("認証データが不正です。");
  }

  const now = Math.floor(Date.now() / 1000);

  if (!Number.isInteger(data.exp) || data.exp < now || data.exp > now + 300) {
    throw new Error("認証の有効期限が切れています。");
  }

  if (!/^[a-zA-Z0-9_-]{16,100}$/.test(data.nonce || "")) {
    throw new Error("リクエストIDが不正です。");
  }

  if (!Number.isInteger(data.keyIndex) ||
      data.keyIndex < 1 || data.keyIndex > 8) {
    throw new Error("APIキー番号が不正です。");
  }

  if (typeof data.model !== "string" ||
      data.model.length > 160 ||
      !Array.isArray(data.messages) ||
      data.messages.length < 1 ||
      data.messages.length > 21) {
    throw new Error("リクエスト形式が不正です。");
  }

  for (const message of data.messages) {
    if (!message ||
        !["system", "user", "assistant"].includes(message.role) ||
        typeof message.content !== "string" ||
        message.content.length > 12000) {
      throw new Error("メッセージ形式が不正です。");
    }
  }

  return data;
}

function streamResponse(upstream, headers) {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  let buffer = "";
  let finished = false;

  const stream = new ReadableStream({
    async start(controller) {
      const emit = (data) => {
        controller.enqueue(
          encoder.encode("data: " + JSON.stringify(data) + "\n\n")
        );
      };

      try {
        const reader = upstream.body.getReader();

        while (true) {
          const { value, done } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });

          let boundary;
          while ((boundary = buffer.indexOf("\n")) !== -1) {
            let line = buffer.slice(0, boundary);
            buffer = buffer.slice(boundary + 1);

            line = line.replace(/\r$/, "");
            if (!line.startsWith("data:")) continue;

            const raw = line.slice(5).trim();
            if (!raw || raw === "[DONE]") continue;

            let packet;
            try {
              packet = JSON.parse(raw);
            } catch {
              continue;
            }

            if (packet.error) {
              throw new Error(
                packet.error.message || "OpenRouter APIエラー"
              );
            }

            const choice = packet.choices && packet.choices[0];
            const content = choice && choice.delta &&
              choice.delta.content;

            if (typeof content === "string" && content.length) {
              emit({ type: "delta", text: content });
            } else if (Array.isArray(content)) {
              for (const part of content) {
                if (part && typeof part.text === "string") {
                  emit({ type: "delta", text: part.text });
                }
              }
            }

            if (choice && choice.finish_reason) {
              emit({
                type: "finish",
                reason: choice.finish_reason
              });
            }
          }
        }

        if (buffer.trim().startsWith("data:")) {
          const raw = buffer.trim().slice(5).trim();
          if (raw && raw !== "[DONE]") {
            try {
              const packet = JSON.parse(raw);
              const content = packet.choices?.[0]?.delta?.content;
              if (typeof content === "string" && content) {
                emit({ type: "delta", text: content });
              }
            } catch {}
          }
        }

        emit({ type: "done" });
        finished = true;
        controller.close();
      } catch (error) {
        emit({
          type: "error",
          error: String(error.message || error).slice(0, 500)
        });
        finished = true;
        controller.close();
      }
    },

    cancel() {
      finished = true;
    }
  });

  return new Response(stream, {
    status: 200,
    headers: {
      ...headers,
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      "X-Accel-Buffering": "no"
    }
  });
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const headers = cors(origin);

    if (request.method === "OPTIONS") {
      if (
        origin !== "https://script.google.com" &&
        !origin.endsWith(".googleusercontent.com")
      ) {
        return new Response(null, { status: 403 });
      }

      return new Response(null, { status: 204, headers });
    }

    if (request.method !== "POST") {
      return json({ error: "POST only" }, 405, headers);
    }

    if (
      origin !== "https://script.google.com" &&
      !origin.endsWith(".googleusercontent.com")
    ) {
      return json({ error: "Origin not allowed" }, 403, headers);
    }

    if (!env.STREAM_SHARED_SECRET || !env.STREAM_TICKETS) {
      return json({ error: "Worker configuration missing" }, 500, headers);
    }

    try {
      const length = Number(request.headers.get("Content-Length") || 0);
      if (length > 2000000) {
        return json({ error: "Request too large" }, 413, headers);
      }

      const body = await request.json();
      const ticket = await readTicket(body, env);

      const replayKey = "ticket:" + ticket.nonce;
      const existing = await env.STREAM_TICKETS.get(replayKey);

      if (existing) {
        return json({ error: "このリクエストは既に使用されています。" }, 409, headers);
      }

      await env.STREAM_TICKETS.put(replayKey, "used", {
        expirationTtl: 360
      });

      const apiKey = env["OPENROUTER_API_KEY_" + ticket.keyIndex];

      if (!apiKey) {
        return json({ error: "指定されたAPIキーが設定されていません。" }, 503, headers);
      }

      const upstream = await fetch(OPENROUTER_URL, {
        method: "POST",
        headers: {
          "Authorization": "Bearer " + apiKey,
          "Content-Type": "application/json",
          "HTTP-Referer": "https://github.com/offmix/kai-chats-stream",
          "X-Title": "KAI-Chats NEXT"
        },
        body: JSON.stringify({
          model: ticket.model,
          messages: ticket.messages,
          temperature: 0.7,
          stream: true
        })
      });

      if (!upstream.ok) {
        const detail = (await upstream.text()).slice(0, 1000);
        return json({
          error: "OpenRouter HTTP " + upstream.status,
          detail
        }, upstream.status, headers);
      }

      if (!upstream.body) {
        return json({ error: "ストリームを取得できませんでした。" }, 502, headers);
      }

      return streamResponse(upstream, headers);

    } catch (error) {
      return json({
        error: String(error.message || error).slice(0, 500)
      }, 400, headers);
    }
  }
};
