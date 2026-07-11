const serviceUrl = "http://127.0.0.1:4317";

export async function proxyControl(request: Request, endpoint: "status" | "approvals" | "controls") {
  try {
    const method = endpoint === "status" ? "GET" : "POST";
    const response = await fetch(`${serviceUrl}/${endpoint}`, {
      method,
      headers: method === "POST" ? { "Content-Type": "application/json" } : undefined,
      body: method === "POST" ? await request.text() : undefined,
      cache: "no-store",
      signal: AbortSignal.timeout(3_000),
    });
    return new Response(await response.text(), { status: response.status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ error: "loopback control service unavailable" }, { status: 503, headers: { "Cache-Control": "no-store" } });
  }
}
