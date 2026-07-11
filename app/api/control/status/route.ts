import { proxyControl } from "../_proxy";

export async function GET(request: Request) {
  return proxyControl(request, "status");
}
