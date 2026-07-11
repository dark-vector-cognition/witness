import { proxyControl } from "../_proxy";

export async function POST(request: Request) {
  return proxyControl(request, "approvals");
}
