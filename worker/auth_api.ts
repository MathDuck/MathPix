import { Env } from "./env.d";
import { findTokenOwner } from "./db.tokens";

export async function authFromApiToken(env: Env, req: Request) {
    const authHeader = req.headers.get("authorization") || "";
    const bearerMatch = /^Bearer\s+(.+)$/.exec(authHeader);
    if (!bearerMatch) return null;
    const apiToken = bearerMatch[1].trim();
    const owner = await findTokenOwner(env, apiToken);
    if (!owner) return null;
    return { user_id: owner.user_id, role: owner.role };
}