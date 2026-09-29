import { Env } from "./env.d";
import { findTokenOwner } from "./db.tokens";
import { bumpUserApiCalls } from "./db";

export async function authFromApiToken(env: Env, req: Request) {
    const authHeader = req.headers.get("authorization") || "";
    const bearerMatch = /^Bearer\s+(.+)$/.exec(authHeader);
    if (!bearerMatch) return null;
    const apiToken = bearerMatch[1].trim();
    const owner = await findTokenOwner(env, apiToken);
    if (!owner) return null;
    // Compteur d'appels API (best-effort, ne doit pas bloquer la requête)
    try { await bumpUserApiCalls(env, owner.user_id); } catch { }
    return { user_id: owner.user_id, role: owner.role };
}