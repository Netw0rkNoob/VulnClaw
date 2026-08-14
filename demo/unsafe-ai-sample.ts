// unsafe-ai-sample.ts — intentionally vulnerable sample for VulnClaw code scan
import { OpenAI } from "openai";

const openai = new OpenAI({
  apiKey: "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcd", // L1: hardcoded secret
});

export function renderUserProfile(userInput: string): string {
  const container = document.getElementById("profile")!;
  container.innerHTML = userInput; // L2: DOM XSS
  return container.innerHTML;
}

export async function queryDatabase(userId: string) {
  const query = "SELECT * FROM users WHERE id = '" + userId + "'"; // L2: SQL injection
  return db.run(query);
}

export function runCommand(userCmd: string) {
  const { exec } = require("child_process");
  exec(userCmd); // L2: command injection
}

export async function fetchFromUrl(targetUrl: string) {
  const resp = await fetch(targetUrl); // L2: SSRF
  return resp.json();
}
