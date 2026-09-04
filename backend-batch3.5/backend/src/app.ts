import express, { NextFunction, Request, Response } from "express";
import cors from "cors";
import multer from "multer";
import { healthRouter } from "./routes/health";
import { emailsRouter } from "./routes/emails";
import { gmailRouter } from "./routes/gmail";
import { ApiError } from "./utils/apiError";
import type { ApiErrorBody } from "./schemas/types";

export function createApp() {
  const app = express();

  // Batch 7 hardening: don't advertise the framework, and apply two
  // zero-dependency, low-risk safe headers appropriate for a JSON API.
  app.disable("x-powered-by");
  app.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    next();
  });

  // Default cors() reflects the requesting Origin — enough for local Vite
  // (typically :5173) talking to this API (typically :4000). Optional
  // CORS_ORIGINS is a comma-separated allow-list for tighter setups;
  // never hard-code a production domain here. A Vite proxy is also fine:
  //   // vite.config.ts
  //   server: { proxy: { "/api": "http://localhost:4000" } }
  const originList = (process.env.CORS_ORIGINS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  app.use(originList.length > 0 ? cors({ origin: originList }) : cors());
  app.use(express.json({ limit: "1mb" })); // JSON bodies only; .eml uploads go through multer

  app.use("/api/v1", healthRouter);
  app.use("/api/v1", emailsRouter);
  app.use("/api/v1", gmailRouter);

  app.get("/", (_req, res) => {
    res.status(200).json({ service: "sih26106-backend", ok: true });
  });

  app.use((_req, res) => {
    const body: ApiErrorBody = {
      error: { code: "NOT_FOUND", message: "Route not found." },
    };
    res.status(404).json(body);
  });

  // Centralized error handler — every route throws ApiError or a plain
  // Error; nothing here ever leaks a stack trace to the client.
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof ApiError) {
      const body: ApiErrorBody = { error: { code: err.code, message: err.message } };
      return res.status(err.status).json(body);
    }
    if (err instanceof multer.MulterError) {
      // Batch 7: the spec's expected status for an oversized upload is
      // 413 Payload Too Large, not a generic 400 — every other multer
      // failure (wrong field name, too many files, etc.) stays 400.
      const status = err.code === "LIMIT_FILE_SIZE" ? 413 : 400;
      const body: ApiErrorBody = { error: { code: "UPLOAD_ERROR", message: err.message } };
      return res.status(status).json(body);
    }
    if (err instanceof Error) {
      // Batch 7 hardening: an unclassified Error reaching here means
      // some code path threw without going through our own ApiError
      // convention — its .message could reference internals (a file
      // path, a raw parser error, etc.), so it's logged server-side
      // for diagnosis but never echoed to the client verbatim.
      console.error("Unclassified error:", err);
      const body: ApiErrorBody = {
        error: { code: "BAD_REQUEST", message: "The request could not be processed." },
      };
      return res.status(400).json(body);
    }
    console.error("Unhandled error:", err);
    const body: ApiErrorBody = {
      error: { code: "INTERNAL_ERROR", message: "Something went wrong processing the request." },
    };
    return res.status(500).json(body);
  });

  return app;
}
