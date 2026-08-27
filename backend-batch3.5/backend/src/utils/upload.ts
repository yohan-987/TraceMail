import multer from "multer";
import path from "path";

const MAX_UPLOAD_BYTES = Number(process.env.MAX_UPLOAD_BYTES ?? 5 * 1024 * 1024);

// Memory storage: we need the raw buffer immediately (for hashing) and
// don't want the original filename touching the filesystem at all —
// avoids path traversal / unsafe-filename issues entirely (Batch 7).
const storage = multer.memoryStorage();

function fileFilter(
  _req: unknown,
  file: Express.Multer.File,
  cb: multer.FileFilterCallback
) {
  const ext = path.extname(file.originalname).toLowerCase();
  // Don't trust the extension alone as proof of content, but do use it
  // as a first-pass reject for obviously wrong uploads.
  if (ext !== ".eml") {
    cb(new Error("Only .eml files are accepted"));
    return;
  }
  cb(null, true);
}

export const uploadEml = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: MAX_UPLOAD_BYTES,
    files: 1,
  },
});
