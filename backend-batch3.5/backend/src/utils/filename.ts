import { ApiError } from "./apiError";

// Storage paths are always built from our own generated emailId, never
// from the client-supplied filename — so this can't actually cause a
// path-traversal write. We still validate it, because (a) an unsafe
// filename is a signal worth rejecting outright in an untrusted-input
// pipeline, and (b) the filename is echoed back in API responses and
// forensic reports, so it must not carry control characters or
// traversal sequences into those contexts either.
export function assertSafeFilename(filename: string): void {
  if (!filename || filename.trim() === "") {
    throw new ApiError("UNSAFE_FILENAME", "Filename is missing or empty.", 400);
  }
  if (filename.includes("..")) {
    throw new ApiError("UNSAFE_FILENAME", "Filename must not contain '..'.", 400);
  }
  if (/[/\\]/.test(filename)) {
    throw new ApiError("UNSAFE_FILENAME", "Filename must not contain path separators.", 400);
  }
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f]/.test(filename)) {
    throw new ApiError("UNSAFE_FILENAME", "Filename must not contain control characters.", 400);
  }
  if (filename.length > 255) {
    throw new ApiError("UNSAFE_FILENAME", "Filename is too long.", 400);
  }
}
