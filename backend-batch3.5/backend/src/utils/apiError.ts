// Structured error type thrown by routes/services. The central error
// handler in server.ts converts these to the { error: { code, message } }
// shape and picks the right HTTP status — routes never build error JSON
// by hand, and no internal detail (stack traces, file paths) ever
// reaches the response body.

export class ApiError extends Error {
  code: string;
  status: number;

  constructor(code: string, message: string, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export const Errors = {
  emailNotFound: (emailId: string) =>
    new ApiError(
      "EMAIL_NOT_FOUND",
      `The requested email could not be found: ${emailId}`,
      404
    ),
  missingFile: () =>
    new ApiError("MISSING_FILE", "Upload a .eml file under the 'file' field.", 400),
  emptyFile: () => new ApiError("EMPTY_FILE", "Uploaded file is empty.", 400),
  reportNotAvailable: (emailId: string) =>
    new ApiError(
      "REPORT_NOT_AVAILABLE",
      `No report has been generated yet for email: ${emailId}`,
      404
    ),
  invalidFilter: (message: string) => new ApiError("INVALID_FILTER", message, 400),
  invalidPagination: (message: string) => new ApiError("INVALID_PAGINATION", message, 400),
  // Batch 7 hardening — a route param that doesn't even look like an
  // emailId/caseId (wrong characters, empty, unreasonably long) is
  // rejected outright with a clean 400 instead of being silently
  // stripped down to a different string by storage-layer sanitization
  // and then 404ing. Keeps the raw value out of error messages too.
  invalidEmailId: () =>
    new ApiError("INVALID_EMAIL_ID", "emailId must be a non-empty alphanumeric/hyphen string.", 400),
  invalidFileType: () =>
    new ApiError("INVALID_FILE_TYPE", "Only .eml files are accepted.", 400),
  // A stored record that fails to parse (corrupted/truncated JSON on
  // disk) is a server-side storage problem, not something the client
  // did wrong — never echo the raw parse error (which could reference
  // internal file structure) to the client.
  recordUnreadable: (emailId: string) =>
    new ApiError(
      "RECORD_UNREADABLE",
      `The stored record for ${emailId} could not be read. It may be corrupted.`,
      500
    ),
};
