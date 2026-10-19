/**
 * API error envelope for Vigilante.
 * Every error response follows this shape:
 * { "error": { "code": "string_code", "message": "human readable", "reason": "optional_reason" } }
 * Also provides success: false fallback for backward-compatible consumers.
 */

export interface ApiError {
  code: string;
  message: string;
  reason?: string;
}

export interface ApiErrorBody {
  success: false;
  error: string;
  details?: ApiError;
}

export function errorBody(
  code: string,
  message: string,
  reason?: string
): ApiErrorBody {
  return {
    success: false,
    error: message,
    details: reason ? { code, message, reason } : { code, message }
  };
}

/** Stable code vocabulary for plain HTTP statuses */
export function codeForStatus(status: number): string {
  switch (status) {
    case 400:
      return 'bad_request';
    case 401:
      return 'unauthenticated';
    case 403:
      return 'forbidden';
    case 404:
      return 'not_found';
    case 409:
      return 'conflict';
    case 422:
      return 'unprocessable';
    case 500:
      return 'internal';
    default:
      return status >= 500 ? 'internal' : 'error';
  }
}

/**
 * Safely extract human-readable error message from arbitrary API response payload
 */
export function apiErrorMessage(data: unknown, fallback = 'Request failed'): string {
  if (data !== null && typeof data === 'object') {
    const err = (data as { error?: unknown }).error;
    if (typeof err === 'string' && err) return err;
    if (err !== null && typeof err === 'object') {
      const message = (err as { message?: unknown }).message;
      if (typeof message === 'string' && message) return message;
    }
    const details = (data as { details?: unknown }).details;
    if (details !== null && typeof details === 'object') {
      const message = (details as { message?: unknown }).message;
      if (typeof message === 'string' && message) return message;
    }
  }
  return fallback;
}
