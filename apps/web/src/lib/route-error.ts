import { NextResponse } from 'next/server';
import { AuthzInvariantError } from 'vigilante_lib/engine/authz.js';
import { codeForStatus, errorBody } from './envelope';

export class AuthzError extends Error {
  status: number;
  reason: string;

  constructor(status: number, message: string, reason: string) {
    super(message);
    this.name = 'AuthzError';
    this.status = status;
    this.reason = reason;
  }
}

interface ZodLikeError {
  issues: { path: (string | number)[]; message: string }[];
}

function isZodError(err: unknown): err is ZodLikeError {
  return (
    err instanceof Error &&
    err.name === 'ZodError' &&
    Array.isArray((err as { issues?: unknown }).issues)
  );
}

export interface RouteErrorOptions {
  route?: string;
  status?: number;
  code?: string;
  principalId?: string;
  fallbackMessage?: string;
}

export function routeError(err: unknown, opts: RouteErrorOptions = {}): NextResponse {
  let status = opts.status ?? 500;
  let code = opts.code;
  let reason: string | undefined;
  let message: string;

  if (err instanceof AuthzError) {
    status = err.status;
    code = opts.code ?? (err.status === 401 ? 'unauthenticated' : 'forbidden');
    reason = err.reason;
    message = err.message;
  } else if (err instanceof AuthzInvariantError) {
    status = 409;
    code = opts.code ?? 'conflict';
    reason = 'authz_invariant';
    message = err.message;
  } else if (isZodError(err)) {
    status = 400;
    code = opts.code ?? 'bad_request';
    const first = err.issues[0];
    message = first
      ? `${first.path.join('.') || 'body'}: ${first.message}`
      : 'Invalid request body';
  } else {
    message =
      status < 500 && err instanceof Error && err.message
        ? err.message
        : (opts.fallbackMessage ?? (err instanceof Error ? err.message : 'Internal server error'));
    code = opts.code ?? codeForStatus(status);
  }

  return NextResponse.json(errorBody(code, message, reason), { status });
}

export interface ApiErrorOptions {
  route?: string;
  code?: string;
  reason?: string;
  principalId?: string;
}

export function apiError(
  status: number,
  message: string,
  opts: ApiErrorOptions = {}
): NextResponse {
  const code = opts.code ?? codeForStatus(status);
  return NextResponse.json(errorBody(code, message, opts.reason), { status });
}
