import { NextRequest, NextResponse } from 'next/server';
import { BUILTIN_FALCO_RULES, validateFalcoRule } from 'vigilante_lib/engine/falco.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const denied = await authorizeRequest(req, 'telemetry:read');
  if (denied) return denied;

  try {
    const { searchParams } = new URL(req.url);
    const priority = searchParams.get('priority');

    let rules = BUILTIN_FALCO_RULES;
    if (priority) {
      rules = rules.filter(r => r.priority.toUpperCase() === priority.toUpperCase());
    }

    return NextResponse.json({
      success: true,
      count: rules.length,
      rules
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  const denied = await authorizeRequest(req, 'telemetry:write');
  if (denied) return denied;

  try {
    const body = await req.json();

    const validation = validateFalcoRule(body);

    return NextResponse.json({
      success: true,
      valid: validation.valid,
      errors: validation.errors
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 400 });
  }
}
