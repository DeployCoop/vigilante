import { NextRequest, NextResponse } from 'next/server';
import { BUILTIN_FALCO_RULES, validateFalcoRule, parseFalcoRulesYaml } from 'vigilante_lib/engine/falco.js';
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

    if (typeof body.raw === 'string') {
      const parsedRules = parseFalcoRulesYaml(body.raw);
      if (!parsedRules || parsedRules.length === 0) {
        return NextResponse.json({
          success: true,
          valid: false,
          errors: ['Failed to parse Falco YAML or no rule definition found']
        });
      }
      const allErrors: string[] = [];
      for (const r of parsedRules) {
        const res = validateFalcoRule(r);
        if (!res.valid) {
          allErrors.push(...res.errors);
        }
      }
      return NextResponse.json({
        success: true,
        valid: allErrors.length === 0,
        errors: allErrors,
        parsedRules
      });
    }

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
