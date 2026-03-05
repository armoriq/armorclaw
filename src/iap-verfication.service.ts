type LoggerLike = {
  debug?: (message: string) => void;
  info?: (message: string) => void;
  warn?: (message: string) => void;
  error?: (message: string) => void;
  log?: (message: string) => void;
};

export type CsrgProofHeaders = {
  path?: string;
  proof?: unknown;
  valueDigest?: string;
};

export type CsrgVerifyActionRequest = {
  path: string;
  value: unknown;
  proof: { position: string; sibling_hash: string }[];
  token: Record<string, unknown>;
  context?: Record<string, unknown>;
};

export type CsrgVerifyActionResponse = {
  allowed: boolean;
  reason: string;
  node_hash?: string;
  path?: string;
  merkle_root?: string;
};

export type VerifyStepResponse = {
  allowed: boolean;
  reason: string;
  verification_source?: string;
  node_hash?: string;
  csrg_path?: string;
  csrg_merkle_root?: string;
  step: {
    step_index: number;
    action: string;
    params: Record<string, unknown>;
  };
  execution_state: {
    plan_id: string;
    intent_reference: string;
    executed_steps: number[];
    current_step: number;
    total_steps: number;
    status: string;
    is_completed: boolean;
  };
};

export type CreateAuditLogDto = {
  token: string;
  plan_id?: string;
  step_index: number;
  action: string;
  tool: string;
  input: unknown;
  output: unknown;
  status: "success" | "failed";
  error_message?: string;
  duration_ms: number;
  executed_at: string;
  is_delegated?: boolean;
  delegated_by?: string;
  delegated_to?: string;
  delegation_token_id?: string;
};

export type AuditLogResponse = {
  audit_id: string;
  iap_audit_index?: number;
  iap_commitment?: string;
  iap_sync_status: string;
};

type IapVerificationOptions = {
  iapBaseUrl?: string;
  csrgBaseUrl?: string;
  requireCsrgProofs?: boolean;
  csrgVerifyEnabled?: boolean;
  timeoutMs?: number;
  logger?: LoggerLike;
};

type JsonResponse<T> = {
  ok: boolean;
  status: number;
  data: T | null;
  text: string;
};

// Production: https://customer-iap.armoriq.ai
const DEFAULT_CSRG_URL = "https://customer-iap.armoriq.ai";

function resolveIapBaseUrl(fallback?: string): string {
  const configured = process.env.IAP_BACKEND_URL || process.env.CONMAP_AUTO_URL;
  if (configured) {
    return configured;
  }
  if (fallback) {
    return fallback;
  }
  // Production: https://customer-api.armoriq.ai (Backend)
  return (process.env.NODE_ENV || "").toLowerCase() === "production"
    ? "https://customer-api.armoriq.ai"
    : "https://customer-api.armoriq.ai";
}

function resolveCsrgBaseUrl(fallback?: string): string {
  return fallback || process.env.CSRG_URL || DEFAULT_CSRG_URL;
}

function createLogger(logger?: LoggerLike): Required<LoggerLike> {
  const fallback = logger ?? {};
  const log = fallback.log ?? (() => {});
  return {
    debug: fallback.debug ?? fallback.info ?? log,
    info: fallback.info ?? log,
    warn: fallback.warn ?? log,
    error: fallback.error ?? log,
    log,
  };
}

async function postJson<T>(
  url: string,
  payload: Record<string, unknown>,
  timeoutMs: number,
): Promise<JsonResponse<T>> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    const text = await response.text();
    let data: T | null = null;
    if (text) {
      try {
        data = JSON.parse(text) as T;
      } catch {
        data = null;
      }
    }
    return {
      ok: response.ok,
      status: response.status,
      data,
      text,
    };
  } finally {
    clearTimeout(timeout);
  }
}

export class IAPVerificationService {
  private readonly logger: Required<LoggerLike>;
  private readonly iapBaseUrl: string;
  private readonly csrgBaseUrl: string;
  private readonly requireCsrgProofs: boolean;
  private readonly csrgVerifyEnabled: boolean;
  private readonly timeoutMs: number;

  constructor(options: IapVerificationOptions = {}) {
    this.logger = createLogger(options.logger);
    this.iapBaseUrl = resolveIapBaseUrl(options.iapBaseUrl);
    this.csrgBaseUrl = resolveCsrgBaseUrl(options.csrgBaseUrl);
    this.requireCsrgProofs =
      options.requireCsrgProofs ??
      (process.env.REQUIRE_CSRG_PROOFS ?? "true").toLowerCase() === "true";
    this.csrgVerifyEnabled =
      options.csrgVerifyEnabled ??
      (process.env.CSRG_VERIFY_ENABLED ?? "true").toLowerCase() !== "false";
    this.timeoutMs = options.timeoutMs ?? 30000;

    if (!options.iapBaseUrl && this.iapBaseUrl.includes("localhost")) {
      this.logger.warn(
        `IAP_BACKEND_URL not set; defaulting to local backend at ${this.iapBaseUrl}`,
      );
    }
    this.logger.info(`IAP Verification Service initialized - Base URL: ${this.iapBaseUrl}`);
    this.logger.info(`CSRG Verification URL: ${this.csrgBaseUrl}`);
    if (this.requireCsrgProofs) {
      this.logger.info("CSRG proof headers are REQUIRED for tool execution");
    }
    if (this.csrgVerifyEnabled) {
      this.logger.info("CSRG /verify/action is ENABLED for cryptographic verification");
    }
  }

  /**
   * Verify step with IAP service
   */
  async verifyStep(
    token: string,
    csrgProofs?: CsrgProofHeaders,
    toolName?: string,
  ): Promise<VerifyStepResponse> {
    this.logger.debug("Calling IAP verify-step endpoint...");

    const payload: Record<string, unknown> = { token };

    if (csrgProofs?.path) {
      payload.path = csrgProofs.path;
      const stepMatch = csrgProofs.path.match(/\/steps\/\[(\d+)\]/);
      if (stepMatch) {
        payload.step_index = Number.parseInt(stepMatch[1] ?? "0", 10);
      }
    }
    if (toolName) {
      payload.tool_name = toolName;
    }
    if (csrgProofs?.proof && Array.isArray(csrgProofs.proof)) {
      payload.proof = csrgProofs.proof;
    }
    if (csrgProofs?.valueDigest) {
      payload.context = {
        csrg_value_digest: csrgProofs.valueDigest,
        proof_source: "client",
      };
    }

    const response = await postJson<VerifyStepResponse>(
      `${this.iapBaseUrl}/iap/verify-step`,
      payload,
      this.timeoutMs,
    );

    if (response.ok && response.data) {
      this.logger.debug(
        `IAP verify-step responded: ${response.data.allowed ? "ALLOWED" : "DENIED"} reason=${response.data.reason}`,
      );
      return response.data;
    }

    if (response.data) {
      return response.data;
    }

    throw new Error(
      response.text
        ? `IAP verify-step failed: ${response.text}`
        : `IAP verify-step failed with status ${response.status}`,
    );
  }

  csrgProofsRequired(): boolean {
    return this.requireCsrgProofs;
  }

  csrgVerifyIsEnabled(): boolean {
    return this.csrgVerifyEnabled;
  }

  /**
   * Verify action directly with CSRG service using cryptographic Merkle proof
   * This is the CSRG-first verification path
   */
  async verifyWithCsrg(
    path: string,
    value: unknown,
    proof: { position: string; sibling_hash: string }[],
    token: Record<string, unknown>,
    context?: Record<string, unknown>,
  ): Promise<CsrgVerifyActionResponse> {
    if (!this.csrgVerifyEnabled) {
      throw new Error("CSRG verification is disabled");
    }

    this.logger.debug(`[CSRG] Calling /verify/action for path: ${path}`);

    const payload: CsrgVerifyActionRequest = {
      path,
      value,
      proof,
      token,
      context,
    };

    const response = await postJson<CsrgVerifyActionResponse>(
      `${this.csrgBaseUrl}/verify/action`,
      payload,
      Math.min(this.timeoutMs, 15000),
    );

    if (response.ok && response.data) {
      this.logger.info(
        `[CSRG] /verify/action responded: ${response.data.allowed ? "ALLOWED" : "DENIED"} reason=${response.data.reason}`,
      );
      return response.data;
    }

    if (response.data) {
      this.logger.error(`[CSRG] Error response: ${JSON.stringify(response.data)}`);
      return {
        allowed: false,
        reason:
          response.data.reason || `CSRG verification failed: ${response.text || "unknown error"}`,
      };
    }

    return {
      allowed: false,
      reason: response.text
        ? `CSRG verification failed: ${response.text}`
        : `CSRG verification failed with status ${response.status}`,
    };
  }

  /**
   * Create audit log in IAP service
   */
  async createAuditLog(dto: CreateAuditLogDto): Promise<AuditLogResponse> {
    this.logger.debug("Calling IAP audit endpoint...");
    this.logger.debug(`Payload: ${JSON.stringify(dto, null, 2)}`);

    const response = await postJson<AuditLogResponse>(
      `${this.iapBaseUrl}/iap/audit`,
      dto as unknown as Record<string, unknown>,
      this.timeoutMs,
    );

    if (!response.ok || !response.data) {
      const message = response.text
        ? `IAP audit creation failed: ${response.text}`
        : `IAP audit creation failed with status ${response.status}`;
      this.logger.error(message);
      throw new Error(message);
    }

    this.logger.info(`IAP audit log created: ${response.data.audit_id}`);
    return response.data;
  }
}
