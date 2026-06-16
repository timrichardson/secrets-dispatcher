import type {
  ActionResponse,
  AutoApproveRule,
  ErrorResponse,
  PendingListResponse,
  SavedApprovalRule,
  StatusResponse,
} from "./types";

const API_BASE = "/api/v1";

class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T | null> {
  const url = `${API_BASE}${path}`;
  const response = await fetch(url, {
    ...options,
    credentials: "include", // Include cookies
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (response.status === 401) {
    return null; // Unauthenticated
  }

  if (!response.ok) {
    const error = (await response.json()) as ErrorResponse;
    throw new ApiError(response.status, error.error);
  }

  return response.json() as Promise<T>;
}

/**
 * Exchange a JWT token for a session cookie.
 * Returns true if successful, false if the token was invalid.
 */
export async function exchangeToken(jwt: string): Promise<boolean> {
  try {
    const response = await fetch(`${API_BASE}/auth`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ token: jwt }),
    });
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Get the current server status.
 * Returns null if unauthenticated.
 */
export async function getStatus(): Promise<StatusResponse | null> {
  return request<StatusResponse>("/status");
}

/**
 * Get the list of pending approval requests.
 * Throws if unauthenticated.
 */
export async function getPending(): Promise<PendingListResponse> {
  const result = await request<PendingListResponse>("/pending");
  if (result === null) {
    throw new ApiError(401, "Unauthenticated");
  }
  return result;
}

/**
 * Approve a pending request by ID.
 */
export async function approve(id: string): Promise<ActionResponse> {
  const result = await request<ActionResponse>(`/pending/${id}/approve`, {
    method: "POST",
  });
  if (result === null) {
    throw new ApiError(401, "Unauthenticated");
  }
  return result;
}

/**
 * Approve a pending request and create an auto-approve rule for similar future requests.
 */
export async function approveAndAutoApprove(
  id: string,
): Promise<ActionResponse> {
  const result = await request<ActionResponse>(
    `/pending/${id}/approve-and-auto-approve`,
    {
      method: "POST",
    },
  );
  if (result === null) {
    throw new ApiError(401, "Unauthenticated");
  }
  return result;
}

/**
 * Deny a pending request by ID.
 */
export async function deny(id: string): Promise<ActionResponse> {
  const result = await request<ActionResponse>(`/pending/${id}/deny`, {
    method: "POST",
  });
  if (result === null) {
    throw new ApiError(401, "Unauthenticated");
  }
  return result;
}

/**
 * Create an auto-approve rule from a cancelled request.
 */
export async function createAutoApprove(
  requestId: string,
): Promise<ActionResponse> {
  const result = await request<ActionResponse>("/auto-approve", {
    method: "POST",
    body: JSON.stringify({ request_id: requestId }),
  });
  if (result === null) {
    throw new ApiError(401, "Unauthenticated");
  }
  return result;
}

/**
 * List active auto-approve rules.
 */
export async function listAutoApproveRules(): Promise<AutoApproveRule[]> {
  const result = await request<AutoApproveRule[]>("/auto-approve");
  if (result === null) {
    throw new ApiError(401, "Unauthenticated");
  }
  return result;
}

/**
 * Delete an auto-approve rule by ID.
 */
export async function deleteAutoApproveRule(
  id: string,
): Promise<ActionResponse> {
  const result = await request<ActionResponse>(`/auto-approve/${id}`, {
    method: "DELETE",
  });
  if (result === null) {
    throw new ApiError(401, "Unauthenticated");
  }
  return result;
}

/** Persist a temporary auto-approve rule as a saved approval rule. */
export async function persistAutoApproveRule(
  id: string,
): Promise<SavedApprovalRule> {
  const result = await request<SavedApprovalRule>(`/auto-approve/${id}/persist`, {
    method: "POST",
  });
  if (result === null) {
    throw new ApiError(401, "Unauthenticated");
  }
  return result;
}

/** List saved approval rules. */
export async function listApprovalRules(): Promise<SavedApprovalRule[]> {
  const result = await request<SavedApprovalRule[]>("/approval-rules");
  if (result === null) {
    throw new ApiError(401, "Unauthenticated");
  }
  return result;
}

/** Create a saved approval rule from a pending or recent history request. */
export async function createApprovalRuleFromRequest(
  requestId: string,
): Promise<SavedApprovalRule> {
  const result = await request<SavedApprovalRule>("/approval-rules/from-request", {
    method: "POST",
    body: JSON.stringify({ request_id: requestId }),
  });
  if (result === null) {
    throw new ApiError(401, "Unauthenticated");
  }
  return result;
}

/** Update a saved approval rule. */
export async function updateApprovalRule(
  id: string,
  rule: SavedApprovalRule,
): Promise<SavedApprovalRule> {
  const result = await request<SavedApprovalRule>(`/approval-rules/${id}`, {
    method: "PUT",
    body: JSON.stringify(rule),
  });
  if (result === null) {
    throw new ApiError(401, "Unauthenticated");
  }
  return result;
}

/** Delete a saved approval rule. */
export async function deleteApprovalRule(
  id: string,
): Promise<ActionResponse> {
  const result = await request<ActionResponse>(`/approval-rules/${id}`, {
    method: "DELETE",
  });
  if (result === null) {
    throw new ApiError(401, "Unauthenticated");
  }
  return result;
}

export { ApiError };
