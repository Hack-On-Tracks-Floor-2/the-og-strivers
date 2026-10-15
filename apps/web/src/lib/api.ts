import { z } from 'zod';
import { API_VERSION, envelope } from '@proofpatch/shared';
export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public code: string,
  ) {
    super(message);
  }
}
export async function api<T extends z.ZodTypeAny>(
  path: string,
  schema: T,
  body?: unknown,
  method?: string,
): Promise<z.infer<T>> {
  const res = await fetch(`/api${path}`, {
    method: method ?? (body === undefined ? 'GET' : 'POST'),
    credentials: 'same-origin',
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let json: unknown;
  try {
    json = await res.json();
  } catch {
    throw new ApiError(
      'The API is unavailable. Check that the backend is running, then retry.',
      res.status >= 400 ? res.status : 502,
      'API_UNAVAILABLE',
    );
  }
  if (!res.ok) {
    const failure = z
      .object({ error: z.object({ message: z.string(), code: z.string() }) })
      .safeParse(json);
    throw new ApiError(
      failure.success ? failure.data.error.message : 'Request failed. Please retry.',
      res.status,
      failure.success ? failure.data.error.code : 'REQUEST_FAILED',
    );
  }
  return envelope(schema).parse(json).data;
}
