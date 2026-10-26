export interface GuardOptions {
  body?: boolean;
  query?: boolean;
  params?: boolean;
  noSql?: boolean;
  protoPollution?: boolean;
  trim?: boolean;
  xss?: boolean;
  maxDepth?: number;
  block?: boolean;
  whitelist?: string[];
  onViolation?: (req: any, res: any, next: any, violations: any[]) => void;
}

export interface SanitizeResult<T = any> {
  data: T;
  violations: Array<{
    type: string;
    message: string;
    key?: string;
  }>;
  isValid: boolean;
}

export declare function payloadGuard(options?: GuardOptions): (req: any, res: any, next: any) => void;
export declare function sanitize<T = any>(input: T, options?: GuardOptions): SanitizeResult<T>;

export default payloadGuard;
