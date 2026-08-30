export class HttpError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export class RunCancelledError extends Error {
  constructor() {
    super("Run cancelled");
    this.name = "RunCancelledError";
  }
}

export class SecurityViolationError extends HttpError {
  constructor(
    message: string,
    public readonly category?: string,
    public readonly reason?: string,
  ) {
    super(400, message);
    this.name = "SecurityViolationError";
  }
}
