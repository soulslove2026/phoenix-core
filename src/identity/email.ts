export class EmailValidationError extends Error {
  constructor() {
    super("email_invalid");
  }
}

const LOCAL_PART = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/;
const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function normalizeAndValidateEmail(input: string): string {
  const email = input.trim().toLowerCase();
  if (email.length < 3 || email.length > 320 || /\s/.test(email)) {
    throw new EmailValidationError();
  }

  const firstAt = email.indexOf("@");
  if (firstAt <= 0 || firstAt !== email.lastIndexOf("@")) {
    throw new EmailValidationError();
  }

  const local = email.slice(0, firstAt);
  const domain = email.slice(firstAt + 1);
  if (
    local.length > 64 ||
    domain.length > 255 ||
    local.startsWith(".") ||
    local.endsWith(".") ||
    local.includes("..") ||
    !LOCAL_PART.test(local)
  ) {
    throw new EmailValidationError();
  }

  const labels = domain.split(".");
  if (labels.length < 2 || labels.some((label) => !DOMAIN_LABEL.test(label))) {
    throw new EmailValidationError();
  }

  return email;
}
