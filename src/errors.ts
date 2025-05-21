/**
 * The base class for exceptions (errors).
 */
export class Err extends Error {
  inner: Error | undefined = undefined;

  public constructor(message: string, inner?: Error) {
    super(message);
    this.inner = inner;
  }
}

export class ErrCannotSignSingleTransaction extends Err {
  public constructor() {
    super('Cannot sign single transaction.');
  }
}

export class ErrAccountNotConnected extends Err {
  public constructor() {
    super('Account is not connected.');
  }
}

export class AuthenticatorNotSupported extends Err {
  public constructor() {
    super('Passkey authenticator does not support PRF.');
  }
}

export class UserCanceledPasskeyOperation extends Err {
  public constructor() {
    super('User canceled the passkey operation.');
  }
}

export class PasskeyAuthenticationFailed extends Err {
  public constructor(
    message = 'Passkey authentication failed.',
    inner?: Error
  ) {
    super(message, inner);
  }
}

export class PasskeyRegistrationFailed extends Err {
  public constructor(message = 'Passkey registration failed.', inner?: Error) {
    super(message, inner);
  }
}
