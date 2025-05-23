import {
  AuthenticatorNotSupported,
  UserCanceledPasskeyOperation,
  PasskeyAuthenticationFailed,
  PasskeyRegistrationFailed,
  ErrCannotSignSingleTransaction
} from '../errors';
import { PasskeyProvider } from '../passkeyProvider';

describe('PasskeyProvider', () => {
  let passkeyProvider: PasskeyProvider;
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    passkeyProvider = PasskeyProvider.getInstance();
    consoleSpy = jest.spyOn(console, 'error').mockImplementation();
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  test('throws when not initialized', async () => {
    Object.defineProperty(passkeyProvider, 'initialized', { value: false });

    await expect(passkeyProvider.login()).rejects.toThrow(
      'Passkey provider is not initialised, call init() first'
    );

    await expect(passkeyProvider.getAddress()).rejects.toThrow(
      'Passkey provider is not initialised, call init() first'
    );

    await expect(passkeyProvider.logout()).rejects.toThrow(
      'Passkey provider is not initialised, call init() first'
    );
  });

  test('throws when passkey service URL is not set', async () => {
    await passkeyProvider.init();

    Object.defineProperty(passkeyProvider, 'config', {
      value: { extrasApiUrl: '' }
    });

    await expect(
      passkeyProvider.createAccount({ walletName: 'test' })
    ).rejects.toThrow('Passkey service URL is not set');
  });

  describe('handlePasskeyErrors', () => {
    const callHandlePasskeyErrors = (error: unknown): Error => {
      try {
        passkeyProvider.handlePasskeyErrors({
          error,
          operation: 'Test operation'
        });
      } catch (e) {
        return e as Error;
      }
    };

    test('rethrows AuthenticatorNotSupported error', () => {
      const error = new AuthenticatorNotSupported();
      const result = callHandlePasskeyErrors(error);

      expect(result).toBe(error);
      expect(result).toBeInstanceOf(AuthenticatorNotSupported);
      expect(consoleSpy).not.toHaveBeenCalled();
    });

    test('rethrows UserCanceledPasskeyOperation error', () => {
      const error = new UserCanceledPasskeyOperation();
      const result = callHandlePasskeyErrors(error);

      expect(result).toBe(error);
      expect(result).toBeInstanceOf(UserCanceledPasskeyOperation);
      expect(consoleSpy).not.toHaveBeenCalled();
    });

    test('rethrows PasskeyAuthenticationFailed error', () => {
      const error = new PasskeyAuthenticationFailed();
      const result = callHandlePasskeyErrors(error);

      expect(result).toBe(error);
      expect(result).toBeInstanceOf(PasskeyAuthenticationFailed);
      expect(consoleSpy).not.toHaveBeenCalled();
    });

    test('rethrows PasskeyRegistrationFailed error', () => {
      const error = new PasskeyRegistrationFailed();
      const result = callHandlePasskeyErrors(error);

      expect(result).toBe(error);
      expect(result).toBeInstanceOf(PasskeyRegistrationFailed);
      expect(consoleSpy).not.toHaveBeenCalled();
    });

    test('rethrows ErrCannotSignSingleTransaction error', () => {
      const error = new ErrCannotSignSingleTransaction();
      const result = callHandlePasskeyErrors(error);

      expect(result).toBe(error);
      expect(result).toBeInstanceOf(ErrCannotSignSingleTransaction);
      expect(consoleSpy).not.toHaveBeenCalled();
    });

    test('converts DOMException NotAllowedError to UserCanceledPasskeyOperation', () => {
      const domError = new DOMException('User aborted', 'NotAllowedError');
      const result = callHandlePasskeyErrors(domError);

      expect(result).toBeInstanceOf(UserCanceledPasskeyOperation);
      expect((result as UserCanceledPasskeyOperation).message).toBe(
        'User canceled the passkey operation.'
      );
      expect(consoleSpy).not.toHaveBeenCalled();
    });

    test('converts TypeError to AuthenticatorNotSupported', () => {
      const typeError = new TypeError('PRF not supported');
      const result = callHandlePasskeyErrors(typeError);

      expect(result).toBeInstanceOf(AuthenticatorNotSupported);
      expect((result as AuthenticatorNotSupported).message).toBe(
        'Passkey authenticator does not support PRF.'
      );
      expect(consoleSpy).not.toHaveBeenCalled();
    });

    test('converts Error containing "prf" to AuthenticatorNotSupported', () => {
      const prfError = new Error('The authenticator does not support prf');
      const result = callHandlePasskeyErrors(prfError);

      expect(result).toBeInstanceOf(AuthenticatorNotSupported);
      expect((result as AuthenticatorNotSupported).message).toBe(
        'Passkey authenticator does not support PRF.'
      );
      expect(consoleSpy).not.toHaveBeenCalled();
    });

    test('logs and wraps unknown errors', () => {
      const unknownError = new Error('Some unknown error');
      const result = callHandlePasskeyErrors(unknownError);

      expect((result as Error).message).toBe(
        'Test operation failed: Some unknown error'
      );
      expect(consoleSpy).toHaveBeenCalledWith(unknownError);
    });

    test('executes cleanup function when provided', () => {
      const cleanupFn = jest.fn();
      const error = new Error('Test error');

      try {
        passkeyProvider.handlePasskeyErrors({
          error,
          operation: 'Test operation',
          cleanupFn
        });
      } catch (e) {}

      expect(cleanupFn).toHaveBeenCalledTimes(1);
    });
  });

  test('aborts login when cancelAction is called', async () => {
    await passkeyProvider.init();
    passkeyProvider.setPasskeyServiceUrl('https://multiversx.com');

    const originalGet = passkeyProvider['axiosInstance'].get;
    passkeyProvider['axiosInstance'].get = jest.fn((...args) => {
      const config = args[1] || {};
      return new Promise((resolve, reject) => {
        config.signal?.addEventListener?.('abort', () => {
          reject(new Error('canceled'));
        });

        setTimeout(() => resolve({ data: { challenge: 'test' } } as any), 1000);
      });
    });

    const loginPromise = passkeyProvider.login();

    setTimeout(() => {
      passkeyProvider.cancelAction();
    }, 100);

    await expect(loginPromise).rejects.toThrow(/canceled|abort|User canceled/i);
    passkeyProvider['axiosInstance'].get = originalGet;
  });
});
