jest.mock('axios', () => ({
  create: jest.fn().mockReturnValue({
    get: jest.fn().mockImplementation((url) => {
      if (url.includes('challenge')) {
        return Promise.resolve({ data: { challenge: 'mock-challenge' } });
      }
      return Promise.resolve({ data: {} });
    }),
    post: jest.fn().mockImplementation((url) => {
      if (url.includes('register')) {
        return Promise.resolve({ data: { isVerified: true } });
      }
      if (url.includes('authenticate')) {
        return Promise.resolve({ data: { isVerified: true } });
      }
      return Promise.resolve({ data: {} });
    })
  })
}));

jest.mock('../lib/webauthn-prf', () => ({
  client: {
    register: jest.fn().mockResolvedValue({
      registration: {
        extensionResults: new Uint8Array(32)
      },
      registrationResponse: {}
    }),
    authenticate: jest.fn().mockResolvedValue({
      authentication: {
        extensionResults: new Uint8Array(32)
      },
      authenticationResponse: {}
    })
  }
}));

jest.mock('../constants', () => ({
  PASSKEY_AUTHENTICATE_ENDPOINT: '/passkey/authenticate',
  PASSKEY_CHALLENGE_ENDPOINT: '/passkey/challenge',
  PASSKEY_REGISTER_ENDPOINT: '/passkey/register',
  safeWindow: undefined
}));

describe('Setup', () => {
  test('mocks are properly configured', () => {
    expect(jest.isMockFunction(require('axios').create)).toBe(true);
    expect(
      jest.isMockFunction(require('../lib/webauthn-prf').client.register)
    ).toBe(true);
  });
});
