export const PASSKEY_CHALLENGE_ENDPOINT = '/passkeys/challenge';
export const PASSKEY_AUTHENTICATE_ENDPOINT = '/passkeys/authentication/verify';
export const PASSKEY_REGISTER_ENDPOINT = '/passkeys/register/verify';

export const safeWindow = typeof window !== 'undefined' ? window : undefined;
