import {
  Address,
  Message,
  MessageComputer,
  Transaction,
  TransactionComputer,
  UserSecretKey,
  UserSigner
} from '@multiversx/sdk-core';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';

import axios from 'axios';
import {
  PASSKEY_AUTHENTICATE_ENDPOINT,
  PASSKEY_CHALLENGE_ENDPOINT,
  PASSKEY_REGISTER_ENDPOINT,
  safeWindow
} from './constants';
import {
  AuthenticatorNotSupported,
  ErrCannotSignSingleTransaction,
  UserCanceledPasskeyOperation,
  PasskeyAuthenticationFailed,
  PasskeyRegistrationFailed,
  PasskeyMismatchError,
  PasskeyServiceUrlNotSetError
} from './errors';
import { client } from './lib/webauthn-prf';

interface IPasskeyAccount {
  address: string;
  name?: string;
  signature?: string;
}

interface ISignMessageParams {
  message: string;
  address?: string;
  privateKey: string;
}

interface IHandlePasskeyErrorsParams {
  error: unknown;
  operation: string;
  cleanupFn?: () => void;
}

// By setting this property, we're telling the library
// which specific SHA-512 implementation to use
// when performing cryptographic operations
// like generating keys and signing data
ed.etc.sha512Sync = sha512;

export class PasskeyProvider {
  public account: IPasskeyAccount = { address: '' };
  private initialized = false;
  private static _instance: PasskeyProvider = new PasskeyProvider();
  private keyPair: { privateKey: string; publicKey: string } | undefined =
    undefined;
  private axiosInstance = axios.create();
  private config = {
    extrasApiUrl: ''
  };

  private constructor() {
    if (PasskeyProvider._instance) {
      throw new Error(
        'Error: Instantiation failed: Use PasskeyProvider.getInstance() instead of new.'
      );
    }
    PasskeyProvider._instance = this;
  }

  public static getInstance(): PasskeyProvider {
    return PasskeyProvider._instance;
  }

  public setAddress(address: string): PasskeyProvider {
    this.account.address = address;
    return PasskeyProvider._instance;
  }

  public setPasskeyServiceUrl(url: string): PasskeyProvider {
    this.config.extrasApiUrl = url;
    return PasskeyProvider._instance;
  }

  async init(): Promise<boolean> {
    this.initialized = true;
    return this.initialized;
  }

  async login(
    options: {
      callbackUrl?: string;
      token?: string;
    } = {}
  ): Promise<{ address: string; signature?: string }> {
    try {
      if (!this.initialized) {
        throw new Error(
          'Passkey provider is not initialised, call init() first'
        );
      }
      const { token } = options;
      await this.ensureConnected();

      if (!this.keyPair?.privateKey || !this.keyPair?.publicKey) {
        throw new Error('Could not retrieve key pair.');
      }

      this.account.address = this.keyPair.publicKey;

      if (token) {
        const signedToken = await this.signMessageWithPrivateKey({
          address: this.account.address,
          message: `${this.account.address}${token}{}`,
          privateKey: this.keyPair.privateKey
        });

        if (!signedToken.signature) {
          throw new Error('Could not sign token');
        }

        this.account.signature = Buffer.from(signedToken.signature).toString(
          'hex'
        );
      }

      this.destroyKeyPair();

      return {
        address: this.account.address,
        signature: this.account.signature
      };
    } catch (error) {
      throw error;
    }
  }

  private destroyKeyPair() {
    this.keyPair = undefined;
  }

  private async signMessageWithPrivateKey({
    message,
    address,
    privateKey
  }: ISignMessageParams): Promise<Message> {
    const signer = new UserSigner(UserSecretKey.fromString(privateKey));

    const msg = new Message({
      ...(address ? { address: new Address(address) } : {}),
      data: Buffer.from(message)
    });

    const messageComputer = new MessageComputer();

    const messageToSign = new Uint8Array(
      messageComputer.computeBytesForSigning(msg)
    );

    const signature = await signer.sign(Buffer.from(messageToSign));

    msg.signature = new Uint8Array(signature);

    return msg;
  }

  // Derive the private key seed using HKDF (Web Crypto API)
  private async derivePrivateKeySeed(
    prfOutput: Uint8Array
  ): Promise<Uint8Array> {
    if (!safeWindow) {
      throw new Error('Web Crypto API is not available');
    }

    // Import the PRF output as a CryptoKey
    const keyMaterial = await safeWindow.crypto.subtle.importKey(
      'raw', // format of the key material
      prfOutput.buffer, // the key material
      'HKDF', // HMAC-based Key Derivation Function
      false, // non-extractable
      ['deriveBits'] // keyUsages
    );

    //should be hardcoded in order to have deterministic output
    const salt = new Uint8Array([]); // Empty salt
    const info = new TextEncoder().encode('Ed25519 Key Generation');

    const derivedBitsBuffer = await safeWindow.crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt.buffer,
        info: info.buffer
      },
      keyMaterial,
      256 // Length in bits
    );

    return new Uint8Array(derivedBitsBuffer);
  }

  // Generate the Ed25519 key pair
  private generateEd25519KeyPair(privateKeySeed: Uint8Array) {
    const privateKey = privateKeySeed;
    const publicKey = ed.getPublicKey(privateKey);

    return {
      publicKey,
      privateKey
    };
  }

  public async getUserKeyPair(prfOutput: Uint8Array) {
    const privateKeySeed = await this.derivePrivateKeySeed(prfOutput);
    const { privateKey } = this.generateEd25519KeyPair(privateKeySeed);

    const userSecretKey = new UserSecretKey(privateKey);
    const address = userSecretKey.generatePublicKey().toAddress();

    return {
      privateKey: userSecretKey.hex(),
      publicKey: address.bech32()
    };
  }

  public async setUserKeyPair(prfOutput: Uint8Array) {
    this.keyPair = await this.getUserKeyPair(prfOutput);
  }

  public async createAccount({
    walletName,
    token
  }: {
    walletName: string;
    token?: string;
  }) {
    if (!this.config.extrasApiUrl) {
      throw new PasskeyServiceUrlNotSetError();
    }

    try {
      const {
        data: { challenge }
      } = await this.axiosInstance.get(
        `${this.config.extrasApiUrl}${PASSKEY_CHALLENGE_ENDPOINT}`
      );
      const {
        registration: { extensionResults },
        registrationResponse
      } = await client.register(walletName, challenge, {
        authenticatorType: 'extern'
      });

      const keyPairData = await this.getUserKeyPair(extensionResults);

      const { data } = await this.axiosInstance.post(
        `${this.config.extrasApiUrl}${PASSKEY_REGISTER_ENDPOINT}`,
        {
          registrationResponse: {
            ...registrationResponse,
            clientExtensionResults: {}
          },
          challenge,
          passKeyId: keyPairData?.publicKey
        }
      );

      if (!data.isVerified) {
        throw new PasskeyRegistrationFailed('Passkey verification failed');
      }

      await this.setUserKeyPair(extensionResults);

      return this.login({ token });
    } catch (error) {
      this.handlePasskeyErrors({
        error,
        operation: 'Passkey registration'
      });
    }
  }

  private async ensureConnected() {
    try {
      if (this.keyPair?.privateKey || this.keyPair?.publicKey) {
        return;
      }

      if (!this.config.extrasApiUrl) {
        throw new PasskeyServiceUrlNotSetError();
      }

      const {
        data: { challenge }
      } = await this.axiosInstance.get(
        `${this.config.extrasApiUrl}${PASSKEY_CHALLENGE_ENDPOINT}`
      );

      const {
        authentication: { extensionResults },
        authenticationResponse
      } = await client.authenticate([], challenge, {
        userVerification: 'required',
        authenticatorType: 'extern'
      });

      const keyPairData = await this.getUserKeyPair(extensionResults);

      // Ensure we are signing with the same address we logged in with
      if (
        this.account.address &&
        keyPairData?.publicKey &&
        this.account.address !== keyPairData?.publicKey
      ) {
        throw new PasskeyMismatchError();
      }

      const { data } = await this.axiosInstance.post(
        `${this.config.extrasApiUrl}${PASSKEY_AUTHENTICATE_ENDPOINT}`,
        {
          authenticationResponse: {
            ...authenticationResponse,
            clientExtensionResults: {}
          },
          challenge,
          passKeyId: keyPairData?.publicKey
        }
      );

      if (!data.isVerified) {
        throw new PasskeyAuthenticationFailed('Passkey verification failed');
      }

      await this.setUserKeyPair(extensionResults);
    } catch (error) {
      this.handlePasskeyErrors({
        error,
        operation: 'Passkey authentication'
      });
    }
  }

  public handlePasskeyErrors({
    error,
    operation,
    cleanupFn
  }: IHandlePasskeyErrorsParams): never {
    if (cleanupFn) {
      cleanupFn();
    }

    console.error(error);

    if (
      error instanceof UserCanceledPasskeyOperation ||
      error instanceof AuthenticatorNotSupported ||
      error instanceof PasskeyAuthenticationFailed ||
      error instanceof ErrCannotSignSingleTransaction ||
      error instanceof PasskeyRegistrationFailed ||
      error instanceof PasskeyMismatchError
    ) {
      throw error;
    }

    if (error instanceof DOMException && error.name === 'NotAllowedError') {
      throw new UserCanceledPasskeyOperation();
    }

    if (
      error instanceof TypeError ||
      (error instanceof Error && error.message.includes('prf'))
    ) {
      throw new AuthenticatorNotSupported();
    }

    throw new Error(
      `${operation} failed: ${
        error instanceof Error ? error.message : 'Unknown error'
      }`
    );
  }

  public async isExistingUser(email: string) {
    return Boolean(window.localStorage.getItem(email));
  }

  async logout(): Promise<boolean> {
    if (!this.initialized) {
      throw new Error('Passkey provider is not initialised, call init() first');
    }
    try {
      this.disconnect();
    } catch (error) {
      console.warn('Passkey origin url is already cleared!', error);
    }

    return true;
  }

  private disconnect() {
    this.account = { address: '' };
  }

  async getAddress(): Promise<string> {
    if (!this.initialized) {
      throw new Error('Passkey provider is not initialised, call init() first');
    }
    return this.account ? this.account.address : '';
  }

  isInitialized(): boolean {
    return this.initialized;
  }

  async isConnected(): Promise<boolean> {
    return Boolean(this.account.address);
  }

  async signTransaction(transaction: Transaction): Promise<Transaction> {
    try {
      await this.ensureConnected();

      const signedTransactions = await this.signTransactions([transaction]);

      if (signedTransactions.length != 1) {
        throw new ErrCannotSignSingleTransaction();
      }
      this.destroyKeyPair();
      return signedTransactions[0];
    } catch (error) {
      this.handlePasskeyErrors({
        error,
        operation: 'Transaction signing',
        cleanupFn: () => this.destroyKeyPair()
      });
    }
  }

  async signTransactions(transactions: Transaction[]): Promise<Transaction[]> {
    try {
      await this.ensureConnected();

      const privateKey = this.keyPair?.privateKey;

      if (!privateKey) {
        throw new Error('Private key missing – unable to sign transactions');
      }

      const signer = new UserSigner(UserSecretKey.fromString(privateKey));
      const transactionComputer = new TransactionComputer();

      for (const transaction of transactions) {
        const bytesToSign =
          transactionComputer.computeBytesForSigning(transaction);
        const signature = await signer.sign(bytesToSign);
        transaction.signature = new Uint8Array(signature);
      }

      this.destroyKeyPair();
      return transactions;
    } catch (error) {
      this.handlePasskeyErrors({
        error,
        operation: 'Transaction signing',
        cleanupFn: () => this.destroyKeyPair()
      });
    }
  }

  async signMessage(message: Message): Promise<Message> {
    try {
      await this.ensureConnected();
      const privateKey = this.keyPair?.privateKey;

      if (!privateKey) {
        throw new Error('Unable to sign message');
      }

      const signedMessage = await this.signMessageWithPrivateKey({
        message: message.data.toString(),
        address: this.account.address,
        privateKey
      });

      message.signature = signedMessage.signature;

      this.destroyKeyPair();
      return message;
    } catch (error) {
      this.handlePasskeyErrors({
        error,
        operation: 'Message signing',
        cleanupFn: () => this.destroyKeyPair()
      });
    }
  }

  cancelAction() {
    return true;
  }
}
