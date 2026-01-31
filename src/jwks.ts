import { Options, JwksClient } from 'jwks-rsa'

export class JwksManager {
  private client: JwksClient

  constructor(options: Options) {
    this.client = new JwksClient(options)
  }

  getClient() {
    return this.client
  }

  async getSigningKey(kid: string): Promise<string> {
    const key = await this.client.getSigningKey(kid)
    return key.getPublicKey()
  }
}
