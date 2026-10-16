/**
 * Minimal Stripe client surface used by the refund action.
 *
 * In production this wraps `stripe` from 'stripe' npm package with keys from
 * the secret manager. Here it is a typed seam so the gated-action code
 * typechecks and is unit-testable via injection.
 */

export interface StripeRefundResult {
  id: string;
  status: 'succeeded' | 'pending' | 'failed';
  amount: number;
  payment_intent: string;
}

export interface StripeRefundsClient {
  create(params: {
    payment_intent: string;
    amount: number; // cents
    reason?: 'duplicate' | 'fraudulent' | 'requested_by_customer';
  }): Promise<StripeRefundResult>;
}

export interface StripeClient {
  refunds: StripeRefundsClient;
  /** Optional balance check used to guard against over-refunding (TOCTOU). */
  paymentIntents?: {
    retrieve(id: string): Promise<{
      id: string;
      amount: number;
      amount_refunded: number;
      currency: string;
      status: string;
    }>;
  };
}

// Env-gated real/inert implementations -------------------------------------

declare const process: { env: Record<string, string | undefined> };

const API_KEY = process.env.STRIPE_SECRET_KEY ?? '';

class LiveStripeRefunds implements StripeRefundsClient {
  async create(_params: {
    payment_intent: string;
    amount: number;
    reason?: 'duplicate' | 'fraudulent' | 'requested_by_customer';
  }): Promise<StripeRefundResult> {
    if (!API_KEY) {
      throw new Error('STRIPE_SECRET_KEY is not configured.');
    }
    // Real implementation would call https://api.stripe.com/v1/refunds here.
    throw new Error(
      'LiveStripeRefunds.create is not wired to a network transport in this ' +
        'environment; inject a StripeClient (e.g. a mock) instead.'
    );
  }
}

/** Default export-shaped client; replace/inject in tests via setStripeClient(). */
let currentClient: StripeClient = {
  refunds: new LiveStripeRefunds(),
};

export function getStripeClient(): StripeClient {
  return currentClient;
}

export function setStripeClient(client: StripeClient): void {
  currentClient = client;
}

/** Convenience proxy so existing `stripeClient.refunds...` call sites work. */
export const stripeClient: StripeClient = {
  get refunds() {
    return currentClient.refunds;
  },
  get paymentIntents() {
    return currentClient.paymentIntents;
  },
};
