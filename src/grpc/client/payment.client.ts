import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import path from 'path';

const protoLoaderOptions: protoLoader.Options = {
    keepCase: false,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
};


interface Timestamp {
    seconds: number;
    nanos: number;
}
interface Currency {
    code: number;
    name: string;
    symbol: string;
}
interface Wallet {
    walletId: string;
    userId: string;
    status: number;
    currency?: Currency;
    totalBalanceMinor: number;
    availableBalanceMinor: number;
    heldBalanceMinor: number;
    createdAt?: Timestamp;
    updatedAt?: Timestamp;
}
interface WalletTransaction {
    transactionId: string;
    walletId: string;
    userId: string;
    amountMinor: number;
    direction: string;
    entryType: string;
    referenceType: string;
    referenceId: string;
    note: string;
    createdAt?: Timestamp;
}
interface Withdrawal {
    withdrawalId: string;
    walletId: string;
    userId: string;
    amountMinor: number;
    currency?: Currency;
    status: number;
    bankCode: string;
    accountNumberLast4: string;
    accountName: string;
    providerReference: string;
    failureReason: string;
    createdAt?: Timestamp;
    updatedAt?: Timestamp;
}
interface PaginationMeta {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
}
// Response types
interface CreateWalletResponse {
    success: boolean;
    message: string;
    wallet?: Wallet;
}
interface GetWalletResponse {
    success: boolean;
    message: string;
    wallet?: Wallet;
}
interface WalletMutationResponse {
    success: boolean;
    message: string;
    wallet?: Wallet;
    transaction?: WalletTransaction;
}
interface ListWalletTransactionsResponse {
    success: boolean;
    transactions: WalletTransaction[];
    meta?: PaginationMeta;
}
interface RequestWithdrawalResponse {
    success: boolean;
    message: string;
    withdrawal?: Withdrawal;
}
interface ListWithdrawalsResponse {
    success: boolean;
    withdrawals: Withdrawal[];
    meta?: PaginationMeta;
}

export enum CurrencyCode {
    UNSPECIFIED = 0,
    NGN = 1,
    USD = 2,
}




export class PaymentServiceClient {
    private client: any;
    private connected: boolean = false;

    /**
    * Create a new Payment Service client
    * @param address - gRPC server address (e.g., 'localhost:50053' or 'payment-service:50053')
    * @param protoPath - Optional custom path to payment.proto file
    */

    constructor(
        private address: string,
        protoPath?: string
    ) {
        const PROTO_PATH = protoPath || path.resolve(__dirname, '..', '..', '..', 'proto', 'payment', 'v1', 'payment.proto');
        const packageDefinition = protoLoader.loadSync(
            PROTO_PATH,
            protoLoaderOptions
        );
        const paymentProto = grpc.loadPackageDefinition(packageDefinition) as any;

        this.client = new paymentProto.payment.WalletService(
            address,
            grpc.credentials.createInsecure()
        );
    }

    private promisify<T>(
        method: string,
        params: Record<string, any>
    ): Promise<T> {
        return new Promise((resolve, reject) => {
            // keepCase: false in proto-loader handles camelCase <-> snake_case conversion
            this.client[method](params, (error: any, response: T) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(response);
                }
            });
        });
    }

    async createWallet(userId: string, currencyCode: CurrencyCode): Promise<CreateWalletResponse> {
        return this.promisify<CreateWalletResponse>('CreateWallet', { userId, currencyCode });
    }

    async getWalletByUserId(userId: string): Promise<GetWalletResponse> {
        return this.promisify('GetWalletByUserId', { userId });
    }

    async getWalletById(walletId: string): Promise<GetWalletResponse> {
        return this.promisify('GetWalletById', { walletId });
    }

    async creditWallet(params: {
        userId: string;
        amountMinor: number;
        referenceType: string;
        referenceId: string;
        note?: string;
        idempotencyKey: string;
    }): Promise<WalletMutationResponse> {
        return this.promisify('CreditWallet', params);
    }
    async debitWallet(params: {
        userId: string;
        amountMinor: number;
        referenceType: string;
        referenceId: string;
        note?: string;
        idempotencyKey: string;
    }): Promise<WalletMutationResponse> {
        return this.promisify('DebitWallet', params);
    }

    async listWalletTransactions(params: {
        userId: string;
        pagination?: { page: number; limit: number };
        referenceType?: string;
        referenceId?: string;
    }): Promise<ListWalletTransactionsResponse> {
        return this.promisify('ListWalletTransactions', params);
    }
    async requestWithdrawal(params: {
        userId: string;
        amountMinor: number;
        bankCode: string;
        accountNumber: string;
        accountName: string;
        idempotencyKey: string;
    }): Promise<RequestWithdrawalResponse> {
        return this.promisify('RequestWithdrawal', params);
    }
    async listWithdrawals(params: {
        userId: string;
        pagination?: { page: number; limit: number };
        status?: number;
    }): Promise<ListWithdrawalsResponse> {
        return this.promisify('ListWithdrawals', params);
    }

    async waitForReady(timeoutMs: number = 5000): Promise<void> {
        return new Promise((resolve, reject) => {
            const deadline = Date.now() + timeoutMs;
            this.client.waitForReady(deadline, (error: any) => {
                if (error) {
                    reject(
                        new Error(
                            `Failed to connect to user service at ${this.address}: ${error.message}`
                        )
                    );
                } else {
                    this.connected = true;
                    resolve();
                }
            });
        });
    }

    isConnected(): boolean {
        return this.connected;
    }

    close(): void {
        if (this.client) {
            grpc.closeClient(this.client);
        }
    }

}

let defaultClient: PaymentServiceClient | null = null;

/**
 * Get or create a singleton Payment Service client
 * @param address - gRPC server address (only used on first call)
 */
export const getPaymentClient = (address?: string): PaymentServiceClient => {
    const serverAddress = address || process.env.PAYMENT_SERVICE_GRPC_URL;
    if (!serverAddress) {
        throw new Error('PAYMENT_SERVICE_GRPC_URL environment variable is not set');
    }
    if (!defaultClient) {
        defaultClient = new PaymentServiceClient(serverAddress);
    }
    return defaultClient;
}

export const closePaymentClient = (): void => {
    if (defaultClient) {
        defaultClient.close();
        defaultClient = null;
    }
};

export default PaymentServiceClient;