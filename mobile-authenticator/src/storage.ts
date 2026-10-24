// Las semillas se guardan en el llavero del sistema (Keychain / Keystore).
import * as SecureStore from 'expo-secure-store';

export type Account = {
  id: string;
  issuer: string;
  label: string;
  secret: string;
};

const STORAGE_KEY = 'totp_accounts_v1';

export async function loadAccounts(): Promise<Account[]> {
  const raw = await SecureStore.getItemAsync(STORAGE_KEY);
  if (!raw) return [];
  try {
    return JSON.parse(raw) as Account[];
  } catch {
    return [];
  }
}

export async function saveAccounts(accounts: Account[]): Promise<void> {
  await SecureStore.setItemAsync(STORAGE_KEY, JSON.stringify(accounts));
}

export function newAccountId(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}
