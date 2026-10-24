import { StatusBar } from 'expo-status-bar';
import { useCallback, useEffect, useState } from 'react';
import { Alert, FlatList, Pressable, StyleSheet, Text, View } from 'react-native';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';

import { AccountCard } from './src/components/AccountCard';
import { ManualEntry } from './src/components/ManualEntry';
import { QrScanner } from './src/components/QrScanner';
import { Account, loadAccounts, newAccountId, saveAccounts } from './src/storage';
import { colors } from './src/theme';
import { decodeBase32, normalizeBase32 } from './src/totp/base32';
import { parseOtpAuthUri } from './src/totp/otpauth';

type Screen = 'list' | 'scan' | 'manual';

/** Reloj compartido: re-renderiza cada 500 ms para que el cambio de ventana se vea al instante. */
function useNowSeconds(): number {
  const [now, setNow] = useState(() => Date.now() / 1000);
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now() / 1000), 500);
    return () => clearInterval(id);
  }, []);
  return now;
}

export default function App() {
  const [screen, setScreen] = useState<Screen>('list');
  const [accounts, setAccounts] = useState<Account[]>([]);
  const nowSeconds = useNowSeconds();

  useEffect(() => {
    loadAccounts().then(setAccounts).catch(() => setAccounts([]));
  }, []);

  const persist = useCallback(async (next: Account[]) => {
    setAccounts(next);
    await saveAccounts(next);
  }, []);

  const addAccount = useCallback(
    async (account: Omit<Account, 'id'>) => {
      const duplicate = accounts.some((a) => a.secret === account.secret);
      if (duplicate) {
        Alert.alert('Cuenta repetida', 'Ese secreto ya está registrado.');
      } else {
        await persist([...accounts, { ...account, id: newAccountId() }]);
      }
      setScreen('list');
    },
    [accounts, persist],
  );

  const handleScanned = (data: string) => {
    try {
      addAccount(parseOtpAuthUri(data));
    } catch (error) {
      Alert.alert('QR inválido', (error as Error).message);
      setScreen('list');
    }
  };

  const handleManual = ({ issuer, label, secretOrUri }: { issuer: string; label: string; secretOrUri: string }) => {
    try {
      const value = secretOrUri.trim();
      if (value.toLowerCase().startsWith('otpauth://')) {
        addAccount(parseOtpAuthUri(value));
        return;
      }
      const secret = normalizeBase32(value);
      decodeBase32(secret); // valida o lanza
      addAccount({ secret, issuer: issuer.trim() || 'Sin emisor', label: label.trim() || 'cuenta' });
    } catch (error) {
      Alert.alert('Secreto inválido', (error as Error).message);
    }
  };

  const confirmDelete = (account: Account) => {
    Alert.alert('Eliminar cuenta', `¿Eliminar ${account.issuer} (${account.label})?`, [
      { text: 'Cancelar', style: 'cancel' },
      {
        text: 'Eliminar',
        style: 'destructive',
        onPress: () => persist(accounts.filter((a) => a.id !== account.id)),
      },
    ]);
  };

  return (
    <SafeAreaProvider>
      <SafeAreaView style={styles.container}>
        <StatusBar style="dark" />
        {screen === 'scan' && <QrScanner onScanned={handleScanned} onCancel={() => setScreen('list')} />}
        {screen === 'manual' && <ManualEntry onSubmit={handleManual} onCancel={() => setScreen('list')} />}
        {screen === 'list' && (
          <View style={styles.fill}>
            <Text style={styles.title}>Authenticator</Text>
            <Text style={styles.subtitle}>TOTP RFC 6238 · funciona sin conexión</Text>
            <FlatList
              data={accounts}
              keyExtractor={(a) => a.id}
              contentContainerStyle={styles.list}
              renderItem={({ item }) => (
                <AccountCard account={item} nowSeconds={nowSeconds} onLongPress={confirmDelete} />
              )}
              ListEmptyComponent={
                <Text style={styles.empty}>Aún no hay cuentas. Escanea el QR de la web app o pega el secreto.</Text>
              }
            />
            <View style={styles.actions}>
              <Pressable style={styles.button} onPress={() => setScreen('scan')}>
                <Text style={styles.buttonText}>Escanear QR</Text>
              </Pressable>
              <Pressable style={[styles.button, styles.secondary]} onPress={() => setScreen('manual')}>
                <Text style={styles.secondaryText}>Pegar secreto</Text>
              </Pressable>
            </View>
          </View>
        )}
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  fill: { flex: 1 },
  title: { color: colors.text, fontSize: 28, fontWeight: '800', paddingHorizontal: 20, paddingTop: 12 },
  subtitle: { color: colors.muted, paddingHorizontal: 20, marginBottom: 12 },
  list: { paddingHorizontal: 16, paddingBottom: 16, flexGrow: 1 },
  empty: { color: colors.muted, textAlign: 'center', marginTop: 48, paddingHorizontal: 24 },
  actions: { flexDirection: 'row', gap: 12, padding: 16 },
  button: { flex: 1, backgroundColor: colors.accent, paddingVertical: 14, borderRadius: 12, alignItems: 'center' },
  buttonText: { color: colors.onAccent, fontWeight: '700', fontSize: 16 },
  secondary: { backgroundColor: 'transparent', borderWidth: 1.5, borderColor: colors.accent },
  secondaryText: { color: colors.accentDark, fontWeight: '600', fontSize: 16 },
});
