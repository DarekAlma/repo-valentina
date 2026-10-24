import { Pressable, StyleSheet, Text, View } from 'react-native';

import { Account } from '../storage';
import { generateTotp, PERIOD_SECONDS, secondsRemaining, timeCounter } from '../totp/totp';
import { colors } from '../theme';

type Props = {
  account: Account;
  nowSeconds: number;
  onLongPress: (account: Account) => void;
};

export function AccountCard({ account, nowSeconds, onLongPress }: Props) {
  const code = generateTotp(account.secret, nowSeconds);
  const remaining = secondsRemaining(nowSeconds);
  const urgent = remaining <= 5;

  return (
    <Pressable onLongPress={() => onLongPress(account)} style={styles.card}>
      <Text style={styles.issuer}>{account.issuer}</Text>
      <Text style={styles.label}>{account.label}</Text>
      <Text style={[styles.code, urgent && styles.urgent]} selectable>
        {code.slice(0, 3)} {code.slice(3)}
      </Text>
      <View style={styles.row}>
        <View style={styles.track}>
          <View
            style={[
              styles.bar,
              { width: `${(remaining / PERIOD_SECONDS) * 100}%` },
              urgent && styles.barUrgent,
            ]}
          />
        </View>
        <Text style={[styles.seconds, urgent && styles.urgent]}>{remaining}s</Text>
      </View>
      <Text style={styles.counter}>C = {timeCounter(nowSeconds)}</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: colors.card,
    borderRadius: 20,
    padding: 20,
    marginBottom: 14,
    borderWidth: 1,
    borderColor: colors.line,
  },
  issuer: { color: colors.accent, fontSize: 14, fontWeight: '700' },
  label: { color: colors.muted, fontSize: 14, marginTop: 2 },
  code: {
    color: colors.text,
    fontSize: 48,
    fontWeight: '700',
    letterSpacing: 4,
    marginVertical: 8,
    fontVariant: ['tabular-nums'],
  },
  urgent: { color: colors.danger },
  row: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  track: { flex: 1, height: 8, borderRadius: 4, backgroundColor: colors.track, overflow: 'hidden' },
  bar: { height: '100%', backgroundColor: colors.accent },
  barUrgent: { backgroundColor: colors.danger },
  seconds: { color: colors.muted, width: 34, textAlign: 'right', fontVariant: ['tabular-nums'] },
  counter: { color: colors.muted, fontSize: 11, marginTop: 8 },
});
