import { useState } from 'react';
import { Pressable, StyleSheet, Text, TextInput, View } from 'react-native';

import { colors } from '../theme';

type Props = {
  onSubmit: (input: { issuer: string; label: string; secretOrUri: string }) => void;
  onCancel: () => void;
};

export function ManualEntry({ onSubmit, onCancel }: Props) {
  const [issuer, setIssuer] = useState('PatronesLab');
  const [label, setLabel] = useState('');
  const [secretOrUri, setSecretOrUri] = useState('');

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Agregar cuenta manualmente</Text>
      <Text style={styles.hint}>Pega el secreto Base32 o la URI otpauth:// completa.</Text>

      <Text style={styles.label}>Secreto o URI</Text>
      <TextInput
        style={[styles.input, styles.multiline]}
        value={secretOrUri}
        onChangeText={setSecretOrUri}
        autoCapitalize="characters"
        autoCorrect={false}
        multiline
        placeholder="JBSWY3DPEHPK3PXP..."
        placeholderTextColor={colors.muted}
      />
      <Text style={styles.label}>Emisor</Text>
      <TextInput style={styles.input} value={issuer} onChangeText={setIssuer} />
      <Text style={styles.label}>Cuenta</Text>
      <TextInput
        style={styles.input}
        value={label}
        onChangeText={setLabel}
        autoCapitalize="none"
        placeholder="usuario"
        placeholderTextColor={colors.muted}
      />

      <View style={styles.actions}>
        <Pressable style={[styles.button, styles.secondary]} onPress={onCancel}>
          <Text style={styles.secondaryText}>Cancelar</Text>
        </Pressable>
        <Pressable style={styles.button} onPress={() => onSubmit({ issuer, label, secretOrUri })}>
          <Text style={styles.buttonText}>Guardar</Text>
        </Pressable>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { padding: 20 },
  title: { color: colors.text, fontSize: 22, fontWeight: '700' },
  hint: { color: colors.muted, marginTop: 4, marginBottom: 12 },
  label: { color: colors.muted, fontSize: 13, marginTop: 12, marginBottom: 4 },
  input: {
    backgroundColor: colors.input,
    color: colors.text,
    borderRadius: 10,
    padding: 12,
    fontSize: 16,
    borderWidth: 1,
    borderColor: colors.track,
  },
  multiline: { minHeight: 80, textAlignVertical: 'top' },
  actions: { flexDirection: 'row', justifyContent: 'flex-end', gap: 12, marginTop: 20 },
  button: { backgroundColor: colors.accent, paddingVertical: 12, paddingHorizontal: 24, borderRadius: 10 },
  buttonText: { color: colors.onAccent, fontWeight: '700' },
  secondary: { backgroundColor: 'transparent', borderWidth: 1.5, borderColor: colors.accent },
  secondaryText: { color: colors.accentDark, fontWeight: '600' },
});
