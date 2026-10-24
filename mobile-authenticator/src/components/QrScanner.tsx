import { CameraView, useCameraPermissions } from 'expo-camera';
import { useRef } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';

import { colors } from '../theme';

type Props = {
  onScanned: (data: string) => void;
  onCancel: () => void;
};

export function QrScanner({ onScanned, onCancel }: Props) {
  const [permission, requestPermission] = useCameraPermissions();
  // onBarcodeScanned dispara muchas veces por segundo; procesamos solo la primera.
  const handled = useRef(false);

  if (!permission) return <View style={styles.center} />;

  if (!permission.granted) {
    return (
      <View style={styles.center}>
        <Text style={styles.text}>Se necesita la cámara para escanear el QR.</Text>
        <Pressable style={styles.button} onPress={requestPermission}>
          <Text style={styles.buttonText}>Dar permiso</Text>
        </Pressable>
        <Pressable style={[styles.button, styles.secondary]} onPress={onCancel}>
          <Text style={styles.secondaryText}>Cancelar</Text>
        </Pressable>
      </View>
    );
  }

  return (
    <View style={styles.fill}>
      <CameraView
        style={styles.fill}
        facing="back"
        barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
        onBarcodeScanned={({ data }) => {
          if (handled.current) return;
          handled.current = true;
          onScanned(data);
        }}
      />
      <View style={styles.overlay}>
        <Text style={styles.text}>Apunta al QR que muestra la web app</Text>
        <Pressable style={[styles.button, styles.secondary]} onPress={onCancel}>
          <Text style={styles.secondaryText}>Cancelar</Text>
        </Pressable>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1 },
  center: { flex: 1, justifyContent: 'center', alignItems: 'center', padding: 24, gap: 12 },
  overlay: {
    position: 'absolute',
    bottom: 40,
    left: 20,
    right: 20,
    alignItems: 'center',
    gap: 12,
    backgroundColor: 'rgba(255,255,255,0.94)',
    borderRadius: 12,
    padding: 16,
  },
  text: { color: colors.text, fontSize: 16, textAlign: 'center' },
  button: { backgroundColor: colors.accent, paddingVertical: 12, paddingHorizontal: 24, borderRadius: 10 },
  buttonText: { color: colors.onAccent, fontWeight: '700' },
  secondary: { backgroundColor: 'transparent', borderWidth: 1.5, borderColor: colors.accent },
  secondaryText: { color: colors.accentDark, fontWeight: '600' },
});
