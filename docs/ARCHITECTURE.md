# pkpt — Arquitectura

App multiplataforma, local-first, para firmar y cifrar archivos con clave pública
sin que el usuario tenga que entender criptografía. El usuario nunca ve la palabra
"clave".

## Principios

- **No inventar cripto.** age para cifrar, Ed25519 para firmar, core en Rust.
- **Mínimas funciones.** Si una feature complica el uso, no entra.
- **Local-first.** Las claves privadas nunca salen del dispositivo ni van a la nube.
- **Sin servidores de confianza.** Cualquier infraestructura que exista es tonta,
  reemplazable y ciega: si es maliciosa, a lo sumo no entrega; nunca lee ni falsifica.

## Funciones (6, ni una más)

1. **Mi identidad**: QR + link `pkpt1…` para compartir.
2. **Agregar contacto**: escanear QR o abrir link, y verificar.
3. **Cifrar para…**: archivo + contacto(s) → `.age`.
4. **Abrir**: doble click / "Compartir con pkpt" → descifra.
5. **Firmar**: archivo o texto → `.sig` desprendido.
6. **Verificar**: "Firmado por Juana ✅ (verificada en persona)".

Integración con el share sheet del SO y asociación de archivos `.age` / `.sig`.

## Identidad

- Sin CA ni directorio global. Modelo Signal: **TOFU + verificación en persona**.
- Contacto por QR en persona → **verificado**. Por link → **no verificado** hasta
  comparar 6 palabras de seguridad (por teléfono, en persona).
- **Apodos locales**: el nombre del contacto lo pone cada uno.
- Pruebas públicas opcionales estilo Keyoxide (DNS, GitHub, Mastodon). Post-MVP.

## Modelo de claves

```
Root identity key (Ed25519)
 ├─ derivada de 24 palabras (BIP39) → backup en PAPEL, nunca en la nube
 ├─ solo firma cambios de la device list
 │
 ├─ Device key A (Ed25519 firma + X25519 cifrado)
 ├─ Device key B …
 └─ Device list firmada + contador de versión monótono = identidad pública
```

- Cada dispositivo tiene su propia clave. Las privadas nunca se copian entre dispositivos.
- Cifrar para alguien = cifrar para todas sus device keys (age multi-recipient).
- Firmar = la device key firma; la firma incluye la device list vigente.
- Pérdida total de dispositivos → las 24 palabras regeneran la root, se revoca todo.
- **Almacenamiento:** Secure Enclave no soporta curvas 25519, así que las claves van
  en software envueltas con una KEK atada a hardware (Secure Enclave, Android
  StrongBox/Keystore, TPM/Windows Hello, Keychain/libsecret) + desbloqueo biométrico.
  Biometría por operación (firmar/descifrar).

### Cambios de la device list

Un dispositivo solo **no** puede cambiar la lista de inmediato: si pudiera, un celu
robado podría revocar a todos los demás.

| Cambio hecho con | Efecto |
|---|---|
| 2 dispositivos, o las 24 palabras | Inmediato |
| 1 solo dispositivo | A las 72 h, salvo veto de otro dispositivo ("¿Fuiste vos?") |

- **Agregar** dispositivo ya usa dos naturalmente: el viejo escanea el QR del nuevo.
- **Revocar** desde un dispositivo + confirmación de otro → inmediato.
- Los cambios de lista son raros (cambio de celu cada 2–3 años): la fricción es rara.

### No cifrar para uno mismo

Los archivos enviados **no** se cifran también para las device keys propias. El
original ya está en claro en el dispositivo emisor. Evita que un dispositivo robado
y todavía no revocado lea lo enviado.

## Consistencia eventual y revocación

No hay fuente única de verdad: cada contacto guarda su copia de tu device list.

Escenario: te roban el celu, revocás (v5). Tu vieja tiene v4 y cifra también para el
celu robado hasta enterarse. Mitigaciones:

- **Contador monótono**: nunca se acepta una versión menor a la conocida.
- **Lista adjunta y cubierta por la firma** en cada `.age`/`.sig`: un MITM no puede
  quitarla ni reemplazarla sin romper la firma (formato: firmar, después cifrar).
- **Vencimiento**: la lista expira a los 30 días; los dispositivos la re-firman solos.
  Lista vencida → la app avisa antes de cifrar.
- **Sync prioritario entre dispositivos propios** y push de la revocación a todos los
  contactos alcanzables.
- **Gossip** (ver abajo).

Bloqueo total de la comunicación no lo resuelve ningún protocolo; para eso está el
vencimiento.

## Gossip de device lists

- **Directo:** cada mensaje lleva la lista del emisor; en cada conexión P2P se
  intercambian versiones y gana la más alta (verificada contra la root).
- **Transitivo:** un tercero puede reenviar tu lista (no puede falsificarla: está
  firmada por tu root).
- **Escala:** solo se intercambian listas de contactos en común. Nunca viaja la
  agenda entera.
- **Privacidad:** intersección con salt de sesión. Cada parte envía
  `H(salt ‖ pubkey)` de sus contactos; solo puede reconocer claves que ya conoce.
  Se filtra únicamente "los dos conocemos a X".
- Gossip transitivo **opt-in** ("aceptar actualizaciones de terceros").

## Formatos

| Qué | Formato | Por qué |
|---|---|---|
| Cifrado | age (X25519; híbrido ML-KEM768+X25519 a futuro por defecto) | Auditado, interopera con el CLI `age` |
| Firma | Ed25519 desprendida + device list embebida | Verificable offline |
| Contacto | `pkpt1…` en Bech32 | Case-insensitive, sin chars ambiguos, URL-safe, checksum, QR alfanumérico |

## Transporte

1. **Agnóstico (prioridad):** el `.age` viaja por cualquier canal: WhatsApp, mail,
   pendrive. Es el 90 % del valor y no depende de infraestructura.
2. **P2P (después):** iroh (QUIC sobre UDP, hole punching, fallback a relay ciego).
   El NodeId de iroh es Ed25519 → puede ser o derivarse de la device key.
   - Hole punching falla con NAT simétrico/CGNAT → relay (HTTPS:443).
   - iOS mata apps en background → **buzón** en el relay con blobs cifrados.
   - Metadata: en P2P se ven IPs. Avisar en la UI, no prometer anonimato.

## Stack

- **Core:** Rust (`age`, `ed25519-dalek`, `iroh`, `bip39`).
- **UI:** Tauri 2 (desktop + iOS/Android). Plan B mobile: Flutter + `flutter_rust_bridge`.
- **Web:** no. Como mucho, página estática solo para verificar firmas.

## Amenazas

- **Phishing de identidad** → UI que distinga muy fuerte verificado / no verificado.
- **Dispositivo robado** → KEK en hardware, biometría por operación, time-lock de revocación.
- **Pérdida del papel** → irrecuperable. Decirlo con todas las letras en el onboarding.
- **Supply chain** → builds reproducibles, releases firmadas con pkpt.

## Legal (AR)

Firmar con pkpt es **firma electrónica**, no firma digital (Ley 25.506; la digital
requiere certificador licenciado). Sirve para "esto lo mandé yo", no reemplaza
firma digital en contratos.

## Nicho

Entrada: profesionales que reciben documentación sensible de clientes (contadores,
abogados, médicos, RRHH). El profesional paga / motiva; sus clientes usan gratis.
Diferencial: no compite con WhatsApp, viaja por adentro de WhatsApp. Sin cuenta, sin
servidor, compatible con age.

## Roadmap

1. MVP desktop: identidad, contactos (QR/link), cifrar/abrir, firmar/verificar.
2. Mobile + agregar dispositivos por QR.
3. Revocación con time-lock + gossip de device lists.
4. P2P con iroh + buzón.
5. Post-cuántico por defecto, pruebas de identidad opcionales.
