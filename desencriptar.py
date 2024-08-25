from scapy.all import sniff, IP, ICMP, Raw

# Constantes
NUM_DESPLAZAMIENTOS = 26
TIEMPO_CAPTURA = 20  # Aumenta el tiempo de captura a 30 segundos

def cifrado_cesar(texto, desplazamiento):
    texto_cifrado = ""
    
    for char in texto:
        if char.isalpha():  # Verifica si el carácter es una letra
            base = ord('A') if char.isupper() else ord('a')
            texto_cifrado += chr((ord(char) - base + desplazamiento) % 26 + base)
        else:
            texto_cifrado += char
    
    return texto_cifrado

def procesar_paquete(paquete):
    if paquete.haslayer(ICMP) and paquete.haslayer(Raw):
        # Verificar que el paquete es un echo request
        if paquete[ICMP].type == 8:  # Echo request
            # Extraer el mensaje cifrado
            mensaje_cifrado = paquete[Raw].load.decode()
            return mensaje_cifrado
    return None

def recibir_paquetes():
    try:
        paquetes = sniff(filter="icmp", prn=lambda p: procesar_paquete(p), timeout=TIEMPO_CAPTURA)
        mensajes_cifrados = [p for p in paquetes if p]
        return mensajes_cifrados
    except PermissionError:
        print("Error: Permiso denegado para capturar paquetes. Ejecute el script con permisos elevados.")
        return []

def generar_combinaciones(texto_cifrado):
    combinaciones = []
    for desplazamiento in range(NUM_DESPLAZAMIENTOS):
        texto_descifrado = cifrado_cesar(texto_cifrado, -desplazamiento)
        combinaciones.append(texto_descifrado)
    
    return combinaciones

def main():
    print("Esperando paquetes ICMP...")
    paquetes = recibir_paquetes()
    
    if not paquetes:
        print("No se recibieron paquetes.")
        return

    # Extraer y concatenar los mensajes cifrados de los paquetes
    mensajes_cifrados = [procesar_paquete(p) for p in paquetes if procesar_paquete(p)]
    
    if not mensajes_cifrados:
        print("No se encontraron mensajes cifrados en los paquetes.")
        return
    
    texto_cifrado = ''.join(mensajes_cifrados).strip()
    
    print(f"Texto cifrado recibido: {texto_cifrado}")

    combinaciones = generar_combinaciones(texto_cifrado)
    
    print("Posibles combinaciones del mensaje descifrado:")
    for combinacion in combinaciones:
        print(combinacion)

if __name__ == "__main__":
    main()
