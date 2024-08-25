from scapy.all import IP, ICMP, Raw, send
import argparse
import time

def cifrado_cesar(texto, desplazamiento):
    texto_cifrado = ""
    
    for char in texto:
        if char.isalpha():  # Verifica si el carácter es una letra
            base = ord('A') if char.isupper() else ord('a')
            texto_cifrado += chr((ord(char) - base + desplazamiento) % 26 + base)
        else:
            texto_cifrado += char
    
    return texto_cifrado

def enviar_paquete_icmp(dato, destino):
    paquete = IP(dst=destino) / ICMP() / Raw(load=dato.encode())
    send(paquete, verbose=0)
    print(f"Paquete ICMP enviado con dato: {dato}")

def main():
    parser = argparse.ArgumentParser(description='Cifrado César y envío de paquetes ICMP.')
    #parser.add_argument('destino', type=str, help='La dirección IP o el nombre del host de destino.')
    parser.add_argument('texto', type=str, help='El texto a cifrar y enviar.')
    parser.add_argument('desplazamiento', type=int, help='El número de posiciones para el desplazamiento del cifrado César.')
    
    args = parser.parse_args()
    
    texto_original = args.texto
    desplazamiento = args.desplazamiento
    destino = "8.8.8.8"
    
    # Cifrar el texto
    texto_encriptado = cifrado_cesar(texto_original, desplazamiento)
    print(f"Texto cifrado: {texto_encriptado}")

    # Enviar paquetes ICMP con el texto cifrado
    for caracter in texto_encriptado:
        enviar_paquete_icmp(caracter, destino)
        time.sleep(1)  # Esperar 1 segundo entre envíos para evitar congestión

if __name__ == "__main__":
    main()

#interfaz de red 
#identifica que es un protocolo icmp. icmp type tambien es importante, el original es 8, pero el nuestro es 9.
#tambien revisar el data lenght en ICMP de los paquetes reales y simulados
#sudo python3 enviar_ping.py 0.0.0.0 "Texto a enviar" 9