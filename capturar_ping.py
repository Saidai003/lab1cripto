from scapy.all import sniff, ICMP, Raw
import argparse

def mostrar_paquete(paquete):
    print(f"Paquete recibido: {paquete.summary()}")
    if ICMP in paquete:
        icmp = paquete[ICMP]
        print(f"Tipo: {icmp.type}, Código: {icmp.code}, Identificador: {icmp.id}, Secuencia: {icmp.seq}")
    if Raw in paquete:
        print(f"Datos: {bytes(paquete[Raw].load)}")

def capturar_ping(destino, tiempo):
    print("Capturando paquetes ICMP Echo Request reales:")
    paquetes = sniff(filter=f"icmp and host {destino}", timeout=tiempo)
    for paquete in paquetes:
        mostrar_paquete(paquete)

def main():
    parser = argparse.ArgumentParser(description='Captura de paquetes ICMP.')
    parser.add_argument('destino', type=str, help='La dirección IP o el nombre del host de destino.')
    parser.add_argument('tiempo', type=int, help='El número de segundos para capturar paquetes.')

    args = parser.parse_args()
    
    destino = args.destino
    tiempo = args.tiempo

    # Captura de paquetes ICMP reales antes de enviar los personalizados
    print("Captura de ping real antes de enviar paquetes personalizados...")
    capturar_ping(destino, tiempo)

    # Captura de paquetes ICMP personalizados
    print("Captura de ping real después de enviar paquetes personalizados...")
    capturar_ping(destino, tiempo)

if __name__ == "__main__":
    main()