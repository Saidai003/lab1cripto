import argparse

def cifrado_cesar(texto, desplazamiento):
    texto_cifrado = ""
    
    for char in texto:
        if char.isalpha():  # Verifica si el carácter es una letra
            base = ord('A') if char.isupper() else ord('a')
            texto_cifrado += chr((ord(char) - base + desplazamiento) % 26 + base)
        else:
            texto_cifrado += char
    
    return texto_cifrado

def main():
    parser = argparse.ArgumentParser(description='Cifrado César')
    parser.add_argument('texto', type=str, help='El texto a cifrar y enviar.')
    parser.add_argument('desplazamiento', type=int, help='El número de posiciones para el desplazamiento del cifrado César.')
    
    args = parser.parse_args()
    
    texto_original = args.texto
    desplazamiento = args.desplazamiento
    
    # Cifrar el texto
    texto_encriptado = cifrado_cesar(texto_original, desplazamiento)

    # Imprimir texto cifrado
    print(f"Texto cifrado: {texto_encriptado}")

if __name__ == "__main__":
    main()

#sudo python3 encriptacion.py "Texto a enviar" 9