/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ejemplos;

/**
 *
 * @author demon
 */

import java.io.IOException;
import java.io.InputStream;
import java.security.*;

import javax.crypto.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/*

La libreria de BC, nos sirve para el calculo de los numeros p q n
que son grandotes, para la generacion de llaves publicas y privadas
para el algoritmo de rsa

BC no maneja de forma correcta el modo ECB Modo a bloques, por el tamaño
de la llave que debe de ser 512  hay que realizar ese bloque a mano

*/

public class RSALib {
    
    public static void main(String[] args) throws Exception {
        
        //Primero que tenemos que hacer es añadir el nuevo Provider
        //security no tiene ahorita el soporte de BC
        Security.addProvider(new BouncyCastleProvider());
        //esto sirve para la generacion de las llaves
        
        System.out.println("1.- Crear las llaves pública y privada");
        
        //tenemos que ocupar a la clase KeyPairGenerator
        
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
        
        //inicializar el tamaño de la llave
        
        keygen.initialize(1024);
        
        //vamos a asignar las llaves publica y privada
        
        KeyPair clavesRSA = keygen.generateKeyPair();
        
        //definimos la llave pública
        
        PublicKey clavePublica = clavesRSA.getPublic();
        
        
        
        //definimos a la llave privada
        
        PrivateKey clavePrivada = clavesRSA.getPrivate();
        
        System.out.println("2.- Introducir el texto plano a cifrar (maximo 64 caracteres)");
        
        
        
        
        
        
        //almacenar el texto en un arreglo de bytes
        
        byte[] bufferplano = leerLinea(System.in);
        
        //cifrar
        
        Cipher cifrado = Cipher.getInstance("RSA", "BC");
        
        //ciframos con publica
        
        cifrado.init(Cipher.ENCRYPT_MODE, clavePublica);
        
        System.out.println("3.- Ciframos con clave pública ");
        
        byte[] buffercifrado = cifrado.doFinal(bufferplano);
        
        System.out.println("Texto Cifrado : ");
        //no tiene formato el texto asi que es binario
        mostrarBytes(buffercifrado);
        
        System.out.println("");
        
        
        
        
        
        
        //descifrar con clave privada
        
        cifrado.init(Cipher.DECRYPT_MODE, clavePrivada);
        
        System.out.println("4 .- Desciframos con clave privada ");
        
        byte[] bufferdescifrado = cifrado.doFinal(buffercifrado);
        
        System.out.println("Texto Descifrado: ");
        
        mostrarBytes(bufferdescifrado);
        
        System.out.println("");
        
        
        
        
        
    }

    public static byte[] leerLinea(InputStream in) throws IOException {
        byte[] buffer1 = new byte[1000];
        int i = 0;
        byte c;
        
        c = (byte)in.read();
        
        while((c != '\n') && (i < 1000)){
            buffer1[i] = c;
            c = (byte)in.read();
            i++;
        }
        
        byte[] buffer2 = new byte[i];
        for(int j = 0; j < i; j++){
            buffer2[j] = buffer1[j];
        }
        return buffer2;
    }

    public static void mostrarBytes(byte[] buffer) {
        System.out.write(buffer, 0, buffer.length);
    }
    
}
