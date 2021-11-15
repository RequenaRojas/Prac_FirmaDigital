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
import java.io.*;

import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;





public class AlmacenarLlaves {
    
    public static void main(String[] args) throws Exception{
    
        if(args.length != 1){
            mensajeAyuda();
            System.exit(1);
        }
        
        System.out.println("Crear los archivos: " +args[0]+".secreta"
        +args[0]+".privada" +args[0]+".publica");
        
        //agregar BC al provider Security
        Security.addProvider(new BouncyCastleProvider());
        
        //vamos a empezar por la claves de RSA
        
        KeyPairGenerator generadorRSA = KeyPairGenerator.getInstance("RSA", "BC");
        
        generadorRSA.initialize(1024);
        
        KeyPair clavesRSA = generadorRSA.generateKeyPair();
        
        //privada y publica
        
        PrivateKey clavePrivada = clavesRSA.getPrivate();
                
        PublicKey clavePublica = clavesRSA.getPublic();
        
        //proceso de revocacion de la firma digital
        
        
        KeyFactory fabricallavesRSA = KeyFactory.getInstance("RSA","BC");
        
        //codificar la clave privada con PKCS8 
        
        PKCS8EncodedKeySpec pkcs8spec = new PKCS8EncodedKeySpec(clavePrivada.getEncoded());
        
        //archivo para la clave privada codificada con PKCS8
        
        FileOutputStream out = new FileOutputStream(args[0]+".privada");
        out.write(pkcs8spec.getEncoded());
        out.close();
        
        
        byte[] bufferprivado = new byte[5000];
        FileInputStream in = new FileInputStream(args[0]+".privada");
        in.read(bufferprivado, 0, 5000);
        in.close();
        
        
        
        //proceso para recuperar la llave privada 
        PKCS8EncodedKeySpec clavePrivadaspec = new PKCS8EncodedKeySpec(bufferprivado);
        
        PrivateKey clavePrivada2 = fabricallavesRSA.generatePrivate(clavePrivadaspec);
        
        if(clavePrivada.equals(clavePrivada2)){
            System.out.println("OK. la clave privada ha sido guardada y verificada");
        }
        
        //volcado de la llave publica con x509
        
        X509EncodedKeySpec x509spec = new X509EncodedKeySpec(clavePublica.getEncoded());
        
        //vamos a crear el archivo de salida
        
        out = new FileOutputStream(args[0]+".publica");
        out.write(x509spec.getEncoded());
        out.close();
        
        //recuperacion de la firma vs fichero
        byte[] bufferpublico = new byte[5000];
        in = new FileInputStream(args[0]+".publica");
        in.read(bufferpublico, 0, 5000);
        in.close();
        
        //proceso del volcado para verificar las firmas publicas
        
        X509EncodedKeySpec clavePublicaspec = new X509EncodedKeySpec(bufferpublico);
        
        PublicKey clavePublica2 = fabricallavesRSA.generatePublic(clavePublicaspec);
        
        if(clavePublica.equals(clavePublica2)){
            System.out.println("Ok, clave publica ha sido guarda y verificada");
        }
        
        
        KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
        
        generadorDES.init(56);
        
        SecretKey claveSecreta = generadorDES.generateKey();
        
        SecretKeyFactory llavessecretasDES = SecretKeyFactory.getInstance("DES");
        
        out = new FileOutputStream(args[0]+".secreta");
        out.write(claveSecreta.getEncoded());
        out.close();
        
        byte[] buffersecreta = new byte[5000];
        in.read(buffersecreta, 0, 5000);
        in.close();
        
        DESKeySpec DESspec = new DESKeySpec(buffersecreta);
        SecretKey claveSecreta2 = llavessecretasDES.generateSecret(DESspec);
        
        if(claveSecreta.equals(claveSecreta2)){
            System.out.println("ok, clave secreta guardad y verificada");
        }
        
    }

    public static void mensajeAyuda() {
        System.out.println("Ejemplo de almacenamiento de llaves ");
    }
    
}
