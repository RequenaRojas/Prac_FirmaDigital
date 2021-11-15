package ejemplos;

import java.io.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;



public class ImportExportFirmas {
    
    private static Cipher rsa;
    
    public static void main(String[] args)throws Exception{
        
        //generar las llaves de rsa
        KeyPairGenerator generadorRSA = KeyPairGenerator.getInstance("RSA");
        KeyPair llavesRSA = generadorRSA.generateKeyPair();
        
        //generamos publica y privada
        PublicKey llavePublica = llavesRSA.getPublic();
        PrivateKey llavePrivada = llavesRSA.getPrivate();
        
        
        
        //los metodos para guardar y cargar las llaves .key
        saveKey(llavePublica, "publicKey.key");
        
        
        llavePublica = loadPublicKey("publicKey.key");
        
        //los metodos para guardar y cargar las llaves .key
        saveKey(llavePrivada, "privateKey.key");
        llavePrivada = loadPrivateKey("privateKey.key");
        
        rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        
        String text = "Habia una vez un patito que decia miau miau";
        
        rsa.init(Cipher.ENCRYPT_MODE, llavePublica);
        
        //doy forma al arreglo de bytes
        byte[] cifrado = rsa.doFinal(text.getBytes());
        
        
        //descifrar
        rsa.init(Cipher.DECRYPT_MODE, llavePrivada);
        byte[] bytesdescifrados = rsa.doFinal(cifrado);
        String textodescifrado = new String(bytesdescifrados);
        System.out.println("Mensaje Descifrado: " + textodescifrado);
        
    }

    private static void saveKey(Key key, String archivo) throws FileNotFoundException, IOException {
        byte[] llavesPubPriv = key.getEncoded();
        //genero mi archivo
        FileOutputStream fos = new FileOutputStream(archivo);
        fos.write(llavesPubPriv);
        fos.close();
    }

    private static PublicKey loadPublicKey(String archivo) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileInputStream fis = new FileInputStream(archivo);
        int numbytes = fis.available();
        byte[] bytes = new byte[numbytes];
        fis.read(bytes);
        fis.close();
        
        //hay que verificar esa llave
        KeyFactory fabricallaves = KeyFactory.getInstance("RSA");
        //voy a generar la comparacion de las llaves del archivo vs la llave del programa
        KeySpec keyspec = new X509EncodedKeySpec(bytes);
        PublicKey llavedelarchivo = fabricallaves.generatePublic(keyspec);
        return llavedelarchivo;
    }

    private static PrivateKey loadPrivateKey(String archivo) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileInputStream fis = new FileInputStream(archivo);
        int numbytes = fis.available();
        byte[] bytes = new byte[numbytes];
        fis.read(bytes);
        fis.close();
        
        KeyFactory fabricallaves = KeyFactory.getInstance("RSA");
        KeySpec keyspecprivada = new PKCS8EncodedKeySpec(bytes);
        PrivateKey llavedelarchivopriv = fabricallaves.generatePrivate(keyspecprivada);
        return llavedelarchivopriv;
    }
    
}