/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package clases;

import static ejemplos.RSALib.leerLinea;
import static ejemplos.RSALib.mostrarBytes;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import sun.misc.BASE64Encoder;

/**
 *
 * @author sofo9
 */
public class CipherAndAsignature {
    
    public CipherAndAsignature(){}

    /**
     * 
     * @param dirrecion
     * @param mensaje
     * @return también generarán el cifrado, llaves, firma 
     */
    public void CifrarYFirmar(String mensaje,String dirrecion) {
        
        //Genero mis llaves y las guardó
        try{
            this.generarLlaves();
            
            this.saveKey(this.publica, dirrecion, mensaje.getBytes()[0] + ".publickey");
            this.saveKey(this.privada, dirrecion, mensaje.getBytes()[0] + ".privatekey");
            
        }catch(Exception e){
            System.out.println("Error al generar y guardar las llaves");
            System.out.println(e.getMessage());
        }
        
        byte[] cifrado = null;
        
        //Cifro y lo guardo
        try{
            cifrado = this.CifrarRSA(mensaje.getBytes());
            this.saveBytes(cifrado, dirrecion, mensaje.getBytes()[0] + ".cifrado");
        }catch(Exception e){
            System.out.println("Error al cifrar");
            System.out.println(e.getMessage());
        }
        
        byte[] firmafichero = null;
        
        //Ahora con el cifrado voy a firmarlo
        try{
            
            firmafichero = this.Firmar(cifrado);
            this.saveBytes(firmafichero, dirrecion, mensaje.getBytes()[0] + ".firma");
            
        }catch(Exception e){
            System.out.println("Error al firmar");
            System.out.println(e.getMessage());
        }
        
       
        
        
    }
    
    public String ValidarYDescifrar(String dirrecionPublica, String dirrecionPrivada,
                                    String dirrecionCifrado, String dirrecionFirma){
        String secreto = null;
        
        // Primero necesito las claves dada la dirreción
        PublicKey pubKey = null;
        PrivateKey priKey = null;
        try{
            pubKey = this.loadPublicKey(dirrecionPublica);
            priKey = this.loadPrivateKey(dirrecionPrivada);
            
            this.privada = priKey;
            this.publica = pubKey;
        }catch(Exception e){
            System.out.println("Error al leer las claves");
            System.out.println(e.getMessage());
        }
        
        //Asigno los valores al objeto, para que el método funcione
        boolean validado = false;
        byte[] cifrado =null;
        byte[] firma =null;
        
        try{
            cifrado = this.loadBytes(dirrecionCifrado);
            firma = this.loadBytes(dirrecionFirma);
        }catch(Exception e){
            System.out.println("Error al leer el cifrado y la firma");
            System.out.println(e.getMessage());
        }
        
        
        try{
            validado = this.validarFirmar(cifrado, firma);
        }catch(Exception e){
            System.out.println("Error al validar el cifrado ");
        }
        
        if(validado){
            //Si esta validado el archivo entonces lo descifro.
            try{
                secreto = this.descifrarRSA(cifrado);
            }catch(Exception e){
                System.out.println("Error en el descifrado");
                System.out.println(e.getMessage());
            }
        }
        return secreto;
    }
    
    
    
    private void generarLlaves() throws NoSuchAlgorithmException {
        
         //generar las llaves de rsa
        KeyPairGenerator generadorRSA = KeyPairGenerator.getInstance("RSA");
        KeyPair llavesRSA = generadorRSA.generateKeyPair();
        
        //generamos publica y privada
        PublicKey llavePublica = llavesRSA.getPublic();
        PrivateKey llavePrivada = llavesRSA.getPrivate();
        
        this.publica = llavePublica;
        this.privada = llavePrivada;
    }
    
    private PublicKey publica;
    private PrivateKey privada;
    
    

    /**
     * 
     * @param bytes
     * @return el cifrado, nos signo los valores de las llaves
     * @throws Exception 
     */
    private byte[] CifrarRSA(byte[] bytes) throws Exception {
        
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, this.publica);
        
        return rsa.doFinal(bytes);
    }

    
    
    
    /**
     * 
     * @param cifrado
     * @return El fifrado y le asigno valor a la firma
     * @throws Exception 
     */
    
    private byte[] Firmar(byte[] cifrado)throws Exception {

        //vamos a preparar la firma
        Signature firma = Signature.getInstance("MD5WithRSA");
        
        //inicializarla para la llave privada
        firma.initSign(this.privada);
        
        //actualizamos el documento
        firma.update(cifrado);
        
        //Obtenemos la firma digital
        return firma.sign();
    }
    
    
    /**
     * 
     * @param cifrado
     * @param firmadocumento
     * @return Boolean para ver si es veridico
     * @throws Exception 
     */
    private boolean validarFirmar(byte[] cifrado, byte[] firmadocumento)throws Exception {

        //vamos a preparar la firma
        Signature firma = Signature.getInstance("MD5WithRSA");
        
        //inicializarla para la llave privada
        firma.initSign(this.privada);
        
        //proceso de verificacion de la firma
        firma.initVerify(this.publica);
        
        //vamos a actualizar el edo del documento
        firma.update(cifrado);
        
        //Validamos el firma documento
        return firma.verify(firmadocumento);
    }
    
    
    /**
     * 
     * @param key
     * @param dirrecion
     * @param nombre del archivo que se generará
     * @throws FileNotFoundException
     * @throws IOException 
     */
    private static void saveKey(Key key, String dirrecion , String nombre) throws FileNotFoundException, IOException {
        byte[] llavesPubPriv = key.getEncoded();
        //genero mi archivo
        FileOutputStream fos = new FileOutputStream(dirrecion+"/"+nombre);
        fos.write(llavesPubPriv);
        fos.close();
    }

    /**
     * 
     * @param firmaOCifrado
     * @param dirrecion
     * @param nombre
     * @throws Exception 
     */
    private void saveBytes(byte[] firmaOCifrado, String dirrecion , String nombre) throws Exception {
        //genero mi archivo
        FileOutputStream fos = new FileOutputStream(dirrecion+"/"+nombre);
        fos.write(firmaOCifrado);
        fos.close();
    }

    private  PublicKey loadPublicKey(String archivo) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
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

    private  PrivateKey loadPrivateKey(String archivo) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
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
    
    private byte[] loadBytes(String dirrecion) throws FileNotFoundException, IOException{
        FileInputStream fis = new FileInputStream(dirrecion);
        int numbytes = fis.available();
        byte[] bytes = new byte[numbytes];
        fis.read(bytes);
        fis.close();
        return bytes;
    }

    private String descifrarRSA(byte[] cifrado) throws Exception  {
       
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        
        //descifrar
        rsa.init(Cipher.DECRYPT_MODE, this.privada);
        byte[] bytesdescifrados = rsa.doFinal(cifrado);
        return new String(bytesdescifrados);
    }
    
    
}
