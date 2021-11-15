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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

import sun.misc.BASE64Encoder;


public class FirmaDigitalSimple {
    
    public static void main(String[] args) throws Exception {
        
        //realizar la instancia del algoritmo RSA
        KeyPairGenerator generadorRSA = KeyPairGenerator.getInstance("RSA");
        
        //inicilizar la llave
        generadorRSA.initialize(4096);
        
        //realizar las llaves
        KeyPair llaves = generadorRSA.genKeyPair();
        
        
        //texto
        byte[] data = "Habia una vez un patito".getBytes("UTF8");
        
        //vamos a preparar la firma
        
        Signature firma = Signature.getInstance("MD5WithRSA");
        
        //inicializarla para la llave privada
        
        firma.initSign(llaves.getPrivate());
        
        //actualizamos el documento
        firma.update(data);
        
        //vamos a firmar el documento
        byte[] firmadocumento = firma.sign();
        
        System.out.println("La firma digital es: " 
                + new BASE64Encoder().encode(firmadocumento));
        
        
        
        
        
        
        
        
        
        
        //proceso de verificacion de la firma
        
        firma.initVerify(llaves.getPublic());
        
        //vamos a actualizar el edo del documento
        firma.update(data);
        
        System.out.println("¿El documento es veridico? "
                + firma.verify(firmadocumento));
    }
    
}
