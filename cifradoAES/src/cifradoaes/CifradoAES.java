/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package cifradoaes;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author x
 */
public class CifradoAES {
    //El algoritmo AES/CBC es mas seguro, pero requiere un vector de inicializacion
    static String algorithm = "AES/CBC/PKCS5Padding";
    static String ej = "C:\\Users\\yo\\Desktop\\foto.jpg";

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        int e = 0;
        try {

            while (e == 1 || e == 2 || e == 0) {
                System.out.println("Cifrar archivo: -1 \nDescifrar archivo: -2 \nSalir: -0");
                e = new Scanner(System.in).nextInt();
                switch (e) {
                    case 1 -> {
                        System.out.println("Introduce la clave de cifrado");
                        String password = askString();
                        /*El salt se usa para cifrar la contraseña, es necesario conocer el salt para descifrar, el salt podria ser
                        aleatorio pero deberia conocerse tambien el salt para descifrar, para este ejemplo
                        extraemos el salt de la propia contraseña, el salt sera una parte de la contraseña
                        dependiendo de la longitud de esta;
                         */
                        String salt = mixSalt(password);
                        //genera la clave
                        SecretKey key = AESUtil.getKeyFromPassword2(password, getHash(salt));
                        //vector de inicializacion para aes CBC(vector de inicializacion)
                         /*
                        Este objeto se usa como vector de inicializacion para el cifrado de aes en 
                        modo cbc (utiliza los btes anteriores para cifrar los siguientes y necesita unos bytes iniciales), se podria usar numeros
                        aleatorios pero tambien son necesarios para el descifrado con lo cual ahora usaremos unos numeros fijos para no tener que guardar
                        el vector en alguna parte.
                        funcion para hacer el vector de inicializacion aleatorio: IvParameterSpec ivParameterSpec = AESUtil.generateIv();
                        */
                        IvParameterSpec ivParameterSpec = generaIv(password);
                        System.out.println("Introduce la ruta del archivo que desea encriptar:");
                        System.out.println("Por ejemplo: " + ej);
                        File in = new File(askString());
                        System.out.println("Introduce la ruta donde se guardara el archivo encriptado, si no introduces nada se guardara en la carpeta por defecto 'AES' ");
                        System.out.println("Por ejemplo: " + ej);
                        File out = new File(askString());
                        //si la ruta de destino esta vacia, usara una carpeta por defecto para guardar los archivos cifrados
                        if (pathEmpty(out)) {
                            out = rutaDefecto(out);
                        }
                        //comprueba que las rutas no son iguales y guarda el archivo cifrado
                        if (!testRutasIguales(in, out)) {
                            encriptar(key, ivParameterSpec, in, out);
                        } else {
                            errorMismaRuta();
                        }
                    }
                    case 2 -> {
                        System.out.println("Introduce la clave de cifrado");
                        String password = askString();
                        String salt = mixSalt(password);
                        SecretKey key = AESUtil.getKeyFromPassword2(password, getHash(salt));
                        IvParameterSpec ivParameterSpec = generaIv(password);
                        System.out.println("Introduce la ruta del archivo que desea desencriptar:");
                        System.out.println("Por ejemplo: " + ej);
                        File in = new File(askString());
                        System.out.println("Introduce la ruta donde se guardara el archivo desencriptado");
                        System.out.println("Por ejemplo: " + ej);
                        File out = new File(askString());
                        if (!testRutasIguales(in, out)) {
                            desencriptar(key, ivParameterSpec, in, out);
                        } else {
                            errorMismaRuta();
                        }
                    }
                    case 0 -> {
                        System.exit(0);
                    }
                }
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | java.util.InputMismatchException ex) {
            System.exit(0);
        }
    }

    private static String askString() {
        return new Scanner(System.in).nextLine();
    }

    private static void encriptar(SecretKey key, IvParameterSpec ivParameterSpec, File inputFile, File encryptedFile) {
        try {
            AESUtil.encryptFile(algorithm, key, ivParameterSpec, inputFile, encryptedFile);
        } catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException ex) {
            Logger.getLogger(CifradoAES.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static void desencriptar(SecretKey key, IvParameterSpec ivParameterSpec, File inputFile, File encryptedFile) {
        try {
            AESUtil.decryptFile(algorithm, key, ivParameterSpec, inputFile, encryptedFile);
        } catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException ex) {
            Logger.getLogger(CifradoAES.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static boolean testRutasIguales(File in, File out) {
        return in.getPath().equals(out.getPath());
    }

    private static void errorMismaRuta() {
        System.out.println("Error! La ruta de destino debe ser diferente a la ruta del archivo original\n");
    }

    private static File rutaDefecto(File out) {
        String path = "AES/";
        File carpeta = new File(path);
        int maxNumFiles = 999999;
        if (!carpeta.exists()) {
            carpeta.mkdir();
        }
        for (int cont = 0; cont < maxNumFiles; cont++) {
            carpeta = new File(path + "/" + cont);
            if (!carpeta.exists()) {
                return carpeta;
            } else if (cont > maxNumFiles) {
                System.out.println("Se ha superado el numero maximo de archivos en la carpeta por defecto");
            }
        }
        return null;
    }

    private static boolean pathEmpty(File out) {
        return out.getPath().equals("") || out.getPath().equals(" ");
    }

    private static IvParameterSpec generaIv(String password) {
        //utilizamos un hash para crear un vector de iniciacion a partir de la contraseña
        try {
            password = password + (password.length() + 7) + password + (password.length() + 11) + password.charAt(0) + password.substring(password.length() / 2) + password.substring(password.length() / 2, password.length() - 1);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] a = md.digest(password.getBytes(StandardCharsets.UTF_8));
            byte[] b = new byte[16];
            for (int cont = 15; cont < b.length; cont++) {
                b[cont] = a[cont];
            }
            return new IvParameterSpec(b);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CifradoAES.class.getName()).log(Level.SEVERE, null, ex);
            System.out.println("Error al crear vector de inicializacion");
            return null;
        }

    }

    private static byte[] getHash(String a) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
            byte[] b = md.digest(a.getBytes(StandardCharsets.UTF_8));
            return b;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CifradoAES.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    private static String mixSalt(String psswd) {
        String f = psswd;
        for (int cont = 0; cont < psswd.length(); cont++) {
            f= f+ (f.hashCode()/(cont+1))/11;
                if(f.length()>1000){
                    f=f.substring(f.length()-1000, f.length());
                }
        }
        return f;
    }
}
