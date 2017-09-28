import com.sun.org.apache.xml.internal.security.utils.Base64;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class Main {
    //  private static byte[] key = { 'a','b','c','e','d','5','5','6','9','a','d','g','r','y','g','5' };
    private static byte[] key = {'T', 'h', 'e', 'B', 'e', 's', 't', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y'};
    // private static byte[] key = { 0x2d, 0x2a, 0x2d, 0x42, 0x55, 0x49, 0x4c, 0x44, 0x41, 0x43, 0x4f, 0x44, 0x45, 0x2d, 0x2a, 0x2d };


    public static String encrypt(String plainText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] cipherText = cipher.doFinal(plainText.getBytes("UTF8"));
            String encryptedString = new BASE64Encoder().encode(cipherText);
            //Cipher.txt
            try {
                Path file = Paths.get("/Users/sirawich/Desktop/Cipher.txt");
                BufferedWriter writer = Files.newBufferedWriter(file,
                        StandardCharsets.UTF_8);

                //for (int i = 0; i < 20; i++) {
                writer.write("Cipher : " + cipherText);
                writer.newLine();
                //}

                writer.close();
            } catch (IOException e) {
                System.err.println("IOException: " + e.getMessage());
            }
            return encryptedString;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String encryptedText) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] cipherText = new BASE64Decoder().decodeBuffer(encryptedText);
            String decryptedString = new String(cipher.doFinal(cipherText), "UTF-8");

            return decryptedString;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        //ReadFiles

        try {
            Path file = Paths.get("/Users/sirawich/Desktop/plainText.txt");
            BufferedReader reader = Files.newBufferedReader(file,
                    StandardCharsets.UTF_8);

            String line;


            while (((line = reader.readLine()) != null)) {
                String encrypted = encrypt(line);
                System.out.println("Encode plain text : "+encrypted);
                System.out.println("===make encrypted_file===");
                try {
                    Path en = Paths.get("/Users/sirawich/Desktop/encrypted_file.txt");
                    BufferedWriter writer = Files.newBufferedWriter(en,
                            StandardCharsets.UTF_8);

                    //for (int i = 0; i < 20; i++) {
                    writer.write("Encode plain text : " + encrypted);
                    writer.newLine();
                    //}

                    writer.close();
                } catch (IOException e) {
                    System.err.println("IOException: " + e.getMessage());
                }
                String decrypted = decrypt(encrypted);
                System.out.println("Decode plain text : "+decrypted);
                System.out.println("===make decrypted_file===");
                try {
                    Path de = Paths.get("/Users/sirawich/Desktop/decrypted_file.txt");
                    BufferedWriter writer = Files.newBufferedWriter(de,
                            StandardCharsets.UTF_8);

                    //for (int i = 0; i < 20; i++) {
                    writer.write("Decode plain text : " + decrypted);
                    writer.newLine();
                    //}

                    writer.close();
                } catch (IOException e) {
                    System.err.println("IOException: " + e.getMessage());
                }
            }

            reader.close();
        } catch (IOException e) {
            System.err.println("IOException: " + e.getMessage());
        }

        // WriteFiles
        /*try {
            Path file = Paths.get("C:\\Users\\heartbeetbug\\Desktop\\5635512091\\TextOut.txt");
            BufferedWriter writer = Files.newBufferedWriter(file,
                    StandardCharsets.UTF_8);

            //for (int i = 0; i < 20; i++) {
                writer.write("Encrypted String : : " +encryptedString);
                writer.newLine();
            //}

            writer.close();
        } catch (IOException e) {
            System.err.println("IOException: " + e.getMessage());
        }
        */

    }
}