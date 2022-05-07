package example;

import org.mindrot.jbcrypt.*;
import java.io.IOException;
import javax.xml.bind.DatatypeConverter;

public class Encode {

  private static byte[] compress(String hash) throws IOException {
    return GZIPCompression.compress(hash);
  }

  private static String decompress(byte[] hash) throws IOException {
    return GZIPCompression.decompress(hash);
  }

  private static byte[] encrypt(Encryption rsa, String hash) throws Exception {

    byte[] cipherText = rsa.do_RSAEncryption(hash);

    String newHash = DatatypeConverter.printHexBinary(cipherText);

    return compress(newHash);
  }

  private static String decrypt(Encryption rsa, byte[] hash) throws Exception {

    String decompress = decompress(hash);

    return rsa.do_RSADecryption(DatatypeConverter.parseHexBinary(decompress));
  }

  public static String hashpw(Encryption rsa, String pass){
    String stored = BCrypt.hashpw(pass, BCrypt.gensalt());
    try {

      byte[] newHash = encrypt(rsa, stored);

      return DatatypeConverter.printHexBinary(newHash);

    } catch (Exception e) {
      return null;
    }
  }

  public static boolean verify(Encryption rsa, String pass, String hash){

    byte[] hashArray = DatatypeConverter.parseHexBinary(hash);

    try{

      String newHash = decrypt(rsa, hashArray);

      return BCrypt.checkpw(pass, newHash);

    } catch (Exception e) {

      System.out.println("Encode verify error");

      e.printStackTrace();

      return false;
    }
  }
}
