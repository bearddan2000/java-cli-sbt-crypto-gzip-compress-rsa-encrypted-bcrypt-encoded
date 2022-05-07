package example;

public class Main {



    // Driver code
    public static void main(String args[])
        throws Exception
    {

        Encryption rsa = new Encryption();

        String hash = Encode.hashpw(rsa, "pass123");

        boolean test1 = Encode.verify(rsa, "pass123", hash);
        boolean test2 = Encode.verify(rsa, "123pass", hash);

        System.out.println(String.format("%s, %s Match: %s", "pass123", "pass123", (test1) ? "True" : "False"));

        System.out.println(String.format("%s, %s Match: %s", "123pass", "pass123", (test2) ? "True" : "False"));
    }
}
