/*

ABDULGAFFAR ABDULMALIK 15/52HL001
 */
import java.security.*;
import java.util.Arrays;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.*;
import java.io.*;
import java.time.Duration;
import java.time.Instant;

public class ecdhMain{


        public static void main(String[] args) {

            try{
                /**
                 * ECC signature ECDH Settings
                 **/

                ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable
                        .getParameterSpec("prime192v1");
                Security.addProvider( new org.bouncycastle.jce.provider.BouncyCastleProvider());
                KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
                g.initialize(ecSpec, new SecureRandom());
                // Genarate keypair
                KeyPair pair = g.generateKeyPair();
                Signature sig = Signature.getInstance("RIPEMD160withECDSA", "BC");
                File file = new File("C:\\Users\\Emperor_orbitz\\IdeaProjects\\ecdhMain\\src\\files\\test.txt");
                System.out.println("Provider Name :"+ BouncyCastleProvider.PROVIDER_NAME);

                /**
                 * END ECC signature ECDH Settings
                 **/




                /**
                 * Genarate Private and Public keys
                 **/
                PublicKey pubKey = pair.getPublic();
                PrivateKey prikey = pair.getPrivate();

                /**
                 * END Private/ public key generation signature
                 **/






                /**
                 * SIGN the data using private key AND save to file
                 */
               byte[] sign_return = sign(sig, prikey, file);

                readFile pre = new readFile();
                pre.saveByteArrayToFile(sign_return, file.getName());

                //System.out.println("Sign byte array:" + Arrays.toString(sign_return) +"\n SIGNATURE TIME:");
                /**
                 * END SIGN the data using private key AND save to file
                 */







                /**
                  * VERIFY file through signature byte
                 **/
               boolean truefalse = verify (sig, sign_return, file, pubKey);

                /**
                 * END Verification
                 */



            } catch (Exception e) {
                e.printStackTrace();
            }


        }




/*

SIGNATURE AND VERIFICATION UTILITIES
 */

public static byte [] sign(Signature signInstance, PrivateKey privateKey, File file) {

    byte[] signatureBytes = new byte[0];


    try {


        readFile pre = new readFile();
        byte[] inputData = pre.readFileToByteArray(file);
        signInstance.initSign(privateKey);
        signInstance.update(inputData);

        Instant start = Instant.now();
        signatureBytes = signInstance.sign();
        Instant stop = Instant.now();
        Duration timeElapsed = Duration.between(start, stop);
        System.out.println("Time taken for SIGNATURE: "+ timeElapsed.toMillis() +" milliseconds");

    } catch (Exception e) {
        e.printStackTrace();
    }



    return signatureBytes;
}









private static boolean verify(Signature signInstance, byte [] signatureBytes, File file , PublicKey pubKey){
    Boolean ver = null;

     try {

         readFile pre = new readFile();
         byte[] inputData = pre.readFileToByteArray(file);
         signInstance.initVerify(pubKey);
         signInstance.update(inputData);



         Instant start = Instant.now();
         ver = signInstance.verify(signatureBytes);

         Instant stop = Instant.now();
         Duration timeElapsed = Duration.between(start, stop);

         System.out.println("TIME FOR VERIFYING IS: " + timeElapsed.toMillis()+ " milliseconds" );


     }


     catch(Exception e){

         e.printStackTrace();


     }
       return ver;
}




    }





