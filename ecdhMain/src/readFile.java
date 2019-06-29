
import org.apache.commons.io.FilenameUtils;

import java.io.*;

public class readFile {


    /**
     * This method uses java.io.FileInputStream to read
     * file content into a byte array
     * @param file
     * @return
     */
    public static byte[] readFileToByteArray(File file){
        FileInputStream fis = null;
        // Creating a byte array using the length of the file
        // file.length returns long which is cast to int
        byte[] bArray = new byte[(int) file.length()];
        try{
            fis = new FileInputStream(file);
            fis.read(bArray);
            fis.close();

        }catch(IOException ioExp){
            ioExp.printStackTrace();
        }
        return bArray;
    }




    /**
     * This method saves a signature too a file
     * file content into a byte array
     * @param file
     * @return
     */


    public void saveByteArrayToFile(byte [] file, String file_name) {
        /* save the signature in a file */
        String fileNameWithOutExt = FilenameUtils.removeExtension(file_name);

        try {
            PrintWriter writer = new PrintWriter(fileNameWithOutExt + "-signature.txt", "UTF-8");
            writer.println(file);
            writer.println("The second line");
            writer.close();

        }
        catch (IOException err){

            System.out.println("an eceptin was caught"+ err);
        }
    }
}
