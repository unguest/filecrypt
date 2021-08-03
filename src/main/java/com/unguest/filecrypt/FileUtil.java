package com.unguest.filecrypt;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;

public class FileUtil {

    public static String readFile(String filename) {
        String res = new String();
        try {
            File fileObj = new File(filename);
            Scanner fileReader = new Scanner(fileObj);
            while (fileReader.hasNextLine()) {
                String data = fileReader.nextLine();
                res += data;
            }
            fileReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred while reading file " + filename + '.');
            e.printStackTrace();
        }

        return res;
    }

    public static void writeFile(String filename, String toWrite) {
        try {
            File fileObj = new File(filename);
            fileObj.createNewFile(); // Creates the file if it does not already exists
            FileWriter fileWriter = new FileWriter(filename);
            fileWriter.write(toWrite);
            fileWriter.close();
        } catch (IOException e) {
            System.out.println("An error occurred while writing to " + filename + '.');
            e.printStackTrace();
        }
    }
}
