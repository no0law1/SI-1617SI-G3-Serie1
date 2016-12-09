package pt.isel.si.firstserie.commands;

import java.io.File;
import java.util.Scanner;

/**
 * TODO: Commentary
 */
public abstract class CommandWithPassword {

    //private final Scanner scanner = new Scanner(System.in);

    int MIN_ITERATION_COUNT = 1000;

    String ALGORITHM = "PBEWithHmacSHA256AndAES_128";

    int KEY_SIZE = 128;

    String getPassword(){
        System.out.println("Enter your password: ");
        return new Scanner(System.in).nextLine();
    }

    public abstract void execute(File file) throws Exception;
}
