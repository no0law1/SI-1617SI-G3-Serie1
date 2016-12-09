package pt.isel.si.firstserie;

import pt.isel.si.firstserie.commands.*;

import java.io.File;
import java.util.HashMap;

/**
 * Main entry for the program,
 * Receives commands from the args and executes them
 *
 * Example commands:
 * cipher C:\\file.txt C:\\certificate.cer
 * decipher C:\\encrypted.txt C:\\keystore.pfx
 */
public class Application {

    private static HashMap<String, ICommand> commands;
    private static HashMap<String, CommandWithPassword> commandsWithPassword;

    static {
        commands = new HashMap<>();
        commands.put("cipher", new CipherJWECommand());
        commands.put("decipher", new DecipherJWECommand());
        commandsWithPassword = new HashMap<>();
        commandsWithPassword.put("cipher", new CipherJWECommandWithPassword());
        commandsWithPassword.put("decipher", new DecipherJWECommandWithPassword());
    }

    /**
     * Main Entry
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {

        if(args.length < 2){
            throw new IllegalArgumentException("usage: Application {operation} {jwtFilePath} {cerFilePath} || {operation} {jwtFilePath}");
        }
        if(args.length == 3){
            run(args[0], new File(args[1]), new File(args[2]));
        } else {
            runWithPass(args[0], new File(args[1]));
        }
    }

    private static void runWithPass(String operation, File file) throws Exception {
        CommandWithPassword command = commandsWithPassword.get(operation.toLowerCase());
        if(command == null){
            throw new UnsupportedOperationException(operation+" is not supported");
        }

        command.execute(file);
    }

    /**
     * Finds the right command to execute and execute it
     * @param operation
     * @param file
     * @param cert
     * @throws Exception
     */
    private static void run(String operation, File file, File cert) throws Exception {
        ICommand command = commands.get(operation.toLowerCase());
        if(command == null){
            throw new UnsupportedOperationException(operation+" is not supported");
        }

        command.execute(file, cert);
    }
}
