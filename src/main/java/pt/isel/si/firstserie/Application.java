package pt.isel.si.firstserie;

import pt.isel.si.firstserie.commands.CipherJWECommand;
import pt.isel.si.firstserie.commands.DecipherJWECommand;
import pt.isel.si.firstserie.commands.ICommand;

import java.io.File;
import java.util.HashMap;

/**
 * Main entry for the program,
 * Receives commands from the args and executes them
 */
public class Application {

    private static HashMap<String, ICommand> commands;

    static {
        commands = new HashMap<>();
        commands.put("cipher", new CipherJWECommand());
        commands.put("decipher", new DecipherJWECommand());
    }

    /**
     * Main Entry
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {

        if(args.length < 3){
            throw new IllegalArgumentException("usage: Application {operation} {jwtFilePath} {cerFilePath}");
        }

        run(args[0], new File(args[1]), new File(args[2]));
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
