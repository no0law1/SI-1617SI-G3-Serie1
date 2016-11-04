package pt.isel.si.firstserie.application;

import pt.isel.si.firstserie.application.command.CipherCommand;
import pt.isel.si.firstserie.application.command.DecipherCommand;
import pt.isel.si.firstserie.application.command.ICommand;

import java.io.File;
import java.util.HashMap;

/**
 * TODO: Commentary
 */
public class Application {

    private static HashMap<String, ICommand> commands;

    static {
        commands = new HashMap<>();
        commands.put("CIPHER", new CipherCommand());
        commands.put("DECIPHER", new DecipherCommand());
    }

    private String operation;
    private File file;
    private File jwFile;

    public Application(String operation, File jwFile, File file) {
        this.operation = operation.toUpperCase();
        this.jwFile = jwFile;
        this.file = file;
    }

    public static void main(String[] args) throws Exception {
        if(args.length < 3){
            throw new IllegalArgumentException("usage: Application {operation} {jwtFilePath} {cerFilePath}");
        }

        new Application(args[0], new File(args[1]), new File(args[2]))
                .run();
    }

    public void run() throws Exception {
        ICommand command = commands.get(operation);
        if(command == null){
            throw new UnsupportedOperationException(operation+" is not supported");
        }

        command.execute(file, jwFile);
    }
}
