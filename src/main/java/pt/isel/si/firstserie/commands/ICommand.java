package pt.isel.si.firstserie.commands;

import java.io.File;

/**
 * Commands interface
 * All commands should implement this interface
 */
public interface ICommand {

    /**
     *  Executes the command
     *
     * @param jwt file to cipher or decipher
     * @param cert .cert or .pfx file
     * @throws Exception
     */
    void execute(File jwt, File cert) throws Exception;

}
